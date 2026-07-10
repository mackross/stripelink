package stripelink

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestTokenProviderConcurrentClientsConvergeOnStoredGeneration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		storages func(*testing.T) (AuthStorage, AuthStorage)
	}{
		{name: "memory instance", storages: func(t *testing.T) (AuthStorage, AuthStorage) {
			storage := &MemoryStorage{}
			return storage, storage
		}},
		{name: "file instances", storages: func(t *testing.T) (AuthStorage, AuthStorage) {
			path := filepath.Join(t.TempDir(), "auth.json")
			a, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			b, err := NewFileStorage(path)
			if err != nil {
				t.Fatal(err)
			}
			return a, b
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.storages(t)
			if err := storeAuth(a, storedToken("old", "single-use", time.Now().Add(-time.Hour))); err != nil {
				t.Fatal(err)
			}
			transport := newBlockingRefreshTransport()
			providers := []*tokenProvider{
				{storage: a, auth: testAuthResource(transport, a)},
				{storage: b, auth: testAuthResource(transport, b)},
			}
			results := make(chan string, 2)
			errs := make(chan error, 2)
			for _, provider := range providers {
				go func() {
					token, err := provider.token(t.Context(), AccessTokenRequest{ForceRefresh: true, RejectedToken: "old"})
					results <- token
					errs <- err
				}()
			}
			<-transport.started
			deadline := time.Now().Add(5 * time.Second)
			for transport.calls() < 2 {
				if time.Now().After(deadline) {
					t.Fatalf("refresh calls = %d, want both clients in flight", transport.calls())
				}
				runtime.Gosched()
			}
			close(transport.release)
			for range 2 {
				if err := <-errs; err != nil {
					t.Errorf("token error: %v", err)
				}
				if token := <-results; token != "new" {
					t.Errorf("token = %q, want new", token)
				}
			}
			if got := transport.calls(); got != 2 {
				t.Fatalf("refresh calls = %d, want 2 independent clients", got)
			}
		})
	}
}

func TestTokenProviderFreshExpiredAndMissing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := &MemoryStorage{}
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"access_token":"fresh","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`)
		auth := testAuthResource(rt, storage)
		provider := &tokenProvider{storage: storage, auth: auth}

		if _, err := provider.token(t.Context(), AccessTokenRequest{}); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("missing error = %v", err)
		}
		if err := storeAuth(storage, storedToken("current", "refresh", time.Now().Add(61*time.Second))); err != nil {
			t.Fatal(err)
		}
		got, err := provider.token(t.Context(), AccessTokenRequest{})
		if err != nil || got != "current" || len(rt.Requests()) != 0 {
			t.Fatalf("fresh token = %q, %v; requests=%d", got, err, len(rt.Requests()))
		}
		time.Sleep(time.Second)
		got, err = provider.token(t.Context(), AccessTokenRequest{})
		if err != nil || got != "fresh" || len(rt.Requests()) != 1 {
			t.Fatalf("refreshed token = %q, %v; requests=%d", got, err, len(rt.Requests()))
		}
		stored, _ := loadStoredAuth(storage)
		if stored == nil || stored.AccessToken != "fresh" || stored.RefreshToken != "rotated" {
			t.Fatalf("stored tokens = %#v", stored)
		}
	})
}

func TestTokenProviderRefreshIsSingleFlightAndGenerationAware(t *testing.T) {
	storage := &MemoryStorage{}
	if err := storeAuth(storage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	transport := newBlockingRefreshTransport()
	auth := testAuthResource(transport, storage)
	provider := &tokenProvider{storage: storage, auth: auth}

	const callers = 16
	results := make(chan string, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			token, err := provider.token(t.Context(), AccessTokenRequest{ForceRefresh: true, RejectedToken: "old"})
			results <- token
			errs <- err
		})
	}
	<-transport.started
	close(transport.release)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("token error: %v", err)
		}
	}
	for token := range results {
		if token != "new" {
			t.Errorf("token = %q, want new", token)
		}
	}
	if got := transport.calls(); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}

	// A delayed 401 from the old generation reuses the rotated token.
	token, err := provider.token(t.Context(), AccessTokenRequest{ForceRefresh: true, RejectedToken: "old"})
	if err != nil || token != "new" || transport.calls() != 1 {
		t.Fatalf("delayed generation = %q, %v; calls=%d", token, err, transport.calls())
	}
}

func TestTokenProviderWaiterCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	storage := &MemoryStorage{}
	if err := storeAuth(storage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	transport := newBlockingRefreshTransport()
	provider := &tokenProvider{storage: storage, auth: testAuthResource(transport, storage)}

	liveResult := make(chan error, 1)
	go func() {
		_, err := provider.token(t.Context(), AccessTokenRequest{})
		liveResult <- err
	}()
	<-transport.started
	canceledCtx, cancel := context.WithCancel(t.Context())
	canceledResult := make(chan error, 1)
	go func() {
		_, err := provider.token(canceledCtx, AccessTokenRequest{})
		canceledResult <- err
	}()
	cancel()
	if err := <-canceledResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter error = %v", err)
	}
	close(transport.release)
	if err := <-liveResult; err != nil {
		t.Fatalf("live waiter error = %v", err)
	}
	if got := transport.calls(); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
}

func TestTokenProviderFinalCancellationStillPersistsSuccessfulRotation(t *testing.T) {
	storage := &MemoryStorage{}
	if err := storeAuth(storage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	transport := newBlockingRefreshTransport()
	provider := &tokenProvider{storage: storage, auth: testAuthResource(transport, storage)}
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := provider.token(ctx, AccessTokenRequest{})
		result <- err
	}()
	<-transport.started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("token error = %v", err)
	}
	close(transport.release)
	if token, err := provider.token(t.Context(), AccessTokenRequest{}); err != nil || token != "new" {
		t.Fatalf("completed refresh = %q, %v", token, err)
	}
	stored, err := loadStoredAuth(storage)
	if err != nil || stored.AccessToken != "new" || stored.RefreshToken != "rotated" {
		t.Fatalf("stored after cancellation = %#v, %v", stored, err)
	}
}

func TestTokenProviderStorageFailuresAndRetryAfterRefreshFailure(t *testing.T) {
	readFailure := errors.New("read failed")
	storage := &failingAuthStorage{getAuthErr: readFailure}
	provider := &tokenProvider{storage: storage, auth: testAuthResource(&recordingTransport{}, storage)}
	if _, err := provider.token(t.Context(), AccessTokenRequest{}); !errors.Is(err, readFailure) {
		t.Fatalf("read error = %v", err)
	}

	writeFailure := errors.New("write failed")
	storage = &failingAuthStorage{setAuthErr: writeFailure}
	if err := storeAuth(&storage.MemoryStorage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"access_token":"not-usable","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`)
	provider = &tokenProvider{storage: storage, auth: testAuthResource(rt, storage)}
	if token, err := provider.token(t.Context(), AccessTokenRequest{}); !errors.Is(err, writeFailure) || token != "" {
		t.Fatalf("write failure token = %q, error = %v", token, err)
	}
	stored, _ := loadStoredAuth(&storage.MemoryStorage)
	if stored.AccessToken != "old" {
		t.Fatalf("failed persistence clobbered auth: %#v", stored)
	}

	storage = &failingAuthStorage{}
	if err := storeAuth(&storage.MemoryStorage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	rt = &recordingTransport{}
	rt.respond(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"revoked"}`)
	rt.respond(http.StatusOK, `{"access_token":"recovered","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`)
	provider = &tokenProvider{storage: storage, auth: testAuthResource(rt, storage)}
	if _, err := provider.token(t.Context(), AccessTokenRequest{}); err == nil {
		t.Fatal("expected first refresh failure")
	} else if apiErr, ok := errors.AsType[*APIError](err); !ok || apiErr.Code != "invalid_grant" {
		t.Fatalf("refresh failure = %#v", err)
	}
	if token, err := provider.token(t.Context(), AccessTokenRequest{}); err != nil || token != "recovered" {
		t.Fatalf("refresh retry = %q, %v", token, err)
	}
}

func TestTokenProviderConcurrentWaitersShareFailedRefreshAndLaterRetry(t *testing.T) {
	storage := &MemoryStorage{}
	if err := storeAuth(storage, storedToken("old", "refresh", time.Now().Add(-time.Hour))); err != nil {
		t.Fatal(err)
	}
	transport := newFailingThenSuccessfulRefreshTransport()
	provider := &tokenProvider{storage: storage, auth: testAuthResource(transport, storage)}
	const callers = 12
	start := make(chan struct{})
	errs := make(chan error, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			_, err := provider.token(t.Context(), AccessTokenRequest{})
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	<-transport.started
	deadline := time.Now().Add(5 * time.Second)
	for {
		provider.mu.Lock()
		waiters := 0
		if provider.inflight != nil {
			waiters = provider.inflight.waiters
		}
		provider.mu.Unlock()
		if waiters == callers {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("joined waiters = %d, want %d", waiters, callers)
		}
		runtime.Gosched()
	}
	close(transport.releaseFirst)
	var shared *APIError
	for range callers {
		err := <-errs
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Code != "invalid_grant" {
			t.Errorf("waiter error = %#v", err)
			continue
		}
		if shared == nil {
			shared = apiErr
		} else if apiErr != shared {
			t.Errorf("waiters did not receive shared failure: %p != %p", apiErr, shared)
		}
	}
	if got := transport.calls(); got != 1 {
		t.Fatalf("failed refresh calls = %d, want 1", got)
	}
	stored, err := loadStoredAuth(storage)
	if err != nil || stored == nil || stored.AccessToken != "old" || stored.RefreshToken != "refresh" {
		t.Fatalf("failed refresh changed session: %#v, %v", stored, err)
	}
	if token, err := provider.token(t.Context(), AccessTokenRequest{}); err != nil || token != "recovered" {
		t.Fatalf("later retry = %q, %v", token, err)
	}
	if got := transport.calls(); got != 2 {
		t.Fatalf("total refresh calls = %d, want 2", got)
	}
}

type failingThenSuccessfulRefreshTransport struct {
	mu           sync.Mutex
	count        int
	started      chan struct{}
	releaseFirst chan struct{}
	once         sync.Once
}

func newFailingThenSuccessfulRefreshTransport() *failingThenSuccessfulRefreshTransport {
	return &failingThenSuccessfulRefreshTransport{started: make(chan struct{}), releaseFirst: make(chan struct{})}
}

func (t *failingThenSuccessfulRefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.count++
	call := t.count
	t.mu.Unlock()
	if call == 1 {
		t.once.Do(func() { close(t.started) })
		select {
		case <-t.releaseFirst:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return (&recordingTransport{responses: []scriptedResponse{{status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"revoked"}`}}}).RoundTrip(req)
	}
	return (&recordingTransport{responses: []scriptedResponse{{status: http.StatusOK, body: `{"access_token":"recovered","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`}}}).RoundTrip(req)
}

func (t *failingThenSuccessfulRefreshTransport) calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

type blockingRefreshTransport struct {
	mu      sync.Mutex
	count   int
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingRefreshTransport() *blockingRefreshTransport {
	return &blockingRefreshTransport{started: make(chan struct{}), release: make(chan struct{})}
}

func (t *blockingRefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.count++
	t.mu.Unlock()
	t.once.Do(func() { close(t.started) })
	select {
	case <-t.release:
		return (&recordingTransport{responses: []scriptedResponse{{status: http.StatusOK, body: `{"access_token":"new","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`}}}).RoundTrip(req)
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func (t *blockingRefreshTransport) calls() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count
}

func storedToken(access, refresh string, expiresAt time.Time) *AuthTokens {
	return &AuthTokens{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    3600,
		TokenType:    "bearer",
		ExpiresAt:    expiresAt.UnixMilli(),
	}
}
