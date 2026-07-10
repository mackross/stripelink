package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestAuthInitiatePersistsAbsoluteExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"device_code":"device-secret","user_code":"phrase","verification_uri":"https://link.test/verify","verification_uri_complete":"https://link.test/verify?code=phrase","expires_in":600,"interval":5}`)
		storage := &MemoryStorage{}
		auth := testAuthResource(rt, storage)
		started := time.Now()

		da, err := auth.InitiateDeviceAuth(t.Context(), "test-agent")
		if err != nil {
			t.Fatalf("InitiateDeviceAuth: %v", err)
		}
		if got, want := da.ExpiresAt, started.Add(10*time.Minute).UnixMilli(); got != want {
			t.Fatalf("ExpiresAt = %d, want %d", got, want)
		}
		pending, err := storage.GetPendingDeviceAuth()
		if err != nil {
			t.Fatal(err)
		}
		if pending == nil || pending.DeviceCode != da.DeviceCode || pending.ExpiresAt != da.ExpiresAt || pending.Phrase != da.UserCode || pending.VerificationURL != da.VerificationURLComplete {
			t.Fatalf("persisted pending = %#v, device auth = %#v", pending, da)
		}

		reqs := rt.Requests()
		if len(reqs) != 1 {
			t.Fatalf("requests = %d, want 1", len(reqs))
		}
		form, err := url.ParseQuery(reqs[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		if reqs[0].Method != http.MethodPost || reqs[0].URL != "https://auth.test/device/code" {
			t.Fatalf("request = %s %s", reqs[0].Method, reqs[0].URL)
		}
		if got := reqs[0].Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Fatalf("Content-Type = %q", got)
		}
		for key, want := range map[string]string{"client_id": clientID, "scope": defaultScope, "client_hint": "test-agent"} {
			if got := form.Get(key); got != want {
				t.Errorf("form[%s] = %q, want %q", key, got, want)
			}
		}
		if got := form.Get("connection_label"); !strings.HasPrefix(got, "test-agent") {
			t.Errorf("connection_label = %q", got)
		}
	})
}

func TestAuthConcurrentInitiationRejectsSupersededResponse(t *testing.T) {
	storage := &MemoryStorage{}
	transport := newSupersededInitiationTransport()
	first := testAuthResource(transport, storage)
	second := testAuthResource(transport, storage)
	firstResult := make(chan error, 1)
	go func() {
		_, err := first.InitiateDeviceAuth(t.Context(), "first")
		firstResult <- err
	}()
	<-transport.firstStarted
	newer, err := second.InitiateDeviceAuth(t.Context(), "second")
	if err != nil {
		t.Fatalf("newer InitiateDeviceAuth: %v", err)
	}
	close(transport.releaseFirst)
	if err := <-firstResult; !errors.Is(err, errDeviceAuthSuperseded) {
		t.Fatalf("older error = %v, want superseded", err)
	}
	pending, err := storage.GetPendingDeviceAuth()
	if err != nil || pending == nil || pending.DeviceCode != newer.DeviceCode || pending.DeviceCode != "second-device" {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
}

func TestAuthStalePollCannotCommitAfterNewFlowStarts(t *testing.T) {
	storage := &MemoryStorage{}
	if err := storage.SetPendingDeviceAuth(testPending("old-device")); err != nil {
		t.Fatal(err)
	}
	initTransport := newSupersededInitiationTransport()
	newFlow := testAuthResource(initTransport, storage)
	newResult := make(chan error, 1)
	go func() {
		_, err := newFlow.InitiateDeviceAuth(t.Context(), "new")
		newResult <- err
	}()
	<-initTransport.firstStarted // reservation committed; HTTP response is blocked

	pollTransport := &recordingTransport{}
	pollTransport.respond(http.StatusOK, `{"access_token":"stale","refresh_token":"stale-refresh","token_type":"bearer","expires_in":3600}`)
	if _, err := testAuthResource(pollTransport, storage).PollDeviceAuthOnce(t.Context(), "old-device"); !errors.Is(err, errDeviceAuthSuperseded) {
		t.Fatalf("stale poll error = %v", err)
	}
	if auth, err := storage.GetAuth(); err != nil || auth != nil {
		t.Fatalf("stale poll committed auth = %#v, %v", auth, err)
	}

	close(initTransport.releaseFirst)
	if err := <-newResult; err != nil {
		t.Fatalf("new flow: %v", err)
	}
	pending, err := storage.GetPendingDeviceAuth()
	if err != nil || pending == nil || pending.DeviceCode != "first-device" {
		t.Fatalf("new pending = %#v, %v", pending, err)
	}
}

func TestAuthNilContextsAndCredentialSafeErrors(t *testing.T) {
	auth := testAuthResource(&recordingTransport{}, &MemoryStorage{})
	checks := []func() error{
		func() error { _, err := auth.InitiateDeviceAuth(nilContext()); return err },
		func() error { _, err := auth.PollDeviceAuthOnce(nilContext(), "device"); return err },
		func() error {
			_, err := auth.PollDeviceAuth(nilContext(), &DeviceAuth{DeviceCode: "device", Interval: 1, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
			return err
		},
		func() error { _, err := auth.ResumeDeviceAuth(nilContext()); return err },
		func() error { _, err := auth.RefreshToken(nilContext(), "refresh"); return err },
		func() error { return auth.RevokeToken(nilContext(), "token") },
		func() error { return auth.Logout(nilContext()) },
	}
	for i, check := range checks {
		if err := check(); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("nil-context check %d = %v", i, err)
		}
	}

	const secret = "rt_financial_secret"
	rt := &recordingTransport{}
	rt.respond(http.StatusBadRequest, `{"error":"invalid_grant","error_description":"rejected `+secret+`","refresh_token":"`+secret+`"}`)
	_, err := testAuthResource(rt, &MemoryStorage{}).RefreshToken(t.Context(), "refresh")
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Code != "invalid_grant" {
		t.Fatalf("error = %#v", err)
	}
	formatted := fmt.Sprintf("%s %v %+v %#v", err, err, err, err)
	if strings.Contains(formatted, secret) {
		t.Fatalf("authentication error disclosed credential: %s", formatted)
	}
}

func TestAuthAPIErrorsRetainExplicitPayloadButFormatAndLogSafely(t *testing.T) {
	const (
		descriptionCanary = "oauth_description_financial_canary"
		bodyCanary        = "oauth_body_financial_canary"
	)
	structuredBody := `{"error":"invalid_grant","error_description":"` + descriptionCanary + `","request_id":"req_auth_123","refresh_token":"` + bodyCanary + `"}`
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		wantCode    string
		wantDetails bool
	}{
		{name: "structured OAuth", status: http.StatusBadRequest, body: structuredBody, wantCode: "invalid_grant", wantDetails: true},
		{name: "non-JSON gateway", status: http.StatusBadGateway, body: "gateway " + bodyCanary, wantCode: "api_error", wantDetails: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(tc.status, tc.body)
			logger, captured := newCapturingLogger()
			client, err := NewClient(Options{
				AuthStorage: &MemoryStorage{}, HTTPClient: rt.client(), AuthBaseURL: "https://auth.test",
				Logger: logger, Verbose: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Auth.RefreshToken(t.Context(), "request_refresh_secret")
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok {
				t.Fatalf("error = %T, want *APIError", err)
			}
			if apiErr.Status != tc.status || apiErr.Code != tc.wantCode || apiErr.RawBody != tc.body {
				t.Fatalf("explicit error = code=%q status=%d raw=%q", apiErr.Code, apiErr.Status, apiErr.RawBody)
			}
			if tc.wantDetails {
				if !json.Valid(apiErr.Details) || !bytes.Equal(apiErr.Details, []byte(tc.body)) {
					t.Fatalf("Details = %q", apiErr.Details)
				}
				var details map[string]any
				if err := json.Unmarshal(apiErr.Details, &details); err != nil || details["request_id"] != "req_auth_123" || details["refresh_token"] != bodyCanary {
					t.Fatalf("inspect Details = %#v, %v", details, err)
				}
			} else if apiErr.Details != nil {
				t.Fatalf("non-JSON Details = %q, want nil", apiErr.Details)
			}

			implicit := fmt.Sprintf("%s\n%v\n%+v\n%#v", err, err, err, err)
			logs := strings.Join(captured.Lines(), "\n")
			for _, canary := range []string{descriptionCanary, bodyCanary, tc.body} {
				if strings.Contains(implicit, canary) {
					t.Errorf("implicit formatting leaked %q: %s", canary, implicit)
				}
				if strings.Contains(logs, canary) {
					t.Errorf("verbose logs leaked %q: %s", canary, logs)
				}
			}
		})
	}
}

func TestAuthTransportAndMalformedSuccessPreserveSessionAndNeverBearerRetry(t *testing.T) {
	networkFailure := errors.New("network unavailable")
	for _, method := range []string{"initiate", "poll", "refresh", "revoke"} {
		t.Run("transport_"+method, func(t *testing.T) {
			storage := &MemoryStorage{}
			originalAuth := storedToken("old-access", "old-refresh", time.Now().Add(time.Hour))
			originalPending := testPending("old-device")
			if err := storage.SetAuth(originalAuth); err != nil {
				t.Fatal(err)
			}
			if err := storage.SetPendingDeviceAuth(originalPending); err != nil {
				t.Fatal(err)
			}
			rt := &recordingTransport{}
			rt.failWith(networkFailure)
			auth := testAuthResource(rt, storage)
			var err error
			switch method {
			case "initiate":
				_, err = auth.InitiateDeviceAuth(t.Context())
			case "poll":
				_, err = auth.PollDeviceAuthOnce(t.Context(), originalPending.DeviceCode)
			case "refresh":
				_, err = auth.RefreshToken(t.Context(), originalAuth.RefreshToken)
			case "revoke":
				err = auth.RevokeToken(t.Context(), originalAuth.RefreshToken)
			}
			if !errors.Is(err, networkFailure) {
				t.Fatalf("error = %v", err)
			}
			if _, ok := errors.AsType[*TransportError](err); !ok {
				t.Fatalf("error type = %T, want *TransportError", err)
			}
			assertStoredSession(t, storage, originalAuth, originalPending)
		})
	}

	for _, method := range []string{"initiate", "poll", "refresh"} {
		t.Run("malformed_2xx_"+method, func(t *testing.T) {
			storage := &MemoryStorage{}
			originalAuth := storedToken("old-access", "old-refresh", time.Now().Add(time.Hour))
			originalPending := testPending("old-device")
			if err := storage.SetAuth(originalAuth); err != nil {
				t.Fatal(err)
			}
			if err := storage.SetPendingDeviceAuth(originalPending); err != nil {
				t.Fatal(err)
			}
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, `{"unexpected":true}`)
			auth := testAuthResource(rt, storage)
			var err error
			switch method {
			case "initiate":
				_, err = auth.InitiateDeviceAuth(t.Context())
			case "poll":
				_, err = auth.PollDeviceAuthOnce(t.Context(), originalPending.DeviceCode)
			case "refresh":
				_, err = auth.RefreshToken(t.Context(), originalAuth.RefreshToken)
			}
			if err == nil {
				t.Fatal("expected malformed-success error")
			}
			assertStoredSession(t, storage, originalAuth, originalPending)
		})
	}

	t.Run("auth 401 has no bearer or retry", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusUnauthorized, `{"error":"invalid_token"}`)
		tokenCalls := 0
		client, err := NewClient(Options{
			GetAccessToken: func(context.Context, AccessTokenRequest) (string, error) {
				tokenCalls++
				return "must-not-be-used", nil
			},
			AuthStorage: &MemoryStorage{}, HTTPClient: rt.client(), AuthBaseURL: "https://auth.test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Auth.RefreshToken(t.Context(), "refresh-secret"); err == nil {
			t.Fatal("expected auth API error")
		}
		requests := rt.Requests()
		if tokenCalls != 0 || len(requests) != 1 || requests[0].Header.Get("Authorization") != "" {
			t.Fatalf("tokenCalls=%d requests=%#v", tokenCalls, requests)
		}
	})
}

func TestDeviceFlowVerboseLogsMetadataOnlyAndHostnameFailureFallsBack(t *testing.T) {
	const (
		deviceCode = "device_logging_canary"
		userCode   = "user_logging_canary"
		access     = "access_logging_canary"
		refresh    = "refresh_logging_canary"
		fullURL    = "https://verify.example.test/path?device=device_logging_canary#user_logging_canary"
	)
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"device_code":"`+deviceCode+`","user_code":"`+userCode+`","verification_uri":"https://verify.example.test/path","verification_uri_complete":"`+fullURL+`","expires_in":600,"interval":5}`)
	rt.respond(http.StatusOK, `{"access_token":"`+access+`","refresh_token":"`+refresh+`","token_type":"bearer","expires_in":3600}`)
	logger, captured := newCapturingLogger()
	client, err := NewClient(Options{
		ClientName: "metadata-agent", AuthStorage: &MemoryStorage{}, HTTPClient: rt.client(),
		AuthBaseURL: "https://auth.test", Logger: logger, Verbose: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Auth.hostname = func() (string, error) { return "", errors.New("hostname unavailable") }
	da, err := client.Auth.InitiateDeviceAuth(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Auth.PollDeviceAuthOnce(t.Context(), da.DeviceCode); err != nil {
		t.Fatal(err)
	}
	requests := rt.Requests()
	initForm, err := url.ParseQuery(requests[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := initForm.Get("connection_label"); got != "metadata-agent" {
		t.Fatalf("fallback connection_label = %q", got)
	}
	logs := strings.Join(captured.Lines(), "\n")
	for _, secret := range []string{deviceCode, userCode, access, refresh, fullURL, "device=device", "#user"} {
		if strings.Contains(logs, secret) {
			t.Errorf("verbose logs leaked %q: %s", secret, logs)
		}
	}
	for _, metadata := range []string{"POST", "auth.test/device/code", "auth.test/device/token", "status=200"} {
		if !strings.Contains(logs, metadata) {
			t.Errorf("verbose logs missing %q: %s", metadata, logs)
		}
	}
}

func assertStoredSession(t *testing.T, storage AuthStorage, wantAuth *AuthTokens, wantPending *PendingDeviceAuth) {
	t.Helper()
	gotAuth, authErr := storage.GetAuth()
	gotPending, pendingErr := storage.GetPendingDeviceAuth()
	if authErr != nil || pendingErr != nil || gotAuth == nil || gotPending == nil || *gotAuth != *wantAuth || *gotPending != *wantPending {
		t.Fatalf("stored session auth=%#v/%v pending=%#v/%v", gotAuth, authErr, gotPending, pendingErr)
	}
}

func TestAuthValueFormattingRedactsCredentials(t *testing.T) {
	const secret = "auth_financial_secret"
	values := []any{
		AuthTokens{AccessToken: secret, RefreshToken: secret, TokenType: secret},
		&AuthTokens{AccessToken: secret, RefreshToken: secret, TokenType: secret},
		DeviceAuth{DeviceCode: secret, UserCode: secret, VerificationURL: secret, VerificationURLComplete: secret},
		&DeviceAuth{DeviceCode: secret, UserCode: secret, VerificationURL: secret, VerificationURLComplete: secret},
	}
	for _, value := range values {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, secret) || !strings.Contains(got, "<redacted>") {
				t.Errorf("%T with %s formatted unsafely: %s", value, format, got)
			}
		}
	}
}

type supersededInitiationTransport struct {
	mu           sync.Mutex
	calls        int
	firstStarted chan struct{}
	releaseFirst chan struct{}
}

func newSupersededInitiationTransport() *supersededInitiationTransport {
	return &supersededInitiationTransport{firstStarted: make(chan struct{}), releaseFirst: make(chan struct{})}
}

func (t *supersededInitiationTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls++
	call := t.calls
	t.mu.Unlock()
	if call == 1 {
		close(t.firstStarted)
		<-t.releaseFirst
	}
	device := "first-device"
	if call == 2 {
		device = "second-device"
	}
	body := fmt.Sprintf(`{"device_code":%q,"user_code":"phrase","verification_uri":"https://link.test/verify","verification_uri_complete":"https://link.test/verify?code=phrase","expires_in":600,"interval":5}`, device)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

func TestAuthPollOnceClassifiesAndPersists(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"bearer","expires_in":3600}`)
		storage := &MemoryStorage{}
		if err := storage.SetPendingDeviceAuth(testPending("device-secret")); err != nil {
			t.Fatal(err)
		}
		auth := testAuthResource(rt, storage)

		tokens, err := auth.PollDeviceAuthOnce(t.Context(), "device-secret")
		if err != nil {
			t.Fatalf("PollDeviceAuthOnce: %v", err)
		}
		if tokens.AccessToken != "new-access" || tokens.RefreshToken != "new-refresh" || tokens.ExpiresAt == 0 {
			t.Fatalf("tokens = %#v", tokens)
		}
		stored, _ := storage.GetAuth()
		pending, _ := storage.GetPendingDeviceAuth()
		if stored == nil || stored.AccessToken != "new-access" || pending != nil {
			t.Fatalf("stored = %#v, pending = %#v", stored, pending)
		}
	})

	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"pending", `{"error":"authorization_pending"}`, ErrAuthorizationPending},
		{"slow_down_matches_both", `{"error":"slow_down"}`, ErrSlowDown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusBadRequest, tc.body)
			_, err := testAuthResource(rt, &MemoryStorage{}).PollDeviceAuthOnce(t.Context(), "device-secret")
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want match %v", err, tc.want)
			}
			if tc.want == ErrSlowDown && !errors.Is(err, ErrAuthorizationPending) {
				t.Fatalf("slow_down error = %v, want match ErrAuthorizationPending", err)
			}
			if _, ok := errors.AsType[*APIError](err); ok {
				t.Fatalf("error = %T, must not be APIError", err)
			}
		})
	}
}

func TestAuthPollTerminalClearsOnlyMatchingPending(t *testing.T) {
	for _, tc := range []struct {
		code    string
		message string
	}{
		{"expired_token", "Device code expired. Please restart the login flow."},
		{"access_denied", "Authorization denied by user."},
	} {
		t.Run(tc.code, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusBadRequest, `{"error":"`+tc.code+`"}`)
			storage := &MemoryStorage{}
			if err := storage.SetPendingDeviceAuth(testPending("same")); err != nil {
				t.Fatal(err)
			}
			_, err := testAuthResource(rt, storage).PollDeviceAuthOnce(t.Context(), "same")
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok || apiErr.Code != tc.code || apiErr.Message != tc.message {
				t.Fatalf("error = %#v", err)
			}
			pending, _ := storage.GetPendingDeviceAuth()
			if pending != nil {
				t.Fatalf("pending not cleared: %#v", pending)
			}
		})
	}

	rt := &recordingTransport{}
	rt.respond(http.StatusBadRequest, `{"error":"expired_token"}`)
	storage := &MemoryStorage{}
	if err := storage.SetPendingDeviceAuth(testPending("newer")); err != nil {
		t.Fatal(err)
	}
	_, _ = testAuthResource(rt, storage).PollDeviceAuthOnce(t.Context(), "older")
	pending, _ := storage.GetPendingDeviceAuth()
	if pending == nil || pending.DeviceCode != "newer" {
		t.Fatalf("unrelated pending was cleared: %#v", pending)
	}
}

func TestAuthPollUsesAbsoluteExpiryAndCumulativeSlowDown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusBadRequest, `{"error":"slow_down"}`)
		rt.respond(http.StatusBadRequest, `{"error":"slow_down"}`)
		rt.respond(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","expires_in":3600}`)
		storage := &MemoryStorage{}
		if err := storage.SetPendingDeviceAuth(testPending("device")); err != nil {
			t.Fatal(err)
		}
		auth := testAuthResource(rt, storage)
		started := time.Now()
		da := &DeviceAuth{DeviceCode: "device", Interval: 2, ExpiresAt: started.Add(time.Minute).UnixMilli()}

		tokens, err := auth.PollDeviceAuth(t.Context(), da)
		if err != nil {
			t.Fatalf("PollDeviceAuth: %v", err)
		}
		if tokens.AccessToken != "access" {
			t.Fatalf("tokens = %#v", tokens)
		}
		// Polls at 2s, then 9s (+5), then 21s (+5 again).
		if got, want := time.Since(started), 21*time.Second; got != want {
			t.Fatalf("elapsed = %v, want %v", got, want)
		}
	})

	synctest.Test(t, func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"access_token":"must-not-be-used","refresh_token":"r","token_type":"bearer","expires_in":1}`)
		auth := testAuthResource(rt, &MemoryStorage{})
		_, err := auth.PollDeviceAuth(t.Context(), &DeviceAuth{DeviceCode: "device", Interval: 5, ExpiresAt: time.Now().Add(4 * time.Second).UnixMilli()})
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Code != "expired_token" {
			t.Fatalf("error = %#v", err)
		}
		if got := len(rt.Requests()); got != 0 {
			t.Fatalf("requests = %d, want 0", got)
		}
	})
}

func TestAuthRefreshRevokeAndLogout(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"access_token":"a2","refresh_token":"r2","token_type":"bearer","expires_in":3600}`)
	rt.respond(http.StatusNoContent, "")
	rt.respond(http.StatusNoContent, "")
	storage := &MemoryStorage{}
	if err := storage.SetAuth(&AuthTokens{AccessToken: "a1", RefreshToken: "r1", ExpiresIn: 3600, TokenType: "bearer"}); err != nil {
		t.Fatal(err)
	}
	if err := storage.SetPendingDeviceAuth(testPending("d")); err != nil {
		t.Fatal(err)
	}
	auth := testAuthResource(rt, storage)
	auth.c.managesSession = true

	tokens, err := auth.RefreshToken(t.Context(), "r1")
	if err != nil || tokens.RefreshToken != "r2" {
		t.Fatalf("RefreshToken = %#v, %v", tokens, err)
	}
	if err := auth.RevokeToken(t.Context(), "r2"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if err := auth.Logout(t.Context()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	stored, _ := storage.GetAuth()
	pending, _ := storage.GetPendingDeviceAuth()
	if stored != nil || pending != nil {
		t.Fatalf("logout retained auth=%#v pending=%#v", stored, pending)
	}
	requests := rt.Requests()
	if len(requests) != 3 {
		t.Fatalf("requests = %d, want 3", len(requests))
	}
	refreshForm, err := url.ParseQuery(requests[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if refreshForm.Get("grant_type") != "refresh_token" || refreshForm.Get("refresh_token") != "r1" || refreshForm.Get("client_id") != clientID {
		t.Fatalf("refresh form = %v", refreshForm)
	}
	revokeForm, err := url.ParseQuery(requests[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if requests[1].URL != "https://auth.test/device/revoke" || revokeForm.Get("token") != "r2" || revokeForm.Get("client_id") != clientID {
		t.Fatalf("revoke request = %s %v", requests[1].URL, revokeForm)
	}
}

func TestAuthResumeUsesPersistedAbsoluteExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := &MemoryStorage{}
		pending := testPending("resumed-device")
		pending.Interval = 3
		pending.ExpiresAt = time.Now().Add(10 * time.Second).UnixMilli()
		if err := storage.SetPendingDeviceAuth(pending); err != nil {
			t.Fatal(err)
		}
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","token_type":"bearer","expires_in":3600}`)
		started := time.Now()
		tokens, err := testAuthResource(rt, storage).ResumeDeviceAuth(t.Context())
		if err != nil {
			t.Fatalf("ResumeDeviceAuth: %v", err)
		}
		if tokens.AccessToken != "access" || time.Since(started) != 3*time.Second {
			t.Fatalf("tokens = %#v, elapsed = %v", tokens, time.Since(started))
		}
	})
}

func TestAuthPersistedSessionWorksWithNewClient(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"device_code":"device","user_code":"phrase","verification_uri":"https://link.test/verify","verification_uri_complete":"https://link.test/verify?code=phrase","expires_in":600,"interval":5}`)
	rt.respond(http.StatusBadRequest, `{"error":"authorization_pending"}`)
	rt.respond(http.StatusOK, `{"access_token":"session-access","refresh_token":"session-refresh","token_type":"bearer","expires_in":3600}`)
	rt.respond(http.StatusOK, `{"email":"person@example.com"}`)
	storage := &MemoryStorage{}
	options := Options{
		AuthStorage: storage,
		HTTPClient:  rt.client(),
		AuthBaseURL: "https://auth.test",
		APIBaseURL:  "https://api.test",
	}
	first, err := NewClient(options)
	if err != nil {
		t.Fatalf("NewClient(first): %v", err)
	}
	da, err := first.Auth.InitiateDeviceAuth(t.Context())
	if err != nil {
		t.Fatalf("InitiateDeviceAuth: %v", err)
	}
	if _, err := first.Auth.PollDeviceAuthOnce(t.Context(), da.DeviceCode); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("pending poll error = %v", err)
	}
	if _, err := first.Auth.PollDeviceAuthOnce(t.Context(), da.DeviceCode); err != nil {
		t.Fatalf("successful poll: %v", err)
	}

	second, err := NewClient(options)
	if err != nil {
		t.Fatalf("NewClient(second): %v", err)
	}
	info, err := second.UserInfo.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("UserInfo.Retrieve: %v", err)
	}
	if info.Email == nil || *info.Email != "person@example.com" {
		t.Fatalf("user info = %#v", info)
	}
	requests := rt.Requests()
	if got := requests[len(requests)-1].Header.Get("Authorization"); got != "Bearer session-access" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestAuthRejectsMalformedSuccessWithoutMutatingStorage(t *testing.T) {
	for _, method := range []string{"initiate", "poll", "refresh"} {
		t.Run(method, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, `{}`)
			storage := &MemoryStorage{}
			if err := storage.SetAuth(&AuthTokens{AccessToken: "old", RefreshToken: "old-refresh", ExpiresIn: 3600, TokenType: "bearer"}); err != nil {
				t.Fatal(err)
			}
			auth := testAuthResource(rt, storage)
			var err error
			switch method {
			case "initiate":
				_, err = auth.InitiateDeviceAuth(t.Context())
			case "poll":
				_, err = auth.PollDeviceAuthOnce(t.Context(), "device")
			case "refresh":
				_, err = auth.RefreshToken(t.Context(), "refresh")
			}
			if err == nil {
				t.Fatal("expected malformed success error")
			}
			stored, _ := storage.GetAuth()
			if stored == nil || stored.AccessToken != "old" {
				t.Fatalf("stored auth changed: %#v", stored)
			}
		})
	}
}

func TestAuthStorageFailuresNeverClaimSuccess(t *testing.T) {
	setPendingFailure := errors.New("set pending failed")
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"device_code":"device","user_code":"phrase","verification_uri":"https://link.test/verify","verification_uri_complete":"https://link.test/verify?code=phrase","expires_in":600,"interval":5}`)
	storage := &failingAuthStorage{setPendingErr: setPendingFailure}
	if da, err := testAuthResource(rt, storage).InitiateDeviceAuth(t.Context()); da != nil || !errors.Is(err, setPendingFailure) {
		t.Fatalf("initiate = %#v, %v", da, err)
	}

	setAuthFailure := errors.New("set auth failed")
	rt = &recordingTransport{}
	rt.respond(http.StatusOK, `{"access_token":"new","refresh_token":"new-refresh","token_type":"bearer","expires_in":3600}`)
	storage = &failingAuthStorage{setAuthErr: setAuthFailure}
	if err := storage.MemoryStorage.SetAuth(&AuthTokens{AccessToken: "old", RefreshToken: "old-refresh", TokenType: "bearer", ExpiresIn: 3600}); err != nil {
		t.Fatal(err)
	}
	if err := storage.MemoryStorage.SetPendingDeviceAuth(testPending("device")); err != nil {
		t.Fatal(err)
	}
	if tokens, err := testAuthResource(rt, storage).PollDeviceAuthOnce(t.Context(), "device"); tokens != nil || !errors.Is(err, setAuthFailure) {
		t.Fatalf("poll = %#v, %v", tokens, err)
	}
	stored, err := storage.MemoryStorage.GetAuth()
	if err != nil || stored.AccessToken != "old" || stored.RefreshToken != "old-refresh" {
		t.Fatalf("stored after failure = %#v, %v", stored, err)
	}
}

func TestAuthPollCancellationPreservesPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		storage := &MemoryStorage{}
		if err := storage.SetPendingDeviceAuth(testPending("device")); err != nil {
			t.Fatal(err)
		}
		rt := &recordingTransport{}
		auth := testAuthResource(rt, storage)
		ctx, cancel := context.WithCancelCause(t.Context())
		cause := errors.New("caller stopped login")
		cancel(cause)
		_, err := auth.PollDeviceAuth(ctx, &DeviceAuth{
			DeviceCode: "device",
			Interval:   5,
			ExpiresAt:  time.Now().Add(time.Hour).UnixMilli(),
		})
		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want context cause", err)
		}
		pending, getErr := storage.GetPendingDeviceAuth()
		if getErr != nil || pending == nil || pending.DeviceCode != "device" {
			t.Fatalf("pending = %#v, %v", pending, getErr)
		}
		if got := len(rt.Requests()); got != 0 {
			t.Fatalf("requests = %d, want 0", got)
		}
	})
}

func TestAuthLogoutFailureRetainsSession(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        string
		clearAllErr error
	}{
		{name: "revocation", status: http.StatusBadRequest, body: `{"error":"invalid_token"}`},
		{name: "clear", status: http.StatusNoContent, clearAllErr: errors.New("clear failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(tc.status, tc.body)
			storage := &failingAuthStorage{clearAllErr: tc.clearAllErr}
			if err := storage.MemoryStorage.SetAuth(&AuthTokens{AccessToken: "access", RefreshToken: "refresh", TokenType: "bearer", ExpiresIn: 3600}); err != nil {
				t.Fatal(err)
			}
			auth := testAuthResource(rt, storage)
			auth.c.managesSession = true
			if err := auth.Logout(t.Context()); err == nil {
				t.Fatal("Logout unexpectedly succeeded")
			}
			stored, err := storage.MemoryStorage.GetAuth()
			if err != nil || stored == nil || stored.RefreshToken != "refresh" {
				t.Fatalf("stored = %#v, %v", stored, err)
			}
		})
	}
}

func testAuthResource(rt http.RoundTripper, storage AuthStorage) *AuthResource {
	return &AuthResource{c: &core{
		httpClient:           &http.Client{Transport: rt},
		storage:              storage,
		authBaseURL:          "https://auth.test",
		clientName:           "default-agent",
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		maxResponseBodyBytes: defaultMaxResponseBodyBytes,
	}}
}

func testPending(deviceCode string) *PendingDeviceAuth {
	return &PendingDeviceAuth{
		DeviceCode:      deviceCode,
		Interval:        5,
		ExpiresAt:       time.Now().Add(time.Hour).UnixMilli(),
		VerificationURL: "https://link.test/verify?code=phrase",
		Phrase:          "phrase",
	}
}

// failingAuthStorage is intentionally small and deterministic. It wraps a
// real value-semantic MemoryStorage while allowing individual operations to
// fail without partially mutating it.
type failingAuthStorage struct {
	MemoryStorage
	muFail          sync.Mutex
	getAuthErr      error
	setAuthErr      error
	setPendingErr   error
	clearPendingErr error
	clearAllErr     error
}

func (s *failingAuthStorage) GetAuth() (*AuthTokens, error) {
	s.muFail.Lock()
	err := s.getAuthErr
	s.muFail.Unlock()
	if err != nil {
		return nil, err
	}
	return s.MemoryStorage.GetAuth()
}

func (s *failingAuthStorage) SetAuth(tokens *AuthTokens) error {
	s.muFail.Lock()
	err := s.setAuthErr
	s.muFail.Unlock()
	if err != nil {
		return err
	}
	return s.MemoryStorage.SetAuth(tokens)
}

func (s *failingAuthStorage) SetPendingDeviceAuth(pending *PendingDeviceAuth) error {
	s.muFail.Lock()
	err := s.setPendingErr
	s.muFail.Unlock()
	if err != nil {
		return err
	}
	return s.MemoryStorage.SetPendingDeviceAuth(pending)
}

func (s *failingAuthStorage) ClearPendingDeviceAuth() error {
	s.muFail.Lock()
	err := s.clearPendingErr
	s.muFail.Unlock()
	if err != nil {
		return err
	}
	return s.MemoryStorage.ClearPendingDeviceAuth()
}

func (s *failingAuthStorage) ClearAll() error {
	s.muFail.Lock()
	err := s.clearAllErr
	s.muFail.Unlock()
	if err != nil {
		return err
	}
	return s.MemoryStorage.ClearAll()
}

func (s *failingAuthStorage) Update(ctx context.Context, update func(*AuthStorageState) error) error {
	s.muFail.Lock()
	getAuthErr := s.getAuthErr
	setAuthErr := s.setAuthErr
	setPendingErr := s.setPendingErr
	clearPendingErr := s.clearPendingErr
	clearAllErr := s.clearAllErr
	s.muFail.Unlock()
	if getAuthErr != nil {
		return getAuthErr
	}
	return s.MemoryStorage.Update(ctx, func(state *AuthStorageState) error {
		beforeAuth := cloneAuth(state.Auth)
		beforePending := clonePending(state.PendingDeviceAuth)
		if err := update(state); err != nil {
			return err
		}
		if setAuthErr != nil && !authTokensEqual(beforeAuth, state.Auth) {
			return setAuthErr
		}
		if setPendingErr != nil && !pendingDeviceAuthEqual(beforePending, state.PendingDeviceAuth) && state.PendingDeviceAuth != nil {
			return setPendingErr
		}
		if clearPendingErr != nil && beforePending != nil && state.PendingDeviceAuth == nil {
			return clearPendingErr
		}
		if clearAllErr != nil && beforeAuth != nil && state.Auth == nil && state.PendingDeviceAuth == nil {
			return clearAllErr
		}
		return nil
	})
}

func authTokensEqual(a, b *AuthTokens) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func pendingDeviceAuthEqual(a, b *PendingDeviceAuth) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

var _ AuthStorage = (*failingAuthStorage)(nil)
