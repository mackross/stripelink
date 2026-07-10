package stripelink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testWebBotExpiry = "2035-01-02T03:04:05Z"

func webBotResponse(authority, expiresAt string) string {
	return fmt.Sprintf(`{"web_bot_auth":{"signature":"sig1=:secret-signature:","signature_input":"sig1=(\"@authority\");keyid=\"secret-key\"","signature_agent":"https://api.link.com/.well-known/http-message-signatures-directory","authority":%q,"expires_at":%q}}`, authority, expiresAt)
}

func TestWebBotAuthSignURLValidatesBeforeAuthentication(t *testing.T) {
	for _, rawURL := range []string{
		"not-a-url", "/relative", "//merchant.example/path", "ftp://merchant.example/path",
		"mailto:buyer@example.test", "https:///missing-host", "https://./path", "https://buyer:secret@merchant.example/path",
	} {
		t.Run(rawURL, func(t *testing.T) {
			var tokenCalls atomic.Int32
			rt := &recordingTransport{}
			client := newResourceTestClient(t, rt, func(context.Context, AccessTokenRequest) (string, error) {
				tokenCalls.Add(1)
				return "secret-token", nil
			})
			_, err := client.WebBotAuth.SignURL(t.Context(), rawURL)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("SignURL error = %v", err)
			}
			for _, secret := range []string{"buyer", "secret", "@merchant.example", "?", "#"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("SignURL error reflects invalid URL component %q: %v", secret, err)
				}
			}
			if tokenCalls.Load() != 0 || len(rt.Requests()) != 0 {
				t.Fatalf("invalid URL reached auth/HTTP: tokens=%d requests=%d", tokenCalls.Load(), len(rt.Requests()))
			}
		})
	}

	client := newResourceTestClient(t, &recordingTransport{}, nil)
	if _, err := client.WebBotAuth.SignURL(nilContext(), "https://merchant.example/path"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil context error = %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.WebBotAuth.SignURL(canceled, "https://merchant.example/path"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}

func TestWebBotAuthInvalidURLNeverEchoesUserInfoQueryOrFragment(t *testing.T) {
	const secret = "webbot-url-secret-canary"
	client := newResourceTestClient(t, &recordingTransport{}, nil)
	for _, rawURL := range []string{
		"https://buyer:" + secret + "@merchant.example/pay?token=" + secret + "#" + secret,
		"https://merchant.example/%zz?token=" + secret + "#" + secret,
		"not-a-url?token=" + secret + "#" + secret,
	} {
		_, err := client.WebBotAuth.SignURL(t.Context(), rawURL)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("SignURL(%q) error = %v", rawURL, err)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "buyer") || strings.Contains(err.Error(), "token=") {
			t.Fatalf("SignURL(%q) reflected secret: %v", rawURL, err)
		}
	}
}

func TestWebBotAuthBlockFormattingRedactsCredentialsForAllCommonVerbs(t *testing.T) {
	block := WebBotAuthBlock{
		Signature: "sig1=:secret-signature:", SignatureInput: `sig1=("@authority");keyid="secret-key"`,
		SignatureAgent: "https://agent.example/secret-agent", Authority: "secret-authority.example", ExpiresAt: "secret-expiry",
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		got := fmt.Sprintf(format, block)
		for _, secret := range []string{"secret-signature", "secret-key", "secret-agent", "secret-authority", "secret-expiry"} {
			if strings.Contains(got, secret) {
				t.Errorf("%s leaked %q: %s", format, secret, got)
			}
		}
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("%s omitted redaction marker: %s", format, got)
		}
	}
}

func TestWebBotAuthSignURLExactRequestAndCanonicalHostnameCache(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, webBotResponse("merchant.example", testWebBotExpiry))
	client := newResourceTestClient(t, rt, nil)
	client.WebBotAuth.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	rawURL := "https://MERCHANT.Example:8443/checkout?q=keep-this"

	first, err := client.WebBotAuth.SignURL(t.Context(), rawURL)
	if err != nil {
		t.Fatalf("first SignURL: %v", err)
	}
	second, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/another/path")
	if err != nil {
		t.Fatalf("cached SignURL: %v", err)
	}
	requests := rt.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.Method != http.MethodPost || request.URL != "http://127.0.0.1:8080/api/web_bot_auth/sign" ||
		request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Authorization") != "Bearer test-token" ||
		request.Body != `{"url":"https://MERCHANT.Example:8443/checkout?q=keep-this"}` {
		t.Fatalf("request = %#v", request)
	}
	if first == second || *first != *second || first.Authority != "merchant.example" {
		t.Fatalf("results are not equal defensive copies: first=%p %#v second=%p %#v", first, first, second, second)
	}

	first.Signature = "caller mutation"
	third, err := client.WebBotAuth.SignURL(t.Context(), "https://MERCHANT.EXAMPLE./third")
	if err != nil || third.Signature != "sig1=:secret-signature:" || third == first {
		t.Fatalf("cached value was mutable: (%#v, %v)", third, err)
	}
}

func TestWebBotAuthSignURLValidatesCompleteBoundUnexpiredBlock(t *testing.T) {
	valid := WebBotAuthBlock{
		Signature: "sig", SignatureInput: "input", SignatureAgent: "https://agent.example/directory",
		Authority: "merchant.example", ExpiresAt: testWebBotExpiry,
	}
	cases := []struct {
		name  string
		block *WebBotAuthBlock
	}{
		{"missing block", nil},
		{"empty signature", func() *WebBotAuthBlock { b := valid; b.Signature = ""; return &b }()},
		{"empty signature input", func() *WebBotAuthBlock { b := valid; b.SignatureInput = ""; return &b }()},
		{"empty signature agent", func() *WebBotAuthBlock { b := valid; b.SignatureAgent = ""; return &b }()},
		{"empty authority", func() *WebBotAuthBlock { b := valid; b.Authority = ""; return &b }()},
		{"empty expiry", func() *WebBotAuthBlock { b := valid; b.ExpiresAt = ""; return &b }()},
		{"invalid expiry", func() *WebBotAuthBlock { b := valid; b.ExpiresAt = "not-a-date"; return &b }()},
		{"expired", func() *WebBotAuthBlock { b := valid; b.ExpiresAt = "2029-12-31T23:59:59Z"; return &b }()},
		{"wrong authority", func() *WebBotAuthBlock { b := valid; b.Authority = "other.example"; return &b }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			if tc.block == nil {
				rt.respond(http.StatusOK, `{}`)
			} else {
				rt.respond(http.StatusOK, fmt.Sprintf(`{"web_bot_auth":{"signature":%q,"signature_input":%q,"signature_agent":%q,"authority":%q,"expires_at":%q}}`,
					tc.block.Signature, tc.block.SignatureInput, tc.block.SignatureAgent, tc.block.Authority, tc.block.ExpiresAt))
			}
			rt.respond(http.StatusOK, webBotResponse("merchant.example", testWebBotExpiry))
			client := newResourceTestClient(t, rt, nil)
			client.WebBotAuth.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
			if _, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/path"); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("malformed response error = %v", err)
			}
			if _, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/path"); err != nil {
				t.Fatalf("failure was cached: %v", err)
			}
			if len(rt.Requests()) != 2 {
				t.Fatalf("requests = %d, want 2", len(rt.Requests()))
			}
		})
	}
}

func TestWebBotAuthSignURLCacheExpiryBuffer(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, webBotResponse("merchant.example", now.Add(31*time.Second).Format(time.RFC3339Nano)))
	rt.respond(http.StatusOK, webBotResponse("merchant.example", now.Add(time.Hour).Format(time.RFC3339Nano)))
	client := newResourceTestClient(t, rt, nil)
	client.WebBotAuth.now = func() time.Time { return now }

	if _, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/one"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/two"); err != nil {
		t.Fatal(err)
	}
	if len(rt.Requests()) != 2 {
		t.Fatalf("30-second boundary served stale cache: requests=%d", len(rt.Requests()))
	}
}

func TestWebBotAuthSignURLAPITransportAndNoMutationReplay(t *testing.T) {
	t.Run("401 is surfaced without replay", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusUnauthorized, `{"error":{"message":"token expired"}}`)
		var tokenRequests []AccessTokenRequest
		client := newResourceTestClient(t, rt, func(_ context.Context, req AccessTokenRequest) (string, error) {
			tokenRequests = append(tokenRequests, req)
			return "expired-token", nil
		})
		_, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/path")
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Status != http.StatusUnauthorized || apiErr.Message != "Failed to get web bot auth headers (401): token expired" {
			t.Fatalf("error = %#v", err)
		}
		if len(rt.Requests()) != 1 || len(tokenRequests) != 1 || tokenRequests[0].ForceRefresh {
			t.Fatalf("mutation replayed: requests=%d tokens=%#v", len(rt.Requests()), tokenRequests)
		}
	})

	t.Run("transport error retains cause", func(t *testing.T) {
		cause := errors.New("TLS failed")
		rt := &recordingTransport{}
		rt.failWith(cause)
		_, err := newResourceTestClient(t, rt, nil).WebBotAuth.SignURL(t.Context(), "https://merchant.example/path")
		transportErr, ok := errors.AsType[*TransportError](err)
		if !ok || transportErr.Method != http.MethodPost || !errors.Is(err, cause) {
			t.Fatalf("error = %#v", err)
		}
	})
}

type blockingSignTransport struct {
	started chan string
	release <-chan struct{}
	calls   atomic.Int32
}

func (rt *blockingSignTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	authority := ""
	if strings.Contains(string(body), "other.example") {
		authority = "other.example"
	} else {
		authority = "merchant.example"
	}
	rt.calls.Add(1)
	rt.started <- authority
	select {
	case <-rt.release:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	response := webBotResponse(authority, testWebBotExpiry)
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response))}, nil
}

func newBlockingWebBotClient(t *testing.T, rt http.RoundTripper) *Client {
	t.Helper()
	client, err := NewClient(Options{
		APIBaseURL: "http://127.0.0.1:8080/api", HTTPClient: &http.Client{Transport: rt},
		AccessToken: "secret-token", AuthStorage: &MemoryStorage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.WebBotAuth.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	return client
}

func TestWebBotAuthSignURLSingleFlightSameHost(t *testing.T) {
	release := make(chan struct{})
	rt := &blockingSignTransport{started: make(chan string, 20), release: release}
	client := newBlockingWebBotClient(t, rt)
	const callers = 12
	results := make(chan *WebBotAuthBlock, callers)
	errs := make(chan error, callers)
	for i := range callers {
		go func(i int) {
			result, err := client.WebBotAuth.SignURL(t.Context(), fmt.Sprintf("https://MERCHANT.example/path/%d", i))
			results <- result
			errs <- err
		}(i)
	}
	if got := <-rt.started; got != "merchant.example" {
		t.Fatalf("started authority = %q", got)
	}
	assertWebBotWaiters(t, client.WebBotAuth, "merchant.example", callers)
	if rt.calls.Load() != 1 {
		t.Fatalf("HTTP calls before release = %d", rt.calls.Load())
	}
	close(release)
	seen := make(map[*WebBotAuthBlock]bool)
	for range callers {
		if err := <-errs; err != nil {
			t.Errorf("SignURL: %v", err)
		}
		result := <-results
		if result == nil || seen[result] {
			t.Errorf("result is nil or aliased: %p", result)
		}
		seen[result] = true
	}
}

func TestWebBotAuthSignURLDifferentHostsProceedConcurrently(t *testing.T) {
	release := make(chan struct{})
	rt := &blockingSignTransport{started: make(chan string, 2), release: release}
	client := newBlockingWebBotClient(t, rt)
	var wg sync.WaitGroup
	wg.Add(2)
	for _, rawURL := range []string{"https://merchant.example/path", "https://other.example/path"} {
		go func() {
			defer wg.Done()
			if _, err := client.WebBotAuth.SignURL(t.Context(), rawURL); err != nil {
				t.Errorf("SignURL: %v", err)
			}
		}()
	}
	started := map[string]bool{<-rt.started: true, <-rt.started: true}
	if !started["merchant.example"] || !started["other.example"] || rt.calls.Load() != 2 {
		t.Fatalf("started = %#v calls=%d", started, rt.calls.Load())
	}
	close(release)
	wg.Wait()
}

func TestWebBotAuthSignURLCanceledWaiterDoesNotCancelSharedWork(t *testing.T) {
	release := make(chan struct{})
	rt := &blockingSignTransport{started: make(chan string, 2), release: release}
	client := newBlockingWebBotClient(t, rt)
	firstCtx, cancelFirst := context.WithCancel(t.Context())
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.WebBotAuth.SignURL(firstCtx, "https://merchant.example/first")
		firstDone <- err
	}()
	<-rt.started

	secondDone := make(chan error, 1)
	go func() {
		_, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/second")
		secondDone <- err
	}()
	assertWebBotWaiters(t, client.WebBotAuth, "merchant.example", 2)
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller error = %v", err)
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("shared request canceled/restarted: calls=%d", rt.calls.Load())
	}
	close(release)
	if err := <-secondDone; err != nil {
		t.Fatalf("live waiter failed: %v", err)
	}
}

func TestWebBotAuthSignURLCancelsWorkAfterLastWaiterLeaves(t *testing.T) {
	release := make(chan struct{})
	rt := &blockingSignTransport{started: make(chan string, 2), release: release}
	client := newBlockingWebBotClient(t, rt)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := client.WebBotAuth.SignURL(ctx, "https://merchant.example/first")
		done <- err
	}()
	<-rt.started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller error = %v", err)
	}
	assertNoWebBotInflight(t, client.WebBotAuth, "merchant.example")
	close(release)
}

func TestWebBotAuthSignURLVerboseLogsAreMetadataOnly(t *testing.T) {
	logger, logs := newCapturingLogger()
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, webBotResponse("merchant.example", testWebBotExpiry))
	client := newResourceTestClient(t, rt, func(context.Context, AccessTokenRequest) (string, error) {
		return "secret-bearer", nil
	}, func(opts *Options) {
		opts.Verbose = true
		opts.Logger = logger
	})
	client.WebBotAuth.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := client.WebBotAuth.SignURL(t.Context(), "https://merchant.example/pay?card=4111111111111111"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(logs.Lines(), "\n")
	for _, secret := range []string{"secret-bearer", "merchant.example", "4111111111111111", "secret-signature", "secret-key"} {
		if strings.Contains(joined, secret) {
			t.Errorf("logs contain %q: %s", secret, joined)
		}
	}
	if !strings.Contains(joined, "POST") || !strings.Contains(joined, "/web_bot_auth/sign") || !strings.Contains(joined, "status=200") {
		t.Fatalf("logs missing metadata: %s", joined)
	}
}

func assertWebBotWaiters(t *testing.T, resource *WebBotAuthResource, authority string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resource.mu.Lock()
		call := resource.inflight[authority]
		got := 0
		if call != nil {
			got = call.waiters
		}
		resource.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("did not observe %d waiters for %q", want, authority)
}

func assertNoWebBotInflight(t *testing.T, resource *WebBotAuthResource, authority string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resource.mu.Lock()
		_, exists := resource.inflight[authority]
		resource.mu.Unlock()
		if !exists {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("inflight request for %q did not finish", authority)
}
