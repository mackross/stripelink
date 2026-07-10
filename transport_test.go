package stripelink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

type trackingBody struct {
	io.Reader
	mu     sync.Mutex
	closed bool
}

func (b *trackingBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return nil
}

func (b *trackingBody) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

func testCore(t *testing.T, rt http.RoundTripper) *core {
	t.Helper()
	return &core{
		httpClient:           &http.Client{Transport: rt, CheckRedirect: refuseRedirect},
		logger:               newDiscardLogger(),
		maxResponseBodyBytes: 1024,
	}
}

func TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware(t *testing.T) {
	var tokenRequests []AccessTokenRequest
	var authorizations []string
	var bodies []*trackingBody
	attempt := 0
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		authorizations = append(authorizations, req.Header.Get("Authorization"))
		attempt++
		status := http.StatusUnauthorized
		body := `{"error":{"message":"expired"}}`
		if attempt == 2 {
			status = http.StatusOK
			body = `{"ok":true}`
		}
		tracked := &trackingBody{Reader: strings.NewReader(body)}
		bodies = append(bodies, tracked)
		resp := response(req, status, "")
		resp.Body = tracked
		return resp, nil
	}))
	c.getAccessToken = func(_ context.Context, request AccessTokenRequest) (string, error) {
		tokenRequests = append(tokenRequests, request)
		if request.ForceRefresh {
			return "fresh-token", nil
		}
		return "rejected-token", nil
	}

	status, body, err := c.do(t.Context(), apiRequest{
		method:              http.MethodGet,
		url:                 "https://api.example.test/userinfo",
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if status != http.StatusOK || string(body) != `{"ok":true}` {
		t.Fatalf("response = (%d, %q), want (200, JSON)", status, body)
	}
	wantRequests := []AccessTokenRequest{{}, {ForceRefresh: true, RejectedToken: "rejected-token"}}
	if len(tokenRequests) != len(wantRequests) || tokenRequests[0] != wantRequests[0] || tokenRequests[1] != wantRequests[1] {
		t.Fatalf("token requests = %#v, want %#v", tokenRequests, wantRequests)
	}
	if strings.Join(authorizations, ",") != "Bearer rejected-token,Bearer fresh-token" {
		t.Fatalf("Authorization headers = %#v", authorizations)
	}
	for i, body := range bodies {
		if !body.isClosed() {
			t.Errorf("response body %d was not closed", i)
		}
	}
}

func TestCoreDoReturnsSecondUnauthorizedWithoutThirdTokenCall(t *testing.T) {
	var tokenCalls int
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(req, http.StatusUnauthorized, `{"error":"still unauthorized"}`), nil
	}))
	c.getAccessToken = func(_ context.Context, request AccessTokenRequest) (string, error) {
		tokenCalls++
		return "token", nil
	}

	status, _, err := c.do(t.Context(), apiRequest{
		method: http.MethodGet, url: "https://api.example.test/userinfo",
		authenticated: true, retryOnUnauthorized: true,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if status != http.StatusUnauthorized || tokenCalls != 2 {
		t.Fatalf("status/calls = %d/%d, want 401/2", status, tokenCalls)
	}
}

func TestCoreDoNeverReplaysMutation(t *testing.T) {
	var attempts, tokenCalls int
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return response(req, http.StatusUnauthorized, `{"error":"unauthorized"}`), nil
	}))
	c.getAccessToken = func(_ context.Context, request AccessTokenRequest) (string, error) {
		tokenCalls++
		return "token", nil
	}

	status, _, err := c.do(t.Context(), apiRequest{
		method: http.MethodPost, url: "https://api.example.test/spend_requests",
		authenticated: true, retryOnUnauthorized: true,
		body: []byte(`{"amount":100}`),
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if status != http.StatusUnauthorized || attempts != 1 || tokenCalls != 1 {
		t.Fatalf("status/attempts/tokenCalls = %d/%d/%d, want 401/1/1", status, attempts, tokenCalls)
	}
}

func TestCoreDoPreservesTokenProviderError(t *testing.T) {
	want := errors.New("vault unavailable")
	c := testCore(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("HTTP request issued after token failure")
		return nil, nil
	}))
	c.getAccessToken = func(context.Context, AccessTokenRequest) (string, error) { return "", want }

	_, _, err := c.do(t.Context(), apiRequest{method: http.MethodGet, url: "https://api.example.test", authenticated: true})
	if !errors.Is(err, want) {
		t.Fatalf("do error = %v, want provider error identity", err)
	}
}

func TestCoreDoWrapsNetworkAndContextErrors(t *testing.T) {
	for _, cause := range []error{errors.New("dial failed"), context.Canceled} {
		t.Run(cause.Error(), func(t *testing.T) {
			c := testCore(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, cause }))
			_, _, err := c.do(t.Context(), apiRequest{method: http.MethodGet, url: "https://api.example.test/userinfo"})
			transportErr, ok := errors.AsType[*TransportError](err)
			if !ok || transportErr.Method != http.MethodGet || transportErr.URL != "https://api.example.test/userinfo" {
				t.Fatalf("error = %#v, want structured TransportError", err)
			}
			if !errors.Is(err, cause) {
				t.Fatalf("error chain does not preserve %v: %v", cause, err)
			}
		})
	}
}

func TestCoreDoBoundsAndClosesResponse(t *testing.T) {
	tracked := &trackingBody{Reader: strings.NewReader("12345")}
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := response(req, http.StatusOK, "")
		resp.Body = tracked
		return resp, nil
	}))
	c.maxResponseBodyBytes = 4

	_, body, err := c.do(t.Context(), apiRequest{method: http.MethodGet, url: "https://api.example.test"})
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("do error = %v, want ErrResponseTooLarge", err)
	}
	if body != nil {
		t.Fatalf("oversized body returned %q, want nil", body)
	}
	if !tracked.isClosed() {
		t.Fatal("oversized response body was not closed")
	}
}

func TestCoreDoVerboseLogsMetadataOnly(t *testing.T) {
	logger, logs := newCapturingLogger()
	secretValues := []string{
		"bearer-secret", "4111111111111111", "123", "shared-payment-secret",
		"signature-secret", "merchant-query-secret", "cookie-secret",
	}
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := response(req, http.StatusOK, `{"card":{"number":"4111111111111111","cvc":"123"},"shared_payment_token":"shared-payment-secret"}`)
		resp.Header.Set("Set-Cookie", "session=cookie-secret")
		return resp, nil
	}))
	c.logger = logger
	c.verbose = true
	c.getAccessToken = func(context.Context, AccessTokenRequest) (string, error) { return "bearer-secret", nil }

	_, _, err := c.do(t.Context(), apiRequest{
		method:        http.MethodPost,
		url:           "https://api.example.test/web_bot_auth/sign?merchant=merchant-query-secret#fragment-secret",
		header:        http.Header{"Cookie": {"session=cookie-secret"}, "X-Signature": {"signature-secret"}},
		body:          []byte(`{"card":"4111111111111111","cvc":"123"}`),
		authenticated: true,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	joined := strings.Join(logs.Lines(), "\n")
	for _, secret := range secretValues {
		if strings.Contains(joined, secret) {
			t.Errorf("logs contain secret %q: %s", secret, joined)
		}
	}
	for _, metadata := range []string{"POST", "https://api.example.test/web_bot_auth/sign", "status=200", "body_bytes="} {
		if !strings.Contains(joined, metadata) {
			t.Errorf("logs missing %q: %s", metadata, joined)
		}
	}
}

func TestCoreDoNonVerboseDoesNotLog(t *testing.T) {
	logger, logs := newCapturingLogger()
	c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(req, http.StatusOK, `{}`), nil
	}))
	c.logger = logger
	c.verbose = false

	if _, _, err := c.do(t.Context(), apiRequest{method: http.MethodGet, url: "https://api.example.test"}); err != nil {
		t.Fatalf("do: %v", err)
	}
	if got := logs.Lines(); len(got) != 0 {
		t.Fatalf("non-verbose logs = %#v, want none", got)
	}
}

func TestDoJSONStatusAndDecode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return response(req, http.StatusCreated, `{"value":"ok"}`), nil
		}))
		got, err := doJSON[struct {
			Value string `json:"value"`
		}](t.Context(), c, apiRequest{method: http.MethodGet, url: "https://api.example.test"})
		if err != nil || got.Value != "ok" {
			t.Fatalf("doJSON = (%#v, %v)", got, err)
		}
	})

	t.Run("structured API error", func(t *testing.T) {
		c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return response(req, http.StatusForbidden, `{"error":{"message":"denied"},"request_id":"req_123"}`), nil
		}))
		_, err := doJSON[map[string]any](t.Context(), c, apiRequest{method: http.MethodGet, url: "https://api.example.test"})
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Status != http.StatusForbidden || apiErr.Message != "denied" ||
			apiErr.RawBody == "" || !bytes.Contains(apiErr.Details, []byte("req_123")) {
			t.Fatalf("error = %#v, want populated APIError", err)
		}
	})

	t.Run("plain text API error", func(t *testing.T) {
		c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return response(req, http.StatusBadGateway, "load balancer failed"), nil
		}))
		_, err := doJSON[map[string]any](t.Context(), c, apiRequest{method: http.MethodGet, url: "https://api.example.test"})
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Message != "remote API returned a non-JSON error" || apiErr.Details != nil {
			t.Fatalf("error = %#v, want plain-text APIError", err)
		}
	})

	t.Run("invalid success JSON", func(t *testing.T) {
		c := testCore(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return response(req, http.StatusOK, "not JSON"), nil
		}))
		_, err := doJSON[map[string]any](t.Context(), c, apiRequest{method: http.MethodGet, url: "https://api.example.test"})
		if _, ok := errors.AsType[*APIError](err); err == nil || ok {
			t.Fatalf("error = %#v, want non-API decode error", err)
		}
	})
}

func TestExtractAPIErrorMessageRedactsCredentialFieldsAndBoundsDiagnostics(t *testing.T) {
	const (
		card      = "4242424242424242"
		cvc       = "987"
		token     = "spt_super_secret_token"
		signature = "sig1=:super-secret-signature:"
	)
	for _, body := range [][]byte{
		[]byte(`{"error":{"message":"payment declined: card_number=` + card + ` cvc=` + cvc + ` access_token=` + token + ` signature=` + signature + `"}}`),
		[]byte(`{"error":"payment declined; card: ` + card + `; cvc: ` + cvc + `; refresh_token: ` + token + `; signature_input: ` + signature + `"}`),
		[]byte(card + " " + cvc + " " + token + " " + signature),
	} {
		got := extractAPIErrorMessage(body)
		for _, secret := range []string{card, cvc, token, signature} {
			if strings.Contains(got, secret) {
				t.Errorf("diagnostic contains %q: %q", secret, got)
			}
		}
		if len(got) > maxDiagnosticBytes {
			t.Errorf("diagnostic len=%d, want <= %d", len(got), maxDiagnosticBytes)
		}
	}
	if got := extractAPIErrorMessage([]byte(`{"error":"987"}`)); got != "<redacted>" {
		t.Fatalf("bare CVC diagnostic = %q", got)
	}
	if got := extractAPIErrorMessage([]byte(`{"error":"request 987 failed with status 422"}`)); got != "request 987 failed with status 422" {
		t.Fatalf("ordinary numeric diagnostic was generically stripped: %q", got)
	}

	long := `{"error":{"message":"` + strings.Repeat("safe ", maxDiagnosticBytes) + `"}}`
	if got := extractAPIErrorMessage([]byte(long)); len(got) > maxDiagnosticBytes {
		t.Fatalf("long diagnostic len=%d", len(got))
	}
}

func TestCoreDoRefusesRedirectWithoutFollowing(t *testing.T) {
	var destinationHits int
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationHits++
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer origin.Close()

	c := testCore(t, http.DefaultTransport)
	_, _, err := c.do(t.Context(), apiRequest{method: http.MethodGet, url: origin.URL})
	if _, ok := errors.AsType[*TransportError](err); !errors.Is(err, ErrRedirect) || !ok {
		t.Fatalf("do error = %#v, want TransportError matching ErrRedirect", err)
	}
	if destinationHits != 0 {
		t.Fatalf("redirect destination received %d requests, want 0", destinationHits)
	}
}
