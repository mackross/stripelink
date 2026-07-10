package stripelink

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewClientZeroOptions(t *testing.T) {
	t.Setenv(envAuthBaseURL, "")
	t.Setenv(envAPIBaseURL, "")
	t.Setenv(envHTTPProxy, "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	client, err := NewClient(Options{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.Auth == nil || client.SpendRequests == nil || client.PaymentMethods == nil ||
		client.ShippingAddresses == nil || client.UserInfo == nil || client.WebBotAuth == nil ||
		client.Reports == nil {
		t.Fatal("NewClient returned a nil resource")
	}
	if client.Auth.c.httpClient.Timeout != 0 {
		t.Fatalf("default timeout = %v, want zero", client.Auth.c.httpClient.Timeout)
	}
	if client.Auth.c != client.SpendRequests.c || client.Auth.c != client.Reports.c {
		t.Fatal("resources do not share one resolved core")
	}
}

func TestNewClientResolvesConfigurationOnce(t *testing.T) {
	t.Setenv(envAuthBaseURL, "https://auth.env.example/base/")
	t.Setenv(envAPIBaseURL, "https://api.env.example/v1/")
	t.Setenv(envHTTPProxy, "")

	client, err := NewClient(Options{
		AuthBaseURL: "https://auth.option.example/root/",
		AuthStorage: &MemoryStorage{},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	core := client.Auth.c
	if got, want := core.authBaseURL, "https://auth.option.example/root"; got != want {
		t.Fatalf("authBaseURL = %q, want %q", got, want)
	}
	if got, want := core.apiBaseURL, "https://api.env.example/v1"; got != want {
		t.Fatalf("apiBaseURL = %q, want %q", got, want)
	}
	if got, want := core.spendRequestBaseURL, core.apiBaseURL; got != want {
		t.Fatalf("spendRequestBaseURL = %q, want %q", got, want)
	}

	t.Setenv(envAuthBaseURL, "https://changed.example")
	t.Setenv(envAPIBaseURL, "https://changed.example")
	if core.authBaseURL != "https://auth.option.example/root" || core.apiBaseURL != "https://api.env.example/v1" {
		t.Fatal("existing client changed after environment mutation")
	}
}

func TestNewClientRejectsUnsafeBaseURLs(t *testing.T) {
	t.Setenv(envHTTPProxy, "")
	tests := []string{
		"relative/path",
		"ftp://api.example.com",
		"https:///missing-host",
		"https://user:password@api.example.com",
		"https://api.example.com?token=secret",
		"https://api.example.com/#fragment",
		"http://api.example.com",
	}
	for _, rawURL := range tests {
		t.Run(rawURL, func(t *testing.T) {
			_, err := NewClient(Options{APIBaseURL: rawURL, AuthStorage: &MemoryStorage{}})
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewClient error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}

	for _, rawURL := range []string{"http://localhost:8080/", "http://127.0.0.1:8080/", "http://[::1]:8080/"} {
		t.Run("allows_"+rawURL, func(t *testing.T) {
			client, err := NewClient(Options{APIBaseURL: rawURL, AuthStorage: &MemoryStorage{}})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if client.Auth.c.apiBaseURL[len(client.Auth.c.apiBaseURL)-1] == '/' {
				t.Fatalf("base URL was not normalized: %q", client.Auth.c.apiBaseURL)
			}
		})
	}
}

func TestNewClientPreservesEscapedBasePathSegments(t *testing.T) {
	client, err := NewClient(Options{
		APIBaseURL:  "https://api.example.test/tenant%2Fone/",
		AuthStorage: &MemoryStorage{},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if got, want := client.Auth.c.apiBaseURL, "https://api.example.test/tenant%2Fone"; got != want {
		t.Fatalf("apiBaseURL = %q, want %q", got, want)
	}
}

func TestNewClientRejectsReservedAndMalformedDefaultHeaders(t *testing.T) {
	for _, name := range []string{
		"Authorization", "proxy-authorization", "Cookie", "Set-Cookie", "Host",
		"Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive",
		"Proxy-Authenticate", "TE", "Trailer", "Upgrade",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient(Options{
				AuthStorage:    &MemoryStorage{},
				DefaultHeaders: map[string]string{name: "unsafe"},
			})
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("NewClient error = %v, want ErrInvalidConfiguration", err)
			}
		})
	}

	_, err := NewClient(Options{
		AuthStorage:    &MemoryStorage{},
		DefaultHeaders: map[string]string{"X-Good\r\nInjected": "value"},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("malformed name error = %v, want ErrInvalidConfiguration", err)
	}
	_, err = NewClient(Options{
		AuthStorage:    &MemoryStorage{},
		DefaultHeaders: map[string]string{"X-Good": "value\r\nInjected: yes"},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("malformed value error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestNewClientClonesCallerConfiguration(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{}`)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	redirect := func(*http.Request, []*http.Request) error { return errors.New("caller's redirect policy") }
	original := &http.Client{Transport: rt, Timeout: 17 * time.Second, Jar: jar, CheckRedirect: redirect}
	headers := map[string]string{"X-Agent": "original", "x-empty": "default"}

	client, err := NewClient(Options{
		AccessToken:    "token",
		HTTPClient:     original,
		DefaultHeaders: headers,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	headers["X-Agent"] = "mutated"
	if client.Auth.c.httpClient == original {
		t.Fatal("NewClient retained caller's http.Client pointer")
	}
	if original.Transport != rt || original.Timeout != 17*time.Second || original.Jar != jar || original.CheckRedirect == nil {
		t.Fatal("NewClient mutated caller's http.Client")
	}
	if client.Auth.c.httpClient.Timeout != original.Timeout || client.Auth.c.httpClient.Jar != jar {
		t.Fatal("shallow copy did not preserve timeout or jar")
	}

	reqHeader := make(http.Header)
	reqHeader["X-Empty"] = []string{}
	_, _, err = client.Auth.c.do(t.Context(), apiRequest{
		method: http.MethodGet,
		url:    "https://api.example.test/thing",
		header: reqHeader,
	})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	requests := rt.Requests()
	if got := requests[0].Header.Get("X-Agent"); got != "original" {
		t.Fatalf("X-Agent = %q, want copied original", got)
	}
	if _, ok := requests[0].Header["X-Empty"]; !ok || len(requests[0].Header["X-Empty"]) != 0 {
		t.Fatalf("request's explicitly present empty header was replaced: %#v", requests[0].Header)
	}
	if len(reqHeader) != 1 || len(reqHeader["X-Empty"]) != 0 {
		t.Fatalf("request header mutated: %#v", reqHeader)
	}
}

func TestNewClientTokenSourcePrecedence(t *testing.T) {
	customCalls := 0
	client, err := NewClient(Options{
		AccessToken: "static",
		GetAccessToken: func(context.Context, AccessTokenRequest) (string, error) {
			customCalls++
			return "custom", nil
		},
		AuthStorage: &MemoryStorage{},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if got := req.Header.Get("Authorization"); got != "Bearer custom" {
				t.Fatalf("Authorization = %q, want custom token", got)
			}
			return response(req, http.StatusOK, `{}`), nil
		})},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, _, err = client.Auth.c.do(t.Context(), apiRequest{method: http.MethodGet, url: "https://api.example.test", authenticated: true})
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if customCalls != 1 {
		t.Fatalf("custom provider calls = %d, want 1", customCalls)
	}
}

func TestNewClientTokenSourceCompletePrecedenceAndLazyFailure(t *testing.T) {
	freshStorage := func(t *testing.T, token string) *MemoryStorage {
		t.Helper()
		storage := &MemoryStorage{}
		if err := storage.SetAuth(storedToken(token, "stored-refresh", time.Now().Add(time.Hour))); err != nil {
			t.Fatal(err)
		}
		return storage
	}
	for _, tc := range []struct {
		name       string
		options    func(*testing.T, *recordingTransport) Options
		wantBearer string
	}{
		{
			name: "custom beats static and storage",
			options: func(t *testing.T, rt *recordingTransport) Options {
				return Options{
					GetAccessToken: func(context.Context, AccessTokenRequest) (string, error) { return "custom", nil },
					AccessToken:    "static",
					AuthStorage:    freshStorage(t, "stored"),
					HTTPClient:     rt.client(), APIBaseURL: "https://api.test",
				}
			},
			wantBearer: "Bearer custom",
		},
		{
			name: "static beats storage",
			options: func(t *testing.T, rt *recordingTransport) Options {
				return Options{AccessToken: "static", AuthStorage: freshStorage(t, "stored"), HTTPClient: rt.client(), APIBaseURL: "https://api.test"}
			},
			wantBearer: "Bearer static",
		},
		{
			name: "storage provider is default",
			options: func(t *testing.T, rt *recordingTransport) Options {
				return Options{AuthStorage: freshStorage(t, "stored"), HTTPClient: rt.client(), APIBaseURL: "https://api.test"}
			},
			wantBearer: "Bearer stored",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, `{"email":"person@example.test"}`)
			client, err := NewClient(tc.options(t, rt))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.UserInfo.Retrieve(t.Context()); err != nil {
				t.Fatal(err)
			}
			requests := rt.Requests()
			if len(requests) != 1 || requests[0].Header.Get("Authorization") != tc.wantBearer {
				t.Fatalf("requests = %#v, want Authorization %q", requests, tc.wantBearer)
			}
		})
	}

	t.Run("missing credentials fail lazily without HTTP", func(t *testing.T) {
		rt := &recordingTransport{}
		client, err := NewClient(Options{AuthStorage: &MemoryStorage{}, HTTPClient: rt.client(), APIBaseURL: "https://api.test"})
		if err != nil {
			t.Fatalf("construction must succeed: %v", err)
		}
		if _, err := client.UserInfo.Retrieve(t.Context()); !errors.Is(err, ErrNotAuthenticated) {
			t.Fatalf("Retrieve error = %v", err)
		}
		if got := len(rt.Requests()); got != 0 {
			t.Fatalf("HTTP requests = %d, want 0", got)
		}
	})
}

func TestNewClientRejectsTypedNilAuthStorage(t *testing.T) {
	var storage *MemoryStorage
	_, err := NewClient(Options{AuthStorage: storage})
	if !errors.Is(err, ErrInvalidConfiguration) || !strings.Contains(err.Error(), "typed-nil AuthStorage") {
		t.Fatalf("NewClient error = %v", err)
	}
}

type typedNilRoundTripper struct{}

func (*typedNilRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("typed-nil transport must never be called")
}

func TestNewClientRejectsTypedNilHTTPTransport(t *testing.T) {
	var transport *typedNilRoundTripper
	_, err := NewClient(Options{
		HTTPClient:  &http.Client{Transport: transport},
		AuthStorage: &MemoryStorage{},
	})
	if !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("error = %v, want ErrInvalidConfiguration", err)
	}
}

func TestClientConfigurationFormattingRedactsCredentials(t *testing.T) {
	const secret = "configuration_financial_secret"
	values := []any{
		AccessTokenRequest{ForceRefresh: true, RejectedToken: secret},
		Options{ClientName: secret, AccessToken: secret, DefaultHeaders: map[string]string{"X-Secret": secret}, AuthBaseURL: "https://" + secret + ".test"},
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

func TestNewClientCapturesLinkHTTPProxyOnlyForDefaultClient(t *testing.T) {
	t.Setenv(envHTTPProxy, "https://proxy.example.test:8443")
	client, err := NewClient(Options{AuthStorage: &MemoryStorage{}})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	transport, ok := client.Auth.c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Auth.c.httpClient.Transport)
	}
	requestURL, _ := url.Parse("https://api.link.com/userinfo")
	proxyURL, err := transport.Proxy(&http.Request{URL: requestURL})
	if err != nil {
		t.Fatalf("proxy resolution: %v", err)
	}
	if got, want := proxyURL.String(), "https://proxy.example.test:8443"; got != want {
		t.Fatalf("proxy URL = %q, want %q", got, want)
	}
	t.Setenv(envHTTPProxy, "https://changed.example.test")
	proxyURL, err = transport.Proxy(&http.Request{URL: requestURL})
	if err != nil || proxyURL.String() != "https://proxy.example.test:8443" {
		t.Fatalf("existing client proxy changed: (%v, %v)", proxyURL, err)
	}

	customTransport := &recordingTransport{}
	customClient, err := NewClient(Options{
		AuthStorage: &MemoryStorage{},
		HTTPClient:  &http.Client{Transport: customTransport},
	})
	if err != nil {
		t.Fatalf("NewClient with custom HTTP client: %v", err)
	}
	if customClient.Auth.c.httpClient.Transport != customTransport {
		t.Fatalf("custom transport wrapped unexpectedly: %T", customClient.Auth.c.httpClient.Transport)
	}
}
