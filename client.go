package stripelink

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"reflect"
	"strings"
)

// Default configuration values (parity: config.ts:35-36; the client name is
// GUIDANCE §6.2 deviation #11 — the JS SDK defaults to "Link CLI").
const (
	defaultAuthBaseURL = "https://login.link.com"
	defaultAPIBaseURL  = "https://api.link.com"
	defaultClientName  = "github.com/mackross/stripelink"

	// defaultMaxResponseBodyBytes bounds every success and error response.
	// Link API payloads are small; callers expecting a larger documented
	// payload can opt into a different positive bound.
	defaultMaxResponseBodyBytes int64 = 4 << 20
)

// Environment variables consulted by NewClient (parity: config.ts:118-131).
// LINK_ACCESS_TOKEN, LINK_AUTH_FILE, and LINK_NO_REFRESH are CLI-level in JS
// and are deliberately not read here (GUIDANCE §6.1).
const (
	envAuthBaseURL = "LINK_AUTH_BASE_URL"
	envAPIBaseURL  = "LINK_API_BASE_URL"
	envHTTPProxy   = "LINK_HTTP_PROXY"
)

// AccessTokenRequest describes why the transport is requesting a bearer
// token. RejectedToken contains a bearer credential and must be handled as a
// secret. It is the token that received a 401, when ForceRefresh is true.
// Providers must first compare RejectedToken with their current token:
// when they differ, another caller has already rotated the token and the
// current token must be returned without performing another refresh.
type AccessTokenRequest struct {
	ForceRefresh  bool
	RejectedToken string
}

// String returns a credential-safe summary of the token request.
func (r AccessTokenRequest) String() string {
	return fmt.Sprintf("AccessTokenRequest{ForceRefresh:%t RejectedToken:<redacted>}", r.ForceRefresh)
}

// Format makes every fmt verb use the credential-safe summary.
func (r AccessTokenRequest) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(r.String())) }

// AccessTokenFunc supplies a bearer token for authenticated API calls. It
// replaces the JS AccessTokenProvider plus GetAccessTokenOptions. Providers
// must be safe for concurrent use and honor the generation check documented
// by AccessTokenRequest.
type AccessTokenFunc func(ctx context.Context, request AccessTokenRequest) (string, error)

// Options configures NewClient. The zero value produces a working client:
// default base URLs (after consulting LINK_AUTH_BASE_URL and
// LINK_API_BASE_URL), file-backed token storage at the default path, and a
// storage-backed auto-refreshing token provider.
type Options struct {
	// ClientName identifies the agent or application in the user's Link app
	// via the device flow's connection_label ("<ClientName> on <hostname>")
	// and client_hint. It defaults to "github.com/mackross/stripelink"
	// (GUIDANCE §6.2 deviation #11; the JS SDK defaults to "Link CLI").
	ClientName string

	// AccessToken is a static bearer token used for all authenticated calls.
	AccessToken string

	// GetAccessToken supplies bearer tokens dynamically and overrides
	// AccessToken when set.
	GetAccessToken AccessTokenFunc

	// AuthStorage loads, transactionally updates, and clears the complete OAuth
	// and pending device-authorization state.
	// It defaults to a FileStorage at the default path. When neither
	// AccessToken nor GetAccessToken is set, NewClient wires a
	// storage-backed auto-refreshing token provider on top of it.
	AuthStorage AuthStorage

	// HTTPClient performs all HTTP requests. When set, NewClient makes a
	// shallow copy before installing its DefaultHeaders transport wrapper;
	// the caller's client is never mutated. LINK_HTTP_PROXY is ignored,
	// exactly as the JS SDK ignores the proxy when options.fetch is passed.
	// When nil, a client honoring LINK_HTTP_PROXY is built (GUIDANCE §5.4).
	HTTPClient *http.Client

	// DefaultHeaders are added to every request, each header set only if the
	// request does not already have it (parity: config.ts:69-82). NewClient
	// rejects credential-bearing, routing, and framing headers such as
	// Authorization, Cookie, Host, Content-Length, and Transfer-Encoding.
	DefaultHeaders map[string]string

	// MaxResponseBodyBytes is the maximum response body read for any request,
	// including error responses. Zero selects 4 MiB; negative values are
	// invalid. Responses over the limit return ErrResponseTooLarge.
	MaxResponseBodyBytes int64

	// AuthBaseURL is the base URL for the device-auth endpoints. Precedence:
	// this option, then the LINK_AUTH_BASE_URL environment variable, then
	// https://login.link.com.
	AuthBaseURL string

	// APIBaseURL is the base URL for the API endpoints. Precedence: this
	// option, then the LINK_API_BASE_URL environment variable, then
	// https://api.link.com.
	APIBaseURL string

	// SpendRequestBaseURL is the base URL for the spend-requests endpoints.
	// It defaults to APIBaseURL.
	SpendRequestBaseURL string

	// Logger receives debug-level request/response metadata when Verbose is
	// true. Request and response bodies and header values are never logged.
	// When nil, it defaults to a text handler on stderr at LevelDebug when
	// Verbose is true, and a discard
	// handler otherwise.
	Logger *slog.Logger

	// Verbose enables safe request/response metadata logging. It logs method,
	// a sanitized URL without user information or query values, status,
	// duration, body size, and header names only. It never logs bodies or
	// header values because they can contain OAuth tokens, payment credentials,
	// cookies, or other financial data (GUIDANCE §5.4).
	Verbose bool
}

// String returns a bounded credential-safe summary. Configuration strings,
// header values, tokens, callbacks, and dependency internals are omitted.
func (o Options) String() string {
	return fmt.Sprintf("Options{ClientName:<redacted> AccessToken:<redacted> GetAccessToken:<redacted> AuthStorage:<redacted> HTTPClient:<redacted> DefaultHeaders:<redacted> MaxResponseBodyBytes:%d AuthBaseURL:<redacted> APIBaseURL:<redacted> SpendRequestBaseURL:<redacted> Logger:<redacted> Verbose:%t}", o.MaxResponseBodyBytes, o.Verbose)
}

// Format makes every fmt verb use the credential-safe summary.
func (o Options) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(o.String())) }

// Client is the entry point to the Link SDK. Construct it with NewClient.
// The Client and every resource on it are safe for concurrent use by
// multiple goroutines.
type Client struct {
	// Auth implements the OAuth 2.0 device authorization flow.
	Auth *AuthResource

	// SpendRequests creates, lists, retrieves, updates, and cancels spend
	// requests.
	SpendRequests *SpendRequestsResource

	// PaymentMethods lists the user's saved payment methods.
	PaymentMethods *PaymentMethodsResource

	// ShippingAddresses lists the user's saved shipping addresses.
	ShippingAddresses *ShippingAddressesResource

	// UserInfo retrieves the authenticated user's profile.
	UserInfo *UserInfoResource

	// WebBotAuth signs merchant URLs with web-bot-auth signature headers.
	WebBotAuth *WebBotAuthResource

	// Reports submits agent observation reports.
	Reports *ReportsResource
}

// NewClient returns a Client configured by opts. Configuration is resolved
// exactly once: explicit option, then environment variable, then default
// (parity: config.ts:118-131). A zero Options is valid. Base URLs must be
// absolute HTTP(S) URLs without user information, query, or fragment; plain
// HTTP is accepted only for loopback hosts. Redirects are never followed, so
// bearer tokens and caller-supplied headers cannot cross origins.
//
// The client applies no client-wide HTTP timeout, matching the JS SDK;
// cancellation and deadlines for ordinary requests come from the context
// passed to each method. A started automatic token refresh uses a bounded
// internal context so caller cancellation cannot strand a successful rotation.
func NewClient(opts Options) (*Client, error) {
	clientName := opts.ClientName
	if clientName == "" {
		clientName = defaultClientName
	}

	authBaseURL, err := resolveBaseURL(opts.AuthBaseURL, os.Getenv(envAuthBaseURL), defaultAuthBaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: auth base URL: %w", ErrInvalidConfiguration, err)
	}
	apiBaseURL, err := resolveBaseURL(opts.APIBaseURL, os.Getenv(envAPIBaseURL), defaultAPIBaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: API base URL: %w", ErrInvalidConfiguration, err)
	}
	spendRequestBaseURL := apiBaseURL
	if opts.SpendRequestBaseURL != "" {
		spendRequestBaseURL, err = normalizeBaseURL(opts.SpendRequestBaseURL)
		if err != nil {
			return nil, fmt.Errorf("%w: spend-request base URL: %w", ErrInvalidConfiguration, err)
		}
	}

	maxResponseBodyBytes := opts.MaxResponseBodyBytes
	if maxResponseBodyBytes < 0 {
		return nil, fmt.Errorf("%w: MaxResponseBodyBytes must not be negative", ErrInvalidConfiguration)
	}
	if maxResponseBodyBytes == 0 {
		maxResponseBodyBytes = defaultMaxResponseBodyBytes
	}

	defaultHeaders, err := copyAndValidateDefaultHeaders(opts.DefaultHeaders)
	if err != nil {
		return nil, fmt.Errorf("%w: default headers: %w", ErrInvalidConfiguration, err)
	}

	httpClient, err := resolveHTTPClient(opts.HTTPClient, os.Getenv(envHTTPProxy), defaultHeaders)
	if err != nil {
		return nil, fmt.Errorf("%w: HTTP client: %w", ErrInvalidConfiguration, err)
	}

	storage := opts.AuthStorage
	if storage == nil {
		storage, err = NewFileStorage("")
		if err != nil {
			return nil, fmt.Errorf("%w: auth storage: %w", ErrInvalidConfiguration, err)
		}
	} else if isNilInterface(storage) {
		return nil, fmt.Errorf("%w: auth storage: typed-nil AuthStorage", ErrInvalidConfiguration)
	}

	logger := opts.Logger
	if logger == nil {
		if opts.Verbose {
			logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		} else {
			logger = newDiscardLogger()
		}
	}

	c := &core{
		clientName:           clientName,
		httpClient:           httpClient,
		storage:              storage,
		authBaseURL:          authBaseURL,
		apiBaseURL:           apiBaseURL,
		spendRequestBaseURL:  spendRequestBaseURL,
		logger:               logger,
		verbose:              opts.Verbose,
		maxResponseBodyBytes: maxResponseBodyBytes,
	}
	client := &Client{
		Auth:              &AuthResource{c: c},
		SpendRequests:     &SpendRequestsResource{c: c},
		PaymentMethods:    &PaymentMethodsResource{c: c},
		ShippingAddresses: &ShippingAddressesResource{c: c},
		UserInfo:          &UserInfoResource{c: c},
		WebBotAuth: &WebBotAuthResource{
			c:        c,
			cache:    make(map[string]webBotAuthCacheEntry),
			inflight: make(map[string]*webBotAuthCall),
		},
		Reports: &ReportsResource{c: c},
	}

	switch {
	case opts.GetAccessToken != nil:
		c.getAccessToken = opts.GetAccessToken
	case opts.AccessToken != "":
		staticToken := opts.AccessToken
		c.getAccessToken = func(context.Context, AccessTokenRequest) (string, error) {
			return staticToken, nil
		}
	default:
		provider := &tokenProvider{storage: storage, auth: client.Auth}
		c.getAccessToken = provider.token
		c.managesSession = true
	}

	return client, nil
}

func resolveBaseURL(option, environment, fallback string) (string, error) {
	rawURL := option
	if rawURL == "" {
		rawURL = environment
	}
	if rawURL == "" {
		rawURL = fallback
	}
	return normalizeBaseURL(rawURL)
}

func normalizeBaseURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("must be an absolute hierarchical URL with a host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("user information is not permitted")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return "", fmt.Errorf("query is not permitted")
	}
	if u.Fragment != "" || u.RawFragment != "" {
		return "", fmt.Errorf("fragment is not permitted")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("plain HTTP is permitted only for loopback hosts")
	}
	if u.RawPath == "" {
		u.Path = strings.TrimRight(u.Path, "/")
	} else {
		trimmedRawPath := strings.TrimRight(u.RawPath, "/")
		literalSlashesRemoved := len(u.RawPath) - len(trimmedRawPath)
		u.RawPath = trimmedRawPath
		for range literalSlashesRemoved {
			u.Path = strings.TrimSuffix(u.Path, "/")
		}
	}
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var reservedDefaultHeaders = map[string]struct{}{
	"Authorization":       {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Cookie":              {},
	"Set-Cookie":          {},
	"Host":                {},
	"Content-Length":      {},
	"Transfer-Encoding":   {},
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailer":             {},
	"Upgrade":             {},
}

func copyAndValidateDefaultHeaders(headers map[string]string) (http.Header, error) {
	copy := make(http.Header, len(headers))
	for name, value := range headers {
		canonicalName := textproto.CanonicalMIMEHeaderKey(name)
		if canonicalName == "" || strings.ContainsAny(name, "\r\n") {
			return nil, fmt.Errorf("invalid header name %q", name)
		}
		if _, reserved := reservedDefaultHeaders[canonicalName]; reserved {
			return nil, fmt.Errorf("header %q is reserved", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("header %q has an invalid value", name)
		}
		copy[canonicalName] = []string{value}
	}
	return copy, nil
}

func resolveHTTPClient(caller *http.Client, rawProxyURL string, defaultHeaders http.Header) (*http.Client, error) {
	var client http.Client
	var transport http.RoundTripper
	if caller != nil {
		client = *caller
		transport = caller.Transport
		if transport == nil {
			transport = http.DefaultTransport
		} else if isNilInterface(transport) {
			return nil, fmt.Errorf("custom HTTP transport is typed nil")
		}
	} else {
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("default transport has unexpected type %T", http.DefaultTransport)
		}
		configured := base.Clone()
		configured.Proxy = nil
		if rawProxyURL != "" {
			proxyURL, err := url.Parse(rawProxyURL)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", envHTTPProxy, err)
			}
			if !proxyURL.IsAbs() || proxyURL.Host == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
				return nil, fmt.Errorf("invalid %s: proxy must be an absolute HTTP(S) URL", envHTTPProxy)
			}
			configured.Proxy = http.ProxyURL(proxyURL)
		}
		transport = configured
	}

	if len(defaultHeaders) != 0 {
		transport = &defaultHeaderTransport{base: transport, headers: defaultHeaders}
	}
	client.Transport = transport
	client.CheckRedirect = refuseRedirect
	return &client, nil
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

type defaultHeaderTransport struct {
	base    http.RoundTripper
	headers http.Header
}

func (t *defaultHeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	for name, values := range t.headers {
		if headerPresent(clone.Header, name) {
			continue
		}
		clone.Header[name] = append([]string(nil), values...)
	}
	return t.base.RoundTrip(clone)
}

func headerPresent(header http.Header, name string) bool {
	for existing := range header {
		if strings.EqualFold(existing, name) {
			return true
		}
	}
	return false
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
