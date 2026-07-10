package stripelink

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// webBotAuthExpiryBuffer is how long before a cached signature's expiry it
// stops being served from cache (parity: EXPIRY_BUFFER_MS,
// web-bot-auth.ts:25).
const webBotAuthExpiryBuffer = 30 * time.Second

// WebBotAuthResource obtains web-bot-auth signature headers from
// POST {APIBaseURL}/web_bot_auth/sign. Signatures are cached per authority
// (hostname) until 30 seconds before their expiry, so repeated calls for the
// same domain within the signature window are served without a network
// round-trip. WebBotAuthResource is safe for concurrent use; concurrent
// SignURL calls for the same authority are single-flighted (GUIDANCE §7).
type WebBotAuthResource struct {
	c *core

	mu       sync.Mutex
	cache    map[string]webBotAuthCacheEntry
	inflight map[string]*webBotAuthCall

	// now is replaceable by package tests so expiry boundaries do not depend
	// on wall-clock sleeps. Production clients leave it nil and use time.Now.
	now func() time.Time
}

// webBotAuthCacheEntry pairs a signature block with its parsed expiry.
type webBotAuthCacheEntry struct {
	block     WebBotAuthBlock
	expiresAt time.Time
}

// webBotAuthCall carries one authority's shared in-flight signing result.
type webBotAuthCall struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	completed bool
	block     WebBotAuthBlock
	err       error
}

// SignURL returns web-bot-auth signature headers for rawURL's authority.
// Pass the full merchant URL (e.g. https://merchant.com/checkout); the
// hostname is extracted as the cache key. Attach the returned Signature and
// SignatureInput values as the Signature and Signature-Input HTTP headers on
// outbound requests to the merchant site.
//
// An unparseable rawURL wraps ErrInvalidArgument with the message
// "Invalid URL: <url>"; a 2xx response missing the web_bot_auth block or
// carrying an unparseable expires_at also wraps ErrInvalidArgument (parity:
// web-bot-auth.ts:136-186). Waiters can stop waiting independently; shared
// work is canceled only when no waiters remain. A 401 response is not
// automatically replayed because the signing POST has no documented
// idempotency guarantee.
func (r *WebBotAuthResource) SignURL(ctx context.Context, rawURL string) (*WebBotAuthBlock, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	authority, err := webBotAuthority(rawURL)
	if err != nil {
		// net/url errors and rawURL can both contain user information, query
		// values, and fragments. They are intentionally not reflected.
		return nil, fmt.Errorf("%w: invalid merchant URL", ErrInvalidArgument)
	}
	if r == nil || r.c == nil {
		return nil, fmt.Errorf("%w: web-bot-auth resource is not configured", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := r.currentTime()
	r.mu.Lock()
	if cached, ok := r.cache[authority]; ok {
		if now.Before(cached.expiresAt.Add(-webBotAuthExpiryBuffer)) {
			block := cached.block
			r.mu.Unlock()
			return &block, nil
		}
		delete(r.cache, authority)
	}
	if call := r.inflight[authority]; call != nil {
		call.waiters++
		r.mu.Unlock()
		return r.waitForWebBotAuth(ctx, authority, call)
	}

	// Shared work retains values from the initiating context but owns its
	// cancellation. Each caller can leave independently; cancellation reaches
	// the HTTP request only after the final waiter leaves.
	workCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	call := &webBotAuthCall{
		done:    make(chan struct{}),
		cancel:  cancel,
		waiters: 1,
	}
	r.inflight[authority] = call
	r.mu.Unlock()

	go r.signWebBotAuth(workCtx, authority, rawURL, call)
	return r.waitForWebBotAuth(ctx, authority, call)
}

func (r *WebBotAuthResource) currentTime() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// webBotAuthority validates rawURL without consulting authentication or the
// network and returns its normalized, port-independent hostname identity.
func webBotAuthority(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if !u.IsAbs() || u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("must be an absolute hierarchical URL with a host")
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("scheme must be HTTP or HTTPS")
	}
	if u.User != nil {
		return "", fmt.Errorf("user information is not permitted")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return "", fmt.Errorf("hostname must not be empty")
	}
	if strings.ContainsAny(hostname, " \t\r\n\x00") {
		return "", fmt.Errorf("hostname contains invalid whitespace")
	}
	canonical := canonicalWebBotHostname(hostname)
	if canonical == "" {
		return "", fmt.Errorf("hostname must not be empty")
	}
	return canonical, nil
}

func canonicalWebBotHostname(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".")
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.String()
	}
	return strings.ToLower(hostname)
}

func (r *WebBotAuthResource) waitForWebBotAuth(ctx context.Context, authority string, call *webBotAuthCall) (*WebBotAuthBlock, error) {
	select {
	case <-call.done:
		r.releaseWebBotWaiter(authority, call, false)
		if call.err != nil {
			return nil, call.err
		}
		block := call.block
		return &block, nil
	case <-ctx.Done():
		r.releaseWebBotWaiter(authority, call, true)
		return nil, ctx.Err()
	}
}

func (r *WebBotAuthResource) releaseWebBotWaiter(authority string, call *webBotAuthCall, canceled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if call.waiters > 0 {
		call.waiters--
	}
	if canceled && call.waiters == 0 && !call.completed {
		// Remove the abandoned generation before cancellation so a new caller
		// can start fresh instead of joining work that is already doomed.
		if r.inflight[authority] == call {
			delete(r.inflight, authority)
		}
		call.cancel()
	}
}

func (r *WebBotAuthResource) signWebBotAuth(ctx context.Context, authority, rawURL string, call *webBotAuthCall) {
	block, expiresAt, err := r.fetchWebBotAuth(ctx, authority, rawURL)

	r.mu.Lock()
	current := r.inflight[authority] == call
	call.completed = true
	call.err = err
	if block != nil {
		call.block = *block
	}
	if current {
		delete(r.inflight, authority)
		if err == nil && r.currentTime().Before(expiresAt.Add(-webBotAuthExpiryBuffer)) {
			r.cache[authority] = webBotAuthCacheEntry{block: *block, expiresAt: expiresAt}
		}
	}
	close(call.done)
	r.mu.Unlock()
	call.cancel()
}

func (r *WebBotAuthResource) fetchWebBotAuth(ctx context.Context, authority, rawURL string) (*WebBotAuthBlock, time.Time, error) {
	body, err := json.Marshal(struct {
		URL string `json:"url"`
	}{URL: rawURL})
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("stripelink: encode web-bot-auth request: %w", err)
	}
	type signResponse struct {
		WebBotAuth *WebBotAuthBlock `json:"web_bot_auth"`
	}
	response, err := doJSON[*signResponse](ctx, r.c, apiRequest{
		method:              http.MethodPost,
		url:                 r.c.apiBaseURL + "/web_bot_auth/sign",
		header:              http.Header{"Content-Type": {"application/json"}},
		body:                body,
		authenticated:       true,
		retryOnUnauthorized: false,
	})
	if err != nil {
		return nil, time.Time{}, resourceOperationError(err, "Failed to get web bot auth headers")
	}
	if response == nil || response.WebBotAuth == nil {
		return nil, time.Time{}, fmt.Errorf("%w: Sign response missing web_bot_auth block", ErrInvalidArgument)
	}
	block := *response.WebBotAuth
	expiresAt, err := validateWebBotAuthBlock(block, authority, r.currentTime())
	if err != nil {
		return nil, time.Time{}, err
	}
	return &block, expiresAt, nil
}

func validateWebBotAuthBlock(block WebBotAuthBlock, authority string, now time.Time) (time.Time, error) {
	for name, value := range map[string]string{
		"signature": block.Signature, "signature_input": block.SignatureInput,
		"signature_agent": block.SignatureAgent, "authority": block.Authority, "expires_at": block.ExpiresAt,
	} {
		if strings.TrimSpace(value) == "" {
			return time.Time{}, fmt.Errorf("%w: web_bot_auth.%s must not be empty", ErrInvalidArgument, name)
		}
	}
	boundAuthority, err := canonicalWebBotBlockAuthority(block.Authority)
	if err != nil || boundAuthority != authority {
		return time.Time{}, fmt.Errorf("%w: web_bot_auth authority does not match requested hostname", ErrInvalidArgument)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, block.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: credentials response has invalid expires_at", ErrInvalidArgument)
	}
	if !now.Before(expiresAt) {
		return time.Time{}, fmt.Errorf("%w: credentials response is expired", ErrInvalidArgument)
	}
	return expiresAt, nil
}

func canonicalWebBotBlockAuthority(authority string) (string, error) {
	if authority != strings.TrimSpace(authority) || strings.ContainsAny(authority, "/@?# \t\r\n\x00") {
		return "", fmt.Errorf("invalid authority")
	}
	hostname := authority
	if strings.HasPrefix(hostname, "[") && strings.HasSuffix(hostname, "]") {
		hostname = strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	}
	if hostname == "" || (strings.Contains(hostname, ":") && net.ParseIP(hostname) == nil) {
		return "", fmt.Errorf("invalid authority")
	}
	return canonicalWebBotHostname(hostname), nil
}
