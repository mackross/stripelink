package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// Diagnostics are deliberately much smaller than the response-body bound:
	// errors are commonly logged and must not become an amplification vector.
	maxDiagnosticBytes      = 512
	maxDiagnosticInputBytes = 4096
)

var (
	credentialFieldPattern = regexp.MustCompile(`(?i)["']?(authorization|cookie|access[_ -]?token|refresh[_ -]?token|device[_ -]?code|user[_ -]?code|card(?:[_ -]?number)?|number|cvc|cvv|shared[_ -]?payment[_ -]?token|link[_ -]?pay[_ -]?token|signature(?:[_ -]?input)?|payment[_ -]?details)["']?\s*(?::|=)\s*(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)`)
	bearerPattern          = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;}\]]+`)
	knownTokenPattern      = regexp.MustCompile(`(?i)\b(?:spt|link_pay|access|refresh|device|tok|sk|rk)_[A-Za-z0-9._~+/=-]{6,}`)
	signaturePattern       = regexp.MustCompile(`\bsig[0-9]+=:?[^:\s]+:`)
	panCandidatePattern    = regexp.MustCompile(`[0-9](?:[0-9 -]{10,23})[0-9]`)
)

// core is the single shared request engine behind every resource — the Go
// consolidation of the per-resource rawFetch/apiFetch copies in the JS SDK
// (GUIDANCE §5.4). It owns, in order: metadata-only verbose logging, bearer
// injection, generation-aware 401 refresh with one replay for safe reads only,
// bounded tolerant body decoding (non-JSON bodies are not an error), redirect
// refusal, and wrapping of network-level failures in *TransportError.
type core struct {
	clientName           string
	httpClient           *http.Client
	getAccessToken       AccessTokenFunc
	storage              AuthStorage
	authBaseURL          string
	apiBaseURL           string
	spendRequestBaseURL  string
	logger               *slog.Logger
	verbose              bool
	managesSession       bool
	maxResponseBodyBytes int64
}

// apiRequest describes one HTTP request to the Link API or auth server.
type apiRequest struct {
	method string
	url    string
	header http.Header
	body   []byte // nil means no body

	// authenticated selects bearer injection plus the 401-retry policy. The
	// device-flow endpoints are unauthenticated form posts.
	authenticated bool

	// retryOnUnauthorized permits one replay after generation-aware refresh.
	// It is true only for safe read methods. Mutation POSTs must never be
	// replayed unless the Link API later documents an idempotency guarantee.
	retryOnUnauthorized bool
}

// do executes req and returns the response status and bounded body. Non-2xx
// statuses are not an error at this layer; status handling is the caller's
// job. Network-level failures are returned as *TransportError. It refuses
// redirects and returns ErrResponseTooLarge before decoding an oversized body.
func (c *core) do(ctx context.Context, req apiRequest) (status int, body []byte, err error) {
	if ctx == nil {
		return 0, nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if c == nil || c.httpClient == nil {
		return 0, nil, fmt.Errorf("%w: client transport is not configured", ErrInvalidConfiguration)
	}
	if c.maxResponseBodyBytes <= 0 {
		return 0, nil, fmt.Errorf("%w: response body bound is not configured", ErrInvalidConfiguration)
	}

	token := ""
	if req.authenticated {
		if c.getAccessToken == nil {
			return 0, nil, ErrNotAuthenticated
		}
		token, err = c.getAccessToken(ctx, AccessTokenRequest{})
		if err != nil {
			return 0, nil, err
		}
		if token == "" {
			return 0, nil, ErrNotAuthenticated
		}
	}

	maximumAttempts := 1
	if req.authenticated && req.retryOnUnauthorized && req.method == http.MethodGet {
		maximumAttempts = 2
	}
	for attempt := 1; attempt <= maximumAttempts; attempt++ {
		status, body, err = c.doAttempt(ctx, req, token, attempt)
		if err != nil {
			return 0, nil, err
		}
		if status != http.StatusUnauthorized || attempt == maximumAttempts {
			return status, body, nil
		}

		refreshedToken, tokenErr := c.getAccessToken(ctx, AccessTokenRequest{
			ForceRefresh:  true,
			RejectedToken: token,
		})
		if tokenErr != nil {
			return 0, nil, tokenErr
		}
		if refreshedToken == "" {
			return 0, nil, ErrNotAuthenticated
		}
		token = refreshedToken
	}
	return status, body, nil
}

func (c *core) doAttempt(ctx context.Context, req apiRequest, token string, attempt int) (int, []byte, error) {
	var requestBody io.Reader
	if req.body != nil {
		requestBody = bytes.NewReader(req.body)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, req.method, req.url, requestBody)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: construct HTTP request: %w", ErrInvalidArgument, err)
	}
	if req.header != nil {
		httpRequest.Header = req.header.Clone()
	}
	if req.authenticated {
		httpRequest.Header.Set("Authorization", "Bearer "+token)
	}

	sanitizedURL := sanitizeURLForLog(httpRequest.URL)
	if c.verbose {
		c.logger.DebugContext(ctx, "stripelink HTTP request",
			slog.String("method", httpRequest.Method),
			slog.String("url", sanitizedURL),
			slog.Int("attempt", attempt),
			slog.Any("header_names", sortedHeaderNames(httpRequest.Header)),
		)
	}
	startedAt := time.Now()
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		if c.verbose {
			c.logger.DebugContext(ctx, "stripelink HTTP request failed",
				slog.String("method", httpRequest.Method),
				slog.String("url", sanitizedURL),
				slog.Int("attempt", attempt),
				slog.Duration("duration", time.Since(startedAt)),
			)
		}
		return 0, nil, newTransportError(httpRequest.Method, req.url, err)
	}

	body, readErr := readBoundedAndClose(response.Body, c.maxResponseBodyBytes)
	if c.verbose {
		c.logger.DebugContext(ctx, "stripelink HTTP response",
			slog.String("method", httpRequest.Method),
			slog.String("url", sanitizedURL),
			slog.Int("attempt", attempt),
			slog.Int("status", response.StatusCode),
			slog.Duration("duration", time.Since(startedAt)),
			slog.Int("body_bytes", len(body)),
			slog.Any("header_names", sortedHeaderNames(response.Header)),
		)
	}
	if readErr != nil {
		if readErr == ErrResponseTooLarge {
			return 0, nil, readErr
		}
		return 0, nil, newTransportError(httpRequest.Method, req.url, readErr)
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return 0, nil, newTransportError(httpRequest.Method, req.url, ErrRedirect)
	}
	return response.StatusCode, body, nil
}

func newTransportError(method, rawURL string, cause error) *TransportError {
	return &TransportError{
		Code:   "transport_error",
		Method: method,
		URL:    rawURL,
		Err:    cause,
	}
}

func readBoundedAndClose(body io.ReadCloser, maximum int64) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	readLimit := maximum
	if maximum < math.MaxInt64 {
		readLimit++
	}
	contents, readErr := io.ReadAll(io.LimitReader(body, readLimit))
	closeErr := body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if int64(len(contents)) > maximum {
		return nil, ErrResponseTooLarge
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return contents, nil
}

func sanitizeURLForLog(u *url.URL) string {
	if u == nil {
		return "<invalid-url>"
	}
	copy := *u
	copy.User = nil
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	copy.RawFragment = ""
	return copy.String()
}

// safeURLDiagnostic keeps only the endpoint identity. Parse errors use a
// fixed marker because net/url errors can quote their secret-bearing input.
func safeURLDiagnostic(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return "<invalid-url>"
	}
	safe := sanitizeURLForLog(u)
	if len(safe) > maxDiagnosticBytes {
		return "<redacted-url>"
	}
	return safe
}

func sortedHeaderNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// doJSON executes req via do and decodes a 2xx JSON body into T.
func doJSON[T any](ctx context.Context, c *core, req apiRequest) (T, error) {
	var zero T
	status, body, err := c.do(ctx, req)
	if err != nil {
		return zero, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return zero, newAPIError(status, body)
	}
	var result T
	if err := json.Unmarshal(body, &result); err != nil {
		return zero, fmt.Errorf("stripelink: decode successful response: %w", err)
	}
	return result, nil
}

func newAPIError(status int, body []byte) *APIError {
	details := validJSONCopy(body)
	return &APIError{
		Code:    "api_error",
		Message: extractAPIErrorMessage(body),
		Status:  status,
		RawBody: string(body),
		Details: details,
	}
}

func validJSONCopy(body []byte) json.RawMessage {
	if !json.Valid(body) {
		return nil
	}
	return append(json.RawMessage(nil), body...)
}

func extractAPIErrorMessage(body []byte) string {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil {
		if rawError, ok := fields["error"]; ok {
			var nested struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(rawError, &nested) == nil && nested.Message != "" {
				return sanitizeDiagnosticText(nested.Message, "remote API request failed")
			}
			var message string
			if json.Unmarshal(rawError, &message) == nil && message != "" {
				return sanitizeDiagnosticText(message, "remote API request failed")
			}
		}
		if rawMessage, ok := fields["message"]; ok {
			var message string
			if json.Unmarshal(rawMessage, &message) == nil && message != "" {
				return sanitizeDiagnosticText(message, "remote API request failed")
			}
		}
	}
	if len(bytes.TrimSpace(body)) != 0 {
		// A plain-text or arbitrary JSON body has no field boundary that lets us
		// reliably distinguish a diagnostic from a credential. Keep it available
		// in RawBody for explicit inspection, but never reflect it implicitly.
		if json.Valid(body) {
			return "remote API returned an error response"
		}
		return "remote API returned a non-JSON error"
	}
	return "remote API returned an empty error response"
}

// sanitizeDiagnosticText preserves ordinary human-readable server messages,
// while redacting field-labelled credentials and recognizable credential
// formats. It intentionally does not strip arbitrary digits: amounts, status
// codes, request counts, and dates remain useful diagnostics.
func sanitizeDiagnosticText(value, fallback string) string {
	if value == "" {
		return fallback
	}
	truncatedInput := false
	if len(value) > maxDiagnosticInputBytes {
		value = value[:maxDiagnosticInputBytes]
		for !utf8.ValidString(value) && len(value) > 0 {
			value = value[:len(value)-1]
		}
		truncatedInput = true
	}
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	// A bare three- or four-digit server message has no diagnostic context
	// that can distinguish it from a CVC. Redact only that exact shape; status
	// codes and amounts embedded in ordinary diagnostics remain untouched.
	if isBareCVC(value) {
		return "<redacted>"
	}
	value = credentialFieldPattern.ReplaceAllString(value, "$1=<redacted>")
	value = bearerPattern.ReplaceAllString(value, "Bearer <redacted>")
	value = knownTokenPattern.ReplaceAllString(value, "<redacted>")
	value = signaturePattern.ReplaceAllString(value, "<redacted>")
	value = panCandidatePattern.ReplaceAllStringFunc(value, func(candidate string) string {
		if isPaymentCardNumber(candidate) {
			return "<redacted>"
		}
		return candidate
	})
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return fallback
	}
	if truncatedInput {
		value += " …"
	}
	return truncateDiagnostic(value)
}

func isBareCVC(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 3 || len(value) > 4 {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func truncateDiagnostic(value string) string {
	if len(value) <= maxDiagnosticBytes {
		return value
	}
	const suffix = " …"
	end := maxDiagnosticBytes - len(suffix)
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end] + suffix
}

// isPaymentCardNumber recognizes only 12–19 digit, Luhn-valid candidates.
// This is credential-format detection, not generic digit stripping.
func isPaymentCardNumber(candidate string) bool {
	digits := make([]byte, 0, len(candidate))
	for i := 0; i < len(candidate); i++ {
		if candidate[i] >= '0' && candidate[i] <= '9' {
			digits = append(digits, candidate[i]-'0')
		}
	}
	if len(digits) < 12 || len(digits) > 19 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i, digit := range digits {
		value := int(digit)
		if i%2 == parity {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
	}
	return sum%10 == 0
}
