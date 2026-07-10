package stripelink

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors returned by the SDK. Match them with errors.Is.
var (
	// ErrNotFound is returned by SpendRequestsResource.Retrieve when the API
	// responds 404 (the JS SDK returns null; GUIDANCE §6.2 deviation #1).
	ErrNotFound = errors.New("stripelink: not found")

	// ErrAuthorizationPending is returned by AuthResource.PollDeviceAuthOnce
	// while the user has not yet approved or denied the device authorization.
	ErrAuthorizationPending = errors.New("stripelink: authorization pending")

	// ErrSlowDown is returned by AuthResource.PollDeviceAuthOnce when the
	// authorization server asks the client to increase its polling interval.
	// It is deliberately distinct from ErrAuthorizationPending so a blocking
	// poller can apply RFC 8628's five-second backoff only in this case.
	ErrSlowDown = errors.New("stripelink: slow down device authorization polling")

	// ErrNotAuthenticated is returned by the first authenticated call when no
	// access token is configured and storage holds no tokens (parity with the
	// JS SDK, which also fails lazily at call time).
	ErrNotAuthenticated = errors.New("stripelink: not authenticated")

	// ErrNoPendingDeviceAuth is returned when a caller asks to resume a device
	// authorization but storage contains no unexpired pending flow.
	ErrNoPendingDeviceAuth = errors.New("stripelink: no pending device authorization")

	// ErrInvalidConfiguration identifies invalid client configuration.
	ErrInvalidConfiguration = errors.New("stripelink: invalid configuration")

	// ErrInvalidArgument identifies an invalid method argument.
	ErrInvalidArgument = errors.New("stripelink: invalid argument")

	// ErrResponseTooLarge is returned when an HTTP response exceeds the
	// configured MaxResponseBodyBytes bound.
	ErrResponseTooLarge = errors.New("stripelink: response body too large")

	// ErrStorageTooLarge is returned when an auth file exceeds the fixed safe
	// read bound.
	ErrStorageTooLarge = errors.New("stripelink: auth storage file too large")

	// ErrRedirect is returned when an endpoint responds with a redirect. The
	// SDK never follows redirects because they can leak bearer credentials.
	ErrRedirect = errors.New("stripelink: redirect refused")
)

// APIError reports a non-2xx HTTP response from the Link API or auth server,
// mirroring the JS LinkApiError. Match it with errors.AsType[*APIError]. The
// SDK intentionally has no generic base error type: sentinels classify local
// failures and the two concrete types retain structured API and transport
// details.
type APIError struct {
	// Code identifies the error category, defaulting to "api_error". Device
	// flow responses carry the OAuth error code (e.g. "expired_token",
	// "access_denied") through unchanged.
	Code string

	// Message is the human-readable error message, built from the parity
	// templates in GUIDANCE §6.1 (e.g. "Failed to create spend request (%d): %s").
	Message string

	// Status is the HTTP status code of the failing response.
	Status int

	// RawBody is the raw response body as received, which may not be JSON.
	RawBody string

	// Details is the response body parsed as JSON, or nil when the body was
	// not valid JSON.
	Details json.RawMessage
}

// Error returns the error message.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return sanitizeDiagnosticText(e.Message, "remote API request failed")
}

// String returns the same credential-safe, bounded diagnostic as Error.
func (e *APIError) String() string { return e.Error() }

// GoString returns a credential-safe structural summary. RawBody and Details
// deliberately remain available as explicit fields for callers that need to
// inspect them, but implicit formatting never includes their contents.
func (e *APIError) GoString() string {
	if e == nil {
		return "(*stripelink.APIError)(nil)"
	}
	return truncateDiagnostic(fmt.Sprintf("&stripelink.APIError{Code:%q, Message:%q, Status:%d, RawBody:<redacted %d bytes>, Details:<redacted %d bytes>}",
		sanitizeDiagnosticText(e.Code, "api_error"), e.Error(), e.Status, len(e.RawBody), len(e.Details)))
}

// Format prevents fmt's structural verbs from bypassing Error and exposing
// RawBody or Details.
func (e *APIError) Format(state fmt.State, verb rune) {
	if verb == 'v' && state.Flag('#') {
		_, _ = state.Write([]byte(e.GoString()))
		return
	}
	_, _ = state.Write([]byte(e.Error()))
}

// TransportError reports a network-level failure: the HTTP request could not
// be completed at all (DNS, connection, TLS, context cancellation, …). It
// mirrors the JS LinkTransportError; match it with
// errors.AsType[*TransportError].
type TransportError struct {
	// Code is always "transport_error", matching the JavaScript SDK.
	Code string

	// Method is the HTTP method of the failed request.
	Method string

	// URL is the full URL of the failed request.
	URL string

	// Err is the underlying cause; Unwrap returns it.
	Err error
}

// Error returns the error message ("Request failed: <method> <url>", the JS
// parity template).
func (e *TransportError) Error() string {
	if e == nil {
		return "<nil>"
	}
	method := sanitizeDiagnosticText(e.Method, "HTTP")
	return truncateDiagnostic(fmt.Sprintf("Request failed: %s %s", method, safeURLDiagnostic(e.URL)))
}

// String returns the credential-safe transport diagnostic.
func (e *TransportError) String() string { return e.Error() }

// GoString returns a structural summary without URL credentials, query
// values, fragments, or the possibly sensitive underlying error message.
func (e *TransportError) GoString() string {
	if e == nil {
		return "(*stripelink.TransportError)(nil)"
	}
	return truncateDiagnostic(fmt.Sprintf("&stripelink.TransportError{Code:%q, Method:%q, URL:%q, Err:<redacted>}",
		sanitizeDiagnosticText(e.Code, "transport_error"), sanitizeDiagnosticText(e.Method, "HTTP"), safeURLDiagnostic(e.URL)))
}

// Format prevents fmt's %#v form from exposing URL or cause details.
func (e *TransportError) Format(state fmt.State, verb rune) {
	if verb == 'v' && state.Flag('#') {
		_, _ = state.Write([]byte(e.GoString()))
		return
	}
	_, _ = state.Write([]byte(e.Error()))
}

// Unwrap returns the underlying cause Err.
func (e *TransportError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
