package stripelink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// OAuth device-flow constants (parity: auth.ts:12-13).
const (
	clientID     = "lwlpk_U7Qy7ThG69STZk"
	defaultScope = "userinfo:read payment_methods.agentic"
)

// AuthResource implements the OAuth 2.0 device authorization flow (RFC 8628)
// against POST {AuthBaseURL}/device/code, /device/token, and /device/revoke;
// all requests are form-encoded (application/x-www-form-urlencoded).
// AuthResource is safe for concurrent use.
type AuthResource struct {
	c        *core
	hostname func() (string, error)
}

// String returns a credential-safe summary of a device authorization.
func (d DeviceAuth) String() string {
	return fmt.Sprintf("DeviceAuth{DeviceCode:<redacted> UserCode:<redacted> VerificationURL:<redacted> VerificationURLComplete:<redacted> ExpiresIn:%d ExpiresAt:%d Interval:%d}", d.ExpiresIn, d.ExpiresAt, d.Interval)
}

// GoString returns the credential-safe structural summary.
func (d DeviceAuth) GoString() string { return d.String() }

// Format makes every fmt verb use the credential-safe summary.
func (d DeviceAuth) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(d.String())) }

// String returns a credential-safe summary of OAuth tokens.
func (t AuthTokens) String() string {
	return fmt.Sprintf("AuthTokens{AccessToken:<redacted> RefreshToken:<redacted> ExpiresIn:%d TokenType:<redacted> ExpiresAt:%d}", t.ExpiresIn, t.ExpiresAt)
}

// GoString returns the credential-safe structural summary.
func (t AuthTokens) GoString() string { return t.String() }

// Format makes every fmt verb use the credential-safe summary.
func (t AuthTokens) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(t.String())) }

var errDeviceAuthSuperseded = errors.New("stripelink: device authorization was superseded by a newer flow")

// InitiateDeviceAuth starts and persists a pending device authorization. An
// optional non-empty clientName overrides Options.ClientName for this request;
// passing more than one name returns an error wrapping ErrInvalidArgument.
// The request carries connection_label "<clientName> on <hostname>" (falling
// back to clientName alone if the hostname cannot be determined) and
// client_hint clientName. Direct the user to VerificationURLComplete, then
// call PollDeviceAuth. Starting a new authorization replaces any previously
// persisted pending authorization.
func (a *AuthResource) InitiateDeviceAuth(ctx context.Context, clientName ...string) (*DeviceAuth, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if len(clientName) > 1 {
		return nil, fmt.Errorf("%w: at most one client name may be supplied", ErrInvalidArgument)
	}
	effectiveName := a.c.clientName
	if len(clientName) == 1 {
		if strings.TrimSpace(clientName[0]) == "" {
			return nil, fmt.Errorf("%w: client name must not be empty", ErrInvalidArgument)
		}
		effectiveName = clientName[0]
	}

	var generation uint64
	var previousPending *PendingDeviceAuth
	if err := a.c.storage.Update(ctx, func(state *AuthStorageState) error {
		previousPending = clonePending(state.PendingDeviceAuth)
		state.DeviceAuthGeneration = nextGeneration(state.DeviceAuthGeneration)
		generation = state.DeviceAuthGeneration
		state.PendingDeviceAuth = nil
		return nil
	}); err != nil {
		return nil, fmt.Errorf("stripelink: reserve device authorization: %w", err)
	}

	connectionLabel := effectiveName
	if hostname, err := a.resolveHostname(); err == nil && hostname != "" {
		connectionLabel += " on " + hostname
	}
	status, body, data, err := a.postForm(ctx, "/device/code", url.Values{
		"client_id":        {clientID},
		"scope":            {defaultScope},
		"connection_label": {connectionLabel},
		"client_hint":      {effectiveName},
	})
	if err != nil {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, err)
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, authAPIError("Device auth initiation failed", status, body, data))
	}

	var wire struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := decodeRequiredJSON(body, &wire); err != nil {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, fmt.Errorf("stripelink: decode device authorization response: %w", err))
	}
	if wire.DeviceCode == "" || wire.UserCode == "" || wire.VerificationURI == "" ||
		wire.VerificationURIComplete == "" || wire.ExpiresIn <= 0 || wire.Interval <= 0 {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, errors.New("stripelink: malformed device authorization response"))
	}
	expiresAt, ok := absoluteExpiry(time.Now(), int64(wire.ExpiresIn))
	if !ok {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, errors.New("stripelink: malformed device authorization response"))
	}
	da := &DeviceAuth{
		DeviceCode:              wire.DeviceCode,
		UserCode:                wire.UserCode,
		VerificationURL:         wire.VerificationURI,
		VerificationURLComplete: wire.VerificationURIComplete,
		ExpiresIn:               wire.ExpiresIn,
		ExpiresAt:               expiresAt,
		Interval:                wire.Interval,
	}
	pending := &PendingDeviceAuth{
		DeviceCode:      da.DeviceCode,
		Interval:        da.Interval,
		ExpiresAt:       da.ExpiresAt,
		VerificationURL: da.VerificationURLComplete,
		Phrase:          da.UserCode,
	}
	err = a.c.storage.Update(ctx, func(state *AuthStorageState) error {
		if state.DeviceAuthGeneration != generation {
			return errDeviceAuthSuperseded
		}
		state.PendingDeviceAuth = pending
		return nil
	})
	if err != nil {
		return nil, a.rollbackDeviceAuthReservation(generation, previousPending, fmt.Errorf("stripelink: persist pending device authorization: %w", err))
	}
	return da, nil
}

func (a *AuthResource) resolveHostname() (string, error) {
	if a.hostname != nil {
		return a.hostname()
	}
	return os.Hostname()
}

func (a *AuthResource) rollbackDeviceAuthReservation(generation uint64, previous *PendingDeviceAuth, cause error) error {
	err := a.c.storage.Update(context.Background(), func(state *AuthStorageState) error {
		if state.DeviceAuthGeneration == generation {
			state.PendingDeviceAuth = clonePending(previous)
		}
		return nil
	})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("stripelink: restore previous device authorization: %w", err))
	}
	return cause
}

// PollDeviceAuthOnce performs a single poll of the token endpoint for
// deviceCode — the 1:1 mirror of the JS pollDeviceAuth. While the user has
// not yet decided, it returns ErrAuthorizationPending; an OAuth "slow_down"
// response returns the distinct ErrSlowDown. On success it computes token
// expiry, persists the tokens, and clears the pending authorization. A failure
// surfaces as an *APIError with the OAuth code preserved: "expired_token"
// with message "Device code expired. Please restart the login flow." or
// "access_denied" with message "Authorization denied by user."
// (parity: auth.ts:157-175).
func (a *AuthResource) PollDeviceAuthOnce(ctx context.Context, deviceCode string) (*AuthTokens, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(deviceCode) == "" {
		return nil, fmt.Errorf("%w: device code must not be empty", ErrInvalidArgument)
	}
	status, body, data, err := a.postForm(ctx, "/device/token", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {clientID},
	})
	if err != nil {
		return nil, err
	}
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		tokens, err := decodeAuthTokens(body)
		if err != nil {
			return nil, fmt.Errorf("stripelink: decode device token response: %w", err)
		}

		if err := a.c.storage.Update(ctx, func(state *AuthStorageState) error {
			if state.PendingDeviceAuth == nil || state.PendingDeviceAuth.DeviceCode != deviceCode {
				return errDeviceAuthSuperseded
			}
			state.Auth = tokens
			state.PendingDeviceAuth = nil
			state.DeviceAuthGeneration = nextGeneration(state.DeviceAuthGeneration)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("stripelink: commit device authorization: %w", err)
		}
		return tokens, nil
	}

	code := oauthErrorCode(data)
	if status == http.StatusBadRequest {
		switch code {
		case "authorization_pending":
			return nil, ErrAuthorizationPending
		case "slow_down":
			return nil, errors.Join(ErrAuthorizationPending, ErrSlowDown)
		case "expired_token":
			apiErr := newAuthAPIError(code, "Device code expired. Please restart the login flow.", status, body, data)
			return nil, a.clearTerminalPending(ctx, deviceCode, apiErr)
		case "access_denied":
			apiErr := newAuthAPIError(code, "Authorization denied by user.", status, body, data)
			return nil, a.clearTerminalPending(ctx, deviceCode, apiErr)
		}
	}
	return nil, authAPIError("Token poll failed", status, body, data)
}

// PollDeviceAuth blocks until the device authorization da resolves: it polls
// every da.Interval seconds, adds five seconds on each ErrSlowDown response,
// and stops when ctx is canceled or da.ExpiresAt is reached — expiry
// returns the same "Device code expired. Please restart the login flow."
// *APIError as the server-side expiry. It is a Go-side convenience the JS
// CLI implements externally (GUIDANCE §6.2 deviation #9).
func (a *AuthResource) PollDeviceAuth(ctx context.Context, da *DeviceAuth) (*AuthTokens, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if da == nil || strings.TrimSpace(da.DeviceCode) == "" || da.ExpiresAt <= 0 || da.Interval <= 0 {
		return nil, fmt.Errorf("%w: invalid device authorization", ErrInvalidArgument)
	}
	expiresAt := time.UnixMilli(da.ExpiresAt)
	interval := time.Duration(da.Interval) * time.Second
	for {
		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			return nil, a.clearTerminalPending(ctx, da.DeviceCode, expiredDeviceCodeError())
		}
		wait := min(interval, remaining)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, contextFailure(ctx)
		case <-timer.C:
		}
		if !time.Now().Before(expiresAt) {
			return nil, a.clearTerminalPending(ctx, da.DeviceCode, expiredDeviceCodeError())
		}

		pollCtx, cancel := context.WithDeadline(ctx, expiresAt)
		tokens, err := a.PollDeviceAuthOnce(pollCtx, da.DeviceCode)
		cancel()
		if err == nil {
			return tokens, nil
		}
		if errors.Is(err, ErrSlowDown) {
			interval += 5 * time.Second
			continue
		}
		if errors.Is(err, ErrAuthorizationPending) {
			continue
		}
		if ctx.Err() != nil {
			return nil, contextFailure(ctx)
		}
		if !time.Now().Before(expiresAt) {
			return nil, a.clearTerminalPending(ctx, da.DeviceCode, expiredDeviceCodeError())
		}
		return nil, err
	}
}

// ResumeDeviceAuth loads the unexpired pending authorization created by
// InitiateDeviceAuth and polls it to completion. It returns
// ErrNoPendingDeviceAuth when storage has no resumable flow. This makes the
// default file-backed login lifecycle resumable without exposing the resolved
// storage implementation from Client.
func (a *AuthResource) ResumeDeviceAuth(ctx context.Context) (*AuthTokens, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	pending, err := a.c.storage.GetPendingDeviceAuth()
	if err != nil {
		return nil, fmt.Errorf("stripelink: load pending device authorization: %w", err)
	}
	if pending == nil {
		return nil, ErrNoPendingDeviceAuth
	}
	remaining := max(time.Until(time.UnixMilli(pending.ExpiresAt)), 0)
	da := &DeviceAuth{
		DeviceCode:              pending.DeviceCode,
		UserCode:                pending.Phrase,
		VerificationURLComplete: pending.VerificationURL,
		ExpiresIn:               int((remaining + time.Second - 1) / time.Second),
		ExpiresAt:               pending.ExpiresAt,
		Interval:                pending.Interval,
	}
	return a.PollDeviceAuth(ctx, da)
}

// RefreshToken exchanges refreshToken for fresh tokens via the
// "refresh_token" grant. Failures surface as an *APIError whose message
// follows the "Token refresh failed (%d): %s" parity template.
func (a *AuthResource) RefreshToken(ctx context.Context, refreshToken string) (*AuthTokens, error) {
	if err := requireContext(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("%w: refresh token must not be empty", ErrInvalidArgument)
	}
	status, body, data, err := a.postForm(ctx, "/device/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	})
	if err != nil {
		return nil, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, authAPIError("Token refresh failed", status, body, data)
	}
	tokens, err := decodeAuthTokens(body)
	if err != nil {
		return nil, fmt.Errorf("stripelink: decode token refresh response: %w", err)
	}
	return tokens, nil
}

// RevokeToken revokes token at the revocation endpoint. Failures surface as
// an *APIError whose message follows the "Token revocation failed (%d): %s"
// parity template.
func (a *AuthResource) RevokeToken(ctx context.Context, token string) error {
	if err := requireContext(ctx); err != nil {
		return err
	}
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("%w: token must not be empty", ErrInvalidArgument)
	}
	status, body, data, err := a.postForm(ctx, "/device/revoke", url.Values{
		"client_id": {clientID},
		"token":     {token},
	})
	if err != nil {
		return err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return authAPIError("Token revocation failed", status, body, data)
	}
	return nil
}

// Logout revokes the persisted refresh token and then clears all persisted
// authentication state. If revocation fails, credentials are retained so the
// caller can retry and Logout returns the revocation error. Static tokens and
// custom AccessTokenFunc providers are not owned by the SDK and cannot be
// logged out with this method.
func (a *AuthResource) Logout(ctx context.Context) error {
	if err := requireContext(ctx); err != nil {
		return err
	}
	if !a.c.managesSession {
		return fmt.Errorf("%w: logout is unavailable for caller-owned tokens", ErrInvalidArgument)
	}
	return a.c.storage.Update(ctx, func(state *AuthStorageState) error {
		if state.Auth == nil || state.Auth.RefreshToken == "" {
			return ErrNotAuthenticated
		}
		if err := a.RevokeToken(ctx, state.Auth.RefreshToken); err != nil {
			return err
		}
		state.Auth = nil
		state.PendingDeviceAuth = nil
		state.DeviceAuthGeneration = nextGeneration(state.DeviceAuthGeneration)
		return nil
	})
}

// postForm performs one unauthenticated form request to an OAuth endpoint.
func (a *AuthResource) postForm(ctx context.Context, path string, values url.Values) (int, []byte, json.RawMessage, error) {
	if err := requireContext(ctx); err != nil {
		return 0, nil, nil, err
	}
	encoded := values.Encode()
	status, body, err := a.c.do(ctx, apiRequest{
		method: http.MethodPost,
		url:    a.c.authBaseURL + path,
		header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		body:   []byte(encoded),
	})
	if err != nil {
		return 0, nil, nil, err
	}
	var data json.RawMessage
	if len(body) != 0 && json.Valid(body) {
		data = append(json.RawMessage(nil), body...)
	}
	return status, body, data, nil
}

func decodeRequiredJSON(body []byte, dst any) error {
	if len(body) == 0 || !json.Valid(body) {
		return errors.New("response is not valid JSON")
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}
	return nil
}

func decodeAuthTokens(body []byte) (*AuthTokens, error) {
	var tokens AuthTokens
	if err := decodeRequiredJSON(body, &tokens); err != nil {
		return nil, err
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.TokenType == "" || tokens.ExpiresIn <= 0 {
		return nil, errors.New("malformed token response")
	}
	expiresAt, ok := absoluteExpiry(time.Now(), tokens.ExpiresIn)
	if !ok {
		return nil, errors.New("malformed token response")
	}
	tokens.ExpiresAt = expiresAt
	return &tokens, nil
}

func absoluteExpiry(now time.Time, seconds int64) (int64, bool) {
	if seconds <= 0 || seconds > math.MaxInt64/int64(time.Second) {
		return 0, false
	}
	return now.Add(time.Duration(seconds) * time.Second).UnixMilli(), true
}

func authAPIError(prefix string, status int, body []byte, data json.RawMessage) *APIError {
	code, _ := oauthError(data)
	code = safeOAuthCode(code)
	return newAuthAPIError(code, fmt.Sprintf("%s (%d): %s", prefix, status, code), status, nil, nil)
}

func newAuthAPIError(code, message string, status int, body []byte, data json.RawMessage) *APIError {
	code = safeOAuthCode(code)
	return &APIError{
		Code:    code,
		Message: message,
		Status:  status,
	}
}

func safeOAuthCode(code string) string {
	switch code {
	case "access_denied", "authorization_pending", "expired_token", "invalid_client",
		"invalid_grant", "invalid_request", "invalid_scope", "invalid_token",
		"slow_down", "unauthorized_client", "unsupported_grant_type":
		return code
	default:
		return "api_error"
	}
}

func oauthError(data json.RawMessage) (code, description string) {
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if len(data) != 0 {
		_ = json.Unmarshal(data, &payload)
	}
	return payload.Error, payload.ErrorDescription
}

func oauthErrorCode(data json.RawMessage) string {
	code, _ := oauthError(data)
	return code
}

func expiredDeviceCodeError() *APIError {
	return &APIError{
		Code:    "expired_token",
		Message: "Device code expired. Please restart the login flow.",
		Status:  http.StatusBadRequest,
	}
}

func (a *AuthResource) clearTerminalPending(ctx context.Context, deviceCode string, terminal error) error {
	err := a.c.storage.Update(ctx, func(state *AuthStorageState) error {
		if state.PendingDeviceAuth == nil || state.PendingDeviceAuth.DeviceCode != deviceCode {
			return nil
		}
		state.PendingDeviceAuth = nil
		state.DeviceAuthGeneration = nextGeneration(state.DeviceAuthGeneration)
		return nil
	})
	if err != nil {
		return errors.Join(terminal, err)
	}
	return terminal
}

func contextFailure(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func requireContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	return contextFailure(ctx)
}
