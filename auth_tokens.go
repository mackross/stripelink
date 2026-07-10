package stripelink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
// authentication state. An invalid_token response is treated as already
// revoked. Other revocation failures retain credentials so the caller can
// retry. Once revocation succeeds, clearing uses a bounded internal context so
// caller cancellation cannot retain a token known to be revoked. Static tokens
// and custom AccessTokenFunc providers are caller-owned and cannot be logged
// out with this method.
func (a *AuthResource) Logout(ctx context.Context) error {
	if err := requireContext(ctx); err != nil {
		return err
	}
	if !a.c.managesSession {
		return fmt.Errorf("%w: logout is unavailable for caller-owned tokens", ErrInvalidArgument)
	}
	state, err := a.c.storage.Load(ctx)
	if err != nil {
		return fmt.Errorf("stripelink: load authentication for logout: %w", err)
	}
	if state == nil || state.Auth == nil || state.Auth.RefreshToken == "" {
		return ErrNotAuthenticated
	}
	if err := a.RevokeToken(ctx, state.Auth.RefreshToken); err != nil {
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Code != "invalid_token" {
			return err
		}
	}
	clearCtx, cancel := detachedAuthContext(ctx)
	defer cancel()
	if err := a.c.storage.Clear(clearCtx); err != nil {
		return fmt.Errorf("stripelink: clear revoked authentication: %w", err)
	}
	return nil
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
	return newAuthAPIError(code, fmt.Sprintf("%s (%d): %s", prefix, status, code), status, body, data)
}

func newAuthAPIError(code, message string, status int, body []byte, data json.RawMessage) *APIError {
	code = safeOAuthCode(code)
	return &APIError{
		Code:    code,
		Message: message,
		Status:  status,
		RawBody: string(body),
		Details: append(json.RawMessage(nil), data...),
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
	err := a.c.storage.Transact(ctx, func(state *AuthStorageState) error {
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
