package stripelink

import (
	"context"
	"fmt"
	"net/http"
)

// UserInfoResource retrieves the authenticated user's profile from
// {APIBaseURL}/userinfo (parity: user-info.ts:31). It is safe for concurrent
// use.
type UserInfoResource struct {
	c *core
}

// Retrieve returns the authenticated user's profile. Fields the server omits
// are nil pointers — the Go equivalent of the JS SDK's explicit-null
// coercion (user-info.ts:117-124, GUIDANCE §5.7).
func (r *UserInfoResource) Retrieve(ctx context.Context) (*UserInfo, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if r == nil || r.c == nil || r.c.apiBaseURL == "" {
		return nil, fmt.Errorf("%w: user-info resource is not configured", ErrInvalidArgument)
	}
	response, err := doJSON[*UserInfo](ctx, r.c, apiRequest{
		method:              http.MethodGet,
		url:                 r.c.apiBaseURL + "/userinfo",
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		return nil, resourceOperationError(err, "Failed to retrieve user info")
	}
	if response == nil {
		return nil, fmt.Errorf("stripelink: decode successful response: expected JSON object")
	}
	return response, nil
}
