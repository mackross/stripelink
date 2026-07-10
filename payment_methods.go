package stripelink

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// PaymentMethodsResource lists the user's saved payment methods at
// {APIBaseURL}/payment-details — note the hyphen, not payment_methods
// (GUIDANCE §5.8). It is safe for concurrent use.
type PaymentMethodsResource struct {
	c *core
}

// List returns the user's saved payment methods. The endpoint's
// {"payment_details": [...]} envelope is unwrapped internally; a missing or
// null field yields an empty, non-nil slice (parity:
// payment-methods.ts:122-123).
func (r *PaymentMethodsResource) List(ctx context.Context) ([]PaymentMethod, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if r == nil || r.c == nil || r.c.apiBaseURL == "" {
		return nil, fmt.Errorf("%w: payment-methods resource is not configured", ErrInvalidArgument)
	}
	type listResponse struct {
		PaymentDetails []PaymentMethod `json:"payment_details"`
	}

	response, err := doJSON[*listResponse](ctx, r.c, apiRequest{
		method:              http.MethodGet,
		url:                 r.c.apiBaseURL + "/payment-details",
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		return nil, resourceOperationError(err, "Failed to list payment methods")
	}
	if response == nil {
		return nil, fmt.Errorf("stripelink: decode successful response: expected JSON object")
	}
	if response.PaymentDetails == nil {
		return []PaymentMethod{}, nil
	}
	return response.PaymentDetails, nil
}

// resourceOperationError adds the upstream resource-specific operation text
// while retaining every structured API error field. Non-API errors retain
// their identity unchanged.
func resourceOperationError(err error, operation string) error {
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok {
		return err
	}
	copy := *apiErr
	copy.Message = fmt.Sprintf("%s (%d): %s", operation, copy.Status, copy.Message)
	return &copy
}
