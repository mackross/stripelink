package stripelink

import (
	"context"
	"fmt"
	"net/http"
)

// ShippingAddressesResource lists the user's saved shipping addresses at
// {APIBaseURL}/shipping_addresses (parity: shipping-address.ts:31). It is
// safe for concurrent use.
type ShippingAddressesResource struct {
	c *core
}

// List returns the user's saved shipping addresses. The endpoint's
// {"shipping_addresses": [...]} envelope is unwrapped internally; a missing
// or null field yields an empty, non-nil slice (parity:
// shipping-address.ts:122-125).
func (r *ShippingAddressesResource) List(ctx context.Context) ([]ShippingAddressRecord, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if r == nil || r.c == nil || r.c.apiBaseURL == "" {
		return nil, fmt.Errorf("%w: shipping-addresses resource is not configured", ErrInvalidArgument)
	}
	type listResponse struct {
		ShippingAddresses []ShippingAddressRecord `json:"shipping_addresses"`
	}

	response, err := doJSON[*listResponse](ctx, r.c, apiRequest{
		method:              http.MethodGet,
		url:                 r.c.apiBaseURL + "/shipping_addresses",
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		return nil, resourceOperationError(err, "Failed to list shipping addresses")
	}
	if response == nil {
		return nil, fmt.Errorf("stripelink: decode successful response: expected JSON object")
	}
	if response.ShippingAddresses == nil {
		return []ShippingAddressRecord{}, nil
	}
	return response.ShippingAddresses, nil
}
