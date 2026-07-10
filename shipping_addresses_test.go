package stripelink

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestShippingAddressesListPreservesNullAndPresentEmptyValues(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"shipping_addresses":[{"id":"shad_null","is_default":false,"nickname":null,"address":null},{"id":"shad_values","is_default":true,"nickname":"","address":{"name":"","line_1":"1 Main St","line_2":null,"locality":"Town","dependent_locality":null,"administrative_area":"","postal_code":"12345","sorting_code":null,"country_code":"NZ"}}]}`)

	got, err := newResourceTestClient(t, rt, nil).ShippingAddresses.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].Nickname != nil || got[0].Address != nil {
		t.Fatalf("null record = %#v", got)
	}
	second := got[1]
	if second.Nickname == nil || *second.Nickname != "" || second.Address == nil || second.Address.Name == nil || *second.Address.Name != "" ||
		second.Address.Line2 != nil || second.Address.AdministrativeArea == nil || *second.Address.AdministrativeArea != "" {
		t.Fatalf("present/null distinctions lost: %#v", second)
	}
	requests := rt.Requests()
	if len(requests) != 1 || requests[0].Method != http.MethodGet || requests[0].URL != "http://127.0.0.1:8080/api/shipping_addresses" {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestShippingAddressesListEmptyEnvelopeForms(t *testing.T) {
	for _, body := range []string{`{}`, `{"shipping_addresses":null}`, `{"shipping_addresses":[]}`} {
		t.Run(body, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, body)
			got, err := newResourceTestClient(t, rt, nil).ShippingAddresses.List(t.Context())
			if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("List = (%#v, %v), want non-nil empty", got, err)
			}
		})
	}
}

func TestShippingAddressesListSafe401ReplayAndErrors(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusUnauthorized, `{}`)
	rt.respond(http.StatusOK, `{"shipping_addresses":[]}`)
	var calls int
	token := func(_ context.Context, request AccessTokenRequest) (string, error) {
		calls++
		if request.ForceRefresh {
			return "new", nil
		}
		return "old", nil
	}
	got, err := newResourceTestClient(t, rt, token).ShippingAddresses.List(t.Context())
	if err != nil || got == nil || calls != 2 || len(rt.Requests()) != 2 || rt.Requests()[1].Header.Get("Authorization") != "Bearer new" {
		t.Fatalf("List/replay = (%#v, %v), calls=%d requests=%#v", got, err, calls, rt.Requests())
	}

	rt = &recordingTransport{}
	rt.respond(http.StatusBadGateway, "upstream unavailable")
	_, err = newResourceTestClient(t, rt, nil).ShippingAddresses.List(t.Context())
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Message != "Failed to list shipping addresses (502): remote API returned a non-JSON error" || apiErr.Details != nil {
		t.Fatalf("error = %#v", err)
	}
}

func TestShippingAddressesListRejectsMalformedSuccess(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"shipping_addresses":{}}`)
	if _, err := newResourceTestClient(t, rt, nil).ShippingAddresses.List(t.Context()); err == nil {
		t.Fatal("List accepted malformed envelope")
	}
}
