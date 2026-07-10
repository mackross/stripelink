package stripelink

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestUserInfoRetrievePreservesMissingNullAndEmpty(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		check func(*testing.T, *UserInfo)
	}{
		{"missing", `{}`, func(t *testing.T, got *UserInfo) {
			if got.Email != nil || got.Name != nil || got.FirstName != nil || got.LastName != nil || got.Phone != nil {
				t.Fatalf("missing fields = %#v", got)
			}
		}},
		{"null", `{"email":null,"name":null,"first_name":null,"last_name":null,"phone":null}`, func(t *testing.T, got *UserInfo) {
			if got.Email != nil || got.Name != nil || got.FirstName != nil || got.LastName != nil || got.Phone != nil {
				t.Fatalf("null fields = %#v", got)
			}
		}},
		{"empty and values", `{"email":"","name":"Ada","first_name":"","last_name":"Lovelace","phone":"+640000000"}`, func(t *testing.T, got *UserInfo) {
			if got.Email == nil || *got.Email != "" || got.Name == nil || *got.Name != "Ada" || got.FirstName == nil || *got.FirstName != "" || got.Phone == nil || *got.Phone != "+640000000" {
				t.Fatalf("present fields = %#v", got)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, tc.body)
			got, err := newResourceTestClient(t, rt, nil).UserInfo.Retrieve(t.Context())
			if err != nil {
				t.Fatalf("Retrieve: %v", err)
			}
			tc.check(t, got)
			requests := rt.Requests()
			if len(requests) != 1 || requests[0].Method != http.MethodGet || requests[0].URL != "http://127.0.0.1:8080/api/userinfo" {
				t.Fatalf("requests = %#v", requests)
			}
		})
	}
}

func TestUserInfoRetrieveSafe401ReplayAndErrors(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusUnauthorized, `{}`)
	rt.respond(http.StatusOK, `{"email":"new@example.test"}`)
	token := func(_ context.Context, request AccessTokenRequest) (string, error) {
		if request.ForceRefresh {
			return "fresh", nil
		}
		return "expired", nil
	}
	got, err := newResourceTestClient(t, rt, token).UserInfo.Retrieve(t.Context())
	if err != nil || got.Email == nil || *got.Email != "new@example.test" || len(rt.Requests()) != 2 || rt.Requests()[1].Header.Get("Authorization") != "Bearer fresh" {
		t.Fatalf("Retrieve/replay = (%#v, %v), requests=%#v", got, err, rt.Requests())
	}

	rt = &recordingTransport{}
	rt.respond(http.StatusForbidden, `{"message":"profile denied"}`)
	_, err = newResourceTestClient(t, rt, nil).UserInfo.Retrieve(t.Context())
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Message != "Failed to retrieve user info (403): profile denied" {
		t.Fatalf("error = %#v", err)
	}
}

func TestUserInfoRetrieveRejectsMalformedSuccess(t *testing.T) {
	for _, body := range []string{`not-json`, `null`, `[]`} {
		t.Run(body, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, body)
			if _, err := newResourceTestClient(t, rt, nil).UserInfo.Retrieve(t.Context()); err == nil {
				t.Fatal("Retrieve accepted malformed successful response")
			}
		})
	}
}

func TestReadResourcesVerboseLogsNeverContainResponsePII(t *testing.T) {
	logger, logs := newCapturingLogger()
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"payment_details":[{"id":"secret-payment-id","type":"card","is_default":true,"card_details":{"brand":"visa","last4":"4242","exp_month":12,"exp_year":2031}}]}`)
	rt.respond(http.StatusOK, `{"shipping_addresses":[{"id":"secret-address-id","is_default":true,"nickname":"Home","address":{"name":"Private Person","line_1":"1 Secret Lane","country_code":"NZ"}}]}`)
	rt.respond(http.StatusOK, `{"email":"private@example.test","name":"Private Person","phone":"+649999999"}`)
	client := newResourceTestClient(t, rt, func(context.Context, AccessTokenRequest) (string, error) {
		return "bearer-secret", nil
	}, func(opts *Options) {
		opts.Verbose = true
		opts.Logger = logger
	})
	if _, err := client.PaymentMethods.List(t.Context()); err != nil {
		t.Fatalf("PaymentMethods.List: %v", err)
	}
	if _, err := client.ShippingAddresses.List(t.Context()); err != nil {
		t.Fatalf("ShippingAddresses.List: %v", err)
	}
	if _, err := client.UserInfo.Retrieve(t.Context()); err != nil {
		t.Fatalf("UserInfo.Retrieve: %v", err)
	}
	joined := strings.Join(logs.Lines(), "\n")
	for _, secret := range []string{"bearer-secret", "secret-payment-id", "4242", "secret-address-id", "Private Person", "1 Secret Lane", "private@example.test", "+649999999"} {
		if strings.Contains(joined, secret) {
			t.Errorf("logs contain %q: %s", secret, joined)
		}
	}
}
