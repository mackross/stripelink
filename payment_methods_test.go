package stripelink

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func newResourceTestClient(t *testing.T, rt *recordingTransport, token AccessTokenFunc, options ...func(*Options)) *Client {
	t.Helper()
	if token == nil {
		token = func(context.Context, AccessTokenRequest) (string, error) { return "test-token", nil }
	}
	opts := Options{
		APIBaseURL:     "http://127.0.0.1:8080/api",
		HTTPClient:     rt.client(),
		GetAccessToken: token,
		AuthStorage:    &MemoryStorage{},
	}
	for _, apply := range options {
		apply(&opts)
	}
	client, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestPaymentMethodsListEndpointEnvelopeAndForwardCompatibility(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"payment_details":[{"id":"pm_card","type":"card","is_default":true,"nickname":"daily","card_details":{"brand":"visa","last4":"4242","exp_month":12,"exp_year":2031}},{"id":"pm_bank","type":"future_bank_rail","is_default":false,"bank_account_details":{"last4":"6789","bank_name":"Example Bank"}}]}`)

	got, err := newResourceTestClient(t, rt, nil).PaymentMethods.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0].CardDetails == nil || got[0].CardDetails.Last4 != "4242" ||
		got[1].Type != "future_bank_rail" || got[1].BankAccountDetails == nil || got[1].BankAccountDetails.BankName != "Example Bank" {
		t.Fatalf("payment methods decoded incompletely: %#v", got)
	}
	requests := rt.Requests()
	if len(requests) != 1 || requests[0].Method != http.MethodGet || requests[0].URL != "http://127.0.0.1:8080/api/payment-details" {
		t.Fatalf("requests = %#v", requests)
	}
	if got := requests[0].Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestPaymentMethodsListMissingNullAndEmptyEnvelopesReturnNonNilEmpty(t *testing.T) {
	for _, body := range []string{`{}`, `{"payment_details":null}`, `{"payment_details":[]}`} {
		t.Run(body, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, body)
			got, err := newResourceTestClient(t, rt, nil).PaymentMethods.List(t.Context())
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if got == nil || len(got) != 0 {
				t.Fatalf("result = %#v, want non-nil empty slice", got)
			}
		})
	}
}

func TestPaymentMethodsListSafe401ReplayAndAPIError(t *testing.T) {
	t.Run("replays with refreshed authorization", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusUnauthorized, `{"error":"expired_token"}`)
		rt.respond(http.StatusOK, `{"payment_details":[{"id":"pm_new","type":"future_type","is_default":false}]}`)
		var tokenRequests []AccessTokenRequest
		token := func(_ context.Context, request AccessTokenRequest) (string, error) {
			tokenRequests = append(tokenRequests, request)
			if request.ForceRefresh {
				return "fresh-token", nil
			}
			return "expired-token", nil
		}
		got, err := newResourceTestClient(t, rt, token).PaymentMethods.List(t.Context())
		if err != nil || len(got) != 1 || got[0].ID != "pm_new" {
			t.Fatalf("List = (%#v, %v)", got, err)
		}
		requests := rt.Requests()
		if len(requests) != 2 || requests[0].Header.Get("Authorization") != "Bearer expired-token" || requests[1].Header.Get("Authorization") != "Bearer fresh-token" {
			t.Fatalf("replayed requests = %#v", requests)
		}
		if len(tokenRequests) != 2 || !tokenRequests[1].ForceRefresh || tokenRequests[1].RejectedToken != "expired-token" {
			t.Fatalf("token requests = %#v", tokenRequests)
		}
	})

	t.Run("preserves structured API error", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusForbidden, `{"error":{"message":"wallet unavailable"},"request_id":"req_123"}`)
		_, err := newResourceTestClient(t, rt, nil).PaymentMethods.List(t.Context())
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Status != http.StatusForbidden || apiErr.Message != "Failed to list payment methods (403): wallet unavailable" || !strings.Contains(string(apiErr.Details), "req_123") {
			t.Fatalf("error = %#v", err)
		}
	})
}

func TestPaymentMethodsListRejectsMalformedSuccess(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, `{"payment_details":`)
	if _, err := newResourceTestClient(t, rt, nil).PaymentMethods.List(t.Context()); err == nil {
		t.Fatal("List accepted malformed successful response")
	}
}
