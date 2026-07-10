package stripelink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAPIErrorError(t *testing.T) {
	err := &APIError{Message: "Failed to retrieve user info (403): forbidden"}
	if got, want := err.Error(), err.Message; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestTransportErrorPreservesCause(t *testing.T) {
	cause := context.Canceled
	err := &TransportError{
		Code:   "transport_error",
		Method: "GET",
		URL:    "https://api.link.com/userinfo",
		Err:    cause,
	}

	if got, want := err.Error(), "Request failed: GET https://api.link.com/userinfo"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(%v, context.Canceled) = false", err)
	}
	if got, ok := errors.AsType[*TransportError](err); !ok || got != err {
		t.Fatalf("errors.AsType returned %p, want %p", got, err)
	}
}

func TestAPIErrorFormattingNeverExposesResponseCredentials(t *testing.T) {
	const (
		card      = "4242424242424242"
		cvc       = "987"
		token     = "spt_super_secret_token"
		signature = "sig1=:super-secret-signature:"
	)
	err := &APIError{
		Code:    "card_" + card,
		Message: "declined; card_number=" + card + " cvc=" + cvc + " access_token=" + token + " signature=" + signature,
		Status:  422,
		RawBody: `{"card":{"number":"` + card + `","cvc":"` + cvc + `"},"shared_payment_token":"` + token + `","signature":"` + signature + `"}`,
		Details: []byte(`{"refresh_token":"` + token + `"}`),
	}

	formatted := []string{err.Error(), err.String(), err.GoString()}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		formatted = append(formatted, fmt.Sprintf(format, err))
	}
	for _, got := range formatted {
		for _, secret := range []string{card, cvc, token, signature} {
			if strings.Contains(got, secret) {
				t.Errorf("formatted APIError contains %q: %s", secret, got)
			}
		}
		if len(got) > maxDiagnosticBytes {
			t.Errorf("formatted APIError is unbounded: len=%d", len(got))
		}
	}
	if !strings.Contains(err.Error(), "declined") || !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("safe diagnostic was not retained: %q", err.Error())
	}

	var nilError *APIError
	if got := fmt.Sprintf("%s %v %+v %#v", nilError, nilError, nilError, nilError); strings.Contains(got, "%!") {
		t.Fatalf("nil APIError formatting failed: %s", got)
	}
}

func TestTransportErrorFormattingSanitizesURLAndCause(t *testing.T) {
	const secret = "transport-secret-canary"
	err := &TransportError{
		Code:   "transport_error",
		Method: "GET",
		URL:    "https://buyer:" + secret + "@merchant.example/pay?token=" + secret + "#" + secret,
		Err:    errors.New(secret),
	}
	for _, got := range []string{
		err.Error(), err.String(), err.GoString(),
		fmt.Sprintf("%s", err), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err),
	} {
		if strings.Contains(got, secret) || strings.Contains(got, "buyer") || strings.Contains(got, "token=") {
			t.Errorf("formatted TransportError leaks URL/cause: %s", got)
		}
		if !strings.Contains(got, "https://merchant.example/pay") {
			t.Errorf("formatted TransportError lost safe endpoint: %s", got)
		}
	}
}
