package stripelink

import (
	"fmt"
	"strings"
	"testing"
)

func TestCredentialBearingValueFormattingIsSafeForCommonVerbs(t *testing.T) {
	const card = "4242424242424242"
	const cvc = "987"
	const token = "spt_super_secret_token"
	const signature = "sig1=:super-secret-signature:"
	const canary = "server-controlled-secret-canary"

	address := &BillingAddress{Name: canary, Line1: canary, Country: canary}
	cardValue := Card{
		ID: canary, Brand: canary, ExpMonth: 12, ExpYear: 2035, Number: card, CVC: cvc,
		BillingAddress: address, ValidUntil: canary,
	}
	tokenValue := SharedPaymentToken{ID: token, BillingAddress: address, ValidUntil: canary}
	spendValue := SpendRequest{
		ID: canary, MerchantName: canary, MerchantURL: canary, Context: canary,
		Amount: 1234, Currency: canary, PaymentMethod: canary, PaymentDetails: canary,
		CredentialType: CredentialType(canary), NetworkID: canary, Status: SpendRequestStatus(canary),
		ApprovalURL: canary, Card: &cardValue, SharedPaymentToken: &tokenValue, LinkPayToken: token,
		CreatedAt: canary, UpdatedAt: canary,
	}
	approval := RequestApprovalResponse{ID: canary, ApprovalLink: token}
	webBot := WebBotAuthBlock{
		Signature: signature, SignatureInput: token, SignatureAgent: canary,
		Authority: canary, ExpiresAt: canary,
	}

	values := []any{
		cardValue, &cardValue, tokenValue, &tokenValue, spendValue, &spendValue,
		approval, &approval, webBot, &webBot,
		[]Card{cardValue}, map[string]SharedPaymentToken{"credential": tokenValue},
	}
	for _, value := range values {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			got := fmt.Sprintf(format, value)
			for _, secret := range []string{card, cvc, token, signature, canary} {
				if strings.Contains(got, secret) {
					t.Errorf("%T with %s leaked %q: %s", value, format, secret, got)
				}
			}
			if !strings.Contains(got, "<redacted>") {
				t.Errorf("%T with %s omitted redaction marker: %s", value, format, got)
			}
		}
	}
}
