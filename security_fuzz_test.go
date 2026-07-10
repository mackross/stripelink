package stripelink

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzExtractAPIErrorMessage(f *testing.F) {
	for _, seed := range []string{
		"declined", "gateway unavailable", "\x00\xff", strings.Repeat("long", 2048),
		`card_number=4242424242424242 cvc=987 access_token=spt_super_secret_token signature=sig1=:super-secret-signature:`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		// Arbitrary bodies must never panic or produce an unbounded/invalid
		// diagnostic.
		got := extractAPIErrorMessage(input)
		if len(got) > maxDiagnosticBytes || !utf8.ValidString(got) {
			t.Fatalf("unsafe diagnostic len=%d valid=%v", len(got), utf8.ValidString(got))
		}

		// Put arbitrary attacker-controlled text next to fixed credential
		// canaries in every supported structured message shape.
		const card, cvc = "4242424242424242", "987"
		const token, signature = "spt_super_secret_token", "sig1=:super-secret-signature:"
		noise := string(input)
		for _, canary := range []string{card, cvc, token, signature} {
			noise = strings.ReplaceAll(noise, canary, "<fuzz-noise>")
		}
		message := noise + " card_number=" + card + " cvc=" + cvc +
			" access_token=" + token + " signature=" + signature
		for _, body := range [][]byte{
			fmt.Appendf(nil, `{"error":{"message":%q}}`, message),
			fmt.Appendf(nil, `{"error":%q}`, message),
			fmt.Appendf(nil, `{"message":%q}`, message),
		} {
			diagnostic := extractAPIErrorMessage(body)
			if len(diagnostic) > maxDiagnosticBytes || !utf8.ValidString(diagnostic) {
				t.Fatalf("unsafe structured diagnostic len=%d valid=%v", len(diagnostic), utf8.ValidString(diagnostic))
			}
			for _, secret := range []string{card, cvc, token, signature} {
				if strings.Contains(diagnostic, secret) {
					t.Fatalf("structured diagnostic contains %q: %q", secret, diagnostic)
				}
			}
		}
	})
}

func FuzzWebBotURLParsingDoesNotDiscloseSecrets(f *testing.F) {
	for _, seed := range []string{"merchant.example", "127.0.0.1", "[::1]", "%zz", "host\x00name"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		const secret = "webbot-url-secret-canary"
		rawURL := "https://buyer:" + secret + "@" + host + "/pay?token=" + secret + "#" + secret

		// SignURL validates before dereferencing the resource or requesting a
		// token. Its public error must never include parser text or raw input.
		var resource *WebBotAuthResource
		_, err := resource.SignURL(context.Background(), rawURL)
		if err == nil {
			t.Fatal("secret-bearing userinfo URL was accepted")
		}
		if strings.Contains(err.Error(), secret) || len(err.Error()) > maxDiagnosticBytes {
			t.Fatalf("URL validation disclosed/unbounded secret: %q", err.Error())
		}

		safe := safeURLDiagnostic(rawURL)
		parsed, parseErr := url.Parse(safe)
		if strings.Contains(safe, secret) || len(safe) > maxDiagnosticBytes || parseErr != nil ||
			(parsed != nil && (parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "")) {
			t.Fatalf("safeURLDiagnostic(%q) = %q", rawURL, safe)
		}
	})
}
