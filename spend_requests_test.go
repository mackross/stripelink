package stripelink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const validSpendRequestJSON = `{
  "id":"lsrq_123",
  "merchant_name":"Corner Shop",
  "merchant_url":"https://merchant.example/checkout",
  "context":"office supplies",
  "amount":9007199254740991,
  "currency":"usd",
  "line_items":[{"name":"Pens","url":"https://merchant.example/pens","unit_amount":9007199254740991,"quantity":1}],
  "totals":[{"type":"total","display_text":"Total","amount":9007199254740991}],
  "payment_details":"pd_123",
  "credential_type":"future_credential",
  "status":"future_status",
  "created_at":"2026-07-10T00:00:00Z",
  "updated_at":"2026-07-10T00:00:01Z"
}`

func newSpendTestClient(t *testing.T, rt *recordingTransport, token AccessTokenFunc) *Client {
	t.Helper()
	if token == nil {
		token = func(context.Context, AccessTokenRequest) (string, error) { return "access-secret", nil }
	}
	client, err := NewClient(Options{
		GetAccessToken:      token,
		AuthStorage:         &MemoryStorage{},
		HTTPClient:          rt.client(),
		APIBaseURL:          "https://api.test/v1",
		SpendRequestBaseURL: "https://spend.test/api",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func TestSpendRequestsList(t *testing.T) {
	t.Run("decodes envelope and preserves order and unknown values", func(t *testing.T) {
		rt := &recordingTransport{}
		rt.respond(http.StatusOK, `{"data":[`+validSpendRequestJSON+`,`+strings.Replace(validSpendRequestJSON, `"lsrq_123"`, `"lsrq_456"`, 1)+`]}`)
		requests, err := newSpendTestClient(t, rt, nil).SpendRequests.List(t.Context())
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(requests) != 2 || requests[0].ID != "lsrq_123" || requests[1].ID != "lsrq_456" {
			t.Fatalf("requests = %#v", requests)
		}
		if requests[0].Status != "future_status" || requests[0].CredentialType != "future_credential" {
			t.Fatalf("unknown values were not preserved: %#v", requests[0])
		}
		if requests[0].Amount != 9007199254740991 || requests[0].Totals[0].Amount != 9007199254740991 {
			t.Fatalf("integer precision lost: %#v", requests[0])
		}
		got := rt.Requests()
		if len(got) != 1 || got[0].Method != http.MethodGet || got[0].URL != "https://spend.test/api/spend_requests" || got[0].Header.Get("Authorization") != "Bearer access-secret" {
			t.Fatalf("request = %#v", got)
		}
	})

	for _, body := range []string{`{}`, `{"data":null}`, `{"data":[]}`} {
		t.Run("empty_"+url.QueryEscape(body), func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, body)
			requests, err := newSpendTestClient(t, rt, nil).SpendRequests.List(t.Context())
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if requests == nil || len(requests) != 0 {
				t.Fatalf("requests = %#v, want non-nil empty", requests)
			}
		})
	}

	for _, body := range []string{`null`, `[]`, `{"data":{}}`, `{"data":[{}]}`} {
		t.Run("malformed_"+url.QueryEscape(body), func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, body)
			_, err := newSpendTestClient(t, rt, nil).SpendRequests.List(t.Context())
			if err == nil || strings.Contains(err.Error(), body) {
				t.Fatalf("List error = %v", err)
			}
		})
	}
}

func TestSpendRequestsCreateOmitsZeroValuesWithoutMutatingInput(t *testing.T) {
	params := CreateSpendRequestParams{PaymentDetails: "pd_123", Context: "buy supplies"}
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, validSpendRequestJSON)
	created, err := newSpendTestClient(t, rt, nil).SpendRequests.Create(t.Context(), params)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID != "lsrq_123" {
		t.Fatalf("created = %#v", created)
	}
	requests := rt.Requests()
	if len(requests) != 1 || requests[0].Method != http.MethodPost || requests[0].URL != "https://spend.test/api/spend_requests" {
		t.Fatalf("request = %#v", requests)
	}
	if requests[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", requests[0].Header.Get("Content-Type"))
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(requests[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"credential_type", "network_id", "amount", "currency", "merchant_name", "merchant_url", "line_items", "totals", "request_approval", "test"} {
		if _, ok := body[key]; ok {
			t.Errorf("body included omitted %q: %s", key, rt.Requests()[0].Body)
		}
	}
	if params.PaymentDetails != "pd_123" || params.Context != "buy supplies" {
		t.Fatal("Create mutated caller parameters")
	}
}

func TestSpendRequestsCreateDelegatedRouting(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, validSpendRequestJSON)
	params := CreateSpendRequestParams{PaymentDetails: "pd_123", Context: "delegated purchase", Approve: true}
	if _, err := newSpendTestClient(t, rt, nil).SpendRequests.Create(t.Context(), params); err != nil {
		t.Fatal(err)
	}
	request := rt.Requests()[0]
	if request.URL != "https://spend.test/api/spend_requests/create_delegated" {
		t.Fatalf("URL = %q", request.URL)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(request.Body), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["approve"]; ok {
		t.Fatalf("routing flag was serialized: %s", request.Body)
	}
	if !params.Approve {
		t.Fatal("Create mutated caller parameters")
	}
}

func TestSpendRequestsCreateNestedValuesWithoutPrecisionLoss(t *testing.T) {
	const amount = int64(9007199254740991)
	itemURL := "https://merchant.example/item"
	quantity := 2
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, validSpendRequestJSON)
	_, err := newSpendTestClient(t, rt, nil).SpendRequests.Create(t.Context(), CreateSpendRequestParams{
		PaymentDetails: "pd_123",
		CredentialType: "future_credential",
		NetworkID:      "network_1",
		Amount:         amount,
		Currency:       "usd",
		MerchantURL:    "https://merchant.example",
		Context:        "buy nested item",
		LineItems: []LineItem{{
			Name: "Item", URL: &itemURL, Quantity: &quantity,
			UnitAmount: func() *int64 { value := amount; return &value }(),
			Totals:     []Total{{Type: "subtotal", DisplayText: "Subtotal", Amount: amount}},
		}},
		Totals:          []Total{{Type: "total", DisplayText: "Total", Amount: amount}},
		RequestApproval: true,
		Test:            true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	var body CreateSpendRequestParams
	if err := json.Unmarshal([]byte(rt.Requests()[0].Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Amount != amount || len(body.LineItems) != 1 || body.LineItems[0].UnitAmount == nil || *body.LineItems[0].UnitAmount != amount || body.LineItems[0].Totals[0].Amount != amount || body.Totals[0].Amount != amount || body.CredentialType != "future_credential" || !body.RequestApproval || !body.Test {
		t.Fatalf("request values lost: %#v", body)
	}
}

func TestSpendRequestsUpdateEscapesIDAndPreservesPresence(t *testing.T) {
	zero, empty := int64(0), ""
	params := UpdateSpendRequestParams{PaymentDetails: &empty, Amount: &zero, LineItems: []LineItem{}, Totals: []Total{}}
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, validSpendRequestJSON)
	_, err := newSpendTestClient(t, rt, nil).SpendRequests.Update(t.Context(), "lsrq/a?b#c", params)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	req := rt.Requests()[0]
	if req.URL != "https://spend.test/api/spend_requests/lsrq%2Fa%3Fb%23c" || req.Method != http.MethodPost {
		t.Fatalf("request = %#v", req)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(req.Body), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"payment_details", "amount", "line_items", "totals"} {
		if _, ok := body[key]; !ok {
			t.Errorf("body omitted %q: %s", key, req.Body)
		}
	}
}

func TestSpendRequestsMutationEndpointsAndNo401Replay(t *testing.T) {
	tests := []struct {
		name string
		path string
		call func(*SpendRequestsResource) error
	}{
		{"create", "", func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd", Context: "ctx"})
			return err
		}},
		{"update", "/lsrq_123", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "lsrq_123", UpdateSpendRequestParams{})
			return err
		}},
		{"cancel", "/lsrq_123/cancel", func(r *SpendRequestsResource) error { _, err := r.Cancel(t.Context(), "lsrq_123"); return err }},
		{"request_approval", "/lsrq_123/request_approval", func(r *SpendRequestsResource) error { _, err := r.RequestApproval(t.Context(), "lsrq_123"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusUnauthorized, `{"error":{"message":"expired"}}`)
			var tokenCalls atomic.Int32
			client := newSpendTestClient(t, rt, func(context.Context, AccessTokenRequest) (string, error) {
				tokenCalls.Add(1)
				return "access-secret", nil
			})
			err := tt.call(client.SpendRequests)
			if apiErr, ok := errors.AsType[*APIError](err); !ok || apiErr.Status != http.StatusUnauthorized {
				t.Fatalf("error = %v", err)
			}
			if len(rt.Requests()) != 1 || tokenCalls.Load() != 1 {
				t.Fatalf("mutation replayed: requests=%d token calls=%d", len(rt.Requests()), tokenCalls.Load())
			}
			wantURL := "https://spend.test/api/spend_requests" + tt.path
			if rt.Requests()[0].URL != wantURL || rt.Requests()[0].Body != "" && (tt.name == "cancel" || tt.name == "request_approval") {
				t.Fatalf("request = %#v, want URL %q", rt.Requests()[0], wantURL)
			}
		})
	}
}

func TestSpendRequestsCancelAndRequestApprovalSuccess(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, strings.Replace(validSpendRequestJSON, `"future_status"`, `"canceled"`, 1))
	rt.respond(http.StatusOK, `{"id":"lsrq_123","approval_link":"https://link.test/approve?secret=approval-secret"}`)
	resource := newSpendTestClient(t, rt, nil).SpendRequests
	canceled, err := resource.Cancel(t.Context(), "lsrq_123")
	if err != nil || canceled.Status != SpendRequestStatusCanceled {
		t.Fatalf("Cancel = %#v, %v", canceled, err)
	}
	approval, err := resource.RequestApproval(t.Context(), "lsrq_123")
	if err != nil || approval.ID != "lsrq_123" || approval.ApprovalLink == "" {
		t.Fatalf("RequestApproval = %#v, %v", approval, err)
	}
	formatted := fmt.Sprintf("%v %#v", approval, approval)
	if strings.Contains(formatted, "approval-secret") || !strings.Contains(formatted, "<redacted>") {
		t.Fatalf("approval formatting is unsafe: %s", formatted)
	}
	requests := rt.Requests()
	if len(requests) != 2 || requests[0].Body != "" || requests[1].Body != "" || requests[0].Header.Get("Content-Type") != "" || requests[1].Header.Get("Content-Type") != "" {
		t.Fatalf("bodyless mutation requests = %#v", requests)
	}
}

func TestSpendRequestsRetrieveIncludesNotFoundAndReadRetry(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusUnauthorized, `{"error":"expired"}`)
	rt.respond(http.StatusOK, validSpendRequestJSON)
	var calls atomic.Int32
	client := newSpendTestClient(t, rt, func(_ context.Context, request AccessTokenRequest) (string, error) {
		calls.Add(1)
		if request.ForceRefresh && request.RejectedToken == "old-secret" {
			return "new-secret", nil
		}
		return "old-secret", nil
	})
	request, err := client.SpendRequests.Retrieve(t.Context(), "lsrq/a", SpendRequestIncludeCard, SpendRequestIncludeSharedPaymentToken)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if request.ID != "lsrq_123" || calls.Load() != 2 {
		t.Fatalf("request=%#v token calls=%d", request, calls.Load())
	}
	recorded := rt.Requests()
	if len(recorded) != 2 || recorded[0].URL != "https://spend.test/api/spend_requests/lsrq%2Fa?include=card%2Cshared_payment_token" || recorded[1].Header.Get("Authorization") != "Bearer new-secret" {
		t.Fatalf("requests = %#v", recorded)
	}

	rt = &recordingTransport{}
	rt.respond(http.StatusNotFound, `{"error":{"message":"not found"}}`)
	got, err := newSpendTestClient(t, rt, nil).SpendRequests.Retrieve(t.Context(), "missing")
	_, isAPIError := errors.AsType[*APIError](err)
	if got != nil || !errors.Is(err, ErrNotFound) || isAPIError {
		t.Fatalf("Retrieve = %#v, %v", got, err)
	}

	rt = &recordingTransport{}
	rt.respond(http.StatusOK, validSpendRequestJSON)
	_, err = newSpendTestClient(t, rt, nil).SpendRequests.Retrieve(t.Context(), "lsrq_123")
	if err != nil || strings.Contains(rt.Requests()[0].URL, "include=") {
		t.Fatalf("empty include: URL=%s error=%v", rt.Requests()[0].URL, err)
	}
}

func TestSpendRequestsDecodeCredentialsAndRedactFormatting(t *testing.T) {
	credentialResponse := strings.TrimSuffix(validSpendRequestJSON, "\n}") + `,
	  "card":{"id":"card_1","brand":"visa","exp_month":12,"exp_year":2030,"number":"4242424242424242","cvc":"987","billing_address":{"name":"A","line1":"1 Main","line2":"Unit 2","city":"X","state":"CA","postal_code":"90000","country":"US"},"valid_until":"opaque"},
  "shared_payment_token":{"id":"spt_secret","billing_address":{"name":"A","line1":"1 Main","country":"US"},"valid_until":"later"},
  "link_pay_token":"link_pay_secret",
  "payment_status_details":{"outcome":"failure","code":null,"decline_code":"declined","amount":12,"currency":"usd","created":null,"refund_details":{"amount":2,"currency":"usd","state":"succeeded","created":123}}
}`
	rt := &recordingTransport{}
	rt.respond(http.StatusOK, credentialResponse)
	request, err := newSpendTestClient(t, rt, nil).SpendRequests.Retrieve(t.Context(), "lsrq_123", SpendRequestIncludeCard)
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if request.Card == nil || request.Card.Number != "4242424242424242" || request.Card.CVC != "987" || request.SharedPaymentToken == nil || request.SharedPaymentToken.ID != "spt_secret" || request.LinkPayToken != "link_pay_secret" || request.PaymentStatusDetails == nil || request.PaymentStatusDetails.Code != nil || request.PaymentStatusDetails.RefundDetails == nil {
		t.Fatalf("credentials not completely decoded: %#v", request)
	}
	formatted := fmt.Sprintf("%s\n%v\n%+v\n%#v\n%v\n%#v", request, request, request, request, request.Card, request.SharedPaymentToken)
	for _, secret := range []string{"4242424242424242", "987", "spt_secret", "link_pay_secret"} {
		if strings.Contains(formatted, secret) {
			t.Errorf("formatting leaked %q: %s", secret, formatted)
		}
	}
	if !strings.Contains(formatted, "<redacted>") {
		t.Errorf("formatting did not identify redaction: %s", formatted)
	}
}

func TestSpendRequestsLegacySharedPaymentToken(t *testing.T) {
	var token SharedPaymentToken
	if err := json.Unmarshal([]byte(`"spt_legacy_secret"`), &token); err != nil {
		t.Fatal(err)
	}
	if token.ID != "spt_legacy_secret" || token.BillingAddress != nil || token.ValidUntil != "" {
		t.Fatalf("token = %#v", token)
	}

	for _, raw := range []string{`null`, `true`, `1`, `[]`, `{}`, `""`, `{"id":""}`} {
		t.Run(url.QueryEscape(raw), func(t *testing.T) {
			var malformed SharedPaymentToken
			if err := json.Unmarshal([]byte(raw), &malformed); err == nil || strings.Contains(err.Error(), "spt_") {
				t.Fatalf("UnmarshalJSON(%s) error = %v", raw, err)
			}
		})
	}
}

func TestSpendRequestsAPIErrorContract(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"nested", `{"error":{"message":"nested message","code":"bad"}}`, "nested message"},
		{"string", `{"error":"string message"}`, "string message"},
		{"message", `{"message":"top message"}`, "top message"},
		{"raw", `gateway unavailable`, "remote API returned a non-JSON error"},
		{"redacted credential JSON", `{"number":"4242424242424242","cvc":"987","link_pay_token":"link_secret"}`, "remote API returned an error response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusUnprocessableEntity, tt.body)
			_, err := newSpendTestClient(t, rt, nil).SpendRequests.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd", Context: "ctx"})
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok || apiErr.Status != http.StatusUnprocessableEntity || apiErr.RawBody != tt.body || string(apiErr.Details) != func() string {
				if json.Valid([]byte(tt.body)) {
					return tt.body
				}
				return ""
			}() {
				t.Fatalf("API error = %#v (%v)", apiErr, err)
			}
			if !strings.Contains(err.Error(), "Failed to create spend request (422): "+tt.want) {
				t.Errorf("error = %q", err)
			}
			if strings.Contains(err.Error(), "4242424242424242") || strings.Contains(err.Error(), "link_secret") {
				t.Errorf("error leaked credentials: %v", err)
			}
		})
	}
}

func TestSpendRequestsEveryOperationUsesAPIErrorContract(t *testing.T) {
	const responseBody = `{"error":{"message":"operation failed","code":"conflict"}}`
	tests := []struct {
		name string
		want string
		call func(*SpendRequestsResource) error
	}{
		{"list", "Failed to list spend requests (409): operation failed", func(r *SpendRequestsResource) error { _, err := r.List(t.Context()); return err }},
		{"create", "Failed to create spend request (409): operation failed", func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd", Context: "ctx"})
			return err
		}},
		{"update", "Failed to update spend request (409): operation failed", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "id", UpdateSpendRequestParams{})
			return err
		}},
		{"cancel", "Failed to cancel spend request (409): operation failed", func(r *SpendRequestsResource) error { _, err := r.Cancel(t.Context(), "id"); return err }},
		{"retrieve", "Failed to retrieve spend request (409): operation failed", func(r *SpendRequestsResource) error { _, err := r.Retrieve(t.Context(), "id"); return err }},
		{"request approval", "Failed to request approval (409): operation failed", func(r *SpendRequestsResource) error { _, err := r.RequestApproval(t.Context(), "id"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusConflict, responseBody)
			err := tt.call(newSpendTestClient(t, rt, nil).SpendRequests)
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok || apiErr.Error() != tt.want || apiErr.Status != http.StatusConflict || apiErr.Code != "api_error" || apiErr.RawBody != responseBody || string(apiErr.Details) != responseBody {
				t.Fatalf("API error = %#v, %v", apiErr, err)
			}
		})
	}
}

func TestSpendRequestsValidationBeforeHTTP(t *testing.T) {
	tests := []struct {
		name string
		call func(*SpendRequestsResource) error
	}{
		{"nil context", func(r *SpendRequestsResource) error { _, err := r.List(nilContext()); return err }},
		{"missing payment details", func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{Context: "ctx"})
			return err
		}},
		{"missing context", func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd"})
			return err
		}},
		{"missing line item name", func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd", Context: "ctx", LineItems: []LineItem{{UnitAmount: func() *int64 { value := int64(1); return &value }()}}})
			return err
		}},
		{"missing total type", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "id", UpdateSpendRequestParams{Totals: []Total{{DisplayText: "Total", Amount: 1}}})
			return err
		}},
		{"blank id", func(r *SpendRequestsResource) error { _, err := r.Retrieve(t.Context(), " \t"); return err }},
		{"dot id", func(r *SpendRequestsResource) error { _, err := r.Cancel(t.Context(), ".."); return err }},
		{"control id", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "id\nother", UpdateSpendRequestParams{})
			return err
		}},
		{"space in id", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "id other", UpdateSpendRequestParams{})
			return err
		}},
		{"invalid UTF-8 id", func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), string([]byte{'i', 'd', 0xff}), UpdateSpendRequestParams{})
			return err
		}},
		{"empty include", func(r *SpendRequestsResource) error {
			_, err := r.Retrieve(t.Context(), "id", SpendRequestInclude(""))
			return err
		}},
		{"ambiguous include", func(r *SpendRequestsResource) error {
			_, err := r.Retrieve(t.Context(), "id", SpendRequestInclude("card,other"))
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			err := tt.call(newSpendTestClient(t, rt, nil).SpendRequests)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
			if len(rt.Requests()) != 0 {
				t.Fatalf("validation made %d requests", len(rt.Requests()))
			}
		})
	}

	rt := &recordingTransport{}
	rt.respond(http.StatusOK, strings.Replace(validSpendRequestJSON, `"future_status"`, `"brand_new_status"`, 1))
	created, err := newSpendTestClient(t, rt, nil).SpendRequests.Create(t.Context(), CreateSpendRequestParams{
		PaymentDetails: "pd", Context: "ctx", CredentialType: "brand_new_credential",
	})
	if err != nil || created.Status != "brand_new_status" {
		t.Fatalf("forward-compatible values rejected: %#v, %v", created, err)
	}
}

func TestSpendRequestsConcurrentUse(t *testing.T) {
	const workers = 24
	rt := &recordingTransport{}
	for range workers {
		rt.respond(http.StatusOK, `{"data":[`+validSpendRequestJSON+`]}`)
	}
	resource := newSpendTestClient(t, rt, nil).SpendRequests
	errorsFromWorkers := make(chan error, workers)
	for range workers {
		go func() {
			requests, err := resource.List(t.Context())
			if err == nil && (len(requests) != 1 || requests[0].ID != "lsrq_123") {
				err = fmt.Errorf("unexpected requests: %#v", requests)
			}
			errorsFromWorkers <- err
		}()
	}
	for range workers {
		if err := <-errorsFromWorkers; err != nil {
			t.Fatal(err)
		}
	}
	if len(rt.Requests()) != workers {
		t.Fatalf("requests = %d, want %d", len(rt.Requests()), workers)
	}
}

func TestSpendRequestsRejectMalformedSuccessfulResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		call func(*SpendRequestsResource) error
	}{
		{"create null", `null`, func(r *SpendRequestsResource) error {
			_, err := r.Create(t.Context(), CreateSpendRequestParams{PaymentDetails: "pd", Context: "ctx"})
			return err
		}},
		{"update missing required", `{}`, func(r *SpendRequestsResource) error {
			_, err := r.Update(t.Context(), "id", UpdateSpendRequestParams{})
			return err
		}},
		{"cancel array", `[]`, func(r *SpendRequestsResource) error { _, err := r.Cancel(t.Context(), "id"); return err }},
		{"retrieve bad token", strings.TrimSuffix(validSpendRequestJSON, "\n}") + `,"shared_payment_token":42}`, func(r *SpendRequestsResource) error { _, err := r.Retrieve(t.Context(), "id"); return err }},
		{"retrieve incomplete card", strings.TrimSuffix(validSpendRequestJSON, "\n}") + `,"card":{"id":"card_secret","number":"4242424242424242"}}`, func(r *SpendRequestsResource) error { _, err := r.Retrieve(t.Context(), "id"); return err }},
		{"retrieve incomplete payment status", strings.TrimSuffix(validSpendRequestJSON, "\n}") + `,"payment_status_details":{"amount":1}}`, func(r *SpendRequestsResource) error { _, err := r.Retrieve(t.Context(), "id"); return err }},
		{"approval missing link", `{"id":"id"}`, func(r *SpendRequestsResource) error { _, err := r.RequestApproval(t.Context(), "id"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusOK, tt.body)
			err := tt.call(newSpendTestClient(t, rt, nil).SpendRequests)
			_, isAPIError := errors.AsType[*APIError](err)
			if err == nil || isAPIError || strings.Contains(err.Error(), tt.body) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func FuzzSharedPaymentTokenUnmarshal(f *testing.F) {
	for _, seed := range []string{`"spt_legacy"`, `{"id":"spt_object","valid_until":"opaque"}`, `null`, `{}`, `[]`, `{"id":1}`, `{"id":"ok","billing_address":{"line1":1}}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		var token SharedPaymentToken
		_ = json.Unmarshal([]byte(raw), &token)
	})
}
