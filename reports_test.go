package stripelink

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestReportsCreateRequestPresenceAndCompleteResponse(t *testing.T) {
	empty := ""
	rt := &recordingTransport{}
	rt.respond(http.StatusCreated, `{"object":"agent_report","created_at":"2026-05-20T18:30:00.123456789Z","domain":"merchant.example","outcome":"future_outcome","spend_request_id":"lsrq_123","status":"future_status"}`)
	params := CreateReportParams{
		Domain: "merchant.example", Outcome: ReportOutcome("future_outcome"), SpendRequestID: "lsrq_123",
		Tags: []ReportTag{}, Step: &empty, FreeformContext: &empty,
	}
	got, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), params)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.Outcome != "future_outcome" || got.Status != "future_status" || got.CreatedAt != "2026-05-20T18:30:00.123456789Z" {
		t.Fatalf("response lost forward-compatible data: %#v", got)
	}
	requests := rt.Requests()
	if len(requests) != 1 || requests[0].Method != http.MethodPost || requests[0].URL != "http://127.0.0.1:8080/api/agent_observations" || requests[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("requests = %#v", requests)
	}
	wantBody := `{"domain":"merchant.example","outcome":"future_outcome","spend_request_id":"lsrq_123","tags":[],"step":"","freeform_context":""}`
	if requests[0].Body != wantBody {
		t.Fatalf("body = %s, want %s", requests[0].Body, wantBody)
	}
}

func TestReportsCreateOmitsOptionalFieldsButPreservesKnownValues(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusCreated, `{"object":"agent_report","created_at":"opaque-time","domain":"shop.example","outcome":"blocked","spend_request_id":"lsrq_456","status":"received"}`)
	got, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), CreateReportParams{
		Domain: "shop.example", Outcome: ReportOutcomeBlocked, SpendRequestID: "lsrq_456",
	})
	if err != nil || got.Outcome != "blocked" || got.CreatedAt != "opaque-time" {
		t.Fatalf("Create = (%#v, %v)", got, err)
	}
	want := `{"domain":"shop.example","outcome":"blocked","spend_request_id":"lsrq_456"}`
	if body := rt.Requests()[0].Body; body != want {
		t.Fatalf("body = %s, want %s", body, want)
	}
}

func TestReportsCreatePreservesExplicitEmptyAndUnknownTags(t *testing.T) {
	for _, tc := range []struct {
		name string
		tags []ReportTag
		want string
	}{
		{"explicit empty", []ReportTag{}, `"tags":[]`},
		{"known and unknown", []ReportTag{ReportTagCaptcha, ReportTag("future_signal")}, `"tags":["captcha","future_signal"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusCreated, `{"object":"agent_report","created_at":"now","domain":"shop.example","outcome":"blocked","spend_request_id":"lsrq_456","status":"received"}`)
			_, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), CreateReportParams{
				Domain: "shop.example", Outcome: ReportOutcomeBlocked, SpendRequestID: "lsrq_456", Tags: tc.tags,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if body := rt.Requests()[0].Body; !strings.Contains(body, tc.want) {
				t.Fatalf("body = %s, want field %s", body, tc.want)
			}
		})
	}
}

func TestReportsCreateDoesNotBlindlyReplay401(t *testing.T) {
	rt := &recordingTransport{}
	rt.respond(http.StatusUnauthorized, `{"error":{"message":"token expired"}}`)
	var tokenRequests []AccessTokenRequest
	token := func(_ context.Context, request AccessTokenRequest) (string, error) {
		tokenRequests = append(tokenRequests, request)
		return "expired", nil
	}
	_, err := newResourceTestClient(t, rt, token).Reports.Create(t.Context(), CreateReportParams{
		Domain: "merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_123",
	})
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Status != http.StatusUnauthorized || apiErr.Message != "Failed to create report (401): token expired" {
		t.Fatalf("error = %#v", err)
	}
	if len(rt.Requests()) != 1 || len(tokenRequests) != 1 || tokenRequests[0].ForceRefresh {
		t.Fatalf("POST was retried: requests=%#v tokenRequests=%#v", rt.Requests(), tokenRequests)
	}
}

func TestReportsCreateAPIAndMalformedSuccessErrors(t *testing.T) {
	params := CreateReportParams{Domain: "merchant.example", Outcome: ReportOutcomeBlocked, SpendRequestID: "lsrq_123"}
	for _, tc := range []struct {
		name, body, message string
	}{
		{"nested", `{"error":{"message":"outcome invalid"}}`, "Failed to create report (400): outcome invalid"},
		{"string", `{"error":"feature disabled"}`, "Failed to create report (400): feature disabled"},
		{"plain", `gateway failure`, "Failed to create report (400): remote API returned a non-JSON error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusBadRequest, tc.body)
			_, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), params)
			apiErr, ok := errors.AsType[*APIError](err)
			if !ok || apiErr.Message != tc.message || apiErr.RawBody != tc.body {
				t.Fatalf("error = %#v", err)
			}
		})
	}
	for _, body := range []string{`not-json`, `null`, `[]`} {
		t.Run("malformed "+body, func(t *testing.T) {
			rt := &recordingTransport{}
			rt.respond(http.StatusCreated, body)
			if _, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), params); err == nil {
				t.Fatal("Create accepted malformed successful response")
			}
		})
	}
}

func TestReportsCreateRejectsIncompleteSuccessfulRecord(t *testing.T) {
	valid := map[string]string{
		"object": "agent_report", "created_at": "now", "domain": "merchant.example",
		"outcome": "success", "spend_request_id": "lsrq_123", "status": "received",
	}
	for _, missing := range []string{"object", "created_at", "domain", "outcome", "spend_request_id", "status"} {
		t.Run(missing, func(t *testing.T) {
			fields := make([]string, 0, len(valid)-1)
			for key, value := range valid {
				if key != missing {
					fields = append(fields, fmt.Sprintf("%q:%q", key, value))
				}
			}
			rt := &recordingTransport{}
			rt.respond(http.StatusCreated, "{"+strings.Join(fields, ",")+"}")
			_, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), CreateReportParams{
				Domain: "merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_123",
			})
			if err == nil || strings.Contains(err.Error(), "merchant.example") || strings.Contains(err.Error(), "lsrq_123") {
				t.Fatalf("Create accepted/reflected malformed record: %v", err)
			}
		})
	}
}

func TestReportsCreateNilContextAndZeroReceiver(t *testing.T) {
	var reports *ReportsResource
	if _, err := reports.Create(t.Context(), CreateReportParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero receiver error = %v", err)
	}
	client := newResourceTestClient(t, &recordingTransport{}, nil)
	if _, err := client.Reports.Create(nilContext(), CreateReportParams{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestReportsCreatePreservesTransportError(t *testing.T) {
	cause := errors.New("connection refused")
	rt := &recordingTransport{}
	rt.failWith(cause)
	_, err := newResourceTestClient(t, rt, nil).Reports.Create(t.Context(), CreateReportParams{
		Domain: "merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_123",
	})
	transportErr, ok := errors.AsType[*TransportError](err)
	if !ok || transportErr.Method != http.MethodPost || transportErr.URL != "http://127.0.0.1:8080/api/agent_observations" || !errors.Is(err, cause) {
		t.Fatalf("error = %#v", err)
	}
}

func TestReportsCreateVerboseLogsNeverContainPIIOrCredentials(t *testing.T) {
	logger, logs := newCapturingLogger()
	rt := &recordingTransport{}
	rt.respond(http.StatusCreated, `{"object":"agent_report","created_at":"now","domain":"private-merchant.example","outcome":"success","spend_request_id":"lsrq_secret","status":"received"}`)
	client := newResourceTestClient(t, rt, func(context.Context, AccessTokenRequest) (string, error) {
		return "bearer-secret", nil
	}, func(opts *Options) {
		opts.Verbose = true
		opts.Logger = logger
	})
	_, err := client.Reports.Create(t.Context(), CreateReportParams{
		Domain: "private-merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_secret",
		FreeformContext: new("customer@example.test card 4111111111111111"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	joined := strings.Join(logs.Lines(), "\n")
	for _, secret := range []string{"bearer-secret", "private-merchant.example", "lsrq_secret", "customer@example.test", "4111111111111111"} {
		if strings.Contains(joined, secret) {
			t.Errorf("logs contain %q: %s", secret, joined)
		}
	}
	if !strings.Contains(joined, "POST") || !strings.Contains(joined, "/agent_observations") || !strings.Contains(joined, "status=201") {
		t.Fatalf("logs missing safe metadata: %s", joined)
	}
}
