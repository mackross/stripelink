package stripelink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ReportsResource submits agent observation reports to
// {APIBaseURL}/agent_observations (parity: report.ts:33). It is safe for
// concurrent use.
type ReportsResource struct {
	c *core
}

// Create submits a report describing the outcome of an agent payment attempt.
// Failures surface as an *APIError whose message follows the
// "Failed to create report (%d): %s" parity template. A 401 response is not
// automatically replayed because this POST has no documented idempotency key.
func (r *ReportsResource) Create(ctx context.Context, params CreateReportParams) (*ReportRecord, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if r == nil || r.c == nil || r.c.apiBaseURL == "" {
		return nil, fmt.Errorf("%w: reports resource is not configured", ErrInvalidArgument)
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("stripelink: encode report request: %w", err)
	}

	response, err := doJSON[*ReportRecord](ctx, r.c, apiRequest{
		method:        http.MethodPost,
		url:           r.c.apiBaseURL + "/agent_observations",
		header:        http.Header{"Content-Type": {"application/json"}},
		body:          body,
		authenticated: true,
		// Reports have no documented idempotency key, so a 401 is surfaced
		// without risking duplicate submission.
		retryOnUnauthorized: false,
	})
	if err != nil {
		return nil, resourceOperationError(err, "Failed to create report")
	}
	if response == nil {
		return nil, fmt.Errorf("stripelink: decode successful response: expected JSON object")
	}
	if strings.TrimSpace(response.Object) == "" || strings.TrimSpace(response.CreatedAt) == "" ||
		strings.TrimSpace(response.Domain) == "" || strings.TrimSpace(response.Outcome) == "" ||
		strings.TrimSpace(response.SpendRequestID) == "" || strings.TrimSpace(response.Status) == "" {
		return nil, fmt.Errorf("stripelink: decode successful report response: missing required field")
	}
	return response, nil
}
