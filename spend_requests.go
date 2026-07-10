package stripelink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SpendRequestsResource manages spend requests at
// {SpendRequestBaseURL}/spend_requests. It is safe for concurrent use.
type SpendRequestsResource struct {
	c *core
}

// List returns all spend requests. The endpoint's {"data": [...]} envelope is
// unwrapped internally; a missing or null data field yields an empty,
// non-nil slice (parity: spend-request.ts:163-165).
func (r *SpendRequestsResource) List(ctx context.Context) ([]SpendRequest, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	status, body, err := r.c.do(ctx, apiRequest{
		method:              http.MethodGet,
		url:                 r.endpoint(),
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		return nil, err
	}
	if !successful(status) {
		return nil, newSpendAPIError("list spend requests", status, body)
	}
	if !isJSONObject(body) {
		return nil, malformedSpendResponse("list spend requests", "expected a JSON object envelope")
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, malformedSpendResponse("list spend requests", err.Error())
	}
	if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return []SpendRequest{}, nil
	}
	var requests []SpendRequest
	if err := json.Unmarshal(envelope.Data, &requests); err != nil {
		return nil, malformedSpendResponse("list spend requests", err.Error())
	}
	if requests == nil {
		requests = []SpendRequest{}
	}
	for i := range requests {
		if err := validateSpendRequestResponse(&requests[i]); err != nil {
			return nil, malformedSpendResponse("list spend requests", fmt.Sprintf("item %d: %v", i, err))
		}
	}
	return requests, nil
}

// Create creates a spend request via POST /spend_requests. When
// params.Approve is true the request is routed to
// POST /spend_requests/create_delegated instead, and the Approve field itself
// is never serialized (parity: spend-request.ts:175-178). A 401 response is
// not automatically replayed because the API does not document an idempotency
// guarantee for this mutation.
func (r *SpendRequestsResource) Create(ctx context.Context, params CreateSpendRequestParams) (*SpendRequest, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(params.PaymentDetails) == "" {
		return nil, fmt.Errorf("%w: PaymentDetails must not be empty", ErrInvalidArgument)
	}
	if strings.TrimSpace(params.Context) == "" {
		return nil, fmt.Errorf("%w: Context must not be empty", ErrInvalidArgument)
	}
	if err := validateSpendRequestItems(params.LineItems, params.Totals); err != nil {
		return nil, fmt.Errorf("%w: create spend request: %v", ErrInvalidArgument, err)
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("%w: encode create spend request: %w", ErrInvalidArgument, err)
	}
	endpoint := r.endpoint()
	if params.Approve {
		endpoint += "/create_delegated"
	}
	return r.mutateSpendRequest(ctx, "create spend request", endpoint, body)
}

// Update updates the spend request id via POST /spend_requests/{id}. A 401
// response is not automatically replayed.
func (r *SpendRequestsResource) Update(ctx context.Context, id string, params UpdateSpendRequestParams) (*SpendRequest, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	endpoint, err := r.idEndpoint(id)
	if err != nil {
		return nil, err
	}
	if err := validateSpendRequestItems(params.LineItems, params.Totals); err != nil {
		return nil, fmt.Errorf("%w: update spend request: %v", ErrInvalidArgument, err)
	}
	body, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("%w: encode update spend request: %w", ErrInvalidArgument, err)
	}
	return r.mutateSpendRequest(ctx, "update spend request", endpoint, body)
}

// Cancel cancels the spend request id via POST /spend_requests/{id}/cancel
// and returns it with its updated status. A 401 response is not automatically
// replayed.
func (r *SpendRequestsResource) Cancel(ctx context.Context, id string) (*SpendRequest, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	endpoint, err := r.idEndpoint(id)
	if err != nil {
		return nil, err
	}
	return r.mutateSpendRequest(ctx, "cancel spend request", endpoint+"/cancel", nil)
}

// Retrieve fetches the spend request id via GET /spend_requests/{id}. The
// include values, when present, are joined with "," into the include query
// parameter (for example, "card" or "shared_payment_token" to receive
// unmasked credentials). A 404 response returns (nil, ErrNotFound), a
// deliberate deviation from the JavaScript SDK's null.
func (r *SpendRequestsResource) Retrieve(ctx context.Context, id string, include ...SpendRequestInclude) (*SpendRequest, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	endpoint, err := r.idEndpoint(id)
	if err != nil {
		return nil, err
	}
	if len(include) != 0 {
		values := make([]string, len(include))
		for i, value := range include {
			values[i] = string(value)
			if !validInclude(values[i]) {
				return nil, fmt.Errorf("%w: include value %d is empty or contains invalid characters", ErrInvalidArgument, i)
			}
		}
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: construct spend request URL: %v", ErrInvalidConfiguration, parseErr)
		}
		query := u.Query()
		query.Set("include", strings.Join(values, ","))
		u.RawQuery = query.Encode()
		endpoint = u.String()
	}
	status, body, err := r.c.do(ctx, apiRequest{
		method:              http.MethodGet,
		url:                 endpoint,
		authenticated:       true,
		retryOnUnauthorized: true,
	})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if !successful(status) {
		return nil, newSpendAPIError("retrieve spend request", status, body)
	}
	return decodeSpendRequestResponse("retrieve spend request", body)
}

// RequestApproval asks the user to approve the spend request id via
// POST /spend_requests/{id}/request_approval and returns the approval link to
// present to them. A 401 response is not automatically replayed.
func (r *SpendRequestsResource) RequestApproval(ctx context.Context, id string) (*RequestApprovalResponse, error) {
	if err := r.validate(ctx); err != nil {
		return nil, err
	}
	endpoint, err := r.idEndpoint(id)
	if err != nil {
		return nil, err
	}
	status, body, err := r.c.do(ctx, apiRequest{
		method:        http.MethodPost,
		url:           endpoint + "/request_approval",
		authenticated: true,
	})
	if err != nil {
		return nil, err
	}
	if !successful(status) {
		return nil, newSpendAPIError("request approval", status, body)
	}
	if !isJSONObject(body) {
		return nil, malformedSpendResponse("request approval", "expected a JSON object")
	}
	var response RequestApprovalResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, malformedSpendResponse("request approval", err.Error())
	}
	if response.ID == "" || response.ApprovalLink == "" {
		return nil, malformedSpendResponse("request approval", "missing required id or approval_link")
	}
	return &response, nil
}

func (r *SpendRequestsResource) mutateSpendRequest(ctx context.Context, operation, endpoint string, requestBody []byte) (*SpendRequest, error) {
	header := make(http.Header)
	if requestBody != nil {
		header.Set("Content-Type", "application/json")
	}
	status, body, err := r.c.do(ctx, apiRequest{
		method:        http.MethodPost,
		url:           endpoint,
		header:        header,
		body:          requestBody,
		authenticated: true,
	})
	if err != nil {
		return nil, err
	}
	if !successful(status) {
		return nil, newSpendAPIError(operation, status, body)
	}
	return decodeSpendRequestResponse(operation, body)
}

func decodeSpendRequestResponse(operation string, body []byte) (*SpendRequest, error) {
	if !isJSONObject(body) {
		return nil, malformedSpendResponse(operation, "expected a JSON object")
	}
	var response SpendRequest
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, malformedSpendResponse(operation, err.Error())
	}
	if err := validateSpendRequestResponse(&response); err != nil {
		return nil, malformedSpendResponse(operation, err.Error())
	}
	return &response, nil
}

func validateSpendRequestResponse(response *SpendRequest) error {
	if response == nil || response.ID == "" {
		return fmt.Errorf("missing required id")
	}
	if response.PaymentDetails == "" {
		return fmt.Errorf("missing required payment_details")
	}
	if response.Status == "" {
		return fmt.Errorf("missing required status")
	}
	if response.CreatedAt == "" || response.UpdatedAt == "" {
		return fmt.Errorf("missing required created_at or updated_at")
	}
	if response.LineItems == nil || response.Totals == nil {
		return fmt.Errorf("missing required line_items or totals")
	}
	if err := validateSpendRequestItems(response.LineItems, response.Totals); err != nil {
		return err
	}
	if response.Card != nil {
		if response.Card.ID == "" || response.Card.Brand == "" || response.Card.ExpMonth < 1 || response.Card.ExpMonth > 12 || response.Card.ExpYear < 1 || response.Card.Number == "" {
			return fmt.Errorf("card is missing required credential fields")
		}
		if response.Card.BillingAddress != nil {
			address := response.Card.BillingAddress
			if address.Name == "" || address.Line1 == "" || address.Country == "" {
				return fmt.Errorf("card billing_address is missing required fields")
			}
		}
	}
	if response.SharedPaymentToken != nil && response.SharedPaymentToken.BillingAddress != nil {
		address := response.SharedPaymentToken.BillingAddress
		if address.Name == "" || address.Line1 == "" || address.Country == "" {
			return fmt.Errorf("shared payment token billing_address is missing required fields")
		}
	}
	if response.PaymentStatusDetails != nil {
		details := response.PaymentStatusDetails
		if details.Outcome == "" || details.Currency == "" {
			return fmt.Errorf("payment_status_details is missing required fields")
		}
		if details.RefundDetails != nil && (details.RefundDetails.Currency == "" || details.RefundDetails.State == "") {
			return fmt.Errorf("refund_details is missing required fields")
		}
	}
	return nil
}

func validateSpendRequestItems(lineItems []LineItem, totals []Total) error {
	for i := range lineItems {
		if strings.TrimSpace(lineItems[i].Name) == "" {
			return fmt.Errorf("line_items[%d] is missing required name", i)
		}
		if err := validateSpendRequestTotals(lineItems[i].Totals, fmt.Sprintf("line_items[%d].totals", i)); err != nil {
			return err
		}
	}
	return validateSpendRequestTotals(totals, "totals")
}

func validateSpendRequestTotals(totals []Total, path string) error {
	for i := range totals {
		if strings.TrimSpace(totals[i].Type) == "" || strings.TrimSpace(totals[i].DisplayText) == "" {
			return fmt.Errorf("%s[%d] is missing required type or display_text", path, i)
		}
	}
	return nil
}

func (r *SpendRequestsResource) validate(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context must not be nil", ErrInvalidArgument)
	}
	if r == nil || r.c == nil || r.c.spendRequestBaseURL == "" {
		return fmt.Errorf("%w: spend-request resource is not configured", ErrInvalidArgument)
	}
	return nil
}

func (r *SpendRequestsResource) endpoint() string {
	return r.c.spendRequestBaseURL + "/spend_requests"
}

func (r *SpendRequestsResource) idEndpoint(id string) (string, error) {
	if !validSpendRequestID(id) {
		return "", fmt.Errorf("%w: spend request id must be non-empty and must not contain control characters or path dot-segments", ErrInvalidArgument)
	}
	return r.endpoint() + "/" + url.PathEscape(id), nil
}

func validSpendRequestID(id string) bool {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." {
		return false
	}
	if !utf8.ValidString(id) {
		return false
	}
	for _, character := range id {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validInclude(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) || character == ',' {
			return false
		}
	}
	return true
}

func successful(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func isJSONObject(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) >= 2 && trimmed[0] == '{'
}

func malformedSpendResponse(operation, detail string) error {
	return fmt.Errorf("stripelink: decode successful %s response: %s", operation, detail)
}

func newSpendAPIError(operation string, status int, body []byte) *APIError {
	err := newAPIError(status, body)
	err.Message = fmt.Sprintf("Failed to %s (%d): %s", operation, status, safeSpendAPIErrorMessage(body))
	return err
}

func safeSpendAPIErrorMessage(body []byte) string {
	return extractAPIErrorMessage(body)
}
