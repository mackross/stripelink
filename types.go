package stripelink

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DeviceAuth describes a pending OAuth device authorization, returned by
// AuthResource.InitiateDeviceAuth. The JSON field names mirror the JS SDK's
// DeviceAuthRequest object: the wire's verification_uri /
// verification_uri_complete fields are renamed to verification_url /
// verification_url_complete (parity: auth.ts:127-134, GUIDANCE §5.5).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURL         string `json:"verification_url"`
	VerificationURLComplete string `json:"verification_url_complete"`

	// ExpiresIn is the device-code lifetime in seconds.
	ExpiresIn int `json:"expires_in"`

	// ExpiresAt is the absolute device-code expiry in epoch milliseconds. It
	// is computed when authorization starts so delayed or resumed polling does
	// not accidentally extend the server-issued lifetime.
	ExpiresAt int64 `json:"expires_at"`

	// Interval is the minimum polling interval in seconds (RFC 8628).
	Interval int `json:"interval"`
}

// AuthTokens holds the OAuth access and refresh tokens returned by the device
// flow and persisted by AuthStorage.
type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`

	// ExpiresIn is the access-token lifetime in seconds.
	ExpiresIn int64 `json:"expires_in"`

	TokenType string `json:"token_type"`

	// ExpiresAt is the absolute expiry of the access token in epoch
	// milliseconds. AuthStorage implementations compute it from ExpiresIn
	// when it is zero at store time (parity: storage.ts:35).
	ExpiresAt int64 `json:"expires_at,omitzero"`
}

// LineItem describes a single item in a spend request.
type LineItem struct {
	Name        string  `json:"name"`
	URL         *string `json:"url,omitzero"`
	ImageURL    *string `json:"image_url,omitzero"`
	Description *string `json:"description,omitzero"`
	SKU         *string `json:"sku,omitzero"`
	Totals      []Total `json:"totals,omitzero"`
	Quantity    *int    `json:"quantity,omitzero"`
	UnitAmount  *int64  `json:"unit_amount,omitzero"`
	ProductURL  *string `json:"product_url,omitzero"`
}

// Total is a display total attached to a spend request or line item.
type Total struct {
	Type        string `json:"type"`
	DisplayText string `json:"display_text"`

	// Amount is in the smallest currency unit (cents).
	Amount int64 `json:"amount"`
}

// BillingAddress is the billing address attached to a payment credential.
type BillingAddress struct {
	Name       string `json:"name"`
	Line1      string `json:"line1"`
	Line2      string `json:"line2,omitzero"`
	City       string `json:"city,omitzero"`
	State      string `json:"state,omitzero"`
	PostalCode string `json:"postal_code,omitzero"`
	Country    string `json:"country"`
}

// Card is a one-time-use virtual card credential attached to an approved
// spend request.
type Card struct {
	ID       string `json:"id"`
	Brand    string `json:"brand"`
	ExpMonth int    `json:"exp_month"`
	ExpYear  int    `json:"exp_year"`
	Number   string `json:"number"`
	CVC      string `json:"cvc,omitzero"`

	BillingAddress *BillingAddress `json:"billing_address,omitzero"`

	// ValidUntil is an opaque pass-through timestamp string; its exact wire
	// format is unverified (GUIDANCE §5.7, §10).
	ValidUntil string `json:"valid_until,omitzero"`
}

// String returns a credential-safe summary of c. Card identifiers, account
// numbers, CVCs, and billing addresses are deliberately omitted.
func (c Card) String() string {
	return fmt.Sprintf("Card{ID:<redacted> Brand:<redacted> ExpMonth:%d ExpYear:%d Number:<redacted> CVC:<redacted> BillingAddress:<redacted> ValidUntil:<redacted>}", c.ExpMonth, c.ExpYear)
}

// Format ensures all common fmt verbs use the credential-safe summary.
func (c Card) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(c.String())) }

// SpendRequestStatus is the lifecycle state of a spend request. Unknown
// values are passed through unchanged — never validated or rejected
// (forward compatibility is pinned behaviour, GUIDANCE §5.7).
type SpendRequestStatus string

// Known spend request statuses (parity: types/index.ts:58-66).
const (
	SpendRequestStatusCreated         SpendRequestStatus = "created"
	SpendRequestStatusPendingApproval SpendRequestStatus = "pending_approval"
	SpendRequestStatusExpired         SpendRequestStatus = "expired"
	SpendRequestStatusApproved        SpendRequestStatus = "approved"
	SpendRequestStatusDenied          SpendRequestStatus = "denied"
	SpendRequestStatusSucceeded       SpendRequestStatus = "succeeded"
	SpendRequestStatusFailed          SpendRequestStatus = "failed"
	SpendRequestStatusCanceled        SpendRequestStatus = "canceled"
)

// CredentialType selects the kind of payment credential issued for a spend
// request. Unknown values are passed through unchanged.
type CredentialType string

// Known credential types (parity: types/index.ts:68).
const (
	CredentialTypeSharedPaymentToken CredentialType = "shared_payment_token"
	CredentialTypeCard               CredentialType = "card"
)

// SharedPaymentToken is a shared payment token credential attached to an
// approved spend request.
type SharedPaymentToken struct {
	ID             string          `json:"id"`
	BillingAddress *BillingAddress `json:"billing_address,omitzero"`

	// ValidUntil is an opaque pass-through timestamp string (GUIDANCE §5.7).
	ValidUntil string `json:"valid_until,omitzero"`
}

// UnmarshalJSON implements json.Unmarshaler, accepting both wire forms of
// shared_payment_token: a plain string (old API), normalized to
// SharedPaymentToken{ID: s}, or an object (new API). This replaces the JS
// post-processing in normalizeSpendRequest (spend-request.ts:30-39).
func (t *SharedPaymentToken) UnmarshalJSON(data []byte) error {
	if t == nil {
		return fmt.Errorf("%w: shared payment token receiver must not be nil", ErrInvalidArgument)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("stripelink: decode shared payment token: empty JSON")
	}

	if data[0] == '"' {
		var id string
		if err := json.Unmarshal(data, &id); err != nil {
			return fmt.Errorf("stripelink: decode shared payment token string: %w", err)
		}
		if id == "" {
			return fmt.Errorf("stripelink: decode shared payment token: missing id")
		}
		*t = SharedPaymentToken{ID: id}
		return nil
	}

	type wireSharedPaymentToken SharedPaymentToken
	var decoded wireSharedPaymentToken
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("stripelink: decode shared payment token object: %w", err)
	}
	if data[0] != '{' || decoded.ID == "" {
		return fmt.Errorf("stripelink: decode shared payment token: expected an object with a non-empty id or a non-empty string")
	}
	*t = SharedPaymentToken(decoded)
	return nil
}

// String returns a credential-safe summary of t.
func (t SharedPaymentToken) String() string {
	return "SharedPaymentToken{ID:<redacted> BillingAddress:<redacted> ValidUntil:<redacted>}"
}

// Format ensures all common fmt verbs use the credential-safe summary.
func (t SharedPaymentToken) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(t.String())) }

// RefundDetails describes a refund recorded against a spend request payment.
type RefundDetails struct {
	// Amount is in the smallest currency unit (cents).
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	State    string `json:"state"`
	Created  int64  `json:"created"`
}

// PaymentStatusDetails describes the outcome of a payment attempt on a spend
// request. The pointer fields are explicitly nullable on the wire; nil means
// the server sent null or omitted the field (GUIDANCE §5.7).
type PaymentStatusDetails struct {
	// Outcome is "success" or "failure"; unknown values pass through.
	Outcome string `json:"outcome"`

	Code        *string `json:"code,omitzero"`
	DeclineCode *string `json:"decline_code,omitzero"`

	// Amount is in the smallest currency unit (cents).
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`

	Created       *int64         `json:"created,omitzero"`
	RefundDetails *RefundDetails `json:"refund_details,omitzero"`
}

// SpendRequest is a request for a one-time-use payment credential. CreatedAt
// and UpdatedAt are opaque pass-through timestamp strings (GUIDANCE §5.7).
type SpendRequest struct {
	ID           string `json:"id"`
	MerchantName string `json:"merchant_name,omitzero"`
	MerchantURL  string `json:"merchant_url,omitzero"`
	Context      string `json:"context,omitzero"`

	// Amount is in the smallest currency unit (cents).
	Amount   int64  `json:"amount,omitzero"`
	Currency string `json:"currency,omitzero"`

	LineItems []LineItem `json:"line_items"`
	Totals    []Total    `json:"totals"`

	PaymentMethod  string         `json:"payment_method,omitzero"`
	PaymentDetails string         `json:"payment_details"`
	CredentialType CredentialType `json:"credential_type,omitzero"`
	NetworkID      string         `json:"network_id,omitzero"`

	Status      SpendRequestStatus `json:"status"`
	ApprovalURL string             `json:"approval_url,omitzero"`

	Card                 *Card                 `json:"card,omitzero"`
	SharedPaymentToken   *SharedPaymentToken   `json:"shared_payment_token,omitzero"`
	LinkPayToken         string                `json:"link_pay_token,omitzero"`
	PaymentStatusDetails *PaymentStatusDetails `json:"payment_status_details,omitzero"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// String returns a credential-safe summary of s. Payment credentials and
// billing details are never included.
func (s SpendRequest) String() string {
	return fmt.Sprintf("SpendRequest{ID:<redacted> Status:<redacted> Amount:%d Currency:<redacted> CredentialType:<redacted> Card:<redacted> SharedPaymentToken:<redacted> LinkPayToken:<redacted>}", s.Amount)
}

// Format ensures all common fmt verbs use the credential-safe summary.
func (s SpendRequest) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(s.String())) }

// RequestApprovalResponse is returned by SpendRequestsResource.RequestApproval.
type RequestApprovalResponse struct {
	ID           string `json:"id"`
	ApprovalLink string `json:"approval_link"`
}

// String returns a summary that does not expose the approval link.
func (r RequestApprovalResponse) String() string {
	return "RequestApprovalResponse{ID:<redacted> ApprovalLink:<redacted>}"
}

// Format ensures all common fmt verbs use the credential-safe summary.
func (r RequestApprovalResponse) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(r.String()))
}

// SpendRequestInclude identifies an optional credential expansion for
// SpendRequestsResource.Retrieve. It is string-backed so newly introduced
// server values remain representable.
type SpendRequestInclude string

// Supported spend-request credential expansions.
const (
	SpendRequestIncludeCard               SpendRequestInclude = "card"
	SpendRequestIncludeSharedPaymentToken SpendRequestInclude = "shared_payment_token"
)

// CardDetails summarizes the card behind a saved payment method.
type CardDetails struct {
	Brand    string `json:"brand"`
	Last4    string `json:"last4"`
	ExpMonth int    `json:"exp_month"`
	ExpYear  int    `json:"exp_year"`
}

// BankAccountDetails summarizes the bank account behind a saved payment
// method.
type BankAccountDetails struct {
	Last4    string `json:"last4"`
	BankName string `json:"bank_name,omitzero"`
}

// UserInfo is the authenticated user's profile. All fields are explicitly
// nullable: nil is equivalent to the JS SDK's explicit null coercion
// (user-info.ts:117-124, GUIDANCE §5.7).
type UserInfo struct {
	Email     *string `json:"email"`
	Name      *string `json:"name"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Phone     *string `json:"phone"`
}

// PaymentMethod is a saved payment method in the user's Link wallet.
type PaymentMethod struct {
	ID                 string              `json:"id"`
	Type               string              `json:"type"`
	IsDefault          bool                `json:"is_default"`
	Nickname           string              `json:"nickname,omitzero"`
	CardDetails        *CardDetails        `json:"card_details,omitzero"`
	BankAccountDetails *BankAccountDetails `json:"bank_account_details,omitzero"`
}

// ShippingAddress is a saved shipping address. All fields are explicitly
// nullable on the wire (GUIDANCE §5.7). Note the json tags use line_1 /
// line_2 (underscored), unlike BillingAddress's line1 / line2.
type ShippingAddress struct {
	Name               *string `json:"name"`
	Line1              *string `json:"line_1"`
	Line2              *string `json:"line_2"`
	Locality           *string `json:"locality"`
	DependentLocality  *string `json:"dependent_locality"`
	AdministrativeArea *string `json:"administrative_area"`
	PostalCode         *string `json:"postal_code"`
	SortingCode        *string `json:"sorting_code"`
	CountryCode        *string `json:"country_code"`
}

// ShippingAddressRecord is a saved shipping address entry returned by
// ShippingAddressesResource.List.
type ShippingAddressRecord struct {
	ID        string           `json:"id"`
	IsDefault bool             `json:"is_default"`
	Nickname  *string          `json:"nickname"`
	Address   *ShippingAddress `json:"address"`
}

// WebBotAuthBlock holds web-bot-auth signature headers for a merchant
// authority, returned by WebBotAuthResource.SignURL. ExpiresAt stays a
// string; it is parsed internally only for the signature cache
// (web-bot-auth.ts:176-181, GUIDANCE §5.7).
type WebBotAuthBlock struct {
	Signature      string `json:"signature"`
	SignatureInput string `json:"signature_input"`
	SignatureAgent string `json:"signature_agent"`
	Authority      string `json:"authority"`
	ExpiresAt      string `json:"expires_at"`
}

// String returns a credential-safe summary. Every string is redacted because
// the full block is server-controlled and an invalid server can place secret
// material in a nominally non-secret field.
func (b WebBotAuthBlock) String() string {
	return "WebBotAuthBlock{Signature:<redacted> SignatureInput:<redacted> SignatureAgent:<redacted> Authority:<redacted> ExpiresAt:<redacted>}"
}

// Format ensures all common fmt verbs use the credential-safe summary.
func (b WebBotAuthBlock) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(b.String())) }

// CreateSpendRequestParams are the parameters for
// SpendRequestsResource.Create. Optional scalar zero values are omitted where
// zero is equivalent to absence. Optional slices use nil for omission and a
// non-nil empty slice for an explicit empty array.
type CreateSpendRequestParams struct {
	PaymentDetails string         `json:"payment_details"`
	CredentialType CredentialType `json:"credential_type,omitzero"`
	NetworkID      string         `json:"network_id,omitzero"`

	// Amount is in the smallest currency unit (cents).
	Amount   int64  `json:"amount,omitzero"`
	Currency string `json:"currency,omitzero"`

	MerchantName string `json:"merchant_name,omitzero"`
	MerchantURL  string `json:"merchant_url,omitzero"`

	Context string `json:"context"`

	LineItems []LineItem `json:"line_items,omitzero"`
	Totals    []Total    `json:"totals,omitzero"`

	RequestApproval bool `json:"request_approval,omitzero"`
	Test            bool `json:"test,omitzero"`

	// Approve selects the delegated creation endpoint and is never serialized.
	// Callers need an access token granted the spend_requests:approve scope.
	Approve bool `json:"-"`
}

// UpdateSpendRequestParams are the parameters for
// SpendRequestsResource.Update. Pointer scalars preserve the distinction
// between omission and an explicit zero value; nil slices are omitted while
// non-nil empty slices serialize as empty arrays.
type UpdateSpendRequestParams struct {
	PaymentDetails *string `json:"payment_details,omitzero"`

	// Amount is in the smallest currency unit (cents).
	Amount *int64 `json:"amount,omitzero"`

	MerchantURL *string `json:"merchant_url,omitzero"`
	ProfileID   *string `json:"profile_id,omitzero"`
	MerchantID  *string `json:"merchant_id,omitzero"`
	Currency    *string `json:"currency,omitzero"`

	LineItems []LineItem `json:"line_items,omitzero"`
	Totals    []Total    `json:"totals,omitzero"`
}

// ReportOutcome is the outcome of an agent payment attempt reported via
// ReportsResource.Create. Unknown values are passed through unchanged.
type ReportOutcome string

// Known report outcomes (parity: interfaces.ts:98).
const (
	ReportOutcomeSuccess   ReportOutcome = "success"
	ReportOutcomeBlocked   ReportOutcome = "blocked"
	ReportOutcomeAbandoned ReportOutcome = "abandoned"
)

// ReportTag classifies what an agent encountered during a payment attempt.
// Unknown values are passed through unchanged.
type ReportTag string

// Known report tags (parity: interfaces.ts:101-116).
const (
	ReportTagStripeCheckout   ReportTag = "stripe_checkout"
	ReportTagCaptcha          ReportTag = "captcha"
	ReportTagAntiBotScript    ReportTag = "anti_bot_script"
	ReportTagCDNBlock         ReportTag = "cdn_block"
	ReportTagWAFBlock         ReportTag = "waf_block"
	ReportTagDNSBlock         ReportTag = "dns_block"
	ReportTagRateLimited      ReportTag = "rate_limited"
	ReportTagLoginRequired    ReportTag = "login_required"
	ReportTag3DSChallenge     ReportTag = "3ds_challenge"
	ReportTagPageInaccessible ReportTag = "page_inaccessible"
	ReportTagTimeout          ReportTag = "timeout"
	ReportTagSiteError        ReportTag = "site_error"
	ReportTagPaymentDeclined  ReportTag = "payment_declined"
	ReportTagOther            ReportTag = "other"
)

// CreateReportParams are the parameters for ReportsResource.Create. Optional
// pointer fields preserve omission separately from explicit empty values.
type CreateReportParams struct {
	Domain          string        `json:"domain"`
	Outcome         ReportOutcome `json:"outcome"`
	SpendRequestID  string        `json:"spend_request_id"`
	Tags            []ReportTag   `json:"tags,omitzero"`
	Step            *string       `json:"step,omitzero"`
	FreeformContext *string       `json:"freeform_context,omitzero"`
}

// ReportRecord is the stored report returned by ReportsResource.Create.
// CreatedAt is an opaque pass-through timestamp string (GUIDANCE §5.7).
type ReportRecord struct {
	Object         string `json:"object"`
	CreatedAt      string `json:"created_at"`
	Domain         string `json:"domain"`
	Outcome        string `json:"outcome"`
	SpendRequestID string `json:"spend_request_id"`
	Status         string `json:"status"`
}
