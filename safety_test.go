package stripelink

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPublicResourceMethodsRejectNilContextAndUnconfiguredReceiver(t *testing.T) {
	client := newResourceTestClient(t, &recordingTransport{}, nil)

	configured := []struct {
		name string
		call func() error
	}{
		{"SpendRequests.List", func() error { _, err := client.SpendRequests.List(nilContext()); return err }},
		{"SpendRequests.Create", func() error {
			_, err := client.SpendRequests.Create(nilContext(), CreateSpendRequestParams{})
			return err
		}},
		{"SpendRequests.Update", func() error {
			_, err := client.SpendRequests.Update(nilContext(), "id", UpdateSpendRequestParams{})
			return err
		}},
		{"SpendRequests.Cancel", func() error { _, err := client.SpendRequests.Cancel(nilContext(), "id"); return err }},
		{"SpendRequests.Retrieve", func() error { _, err := client.SpendRequests.Retrieve(nilContext(), "id"); return err }},
		{"SpendRequests.RequestApproval", func() error { _, err := client.SpendRequests.RequestApproval(nilContext(), "id"); return err }},
		{"PaymentMethods.List", func() error { _, err := client.PaymentMethods.List(nilContext()); return err }},
		{"ShippingAddresses.List", func() error { _, err := client.ShippingAddresses.List(nilContext()); return err }},
		{"UserInfo.Retrieve", func() error { _, err := client.UserInfo.Retrieve(nilContext()); return err }},
		{"WebBotAuth.SignURL", func() error {
			_, err := client.WebBotAuth.SignURL(nilContext(), "https://merchant.example/pay")
			return err
		}},
		{"Reports.Create", func() error { _, err := client.Reports.Create(nilContext(), CreateReportParams{}); return err }},
	}
	for _, test := range configured {
		t.Run(test.name+"/nil_context", func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})
	}

	var nilSpend *SpendRequestsResource
	var nilPayment *PaymentMethodsResource
	var nilShipping *ShippingAddressesResource
	var nilUser *UserInfoResource
	var nilWebBot *WebBotAuthResource
	var nilReports *ReportsResource
	ctx := t.Context()
	unconfigured := []struct {
		name string
		call func() error
	}{
		{"SpendRequests.List/nil", func() error { _, err := nilSpend.List(ctx); return err }},
		{"SpendRequests.Create/nil", func() error { _, err := nilSpend.Create(ctx, CreateSpendRequestParams{}); return err }},
		{"SpendRequests.Update/nil", func() error { _, err := nilSpend.Update(ctx, "id", UpdateSpendRequestParams{}); return err }},
		{"SpendRequests.Cancel/nil", func() error { _, err := nilSpend.Cancel(ctx, "id"); return err }},
		{"SpendRequests.Retrieve/nil", func() error { _, err := nilSpend.Retrieve(ctx, "id"); return err }},
		{"SpendRequests.RequestApproval/nil", func() error { _, err := nilSpend.RequestApproval(ctx, "id"); return err }},
		{"PaymentMethods.List/nil", func() error { _, err := nilPayment.List(ctx); return err }},
		{"ShippingAddresses.List/nil", func() error { _, err := nilShipping.List(ctx); return err }},
		{"UserInfo.Retrieve/nil", func() error { _, err := nilUser.Retrieve(ctx); return err }},
		{"WebBotAuth.SignURL/nil", func() error { _, err := nilWebBot.SignURL(ctx, "https://merchant.example/pay"); return err }},
		{"Reports.Create/nil", func() error { _, err := nilReports.Create(ctx, CreateReportParams{}); return err }},
		{"SpendRequests.List/zero", func() error { _, err := new(SpendRequestsResource).List(ctx); return err }},
		{"SpendRequests.Create/zero", func() error { _, err := new(SpendRequestsResource).Create(ctx, CreateSpendRequestParams{}); return err }},
		{"SpendRequests.Update/zero", func() error {
			_, err := new(SpendRequestsResource).Update(ctx, "id", UpdateSpendRequestParams{})
			return err
		}},
		{"SpendRequests.Cancel/zero", func() error { _, err := new(SpendRequestsResource).Cancel(ctx, "id"); return err }},
		{"SpendRequests.Retrieve/zero", func() error { _, err := new(SpendRequestsResource).Retrieve(ctx, "id"); return err }},
		{"SpendRequests.RequestApproval/zero", func() error { _, err := new(SpendRequestsResource).RequestApproval(ctx, "id"); return err }},
		{"PaymentMethods.List/zero", func() error { _, err := new(PaymentMethodsResource).List(ctx); return err }},
		{"ShippingAddresses.List/zero", func() error { _, err := new(ShippingAddressesResource).List(ctx); return err }},
		{"UserInfo.Retrieve/zero", func() error { _, err := new(UserInfoResource).Retrieve(ctx); return err }},
		{"WebBotAuth.SignURL/zero", func() error {
			_, err := new(WebBotAuthResource).SignURL(ctx, "https://merchant.example/pay")
			return err
		}},
		{"Reports.Create/zero", func() error { _, err := new(ReportsResource).Create(ctx, CreateReportParams{}); return err }},
	}
	for _, test := range unconfigured {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestSharedPaymentTokenUnmarshalRejectsNilReceiver(t *testing.T) {
	var token *SharedPaymentToken
	if err := token.UnmarshalJSON([]byte(`"spt_123"`)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("error = %v, want ErrInvalidArgument", err)
	}
}

type mixedResourceTransport struct {
	mu     sync.Mutex
	counts map[string]int
}

func (rt *mixedResourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	rt.mu.Lock()
	if rt.counts == nil {
		rt.counts = make(map[string]int)
	}
	rt.counts[req.URL.Path]++
	rt.mu.Unlock()

	body := ""
	status := http.StatusOK
	switch {
	case strings.HasSuffix(req.URL.Path, "/device/token"):
		body = `{"access_token":"access-new","refresh_token":"refresh-new","expires_in":3600,"token_type":"Bearer"}`
	case strings.HasSuffix(req.URL.Path, "/spend_requests"):
		body = `{"data":[]}`
	case strings.HasSuffix(req.URL.Path, "/payment-details"):
		body = `{"payment_details":[]}`
	case strings.HasSuffix(req.URL.Path, "/shipping_addresses"):
		body = `{"shipping_addresses":[]}`
	case strings.HasSuffix(req.URL.Path, "/userinfo"):
		body = `{}`
	case strings.HasSuffix(req.URL.Path, "/web_bot_auth/sign"):
		body = webBotResponse("merchant.example", testWebBotExpiry)
	case strings.HasSuffix(req.URL.Path, "/agent_observations"):
		status = http.StatusCreated
		body = `{"object":"agent_report","created_at":"2030-01-01T00:00:00Z","domain":"merchant.example","outcome":"success","spend_request_id":"lsrq_123","status":"received"}`
	default:
		status = http.StatusNotFound
		body = `{"error":"unexpected route"}`
	}
	return response(req, status, body), nil
}

func (rt *mixedResourceTransport) count(path string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.counts[path]
}

func TestClientMixedResourceConcurrentUse(t *testing.T) {
	const rounds = 12
	rt := &mixedResourceTransport{}
	client, err := NewClient(Options{
		AuthBaseURL: "http://127.0.0.1:8080/auth",
		APIBaseURL:  "http://127.0.0.1:8080/api",
		HTTPClient:  &http.Client{Transport: rt},
		AccessToken: "static-test-token",
		AuthStorage: &MemoryStorage{},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.WebBotAuth.now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, rounds*7)
	for range rounds {
		operations := []func() error{
			func() error { _, err := client.Auth.RefreshToken(ctx, "refresh-old"); return err },
			func() error { _, err := client.SpendRequests.List(ctx); return err },
			func() error { _, err := client.PaymentMethods.List(ctx); return err },
			func() error { _, err := client.ShippingAddresses.List(ctx); return err },
			func() error { _, err := client.UserInfo.Retrieve(ctx); return err },
			func() error { _, err := client.WebBotAuth.SignURL(ctx, "https://merchant.example/pay"); return err },
			func() error {
				_, err := client.Reports.Create(ctx, CreateReportParams{Domain: "merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_123"})
				return err
			},
		}
		for _, operation := range operations {
			go func(operation func() error) {
				<-start
				results <- operation()
			}(operation)
		}
	}
	close(start)
	for range rounds * 7 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("mixed-resource operation: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("mixed-resource workload deadlocked: %v", ctx.Err())
		}
	}

	for _, path := range []string{
		"/auth/device/token", "/api/spend_requests", "/api/payment-details",
		"/api/shipping_addresses", "/api/userinfo", "/api/web_bot_auth/sign", "/api/agent_observations",
	} {
		if rt.count(path) == 0 {
			t.Errorf("mixed-resource workload did not exercise %s", path)
		}
	}
}

type cancellationDrainTransport struct {
	started   chan struct{}
	completed chan struct{}
}

func (rt *cancellationDrainTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.started <- struct{}{}
	<-req.Context().Done()
	if req.Body != nil {
		_ = req.Body.Close()
	}
	rt.completed <- struct{}{}
	return nil, req.Context().Err()
}

func TestClientCancellationDrainsAllResourceWork(t *testing.T) {
	const operations = 7
	rt := &cancellationDrainTransport{
		started:   make(chan struct{}, operations),
		completed: make(chan struct{}, operations),
	}
	client, err := NewClient(Options{
		AuthBaseURL: "http://127.0.0.1:8080/auth",
		APIBaseURL:  "http://127.0.0.1:8080/api",
		HTTPClient:  &http.Client{Transport: rt},
		AccessToken: "static-test-token",
		AuthStorage: &MemoryStorage{},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	results := make(chan error, operations)
	calls := []func() error{
		func() error { _, err := client.Auth.RefreshToken(ctx, "refresh-old"); return err },
		func() error { _, err := client.SpendRequests.List(ctx); return err },
		func() error { _, err := client.PaymentMethods.List(ctx); return err },
		func() error { _, err := client.ShippingAddresses.List(ctx); return err },
		func() error { _, err := client.UserInfo.Retrieve(ctx); return err },
		func() error { _, err := client.WebBotAuth.SignURL(ctx, "https://merchant.example/pay"); return err },
		func() error {
			_, err := client.Reports.Create(ctx, CreateReportParams{Domain: "merchant.example", Outcome: ReportOutcomeSuccess, SpendRequestID: "lsrq_123"})
			return err
		},
	}
	for _, call := range calls {
		go func(call func() error) { results <- call() }(call)
	}

	deadline, stop := context.WithTimeout(t.Context(), 5*time.Second)
	defer stop()
	for range operations {
		select {
		case <-rt.started:
		case <-deadline.Done():
			t.Fatalf("not all resource requests started: %v", deadline.Err())
		}
	}
	cancel()
	for range operations {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("canceled operation error = %v, want context.Canceled", err)
			}
		case <-deadline.Done():
			t.Fatalf("resource call did not return after cancellation: %v", deadline.Err())
		}
	}
	for range operations {
		select {
		case <-rt.completed:
		case <-deadline.Done():
			t.Fatalf("resource transport work did not drain: %v", deadline.Err())
		}
	}
}
