package stripelink_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/mackross/stripelink"
)

// ExampleClient_deviceAuthentication demonstrates a complete persisted
// device-auth session without contacting Link or using real credentials.
func ExampleClient_deviceAuthentication() {
	var tokenIssued bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/device/code":
			fmt.Fprint(w, `{"device_code":"device-code","user_code":"WXYZ-1234","verification_uri":"https://link.example/activate","verification_uri_complete":"https://link.example/activate?code=WXYZ-1234","expires_in":600,"interval":5}`)
		case "/device/token":
			tokenIssued = true
			fmt.Fprint(w, `{"access_token":"example-access","refresh_token":"example-refresh","token_type":"bearer","expires_in":3600}`)
		case "/userinfo":
			if !tokenIssued || r.Header.Get("Authorization") != "Bearer example-access" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"email":"buyer@example.com"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	storage := &stripelink.MemoryStorage{}
	options := stripelink.Options{
		AuthStorage: storage,
		HTTPClient:  server.Client(),
		AuthBaseURL: server.URL,
		APIBaseURL:  server.URL,
		ClientName:  "example-agent",
	}

	client, err := stripelink.NewClient(options)
	if err != nil {
		panic(err)
	}
	device, err := client.Auth.InitiateDeviceAuth(ctx)
	if err != nil {
		panic(err)
	}
	if _, err := client.Auth.PollDeviceAuthOnce(ctx, device.DeviceCode); err != nil {
		panic(err)
	}

	// A later client can use the same persisted session without receiving or
	// copying tokens through application code.
	restarted, err := stripelink.NewClient(options)
	if err != nil {
		panic(err)
	}
	user, err := restarted.UserInfo.Retrieve(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Println(device.VerificationURL)
	fmt.Println(*user.Email)
	// Output:
	// https://link.example/activate
	// buyer@example.com
}

// ExampleSpendRequestsResource_Retrieve demonstrates retrieving a spend
// request from a local test server. Production callers should not print or log
// expanded payment credentials returned by this operation.
func ExampleSpendRequestsResource_Retrieve() {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"lsrq_example","payment_details":"pd_example","status":"approved","line_items":[],"totals":[],"created_at":"2026-07-10T00:00:00Z","updated_at":"2026-07-10T00:00:01Z"}`)
	}))
	defer server.Close()

	client, err := stripelink.NewClient(stripelink.Options{
		AccessToken:         "example-access",
		HTTPClient:          server.Client(),
		APIBaseURL:          server.URL,
		SpendRequestBaseURL: server.URL,
		AuthStorage:         &stripelink.MemoryStorage{},
	})
	if err != nil {
		panic(err)
	}

	request, err := client.SpendRequests.Retrieve(context.Background(), "lsrq_example")
	if err != nil {
		panic(err)
	}
	fmt.Println(request.ID, request.Status)
	// Output:
	// lsrq_example approved
}
