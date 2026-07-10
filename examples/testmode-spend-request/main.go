// Command testmode-spend-request exercises the real Link API in test mode.
// It reads an existing link-cli credential file, optionally performs an
// interactive device login, creates a test-mode spend request requiring public
// approval, prints the returned test credentials, and cancels the request on
// exit.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	stripelink "github.com/mackross/stripelink"
)

func main() {
	var (
		authFile = flag.String("auth-file", os.Getenv("STRIPELINK_LINK_CLI_AUTH_FILE"), "path to the link-cli credential JSON file")
		login    = flag.Bool("login", false, "perform interactive Link device authentication before creating the request")
	)
	flag.Parse()
	if *authFile == "" {
		fatalf("pass -auth-file or set STRIPELINK_LINK_CLI_AUTH_FILE")
	}

	storage, err := stripelink.NewFileStorage(*authFile)
	if err != nil {
		fatalf("open link-cli credential file: %v", err)
	}
	client, err := stripelink.NewClient(stripelink.Options{
		ClientName:  "stripelink test-mode example",
		AuthStorage: storage,
	})
	if err != nil {
		fatalf("create Link client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if *login {
		if err := authenticate(ctx, client); err != nil {
			fatalf("authenticate with Link: %v", err)
		}
	}

	paymentMethods, err := client.PaymentMethods.List(ctx)
	if err != nil {
		if isInvalidRefreshToken(err) && !*login {
			fatalf("the stored Link login has expired; rerun this command with -login")
		}
		fatalf("list Link payment methods: %v", err)
	}
	if len(paymentMethods) == 0 {
		fatalf("the Link account has no saved payment methods")
	}
	paymentMethodID := paymentMethods[0].ID
	for _, method := range paymentMethods {
		if method.IsDefault {
			paymentMethodID = method.ID
			break
		}
	}

	amount := int64(100)
	quantity := 1
	created, err := client.SpendRequests.Create(ctx, stripelink.CreateSpendRequestParams{
		PaymentDetails: paymentMethodID,
		CredentialType: stripelink.CredentialTypeCard,
		Amount:         amount,
		Currency:       "usd",
		MerchantName:   "stripelink integration example",
		MerchantURL:    "https://example.com/stripelink-integration-example",
		Context: "Explicit test-mode example for the stripelink Go SDK. This request uses Link test card data " +
			"and must never result in a live purchase or fulfillment.",
		LineItems: []stripelink.LineItem{{
			Name:       "Integration example item",
			Quantity:   &quantity,
			UnitAmount: &amount,
		}},
		Totals: []stripelink.Total{{
			Type:        "total",
			DisplayText: "Total",
			Amount:      amount,
		}},
		Test:            true,
		RequestApproval: true,
	})
	if err != nil {
		fatalf("create test-mode spend request and request approval: %v", err)
	}

	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		canceled, cancelErr := client.SpendRequests.Cancel(cleanupCtx, created.ID)
		if cancelErr != nil {
			fmt.Fprintf(os.Stderr, "warning: cancel test-mode spend request %s: %v\n", created.ID, cancelErr)
			return
		}
		printJSON("canceled test-mode spend request", canceled)
	}()

	printJSON("created test-mode spend request", created)
	if created.ApprovalURL != "" {
		fmt.Printf("\nApprove the test-mode spend request at:\n%s\n", created.ApprovalURL)
	}
	retrieved, err := waitForTestCard(ctx, client, created.ID)
	if err != nil {
		fatalf("wait for approved test-mode spend request: %v", err)
	}
	printJSON("retrieved test-mode spend request", retrieved)
	if retrieved.Card == nil || retrieved.Card.Number == "" || retrieved.Card.CVC == "" {
		fatalf("approved test-mode request did not return complete test card credentials")
	}
}

func waitForTestCard(ctx context.Context, client *stripelink.Client, requestID string) (*stripelink.SpendRequest, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		request, err := client.SpendRequests.Retrieve(ctx, requestID, stripelink.SpendRequestIncludeCard)
		if err != nil {
			return nil, err
		}
		switch request.Status {
		case stripelink.SpendRequestStatusApproved:
			if request.Card == nil {
				return nil, fmt.Errorf("approved request has no card")
			}
			return request, nil
		case stripelink.SpendRequestStatusDenied,
			stripelink.SpendRequestStatusExpired,
			stripelink.SpendRequestStatusFailed,
			stripelink.SpendRequestStatusCanceled:
			return nil, fmt.Errorf("request reached terminal status %q", request.Status)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func authenticate(ctx context.Context, client *stripelink.Client) error {
	device, err := client.Auth.InitiateDeviceAuth(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Approve the Link login at:\n%s\n", device.VerificationURLComplete)
	if _, err := client.Auth.PollDeviceAuth(ctx, device); err != nil {
		return err
	}
	fmt.Println("Link authentication completed")
	return nil
}

func isInvalidRefreshToken(err error) bool {
	apiErr, ok := errors.AsType[*stripelink.APIError](err)
	return ok && apiErr.Status == 400 && apiErr.RawBody != ""
}

func printJSON(label string, value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatalf("encode %s: %v", label, err)
	}
	fmt.Printf("\n%s:\n%s\n", label, encoded)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
