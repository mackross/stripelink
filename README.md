# stripelink

`stripelink` is a Go port of the
[`@stripe/link-sdk`](./link-cli/packages/sdk) JavaScript SDK. It provides
programmatic access to Link device authentication, spend requests, saved
payment methods and addresses, user information, web-bot signatures, and agent
observation reports.

This package handles OAuth tokens and may return unmasked, one-time payment
credentials. Treat its inputs, outputs, errors, and storage as sensitive. The
current repository is still undergoing release qualification; see
[CONFORMANCE.md](./CONFORMANCE.md) and [RELEASE.md](./RELEASE.md) before using
it with live financial data.

## Requirements

- Go 1.26.5 or newer. Go 1.26.1 is rejected for production because the pinned
  vulnerability scan found reachable standard-library issues fixed by 1.26.5.
  CI currently qualifies the exact 1.26.5 patch release.
- No third-party runtime dependencies.
- A caller-supplied context deadline for every operation that can block. The
  SDK deliberately does not impose an HTTP client timeout.

## Installation

```sh
go get github.com/mackross/stripelink
```

## Authentication and session ownership

Authentication uses the OAuth 2.0 device authorization flow. By default,
`NewClient` stores credentials at:

```text
<os.UserConfigDir()>/stripelink/auth.json
```

The directory is created owner-only and the credential file is maintained at
mode `0600` on platforms that implement POSIX permissions. The JSON schema is
compatible with link-cli, but the SDK does not search, import, or migrate the
CLI's platform-specific file automatically. Pass an explicit `FileStorage` if
the application deliberately wants to use a known existing file.

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()

client, err := stripelink.NewClient(stripelink.Options{
	ClientName: "my-agent",
})
if err != nil {
	return err
}

device, err := client.Auth.InitiateDeviceAuth(ctx)
if err != nil {
	return err
}
// Present device.VerificationURLComplete to the user through a trusted UI.
// Do not log it: it contains the user code.

if _, err := client.Auth.PollDeviceAuth(ctx, device); err != nil {
	return err
}
// Successful polling persists the session before returning.
```

`ResumeDeviceAuth` resumes a still-valid pending flow after a process restart.
`Logout` revokes the SDK-owned persisted refresh token and clears the session
only after successful revocation. The low-level `RefreshToken` and
`RevokeToken` methods operate only on the token passed to them and do not
change storage. Static tokens and custom token providers remain caller-owned.

For ephemeral or test processes, pass `&stripelink.MemoryStorage{}`. Custom
`AuthStorage` implementations must be concurrency-safe, defensively copy
values, and implement `Update` as one atomic complete-session transaction. A
persistent implementation must hold the transaction lock across cooperating
processes through durable commit so a rotated refresh token cannot be lost.

## Spend retrieval

```go
request, err := client.SpendRequests.Retrieve(ctx, requestID)
if errors.Is(err, stripelink.ErrNotFound) {
	return nil
}
if err != nil {
	return err
}

// Request an expansion only where the payment adapter needs it. Expanded
// Card, SharedPaymentToken, and LinkPayToken fields are credentials: do not
// print, log, persist, or include them in telemetry.
request, err = client.SpendRequests.Retrieve(
	ctx,
	request.ID,
	stripelink.SpendRequestIncludeCard,
)
```

Executable, offline versions of the authentication/session and retrieval
flows live in [example_test.go](./example_test.go).

## Request and retry behavior

- Safe authenticated reads (`GET`) may be retried once after a `401`, using a
  generation-aware token refresh. A second `401` is returned to the caller.
- Mutation `POST`s—including spend mutations, web-bot signing, and reports—are
  never replayed automatically. Link does not document an idempotency contract
  for them.
- Redirects are never followed. `NewClient` shallow-copies a supplied
  `*http.Client`, preserving its transport, timeout, cookie jar, and other
  fields, then replaces the redirect policy on the copy with refusal. The
  caller's client is not mutated.
- All HTTP response reads are bounded. The default maximum is 4 MiB and can be
  reduced or increased with `Options.MaxResponseBodyBytes`.
- A required successful response must contain valid JSON of its documented
  top-level shape. Malformed `2xx` bodies return a decode/SDK error, never a
  fabricated zero value.

## Optional request fields

Optional request scalars are pointers deliberately: `nil` omits a field while
a non-nil pointer preserves explicit `false`, `0`, or `""`. For optional
slices, `nil` omits the field and a non-nil empty slice sends `[]`. Required
identifiers and structurally impossible inputs are validated locally; unknown
string-enum values are preserved for forward compatibility.

## Errors and logging

Use `errors.Is` for exported sentinels and `errors.As` or
`errors.AsType[*stripelink.APIError]` for structured errors. `APIError`
contains the HTTP status and bounded response details. `TransportError`
contains the method, URL, and wrapped network/context cause. There is no
generic SDK base-error type.

Verbose mode logs metadata only: method, sanitized endpoint, status, timing,
body size, attempt number, and header names. It never logs request/response
bodies, header values, URL queries/fragments, OAuth material, payment
credentials, cookies, or signatures. This guarantee applies to custom
loggers supplied through `Options.Logger`.

Do not log returned error structures indiscriminately: an `APIError` exposes
`RawBody` and `Details` for programmatic diagnosis, and an upstream response
may contain sensitive data.

## Platform and storage limitations

On Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD, `FileStorage`
uses an owner-only advisory lock file to coordinate cooperating Go processes
and fsyncs the parent directory after replacement. Other platforms retain
per-instance synchronization, sync the credential file before same-directory
replacement, but cannot portably lock across processes or fsync the directory;
power-loss durability of the directory entry is therefore not guaranteed.
link-cli does not honor the Go lock, so concurrent writes by the CLI and this
SDK remain unsafe on every platform. Applications that need stronger
guarantees should provide an `AuthStorage` backed by an OS credential service
or transactional store.

See [SECURITY.md](./SECURITY.md) for credential-handling requirements and
security-reporting guidance.
