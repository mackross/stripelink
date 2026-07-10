// Package stripelink provides a Go client for Link device authentication,
// spend requests, saved payment methods and addresses, user information,
// web-bot signatures, and agent observation reports.
//
// Construct a Client with NewClient. The zero value of Options uses Link's
// documented service endpoints and file-backed OAuth storage at
// os.UserConfigDir()/stripelink/auth.json. Device-auth initiation persists a
// resumable pending flow; successful polling persists tokens before returning;
// and the default token provider refreshes an expiring session transparently.
// Direct RefreshToken and RevokeToken calls do not mutate storage. Logout is
// the cohesive SDK-owned operation that revokes a persisted refresh token and
// then clears the session.
//
// OAuth material, complete verification URLs, virtual-card data, shared and
// Link payment tokens, web-bot signatures, cookies, and credential-bearing
// response bodies are secrets. Verbose logging contains metadata only: it
// excludes bodies, header values, URL queries and fragments, and credential
// fields. Callers must apply the same rule to returned values and to
// APIError.RawBody and APIError.Details, which may contain sensitive upstream
// data.
//
// A Client and all resources are safe for concurrent goroutine use. Safe GET
// operations may refresh and retry once after a 401. Mutating POST operations
// are never replayed automatically because the API has no documented
// idempotency guarantee. Redirects are refused. The SDK sets no client-wide
// timeout; callers own cancellation and deadlines through each method's
// context.
//
// HTTP bodies are limited to 4 MiB by default, configurable through
// Options.MaxResponseBodyBytes. FileStorage reads are limited to 1 MiB. On
// Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD, FileStorage
// coordinates cooperating Go processes through an advisory lock and fsyncs
// the parent directory after replacement. Other platforms provide
// per-instance synchronization and sync the replacement file, but cannot
// portably lock across processes or fsync the directory. link-cli does not
// honor the Go lock on any platform.
//
// Local conditions are classified by exported sentinel errors. APIError and
// TransportError expose structured remote and transport failures; the package
// deliberately has no generic base error type. Required successful responses
// must contain valid JSON of their documented shape, otherwise the operation
// returns a decode error rather than a zero-value result.
//
// This module requires patched Go 1.26.5 or newer and qualifies Go 1.26.5 in
// CI. Consult CONFORMANCE.md, SECURITY.md, and
// RELEASE.md in the source repository before processing live financial data.
package stripelink
