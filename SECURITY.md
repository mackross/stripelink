# Security policy

## Release status

This repository is not yet qualified for production use. The release evidence
and remaining blockers are tracked in [CONFORMANCE.md](./CONFORMANCE.md) and
[RELEASE.md](./RELEASE.md). Passing unit tests alone is not approval to process
live payment credentials.

## Reporting a vulnerability

Use a private GitHub security advisory for this repository when that facility
is available. Otherwise contact the repository maintainer through a private,
authenticated channel. Do not open a public issue containing a vulnerability,
access token, refresh token, device code, verification URL, payment
credential, signature, cookie, credential-file content, or production request
or response.

A useful report contains a minimal reproduction using synthetic credentials,
the affected commit and Go version, the platform, and the security impact. Do
not test against accounts or systems you do not own or have explicit
authorization to assess.

## Credential-handling contract

The following values are secrets even when they are short-lived:

- OAuth access and refresh tokens;
- device codes, user codes, and complete verification URLs;
- virtual-card numbers and CVCs;
- shared payment tokens and Link payment tokens;
- web-bot signatures and signature inputs;
- cookies, authorization headers, and response bodies that contain any of the
  above.

Callers must keep these values out of logs, traces, metrics, crash reports,
analytics, command history, test fixtures, and support tickets. Pass expanded
payment credentials directly to the component that performs the authorized
payment and discard them as soon as the operation permits. Avoid retaining
whole `SpendRequest`, `APIError`, request, or response values in telemetry.

The SDK's verbose logging is metadata-only and never emits header values,
request or response bodies, URL queries or fragments, or credential fields.
`APIError.RawBody` and `APIError.Details` intentionally remain available to
the caller for diagnosis; they must be handled as potentially sensitive.

## Storage guarantees and limits

The default storage path is
`os.UserConfigDir()/stripelink/auth.json`. Directories created by the SDK are
owner-only and the credential and lock files are maintained at mode `0600` on
platforms with POSIX permissions. Files are read with a 1 MiB limit, symlinks
are rejected, and scoped updates use same-directory atomic replacement.

Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD use an advisory
cross-process lock and fsync the parent directory after atomic replacement.
Other platforms provide per-instance synchronization and sync the replacement
file before rename, but cannot portably lock across processes or fsync the
directory. On those platforms, applications must serialize processes and
cannot assume the renamed directory entry survives sudden power loss unless a
custom store provides that guarantee. The JavaScript link-cli does not honor
the Go advisory lock, so the CLI and SDK must not write the same file
concurrently.

The file format is compatible with link-cli, but the default path is not
promised to be the CLI's path and no automatic discovery or migration occurs.
Do not point the SDK at a shared file unless ownership and writer coordination
are understood.

A custom `AuthStorage` must implement `Transact` as one complete-state atomic
transaction, return defensive copies from `Load`, obey cancellation before
commit, and hold its transaction across processes through durable persistence.
A store that implements `Load` followed by an independently synchronized write
can lose a rotated single-use refresh token and is not safe for this SDK.
Transaction callbacks must be local and side-effect-free; the SDK never holds a
storage transaction open across network I/O.

Automatic refresh is single-flight within one Client, not across independent
processes or Client values. A service sharing one credential set must centralize
refresh through one long-lived Client rather than relying on the storage lock to
serialize network requests.

## Network boundary

Remote base URLs require HTTPS. Plain HTTP is accepted only for loopback test
and development servers. Redirects are refused so bearer tokens and default
headers cannot be forwarded to another origin. Authenticated safe reads may
retry once after a `401`; mutations are never automatically replayed.

Responses are bounded to 4 MiB by default. Applications may configure a
different positive `MaxResponseBodyBytes`, but should use the smallest value
that accommodates their validated workload. Ordinary network operations rely
on the caller's context deadline; the SDK does not install a client-wide
timeout. A started automatic token refresh is detached for at most 30 seconds
so a successful remote rotation can be committed after its caller stops
waiting.

## Dependency and toolchain policy

The security floor is Go 1.26.5. A govulncheck run on Go 1.26.1 found nine
reachable standard-library vulnerabilities fixed through 1.26.5, so 1.26.1
must not be used for release or production. CI qualifies the exact Go 1.26.5
patch release. The package has no third-party runtime dependencies.

CI installs Staticcheck v0.7.0 and govulncheck v1.6.0 from their pinned Go
module versions. Before release, the exact commit must pass the commands in
[RELEASE.md](./RELEASE.md), including the race detector, fuzz smoke tests,
`go vet`, Staticcheck, and govulncheck. The workflow has only read access to
repository contents, does not check out submodules, and does not consume
production secrets or credential files. Tool versions and results must be
retained with the release evidence.
