# Release qualification

This file defines the release procedure; it is not evidence that the current
checkout has passed it. Contract-row evidence and current gaps are recorded in
[CONFORMANCE.md](./CONFORMANCE.md).

## Supported matrix

The security minimum and initial CI release target is Go 1.26.5. A scanner run
on Go 1.26.1 found nine reachable standard-library vulnerabilities fixed
through 1.26.5, so earlier 1.26 patch releases are unsupported. CI and release
evidence must use exact Go 1.26.5 on every supported runner. The minimum
platform set is:

| Runner | Storage qualification |
|---|---|
| Linux | File permissions, special-file/symlink rejection, atomic replacement, directory fsync, and advisory cross-process locking |
| macOS | File permissions, special-file/symlink rejection, atomic replacement, directory fsync, and advisory cross-process locking |
| Windows | MemoryStorage, HTTP behavior, file sync/replacement, and per-instance storage coordination; cross-process lock and directory-fsync tests are skipped as unsupported |

No wider Go-version or operating-system support should be claimed until its
jobs pass and the table is updated. Cross-process file locking is also
implemented for the BSD build targets, but those targets are not release
qualified by this minimum matrix.

The checked-in [CI workflow](./.github/workflows/ci.yml) enforces the matrix
with `actions/checkout@v6`, `actions/setup-go@v6`, and Go 1.26.5. It runs
formatting, no-diff `go fix`, vet, build, ordinary tests, the race suite, docs,
and dependency inspection on Linux, macOS, and Windows. A separate Linux job
runs the race suite ten times. Platform-specific storage tests use build tags
or runtime capability checks and skip only guarantees the target cannot
provide.

Static analysis runs on Linux with Staticcheck v0.7.0 and govulncheck v1.6.0,
installed from pinned Go module versions. Four independent fuzz jobs validate
the seed corpus and run ten-second smoke campaigns. The workflow has
`contents: read` permission only, disables persisted checkout credentials and
submodule checkout, and consumes no production secrets.

## Required clean-checkout gates

Run these commands from the module root with no production credentials or
network proxies configured:

```sh
test -z "$(gofmt -l -- *.go)"
go vet ./...
test -z "$(go fix -diff ./...)"
go test ./... -count=1
go test -race ./... -count=10
go test . -run='^$' -fuzz=FuzzSharedPaymentTokenUnmarshal -fuzztime=10s
go test . -run='^$' -fuzz=FuzzExtractAPIErrorMessage -fuzztime=10s
go test . -run='^$' -fuzz=FuzzWebBotURLParsingDoesNotDiscloseSecrets -fuzztime=10s
go test . -run='^$' -fuzz=FuzzStorageStateDecode -fuzztime=10s
GOBIN="$PWD/.release-tools" go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
GOBIN="$PWD/.release-tools" go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
.release-tools/staticcheck -version
.release-tools/staticcheck ./...
.release-tools/govulncheck -version
.release-tools/govulncheck ./...
go list -m all
go doc .
```

Remove `.release-tools` after recording its versions and results; it must never
be committed. Run every fuzz target present at the release commit, not only
the four named above. `go list -m all` must show no unexpected module
dependency. Record the
Go version, OS/architecture, staticcheck version, govulncheck version, commit,
commands, and complete pass/fail result as immutable release evidence.

The examples use loopback test servers and synthetic tokens. No test or fuzz
target may contact Link production services or read a developer's real default
credential file.

## Manual security review

At least one reviewer who did not author the relevant implementation must
inspect and record findings for:

1. token rotation, generation checks, and bounded persistence after waiter
   cancellation;
2. no automatic replay of spend/report/signing mutations;
3. device-flow persistence, expiry, revoke, and logout transitions;
4. credential-file path, permissions, symlink handling, bounds, atomicity,
   durability, and platform lock limitations;
5. base-URL construction, identifier escaping, redirect refusal, proxy
   handling, and caller-owned HTTP client behavior;
6. metadata-only logs and credential-safe formatting;
7. 4 MiB HTTP and 1 MiB storage read bounds;
8. strict malformed-`2xx` handling and structured error inspection.

The review must also compare every endpoint, method, form/JSON field, envelope,
and pinned error template with the repository's pinned `link-cli` submodule.

## Release decision

A release may proceed only when every conformance row is `DONE` or has an
explicitly approved waiver, all supported matrix jobs pass for the same
commit, scanner findings have been dispositioned, and the manual security
review is complete. The current status must not be summarized as
"production-ready" while any of those conditions remains open.
