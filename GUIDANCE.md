# GUIDANCE.md — Porting `@stripe/link-sdk` to Go

Read this before writing or reviewing any code in this repository. It defines
the ground rules, the verified Go 1.26 facts you may rely on, the JS → Go
mapping decisions, and the behavioural-parity contract. When this document and
your instinct disagree, this document wins. When this document and the JS
source disagree, flag it — do not silently pick one.

This document describes the intended contract. It does not certify a checkout
for production use; `CONFORMANCE.md` and `RELEASE.md` define the evidence
requirements and record the remaining blockers.

## 1. Mission

Port the JavaScript SDK at `link-cli/packages/sdk` to Go, as module
`github.com/mackross/stripelink` (root package `stripelink`).

- The JS SDK is the **canonical source of truth for wire behaviour**:
  endpoints, methods, headers, request bodies, status-code handling, env vars,
  defaults, and error templates. Security and Go API deviations are recorded
  explicitly in §6.2.
- The Go code must read as if **designed natively by a senior Go developer** —
  mirror behaviour 1:1, never transliterate structure. JS warts that exist for
  historical reasons (listed in §6) are not ported.
- `README.md` at the repo root sketches the intended Go API. It is a sketch,
  not a contract; deviations decided here (§5) take precedence and the README
  is updated to match at the end of the port.
- **This is financial software** — it handles live payment credentials.
  Completeness and correctness outrank everything else: speed, brevity, token
  cost, elegance. Never guess at behaviour; verify against the JS source, and
  if still ambiguous, record an open question in §10 instead of deciding
  silently. An unhandled edge case is a defect, not a TODO.

## 2. Verified toolchain facts (Go 1.26.5)

These were verified against the installed `go1.26.5` toolchain and the
official go.dev/doc/go1.26 release notes on 2026-06-12. **Do not rely on
memory for version-specific claims** — if you need a fact not listed here,
verify with `go doc <pkg>` against the local toolchain first.

| Feature | Status | Use it? |
|---|---|---|
| `encoding/json` `omitzero` tag | stable since 1.24 | **Yes** — default for optional request fields |
| `encoding/json/v2` | still GOEXPERIMENT-gated, not in default 1.26 | **No** |
| `testing/synctest` | stable since 1.25 | **Yes** — all time-dependent tests |
| `errors.AsType[E]` | new in 1.26, stable | **Yes** — prefer over `errors.As` |
| `slog.NewMultiHandler` | new in 1.26 | available, not needed by default |
| `testing.T.Context()` | stable since 1.24 | **Yes** in tests |
| `go fix` modernizers | revamped in 1.26 | **Yes** — run as a quality gate |
| Green Tea GC | on by default in 1.26 | no action |
| `net/url.Parse` | 1.26 rejects malformed colon-in-host URLs | relevant to URL-validation tests |

## 3. Modern Go rules (non-negotiable)

- `gofmt`/`goimports` clean; `go vet` clean; `go fix` suggests nothing.
- **Zero third-party dependencies.** Standard library only. The ~15 lines of
  single-flight logic (§7) are written by hand, not imported from `x/sync`.
- `context.Context` is the first parameter of every method that can touch the
  network. Never stored in a struct.
- Errors: wrap with `%w`; match with `errors.Is`/`errors.AsType`; lowercase,
  unpunctuated messages **except** the parity templates in §6.3. No panics in
  library code. No `Must*` in the public API.
- "Accept interfaces, return structs." Export concrete types; the only
  exported interfaces are deliberate extension points (`AuthStorage`).
- No package-level mutable state, no `init()` side effects, no singletons
  (the JS `storage` singleton is not ported).
- Zero value usefulness: `stripelink.Options{}` must produce a working client.
- Generics only where they remove real duplication (the internal
  `doJSON[T]` request helper) — not for show.
- Every exported identifier has a doc comment that is a full sentence starting
  with its name. Package doc lives in `doc.go`. Provide `Example*` tests for
  the flows shown in the README.
- All code is safe under `go test -race`. Anything shared (token refresh,
  web-bot-auth cache) is explicitly synchronized — see §7.
- Tests: table-driven, `t.Context()`, `t.TempDir()`, `testing/synctest` for
  anything involving time. No sleeps.

## 4. Package layout

```
stripelink/            // single public package — the SDK is small; do not split
  doc.go               // package documentation
  client.go            // Client, Options, NewClient
  transport.go         // internal request core: auth injection, 401-retry, logging, decode
  auth.go              // AuthResource: device flow (initiate/poll/refresh/revoke)
  spend_requests.go    // SpendRequestsResource
  payment_methods.go   // PaymentMethodsResource
  shipping_addresses.go
  user_info.go
  web_bot_auth.go      // includes the signature cache
  reports.go
  storage.go           // AuthStorage, FileStorage, MemoryStorage
  tokens.go            // storage-backed auto-refreshing token provider
  types.go             // wire types (SpendRequest, Card, …)
  errors.go            // APIError, TransportError, sentinels
```

No `internal/` package: the transport core stays unexported in the root
package. Resist any urge to add sub-packages.

## 5. JS → Go mapping decisions

### 5.1 Client and options

JS (`client.ts`): `new Link(options)` with four resource fields, each resource
re-resolving config independently. Auth is a separate class the CLI constructs
itself.

Go:

```go
type Options struct {
    ClientName          string            // default "github.com/mackross/stripelink" (deviation #11; JS defaults to "Link CLI", config.ts:144)
    AccessToken         string            // static token
    GetAccessToken      AccessTokenFunc   // overrides AccessToken
    AuthStorage         AuthStorage       // default: FileStorage at default path
    HTTPClient          *http.Client      // default: client honoring LINK_HTTP_PROXY (§5.4)
    DefaultHeaders      map[string]string // set-if-absent, via RoundTripper
    AuthBaseURL         string            // default env LINK_AUTH_BASE_URL, then https://login.link.com
    APIBaseURL          string            // default env LINK_API_BASE_URL, then https://api.link.com
    SpendRequestBaseURL string            // default: APIBaseURL
    MaxResponseBodyBytes int64            // default 4 MiB; every read is bounded
    Logger              *slog.Logger      // default: debug→stderr when Verbose, else discard
    Verbose             bool
}

func NewClient(opts Options) (*Client, error)

type Client struct {
    Auth              *AuthResource
    SpendRequests     *SpendRequestsResource
    PaymentMethods    *PaymentMethodsResource
    ShippingAddresses *ShippingAddressesResource
    UserInfo          *UserInfoResource
    WebBotAuth        *WebBotAuthResource
    Reports           *ReportsResource
}
```

- Config is resolved **once** in `NewClient` and shared by all resources
  (fixes the JS wart of per-resource re-resolution; behaviour is identical
  because resolution is deterministic).
- Env vars are read once, in `NewClient`, mirroring `config.ts:118-131`
  precedence exactly: explicit option > env var > default.
- `Auth` lives on the client (per README), unlike JS where `AuthResource` is
  standalone. Same constants: `CLIENT_ID = "lwlpk_U7Qy7ThG69STZk"`, scope
  `"userinfo:read payment_methods.agentic"` (unexported, `auth.ts:12-13`).

### 5.2 Method names: one per operation

JS exposes dual names (`list`/`listSpendRequests`, `retrieve`/`getSpendRequest`,
… see `resources/interfaces.ts:57-78`) for back-compat. Go is greenfield:
**one method per operation** — `List`, `Create`, `Update`, `Cancel`,
`Retrieve`, `RequestApproval`. Do not port the aliases.

JS exports `I*Resource` interfaces for everything. Go exports **concrete
structs only**; consumers who want interfaces define their own at the point of
use. The exported extension points are:

```go
type AuthStorage interface { ... }                                    // §5.6
type AccessTokenRequest struct {
    ForceRefresh  bool
    RejectedToken string
}
type AccessTokenFunc func(ctx context.Context, request AccessTokenRequest) (string, error)
```

(`AccessTokenFunc` replaces JS `AccessTokenProvider` + `GetAccessTokenOptions`.)
`RejectedToken` is required for generation-aware refresh: after a 401, a
provider compares the rejected token with the currently stored token and
returns the current token without refreshing if another goroutine has already
rotated it. A boolean-only callback cannot safely do this.

### 5.3 Errors

JS hierarchy (`errors.ts`): `LinkSdkError` (code, cause) ← Configuration /
Authentication / Transport / `LinkApiError` (status, rawBody, details).

Go uses sentinels for local conditions and concrete structured types only
where callers need structured data. There is deliberately no generic SDK
base-error type: it complicates `errors.As` without adding a useful Go
capability.

```go
type APIError struct {
    Code, Message string
    Status        int
    RawBody       string
    Details       json.RawMessage
}

type TransportError struct {
    Code, Method, URL string // Code is always "transport_error"
    Err               error  // Unwrap returns this
}

var (
    ErrNotFound             = errors.New("stripelink: not found")
    ErrAuthorizationPending = errors.New("stripelink: authorization pending")
    ErrSlowDown             = errors.New("stripelink: slow down device authorization polling")
    ErrNotAuthenticated     = errors.New("stripelink: not authenticated")
    ErrNoPendingDeviceAuth  = errors.New("stripelink: no pending device authorization")
    ErrInvalidConfiguration = errors.New("stripelink: invalid configuration")
    ErrInvalidArgument      = errors.New("stripelink: invalid argument")
    ErrResponseTooLarge     = errors.New("stripelink: response body too large")
    ErrStorageTooLarge      = errors.New("stripelink: auth storage file too large")
    ErrRedirect             = errors.New("stripelink: redirect refused")
)
```

Behaviour mapping:

| JS behaviour | Go behaviour |
|---|---|
| `retrieve` returns `null` on 404 (`spend-request.ts:278-280`) | `Retrieve` returns `(nil, ErrNotFound)` — **deliberate deviation**, `(nil, nil)` is not idiomatic Go |
| `pollDeviceAuth` returns `null` for `authorization_pending` and `slow_down` (`auth.ts:159-162`) | single-shot poll returns distinct `ErrAuthorizationPending` or `ErrSlowDown`, so the blocking poller applies backoff only to `slow_down` |
| throws `LinkApiError` with code `expired_token` / `access_denied` (`auth.ts:163-175`) | `*APIError` with the same `Code` and the same message text |
| configuration problems throw lazily (e.g. no token → throw inside `getAccessToken`, `config.ts:113-117`) | config problems that are detectable up front return an error from `NewClient`; "no token configured" surfaces as `ErrNotAuthenticated` from the first authenticated call (parity: JS also fails at call time) |
| non-2xx → throw with extracted message (`extractApiError`, `formatOAuthError`) | structured `error.message` / `error` / `message` text is bounded and credential-redacted; unstructured bodies receive a generic diagnostic and remain available only through explicit `RawBody`/`Details` inspection |

### 5.4 Transport (the big consolidation)

JS duplicates `rawFetch`/`apiFetch` in **every** resource with slight
divergence — acknowledged as debt at `web-bot-auth.ts:27-29`. Go has exactly
one implementation in `transport.go`:

```go
// unexported; all resources delegate to it
func (c *core) do(ctx context.Context, req apiRequest) (status int, body []byte, err error)
func doJSON[T any](ctx context.Context, c *core, req apiRequest) (T, error)
```

It owns, in order:
1. **Metadata-only verbose logging** — method, sanitized URL (no user info or
   query values), status, duration, body byte count, and header names may be
   logged. Request/response bodies and header values are never logged.
   Redaction is not an adequate control for
   arbitrary nested payment data, OAuth responses, cookies, or newly added
   credential fields. This deliberately overrides JS logging parity.
2. **Bearer injection** from the configured `AccessTokenFunc`.
3. **401 → generation-aware refresh → retry exactly once for safe reads.**
   GET operations may be replayed. Mutation POSTs are never automatically
   replayed because Link documents no idempotency key or replay guarantee; the
   original 401 is returned as `*APIError`. This deliberately overrides the JS
   `apiFetch` behavior. A second GET 401 is returned as `*APIError`.
4. **Bounded tolerant decode**: read at most `MaxResponseBodyBytes` (default
   4 MiB) plus one detection byte; return `ErrResponseTooLarge` when exceeded.
   Attempt JSON parse; non-JSON
   bodies are not a transport error — status handling decides (parity: every
   `rawFetch`, "non-JSON response (e.g., from load balancer)"). Non-JSON and
   arbitrary JSON error bodies are retained for explicit inspection but are
   never copied into implicit error formatting.
5. Network-level failure → `*TransportError` wrapping the cause. Redirects
   are returned and classified as `ErrRedirect`, never followed.

HTTP client resolution (parity with `config.ts:131-140`):
- If `Options.HTTPClient` is set, make a shallow copy and wrap the copy's
  transport — never mutate the caller's `http.Client`. **`LINK_HTTP_PROXY` is
  ignored**, exactly as JS ignores the proxy when `options.fetch` is passed.
- Otherwise build a client whose `Transport` routes through `LINK_HTTP_PROXY`
  when that env var is set (note: this is **not** `HTTP_PROXY`;
  `http.ProxyFromEnvironment` must NOT be used for this — parse the var
  explicitly). No `undici` equivalent needed; `net/http` does this natively.
- `DefaultHeaders` are copied during `NewClient`, then applied by a
  `RoundTripper` wrapper that clones each request and sets a header only if
  the request doesn't already have it (parity: `config.ts:69-82`). Neither
  the caller's map, client, transport, request, nor headers may be mutated.
- Reject default `Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`, `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  and other hop-by-hop headers. The SDK exclusively owns auth, routing, and
  HTTP framing.
- Validate every resolved base URL during `NewClient`: absolute `http` or
  `https`, non-empty host, and no user info, query, or fragment. Plain `http`
  is permitted only for loopback hosts so `httptest.Server` and local
  development work without weakening remote transport security.
- Install a redirect policy on the internal shallow-copied client that always
  returns `http.ErrUseLastResponse`. Never forward bearer/default headers
  across a redirect boundary.
- **No client-level timeout** (JS has none). Cancellation and deadlines are
  the caller's job via `ctx`. Document this on `NewClient`.

Logging: `*slog.Logger` replaces the JS `LinkSdkLogger`. Default when
`Verbose` is true: text handler to stderr at `LevelDebug`; otherwise a
discard handler. `Verbose` gates metadata logs only; secret-bearing values are
never emitted regardless of logger or level.

### 5.5 Auth resource and device flow

Endpoints (parity, `auth.ts`): `POST {authBaseUrl}/device/code`,
`/device/token` (grant `urn:ietf:params:oauth:grant-type:device_code` and
`refresh_token`), `/device/revoke`. All form-encoded
(`application/x-www-form-urlencoded`). `connection_label` is
`fmt.Sprintf("%s on %s", clientName, hostname)` with `os.Hostname()` (on
error, fall back to clientName alone); `client_hint` is clientName.

```go
func (a *AuthResource) InitiateDeviceAuth(ctx context.Context, clientName ...string) (*DeviceAuth, error)
func (a *AuthResource) PollDeviceAuthOnce(ctx context.Context, deviceCode string) (*AuthTokens, error)
func (a *AuthResource) PollDeviceAuth(ctx context.Context, da *DeviceAuth) (*AuthTokens, error)
func (a *AuthResource) ResumeDeviceAuth(ctx context.Context) (*AuthTokens, error)
func (a *AuthResource) RefreshToken(ctx context.Context, refreshToken string) (*AuthTokens, error)
func (a *AuthResource) RevokeToken(ctx context.Context, token string) error
func (a *AuthResource) Logout(ctx context.Context) error
```

- `InitiateDeviceAuth` computes `DeviceAuth.ExpiresAt` (epoch milliseconds)
  immediately and persists a `PendingDeviceAuth`, replacing any older pending
  flow. A single optional non-empty client name preserves the JS per-call
  override without requiring a second options type.
- `PollDeviceAuthOnce` is the single-shot mirror of JS `pollDeviceAuth`.
  Successful polling computes token expiry, persists the tokens, and clears
  pending auth before returning. `authorization_pending` and `slow_down` are
  separate sentinels.
- `PollDeviceAuth` is a Go-side convenience the JS CLI implements externally:
  it loops every `da.Interval` seconds (RFC 8628), adds 5s on `slow_down`,
  stops at `ctx` cancellation or the absolute `da.ExpiresAt` (then returns the
  same "Device code expired" `*APIError`). Using an absolute expiry prevents
  delayed or resumed polling from extending the server-issued lifetime.
- `ResumeDeviceAuth` reconstructs and polls the unexpired flow in storage;
  absence returns `ErrNoPendingDeviceAuth`. This keeps default storage private
  while making the persisted lifecycle usable across process restarts.
- `Logout` reads the SDK-owned persisted tokens, revokes the refresh token,
  and clears all auth state only after successful revocation. On revocation
  failure credentials are retained for retry. Static-token and custom-provider
  configurations are caller-owned and cannot be logged out by the SDK.
- Direct `RefreshToken` and `RevokeToken` calls are low-level exchanges and do
  not mutate storage, even when their argument happens to match the current
  session. This prevents a caller-supplied token from overwriting or clearing
  an unrelated session. Automatic refresh and `Logout` own the corresponding
  persisted transitions.
- Field rename parity: the wire returns `verification_uri` /
  `verification_uri_complete`; JS renames to `verification_url` /
  `verification_url_complete` (`auth.ts:127-134`). Go structs use the
  *renamed* JSON names since `DeviceAuth` is our type, not the wire's — i.e.
  Go's `DeviceAuth` marshals like the JS `DeviceAuthRequest` object.

### 5.6 Storage and the token provider

JS (`utils/storage.ts`): `AuthStorage` interface, `conf`-backed file storage
(0600), `MemoryStorage`, package singleton. Methods can't fail (JS swallows).

Go — same capabilities, error-returning, no singleton:

```go
type AuthStorage interface {
    GetAuth() (*AuthTokens, error)        // (nil, nil) = not authenticated
    SetAuth(*AuthTokens) error            // must compute ExpiresAt if zero (§5.7)
    ClearAuth() error
    GetPendingDeviceAuth() (*PendingDeviceAuth, error) // expired entries cleared + (nil, nil)
    SetPendingDeviceAuth(*PendingDeviceAuth) error
    ClearPendingDeviceAuth() error
    ClearAll() error
    Update(context.Context, func(*AuthStorageState) error) error
}
```

All `AuthStorage` implementations are safe for concurrent use and obey value
semantics: Get methods return defensive copies and Set methods copy their
arguments. In-memory storage must not leak mutable pointers around its mutex.
`Update` is the atomic session primitive: it locks the complete snapshot,
passes defensive copies to the callback, and commits the complete result only
when the callback and context succeed. Persistent custom stores must hold the
same transaction/lock across processes through durable commit. Callbacks must
not call back into the same storage.

`Path() string` and `Delete() error` are **not** part of the interface — they
are file-storage concerns, so they live as concrete methods on `*FileStorage`
only (`Delete` treats a missing file as success, parity `storage.ts:133-139`).
The JS interface fakes them for `MemoryStorage` (`getPath()` returns the
string `"memory"`, `deleteConfig()` no-ops, `storage.ts:188-194`) — that wart
is not ported. Callers holding the interface who need the path can type-assert
to `*FileStorage`.

`FileStorage`:
- Default path: `os.UserConfigDir()/stripelink/auth.json`; constructor accepts
  an explicit path override (mirrors `StorageOptions.configPath`). The SDK
  does not discover, import, or migrate link-cli's platform-specific default
  file. Schema compatibility permits an explicitly configured shared path,
  subject to the writer-coordination limitation below.
- **File format is byte-compatible with the JS CLI's `conf` file**:
  `{"auth": {...}|null, "pendingDeviceAuth": {...}|null}` — so pointing the Go
  SDK at an existing `link-cli` auth file works. `expires_at` is epoch
  **milliseconds** (parity: `storage.ts:35`).
- Mode `0600` enforced on create *and* on every write (`storage.ts:45` and the
  comment above it explain why: tokens + raceable device_code).
- Reads are bounded at 1 MiB and oversized files return `ErrStorageTooLarge`.
- Writes use an owner-only temp file in the same directory, sync it, close it,
  and rename it. Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD
  then fsync the parent directory. Other platforms have no portable directory
  fsync, so the replacement file is synced but power-loss durability of the
  renamed directory entry is not guaranteed. Never expose caller-owned or
  storage-owned pointer aliases.

`tokens.go` ships the storage-backed `AccessTokenFunc` that `NewClient` wires
by default when neither `AccessToken` nor `GetAccessToken` is set but storage
has tokens. It returns the stored access token while valid, and on
`forceRefresh` (or expiry, using `expires_at` minus a small skew) calls
`Auth.RefreshToken` and persists the result. This logic lives in the CLI in
JS-land; the README promises "tokens are refreshed transparently", so in Go it
is part of the SDK. **It must be generation-aware and single-flight** (§7).
On a forced refresh it compares `AccessTokenRequest.RejectedToken` with the
current stored access token before joining or starting a refresh. If they
differ, it returns the current token without refreshing.

### 5.7 Wire types and JSON

General rules (`types.go`):
- Field names CamelCase, json tags snake_case, matching `types/index.ts`
  exactly. Amounts are `int64` (cents). Counts like `exp_month` are `int`.
- **Request params**: every optional scalar is a pointer. `nil` means omitted;
  a non-nil pointer preserves explicit `false`, `0`, and `""`. Optional slices
  use `omitzero`: nil means omitted and a non-nil empty slice means an explicit
  empty array. Do not use value scalars with `omitzero` where presence is part
  of the API contract. The serialized body must omit unset fields exactly as
  `JSON.stringify` drops `undefined` — the JS tests assert exact bodies.
  `CreateSpendRequestParams.Approve` maps to routing, not the body: when true,
  POST to `/spend_requests/create_delegated` and **strip the field from the
  payload** (`spend-request.ts:175-178`) → tag it `json:"-"`.
- **Response fields**: value types where absence ≡ zero; pointers where the
  wire is explicitly nullable and callers must distinguish (`UserInfo` fields,
  `PaymentStatusDetails`, `ShippingAddress` fields — all `| null` in TS).
- **Enums**: `type SpendRequestStatus string` + constants for the eight known
  values (`types/index.ts:58-66`). **Never validate or reject unknown values**
  — the JS test fixtures themselves use `status: "pending"`, which is not in
  the TS union (`spend-request.test.ts:39`). Forward compatibility is pinned
  behaviour, not an accident.
- **Timestamps stay `string`.** The JS SDK never parses `created_at` /
  `updated_at` / `valid_until` — they are opaque pass-through (and
  `valid_until`'s exact format is unverified). The single exception, exactly
  as in JS: `WebBotAuthBlock.ExpiresAt` is parsed internally for the cache
  (`web-bot-auth.ts:176-181`), and an unparseable value is an error with the
  same message. `AuthTokens.ExpiresAt` is epoch-ms `int64` (§5.6).
- **`shared_payment_token` union**: the wire sends either a plain string (old
  API) or an object (new API). Implement `UnmarshalJSON` on
  `SharedPaymentToken` to accept both, normalizing a string `s` to `{ID: s}`
  (parity: `normalizeSpendRequest`, `spend-request.ts:30-39`). This replaces
  the JS post-processing step entirely.
- **List envelopes**: list endpoints return `{"data": [...]}`; unwrap
  internally; a missing/null `data` yields an empty, **non-nil** slice
  (parity: `spend-request.ts:163-165`).
- `UserInfo`: JS coerces absent fields to explicit `null`
  (`user-info.ts:117-124`); Go pointer fields are simply nil — equivalent.

### 5.8 Per-resource specifics

| Resource | Endpoint (parity source) | Notes |
|---|---|---|
| SpendRequests | `{spendRequestBaseUrl}/spend_requests` | `Retrieve` takes `include []string` joined with `,` as the `include` query param (`spend-request.ts:268-271`); update is `POST /{id}`, cancel `POST /{id}/cancel`, approval `POST /{id}/request_approval` |
| PaymentMethods | `{apiBaseUrl}/payment-details` | note the hyphen — not `payment_methods` |
| ShippingAddresses | `{apiBaseUrl}/shipping_addresses` (`shipping-address.ts:31`) | list unwraps the `shipping_addresses` envelope key; missing → empty non-nil slice (`shipping-address.ts:122-125`) |
| UserInfo | `{apiBaseUrl}/userinfo` (`user-info.ts:31`) | explicit-null mapping (§5.7) |
| WebBotAuth | `{apiBaseUrl}/web_bot_auth/sign` | cache keyed by `url.Hostname()`; 30s expiry buffer (`EXPIRY_BUFFER_MS`); invalid URL wraps `ErrInvalidArgument` with message `"Invalid URL: <url>"`; missing `web_bot_auth` block in response → error (`web-bot-auth.ts:136-186`) |
| Reports | `{apiBaseUrl}/agent_observations` (`report.ts:33`) | `ReportOutcome` / `ReportTag` constants from `interfaces.ts:98-117` |

Where this table says "check during port": read the JS file, mirror it, and
add the endpoint here.

## 6. Behavioural parity contract

### 6.1 Must match the JS SDK byte-for-byte
- URLs, HTTP methods, query strings, content types, form/JSON bodies
  (modulo JSON key order).
- Default base URLs, env var names and precedence (`LINK_AUTH_BASE_URL`,
  `LINK_API_BASE_URL`, `LINK_HTTP_PROXY`).
  (`LINK_ACCESS_TOKEN`, `LINK_AUTH_FILE`, `LINK_NO_REFRESH` are **CLI**-level
  in JS — not the SDK's job; do not read them here.)
- Status-code handling: 2xx success window, generation-aware
  401-refresh-retry-once for safe reads only, no automatic mutation replay,
  404→not-found on retrieve, 400+OAuth-error dispatch in the device flow.
- Metadata-only verbose logs that never contain bodies or header values.
- Error **operation templates** remain recognizable — e.g.
  `Failed to create spend request (%d): %s`,
  `Device code expired. Please restart the login flow.`,
  `Authorization denied by user.`. These are pinned by the JS tests and keep
  cross-SDK conformance checkable. Server-controlled detail inserted into a
  template is bounded and credential-redacted; unstructured bodies use a
  generic diagnostic. This financial-data safety rule takes precedence over
  byte-for-byte upstream error text.
- The auth-file JSON schema (§5.6).

### 6.2 Deliberate deviations (complete list — add here, nowhere else)
1. `Retrieve` 404 → `(nil, ErrNotFound)` instead of `null`.
2. Single-shot poll returns distinct `ErrAuthorizationPending` and
   `ErrSlowDown` instead of `null`.
3. Dual method aliases not ported.
4. Resource interfaces not exported.
5. Config resolved once per client, not per resource.
6. One shared transport core instead of six divergent copies.
7. Storage methods return errors; no package-level singleton; `Path`/`Delete`
   are `*FileStorage`-only methods, dropped from the `AuthStorage` interface.
8. Storage-backed auto-refresh token provider is part of the SDK (in JS it
   lives in the CLI).
9. Blocking `PollDeviceAuth` helper added (JS CLI loops externally).
10. `slog` instead of the custom one-method logger interface.
11. Default `ClientName` is `"github.com/mackross/stripelink"` (JS defaults to
    `"Link CLI"`). Still configurable via `Options.ClientName`; it feeds the
    `connection_label` / `client_hint` shown in the user's Link app (§5.5), so
    a Go client should not masquerade as the JS CLI.
12. No generic JS-style base error class. Go sentinels classify local
    conditions; `APIError` and `TransportError` carry structured details.
13. Verbose logging is metadata-only. The JS SDK logs bodies and header values;
    Go never does because financial credentials and tokens can appear in both.
14. Device authorization has a cohesive persisted lifecycle: initiation saves
    the pending flow, successful polling saves tokens and clears pending state,
    and `Logout` revokes then clears SDK-owned credentials.
15. `DeviceAuth.ExpiresAt` is added and drives blocking/resumed poll expiry.
16. `AccessTokenFunc` receives the token rejected by a 401, enabling
    generation-aware refresh under concurrency.
17. Custom storage is required to provide defensive-copy value semantics.
18. Mutation POSTs are not replayed after 401 because Link has no documented
    idempotency guarantee. The JS SDK retries every operation.
19. HTTP responses and auth-file reads are bounded; the JS SDK reads them
    without an explicit limit.
20. Base URLs, redirects, and default headers are constrained to prevent
    bearer-token disclosure and HTTP routing/framing confusion.
21. API/transport errors retain explicit structured fields for inspection, but
    implicit `Error`, `String`, `GoString`, and `fmt.Formatter` output is
    bounded and credential-safe. Unstructured bodies are not echoed into error
    strings.

### 6.3 JS warts that must NOT be ported
- The `rawFetch`/`apiFetch` copy-paste (and its per-copy divergence).
- The `undici` dynamic-import proxy dance — `net/http` handles proxies.
- Lazily-thrown configuration errors where up-front validation is possible.
- `getPath()`/`deleteConfig()` on the storage *interface*. They are
  file-storage-specific (MemoryStorage fakes them with `"memory"` / a no-op);
  in Go they exist only on `*FileStorage`, as `Path()`/`Delete()`.

## 7. Concurrency (Go-only concerns — JS was single-threaded)

The JS SDK never had to think about races. The Go SDK is presumed to be used
from many goroutines. Required:

1. **Generation-aware single-flight token refresh.** Under concurrent 401s,
   exactly one `RefreshToken` call happens; the others wait and reuse its
   result. Before starting or joining refresh, compare the rejected token with
   current storage: a mismatch means rotation already completed. Refresh
   tokens may be single-use server-side — a duplicate refresh can invalidate
   the session. Hand-roll with `sync.Mutex` + in-flight result sharing; no
   `x/sync` dependency. The goroutine that starts the network refresh owns its
   context. Waiters select on their own context and the shared completion;
   canceling a waiter never cancels the shared refresh.
2. **Web-bot-auth cache** is `sync.Mutex`-guarded; concurrent `SignURL` calls
   for the same authority must single-flight with independent waiter
   cancellation and initiator-owned network context.
3. **`FileStorage`** serializes operations with a mutex, writes atomically
   (§5.6), and uses an owner-only companion lock file for advisory
   cross-process coordination on platforms where the standard library exposes
   file locking (Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD).
   This prevents lost scoped auth/pending updates between cooperating Go
   processes. Other platforms retain per-instance synchronization and sync the
   replacement file, but have no portable cross-process lock or directory
   fsync. The JS `conf` library does not
   honor this lock, so concurrent writes from link-cli remain an external
   limitation rather than a guarantee the Go SDK can provide unilaterally.
4. The `Client` and every resource are safe for concurrent use; document this
   on the `Client` type.
5. Everything above is exercised by `-race` tests (§8).

## 8. Testing requirements

The upstream Vitest suite is source material, not a requirement to preserve
every duplicated or unsafe implementation detail. `CONFORMANCE.md` is the
executable acceptance contract: each of its 73 IDs maps to one or more named
Go tests, and a row becomes `DONE` only when all of its observable behavior is
proved under the race detector. Conventions:

- Fake the HTTP boundary with an injected `http.RoundTripper` (the analogue of
  the stubbed `fetch`) for request-shape assertions: exact URL, method,
  headers, body. Use `httptest.Server` for integration-style flows
  (device-auth poll loop, 401-refresh-retry).
- Table-driven where the JS tests enumerate cases (status codes, OAuth error
  dispatch, error-message extraction precedence).
- `testing/synctest` for everything time-based: token `expires_at` skew,
  pending-device-auth expiry, web-bot-auth 30s buffer, poll intervals and
  `slow_down` backoff. No real sleeps anywhere in the suite.
- `t.TempDir()` for `FileStorage`; assert mode bits are 0600; assert the JSON
  file round-trips a fixture captured from the real JS CLI file format.
- Concurrency tests under `-race`: N goroutines hitting a 401-then-200 server
  must produce exactly one refresh call; concurrent `SignURL` for one host
  must produce at most one sign request per expiry window.
- Fuzz shared-payment-token decoding, API-error decoding, merchant/base URL
  handling, and storage-state decoding. Seed each documented wire form and
  every known malformed top-level shape.
- Keep `CONFORMANCE.md`'s evidence column current. "Done" means the named
  test proves the whole row and passes under `go test -race`; partial evidence
  is recorded but remains `PENDING`.

## 9. Quality gates (all must pass)

The supported release toolchain is patched Go 1.26.5. Go 1.26.1 is prohibited
because govulncheck found nine reachable standard-library vulnerabilities that
are fixed through 1.26.5. The authoritative
commands, platform matrix, scanner requirements, and evidence format are in
`RELEASE.md`. At minimum they include formatting, vet, a no-diff `go fix`,
examples, all tests, repeated race runs, every fuzz target, `staticcheck`,
`govulncheck`, dependency inspection, and `go doc`.

README flows must have equivalent compiling, offline `Example*` tests, and the
§6.2 deviation list must still match reality.

## 10. Resolved release-policy decisions

These choices close the eight policy blockers from the original acceptance
contract. Changing one requires a maintainer decision, updated tests and docs,
and a fresh security review.

1. **Credential path and migration:** the default is exactly
   `os.UserConfigDir()/stripelink/auth.json`. There is no automatic CLI-path
   search or migration. An explicit `NewFileStorage(path)` is required to use
   another known file.
2. **Refresh and revoke storage semantics:** direct `RefreshToken` and
   `RevokeToken` calls do not mutate storage. The automatic token provider
   persists a complete successful refresh before use. `Logout` revokes the
   persisted refresh token and clears all persisted state only after successful
   revocation; failure retains the session.
3. **Optional field shape:** optional request scalars use pointers and optional
   slices preserve nil versus non-nil empty. Spend creation requires non-empty
   `PaymentDetails` and `Context`; spend IDs and nested item/total structure
   are checked locally. Report values are encoded faithfully and changeable
   report business rules remain server-owned. Unknown string-enum values
   remain accepted.
4. **Storage locking and directory durability:** Darwin, DragonFly BSD,
   FreeBSD, Linux, NetBSD, and OpenBSD use an owner-only advisory `flock`
   companion file and directory fsync. Other platforms have per-instance
   locking and a synced replacement file, but no portable cross-process lock
   or directory fsync. link-cli ignores the Go lock, so cross-language
   concurrent writers are unsupported everywhere.
5. **Read limits:** all HTTP bodies default to a 4 MiB maximum, configurable by
   `Options.MaxResponseBodyBytes`; credential files have a fixed 1 MiB maximum.
   Each reader consumes at most one extra byte to detect overflow.
6. **Error hierarchy:** there is no generic public SDK base error. Exported
   sentinels support `errors.Is`; `*APIError` and `*TransportError` support
   structured inspection, and `TransportError.Unwrap` preserves its cause.
7. **Input validation:** validate structural and transport-safety invariants
   locally, including contexts, required identifiers/fields, URL shape,
   control characters, and required successful response structure. Do not
   duplicate changeable server business rules or reject unknown enum values.
8. **Toolchain and security tooling:** Go 1.26.5 is the security minimum and
   exact initial CI target. Linux, macOS, and Windows form the minimum CI matrix with the
   FileStorage limitations in `RELEASE.md`. Formatting, vet, no-diff `go fix`,
   repeated race runs, all fuzz targets, staticcheck, govulncheck, dependency
   inspection, examples, and package docs are release gates; exact tool
   versions and results are recorded per release.

## 11. Open questions — verify during the port, then resolve in this file

1. `valid_until` wire format (ISO date? datetime?) — capture a fixture from
   the JS tests or CLI; until then it stays an opaque string.
2. ~~Exact endpoints for ShippingAddresses / UserInfo / Reports.~~
   **Resolved (skeleton phase, 2026-06-12):** verified against
   `shipping-address.ts:31` (`/shipping_addresses`), `user-info.ts:31`
   (`/userinfo`), `report.ts:33` (`/agent_observations`); §5.8 table updated.
3. Whether `refresh_token` rotation is in the token response of every refresh
   (JS assumes yes — `auth.ts:233-239` always stores the new one).
4. ~~Refresh-skew policy.~~ **Resolved:** mirror
   `packages/cli/src/auth/session.ts`: refresh when current time reaches
   `expires_at - 60s`, as well as after a 401.
5. ~~Generic error hierarchy.~~ **Resolved:** no generic `Error`; use
   sentinels plus concrete `APIError` and `TransportError` (§5.3).
6. ~~Retrieve include shape.~~ **Resolved:** keep idiomatic variadic
   `Retrieve(ctx, id, include ...string)`; README updated.
7. ~~Per-call client-name override.~~ **Resolved:** preserve it as the optional
   variadic argument to `InitiateDeviceAuth` (§5.5).
8. ~~User-info error-extraction divergence.~~ **Resolved:** treat it as a JS
   copy/paste wart and use the full shared precedence in §5.3.
9. ~~Transport error code.~~ **Resolved:** `TransportError.Code` is always
   `"transport_error"`; there is no generic base error match.
10. ~~Explicit `expires_at: 0`.~~ **Resolved:** Go treats zero as absent and
    computes expiry. Epoch zero is not a meaningful valid token expiry.
