# Go SDK behavioral contract

This document is the executable acceptance contract for the Go SDK. It replaces
the former 555-row parity inventory, which duplicated cases, contradicted itself,
and treated TypeScript implementation details as requirements.

The TypeScript SDK remains the primary source for endpoint paths, wire names,
response envelopes, and established error messages. It is not authoritative
where copying it would weaken credential safety, concurrency, cancellation, or
idiomatic Go behavior. Those deviations are explicit below.

## How to use this contract

- Each row names its concrete automated evidence. A table-driven test may cover
  several rows, but evidence must prove the entire observable behavior.
- Mark a row `DONE` only after its named tests pass under `go test -race ./...`.
  Partial evidence is recorded in the table but remains `PENDING`.
- Test through exported APIs unless the behavior (for example token refresh
  coalescing) cannot be observed reliably that way. Do not pin private fields,
  helper names, lock layout, log formatting, or JSON implementation choices.
- Use deterministic clocks/sleep hooks in tests that exercise expiry or polling;
  wall-clock sleeps are not acceptable.
- Network tests use local transports/servers and must assert the request that the
  server actually received. No test may contact Link production services.
- A release requires every row to be `DONE`, every release blocker below to be
  resolved, and the production-readiness gates at the end to pass.

Status values are `PENDING`, `DONE`, or `WAIVED: <recorded reason and approver>`.

## Source notation

- `TS config`, `TS auth`, and so on refer to files under
  `link-cli/packages/sdk/src/`.
- `TS test:<name>` refers to the corresponding Vitest file under
  `resources/__tests__/` (or `utils/__tests__/`).
- `Go safety` is an intentional Go or financial-credential safety requirement
  without an upstream TypeScript equivalent.
- RFC 8628 is the OAuth 2.0 Device Authorization Grant.

## Slice 1 — construct a client and resolve configuration

This slice is complete when a client can be constructed without I/O and every
resource is wired to one consistently resolved configuration.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| CFG-01 | `NewClient(Options{})` succeeds without network access, exposes non-nil Auth, SpendRequests, PaymentMethods, ShippingAddresses, UserInfo, WebBotAuth, and Reports resources, and applies no client-level timeout. | TS `client.ts`; Go safety | `TestNewClientZeroOptions` | DONE |
| CFG-02 | Auth/API base URLs resolve once at construction with precedence option > environment > documented default. SpendRequestBaseURL defaults to the resolved APIBaseURL and, when explicitly set, affects only spend-request calls. Later environment changes do not affect an existing client. | TS `config.ts:118-131`; `spend-request.ts` | `TestNewClientResolvesConfigurationOnce`; `TestSpendRequestsCreateOmitsZeroValuesWithoutMutatingInput`; `TestSpendRequestsCreateDelegatedRouting`; `TestPaymentMethodsListEndpointEnvelopeAndForwardCompatibility` | DONE |
| CFG-03 | Invalid base URLs are rejected by `NewClient` before any request. Accepted bases are normalized so one path separator is produced regardless of a trailing slash. User-provided path segments and query values are escaped rather than concatenated. | Go safety (deliberate deviation) | `TestNewClientRejectsUnsafeBaseURLs`; `TestNewClientPreservesEscapedBasePathSegments`; `TestSpendRequestsUpdateEscapesIDAndPreservesPresence`; `TestSpendRequestsRetrieveIncludesNotFoundAndReadRetry` | DONE |
| CFG-04 | Token-source precedence is GetAccessToken > static AccessToken > AuthStorage-backed provider. With none usable, construction succeeds and the first authenticated call returns an error matching `ErrNotAuthenticated` without issuing HTTP. | TS `config.ts:108-117`; Go session extension | `TestNewClientTokenSourcePrecedence`; `TestNewClientTokenSourceCompletePrecedenceAndLazyFailure`; `TestTokenProviderFreshExpiredAndMissing` | DONE |
| CFG-05 | DefaultHeaders apply at the shared transport boundary, including auth requests, without replacing a header already set by the SDK/request; matching is case-insensitive. Caller maps and requests are not mutated. Credential/routing/framing headers are rejected. | TS `config.ts:69-82`; `config.test.ts`; Go safety | `TestNewClientClonesCallerConfiguration`; `TestNewClientRejectsReservedAndMalformedDefaultHeaders` | DONE |
| CFG-06 | A supplied `*http.Client` remains caller-owned: its timeout, transport, jar, and other fields are preserved and the SDK does not mutate it. The SDK shallow-copies it, then deliberately replaces the copy's redirect policy with refusal. Without a supplied client, `LINK_HTTP_PROXY` is captured at construction and used by the default transport. | TS `config.ts:47-67`; Go safety deviation | `TestNewClientClonesCallerConfiguration`; `TestNewClientCapturesLinkHTTPProxyOnlyForDefaultClient`; `TestCoreDoRefusesRedirectWithoutFollowing` | DONE |
| CFG-07 | A Client and every resource may be used concurrently; a representative mixed-resource workload completes under `go test -race` without corruption, races, or deadlock. | Go safety | `TestClientMixedResourceConcurrentUse`; `TestClientCancellationDrainsAllResourceWork`; `TestSpendRequestsConcurrentUse`; token/storage/web-bot concurrency tests | DONE |

## Slice 2 — one authenticated HTTP exchange

This slice establishes the shared transport and error contract used by every
resource.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| HTTP-01 | An authenticated call obtains a token once, sends `Authorization: Bearer <token>`, preserves endpoint-specific method/body/content type, accepts the 2xx range, and does not retry a successful response. | TS resource `apiFetch` implementations | `TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware`; `TestDoJSONStatusAndDecode`; `TestAuthRefreshRevokeAndLogout` | DONE |
| HTTP-02 | A network/DNS/TLS/redirect/context failure returns `*TransportError` containing method and URL; `errors.Is`/`errors.As` reach the original cause. It is never retried automatically. | TS `LinkTransportError`; Go contexts | `TestCoreDoWrapsNetworkAndContextErrors`; `TestCoreDoRefusesRedirectWithoutFollowing`; `TestTransportErrorPreservesCause` | DONE |
| HTTP-03 | Caller cancellation and deadlines promptly abort ordinary HTTP attempts and token waits. A started automatic refresh continues under a bounded internal context so remote rotation can be persisted even after all callers stop waiting. | Go safety | `TestCoreDoWrapsNetworkAndContextErrors`; `TestAuthPollCancellationPreservesPending`; `TestTokenProviderWaiterCancellationDoesNotCancelSharedRefresh`; `TestTokenProviderFinalCancellationStillPersistsSuccessfulRotation` | DONE |
| HTTP-04 | A non-2xx response returns `*APIError` with status, bounded raw body, parsed JSON details when valid, and a credential-safe bounded operation message. Structured nested/string messages are redacted; unstructured bodies use a generic diagnostic and remain available only through explicit fields. | TS `errors.ts`; Go financial-safety deviation | `TestDoJSONStatusAndDecode`; `TestSpendRequestsAPIErrorContract`; `TestExtractAPIErrorMessageRedactsCredentialFieldsAndBoundsDiagnostics`; `TestAPIErrorFormattingNeverExposesResponseCredentials` | DONE |
| HTTP-05 | A non-JSON error body is preserved in `APIError.RawBody` but is not implicitly echoed; malformed JSON never hides the HTTP status. A 2xx response requiring a body must contain valid JSON of the expected top-level shape or return a non-API decode error rather than fabricated zero values. | TS resource tests; Go safety deviations | `TestDoJSONStatusAndDecode`; `TestExtractAPIErrorMessageRedactsCredentialFieldsAndBoundsDiagnostics`; `TestSpendRequestsRejectMalformedSuccessfulResponses`; `TestPaymentMethodsListRejectsMalformedSuccess`; `TestShippingAddressesListRejectsMalformedSuccess`; `TestUserInfoRetrieveRejectsMalformedSuccess`; `TestReportsCreateAPIAndMalformedSuccessErrors` | DONE |
| HTTP-06 | Response bodies are always closed, including decode failures, non-2xx responses and both attempts of a safe-read 401 retry. | Go resource safety | `TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware`; `TestCoreDoBoundsAndClosesResponse`; `TestDoJSONStatusAndDecode` | DONE |
| HTTP-07 | Verbose logging contains useful request method, sanitized endpoint identity, status, and timing, but never bearer/refresh/device tokens, card number/CVC, shared or Link payment tokens, signature material, cookies, bodies, or URL query/fragment values. The rule applies to custom loggers. | Go financial safety (deviation from raw-body TS logging) | `TestCoreDoVerboseLogsMetadataOnly`; `TestReadResourcesVerboseLogsNeverContainResponsePII`; `TestReportsCreateVerboseLogsNeverContainPIIOrCredentials`; `TestWebBotAuthSignURLVerboseLogsAreMetadataOnly` | DONE |
| HTTP-08 | Non-verbose mode emits no SDK request/response logs. Enabling logging does not change request or response semantics. | TS verbose option; Go safety | `TestCoreDoNonVerboseDoesNotLog`; `TestCoreDoVerboseLogsMetadataOnly` | DONE |

## Slice 3 — authenticate and persist a session

This slice is complete when device authentication produces a durable session
usable by a subsequent authenticated resource call.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| AUTH-01 | InitiateDeviceAuth sends one unauthenticated form POST to `{AuthBaseURL}/device/code` with the fixed client ID/scope and documented client hint/connection label. It maps `verification_uri(_complete)` and captures an absolute device-code expiry. | TS `auth.ts:102-134`; RFC 8628; Go polling extension | `TestAuthInitiatePersistsAbsoluteExpiry` | DONE |
| AUTH-02 | A successful initiation persists a resumable PendingDeviceAuth containing the device code, interval, absolute expiry, verification URL, and phrase. Failed or superseded overlapping initiations preserve the previous resumable flow. If persistence fails, initiation returns that failure. | TS CLI storage flow; Go cohesive-session deviation | `TestAuthInitiatePersistsAbsoluteExpiry`; `TestAuthConcurrentInitiationFailuresPreservePreviousPendingFlow`; `TestAuthStorageFailuresNeverClaimSuccess` | DONE |
| AUTH-03 | PollDeviceAuthOnce sends exactly one unauthenticated device-code form POST. On success it returns all token fields, atomically persists them before success, and clears only the matching still-current pending authorization. An existing flow remains active until a replacement initiation commits. | TS `auth.ts:137-155`; Go cohesive-session deviation | `TestAuthPollOnceClassifiesAndPersists`; `TestAuthPollTerminalClearsOnlyMatchingPending`; `TestAuthExistingPollMayFinishUntilNewFlowCommits` | DONE |
| AUTH-04 | If saving successful poll tokens fails, the call returns an error without exposing success or partially replacing stored credentials. | Go financial safety | `TestAuthStorageFailuresNeverClaimSuccess` | DONE |
| AUTH-05 | `authorization_pending` and `slow_down` are distinguishable; both match `ErrAuthorizationPending`, slow_down also matches `ErrSlowDown`, and only slow_down adds five seconds to subsequent intervals. Neither is an `APIError`. | TS `auth.ts:157-162`; RFC 8628; deliberate Go deviation | `TestAuthPollOnceClassifiesAndPersists`; `TestAuthPollUsesAbsoluteExpiryAndCumulativeSlowDown` | DONE |
| AUTH-06 | Server `expired_token` and `access_denied` become `*APIError` with established codes/messages; other failures preserve bounded response information. Terminal outcomes clear only the matching pending authorization. | TS `auth.ts:163-186`; `auth.test.ts` | `TestAuthPollTerminalClearsOnlyMatchingPending`; `TestDoJSONStatusAndDecode` | DONE |
| AUTH-07 | PollDeviceAuth uses the initiated absolute expiry, observes the initial interval, applies cumulative slow_down increments, stops at expiry without an extra request, and returns the same expired-token classification as the server. | RFC 8628; Go polling convenience | `TestAuthPollUsesAbsoluteExpiryAndCumulativeSlowDown`; `TestAuthResumeUsesPersistedAbsoluteExpiry` | DONE |
| AUTH-08 | Canceling PollDeviceAuth stops promptly, preserves the pending authorization for resume, and returns the context cause without persisting partial tokens. | Go contexts/session safety | `TestAuthPollCancellationPreservesPending` | DONE |
| AUTH-09 | RefreshToken and RevokeToken send one unauthenticated form POST to the documented endpoints, accept the 2xx range, and return structured auth errors otherwise. Direct calls do not mutate storage. Logout clears after successful or already-completed revocation and retains state on other failures. | TS `auth.ts:189-240`; Go session policy | `TestAuthRefreshRevokeAndLogout`; `TestAuthLogoutFailureRetainsSession`; `TestAuthLogoutClearsAlreadyInvalidTokenAndIgnoresPostRevokeCancellation` | DONE |
| AUTH-10 | Auth endpoint transport failures and malformed required 2xx JSON return explicit errors and do not alter stored auth or pending state. Auth endpoints never enter bearer 401-refresh-retry logic. | TS auth transport; Go safety | `TestAuthTransportAndMalformedSuccessPreserveSessionAndNeverBearerRetry`; `TestAuthRejectsMalformedSuccessWithoutMutatingStorage` | DONE |
| AUTH-11 | Device codes, refresh tokens, token bodies, and full verification URLs are absent from verbose logs and implicit error/value formatting. Hostname failure uses the documented fallback connection label. | TS redaction; Go safety | `TestDeviceFlowVerboseLogsMetadataOnlyAndHostnameFailureFallsBack`; `TestAuthNilContextsAndCredentialSafeErrors`; `TestAuthValueFormattingRedactsCredentials`; `TestPendingDeviceAuthFormattingRedactsCredentials`; `TestClientConfigurationFormattingRedactsCredentials` | DONE |
| AUTH-12 | Initiate -> pending poll -> successful poll -> newly constructed client using the same storage -> authenticated API call works without manually transferring a token. | Go cohesive-session acceptance | `TestAuthPersistedSessionWorksWithNewClient`; `ExampleClient_deviceAuthentication` | DONE |

## Slice 4 — credential storage survives real failures

The same semantic tests must run against MemoryStorage and FileStorage where
applicable.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| STORE-01 | `Transact` computes ExpiresAt from ExpiresIn only when absent, preserves explicit ExpiresAt, rejects invalid state without mutation, and does not retain caller aliases. | TS `storage.ts:35-40`; Go safety | `TestAuthStorageValueSemantics`; `TestAuthStorageRejectsInvalidInputWithoutMutation` | DONE |
| STORE-02 | `Load` returns a defensive complete-state snapshot; `Transact` commits a complete snapshot atomically and concurrent readers/writers are race-free. | Go safety deviation | `TestAuthStorageValueSemantics`; `TestAuthStorageTransactIsAtomicAndContextAware`; `TestMemoryStorageConcurrentAccess`; `TestFileStorageCoordinatesConcurrentAccess` | DONE |
| STORE-03 | Storage preserves pending-flow state exactly, including expired state; `ResumeDeviceAuth` atomically removes an expired pending flow. Auth expiry does not erase refresh credentials before refresh handling. | TS `storage.ts:107-115`; explicit storage/auth boundary | `TestAuthStorageValueSemantics`; `TestAuthResumeUsesPersistedAbsoluteExpiry`; `TestTokenProviderFreshExpiredAndMissing` | DONE |
| STORE-04 | `Clear` removes the complete stored state and is idempotent; field-specific auth transitions use `Transact`. MemoryStorage's zero value is usable. | TS `storage.ts`; Go zero-value convention | `TestAuthStorageClearOperations`; `TestMemoryStorageConcurrentAccess` | DONE |
| STORE-05 | FileStorage reads/writes the TypeScript schema and epoch-millisecond expiries. An explicitly configured compatible file can be consumed without losing unknown top-level state; no automatic CLI-path migration occurs. | TS `storage.ts`; interoperability and resolved path policy | `TestFileStorageSchemaPermissionsAndUnknownState` | DONE |
| STORE-06 | Credential files are maintained at `0600` and SDK-created parent directories are owner-only on permission-capable platforms. A pre-existing broad file is tightened before credentials are exposed. | TS `storage.ts:44-50`; financial safety | `TestFileStorageSchemaPermissionsAndUnknownState` | DONE |
| STORE-07 | Writes are atomic and durable enough that failed encode/write/file-sync/close/rename operations leave the last valid file readable; directory-sync failure reports that replacement may already be committed. Temporary files are owner-only and unusable remnants are removed. Directory fsync is guaranteed only on supported Unix platforms. | Go financial safety; platform durability boundary | `TestFileStorageAtomicWriteFaultBoundaries`; `TestFileStorageFailedWritePreservesLastValidState` | DONE |
| STORE-08 | Missing files mean empty storage. Malformed/oversized JSON, unreadable paths, wrong object types, directories, devices, FIFOs, and symlinks return explicit errors and are not overwritten. Device/FIFO and permission tests run only on supported Unix platforms. | Go financial safety deviation; platform boundary | `TestFileStorageRejectsUnsafeOrInvalidFiles`; `TestFileStorageRejectsDeviceAndFIFOWithoutOpening`; `TestFileStorageReportsUnreadablePath`; `TestFileStorageMissingAndDeleteAreIdempotent`; `FuzzStorageStateDecode` | DONE |
| STORE-09 | File operations are safe for concurrent goroutines and cooperating Go processes on Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD and do not lose independent auth/pending updates. Other platforms provide per-instance synchronization and a synced replacement file but no portable cross-process lock or directory fsync; link-cli does not honor the Go lock. Delete is context-aware and idempotent, and Path reports only the configured path. | TS delete behavior; resolved platform policy | `TestFileStorageCoordinatesInstances`; `TestFileStorageCoordinatesProcesses`; `TestFileStorageTransactCoordinatesProcesses`; `TestFileStorageMissingAndDeleteAreIdempotent`; `TestFileStorageDeleteHonorsCancellationWhileWaitingForLock`; `TestFileStorageSchemaPermissionsAndUnknownState` | DONE |
| STORE-10 | The default path is exactly `os.UserConfigDir()/stripelink/auth.json`, with no automatic CLI discovery/migration. A zero-option client reads only an overridden test config root and never touches developer credentials. | Go configuration safety | `TestNewFileStorageDefaultPath`; `TestZeroOptionClientReadsExactDefaultPath`; `TestNewClientZeroOptions` | DONE |

## Slice 5 — refresh safely under concurrency

Refresh tokens can rotate and may be single-use. These behaviors are release
blocking.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| TOKEN-01 | The storage provider returns a sufficiently fresh access token without network I/O, proactively refreshes at the 60-second skew using the stored refresh token, and returns ErrNotAuthenticated when no usable session exists. | TS CLI auth provider; Go session extension | `TestTokenProviderFreshExpiredAndMissing` | DONE |
| TOKEN-02 | A successful automatic refresh persists the complete returned token set before a waiting request can use the new access token. Rotated refresh tokens are not merged with stale fields. | Go financial safety | `TestTokenProviderFreshExpiredAndMissing`; `TestTokenProviderRefreshIsSingleFlightAndGenerationAware` | DONE |
| TOKEN-03 | Concurrent callers of one token provider cause exactly one refresh call and all live waiters receive the result. Independent Clients may refresh concurrently but atomically converge on the committed storage generation. | Go single-flight extension; explicit service-ownership boundary | `TestTokenProviderRefreshIsSingleFlightAndGenerationAware`; `TestTokenProviderConcurrentClientsConvergeOnStoredGeneration` | DONE |
| TOKEN-04 | Refresh is generation-aware: a 401 requests refresh only if the rejected token is still current; a delayed old-generation 401 reuses the rotated token. | Go financial/concurrency safety | `TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware`; `TestTokenProviderRefreshIsSingleFlightAndGenerationAware` | DONE |
| TOKEN-05 | After a 401, only an authenticated safe GET retries once with the current/refreshed token; a second 401 is returned as APIError. Mutation POSTs never replay. Static-token mode cannot invoke OAuth refresh. | TS read behavior; Go no-mutation-replay safety deviation | `TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware`; `TestCoreDoReturnsSecondUnauthorizedWithoutThirdTokenCall`; `TestCoreDoNeverReplaysMutation`; resource mutation tests | DONE |
| TOKEN-06 | A refresh failure is shared with current waiters, never clobbers the stored session, and a later independent call may retry. An invalid/revoked refresh response remains inspectable as APIError. | Go financial safety | `TestTokenProviderConcurrentWaitersShareFailedRefreshAndLaterRetry`; `TestTokenProviderStorageFailuresAndRetryAfterRefreshFailure` | DONE |
| TOKEN-07 | Storage read/write failures retain their identity and are not translated to ErrNotAuthenticated. No resource request uses a token whose persistence failed. | Go financial safety | `TestTokenProviderStorageFailuresAndRetryAfterRefreshFailure`; `TestCoreDoPreservesTokenProviderError` | DONE |
| TOKEN-08 | A canceled refresh waiter returns promptly without canceling the bounded shared refresh. Once remote rotation starts, it may complete and persist successfully even when no caller remains waiting. | Go cancellation and rotating-token safety | `TestTokenProviderWaiterCancellationDoesNotCancelSharedRefresh`; `TestTokenProviderFinalCancellationStillPersistsSuccessfulRotation` | DONE |
| TOKEN-09 | Custom GetAccessToken receives `ForceRefresh=false` initially and `true` only after a safe read receives 401, with the rejected token. Its errors retain identity; custom tokens are caller-owned and not persisted or logged. | TS `GetAccessTokenOptions`; Go error semantics | `TestCoreDoAuthenticatedSafeReadRetriesOnceGenerationAware`; `TestCoreDoPreservesTokenProviderError`; `TestCoreDoVerboseLogsMetadataOnly` | DONE |

## Slice 6 — spend-request lifecycle

These tests use representative full payloads plus focused presence/null cases;
they do not duplicate every struct field mechanically.

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| SPEND-01 | List sends authenticated GET `{SpendRequestBaseURL}/spend_requests`, unwraps `data`, preserves order/unknown enums, and returns a non-nil empty slice for missing/null/empty data. | TS `spend-request.ts:146-165`; tests | `TestSpendRequestsList` | DONE |
| SPEND-02 | Create sends authenticated JSON POST; required and representative nested monetary fields round-trip as `int64`. Approve routes to `/create_delegated`, is never serialized, and requires a separately authorized scope. | TS `spend-request.ts:168-190`; tests | `TestSpendRequestsCreateOmitsZeroValuesWithoutMutatingInput`; `TestSpendRequestsCreateDelegatedRouting`; `TestSpendRequestsCreateNestedValuesWithoutPrecisionLoss` | DONE |
| SPEND-03 | Create-only zero values are omitted where zero/false/empty is equivalent to absence; update fields retain pointer-based explicit clear/zero semantics. Encoding does not mutate caller params. | TS `JSON.stringify`; idiomatic Go API deviation | `TestSpendRequestsCreateOmitsZeroValuesWithoutMutatingInput`; `TestSpendRequestsUpdateEscapesIDAndPreservesPresence` | DONE |
| SPEND-04 | Update sends authenticated JSON POST to `/spend_requests/{escaped id}` and supports explicit clearing/zeroing as well as omission. | TS `spend-request.ts:193-213`; Go safety | `TestSpendRequestsUpdateEscapesIDAndPreservesPresence` | DONE |
| SPEND-05 | RequestApproval and Cancel send authenticated bodyless POSTs to escaped-ID endpoints and decode documented responses. No spend mutation is replayed after 401. | TS `spend-request.ts:216-243`; Go no-mutation-replay deviation | `TestSpendRequestsMutationEndpointsAndNo401Replay`; `TestSpendRequestsCancelAndRequestApprovalSuccess` | DONE |
| SPEND-06 | Retrieve sends authenticated GET for the escaped ID, encodes includes as one comma-joined query value, omits an empty include, maps 404 to `(nil, ErrNotFound)`, and applies the standard API error otherwise. | TS `spend-request.ts:246-283`; deliberate Go not-found deviation | `TestSpendRequestsRetrieveIncludesNotFoundAndReadRetry` | DONE |
| SPEND-07 | Decoding accepts legacy string and current object shared-payment-token forms and rejects malformed forms without silently dropping credentials. | TS `normalizeSpendRequest`; Go safety | `TestSpendRequestsLegacySharedPaymentToken`; `FuzzSharedPaymentTokenUnmarshal` | DONE |
| SPEND-08 | Approved card, shared/Link tokens, nullable payment status, refund/address, and unknown status fields decode without loss. SDK logs and formatting do not expose credential values. | TS types and retrieve tests; financial safety | `TestSpendRequestsDecodeCredentialsAndRedactFormatting`; `TestReadResourcesVerboseLogsNeverContainResponsePII` | DONE |
| SPEND-09 | Every spend operation applies common error precedence and preserves bounded status/body/details for 4xx/5xx responses. | TS spend request tests | `TestSpendRequestsAPIErrorContract`; `TestSpendRequestsEveryOperationUsesAPIErrorContract` | DONE |
| SPEND-10 | Invalid IDs and structurally invalid required inputs fail before HTTP; validation retains unknown enums for forward compatibility. | Go production safety | `TestSpendRequestsValidationBeforeHTTP`; `TestSpendRequestsList` | DONE |

## Slice 7 — remaining resources

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| RES-01 | PaymentMethods.List sends authenticated GET `{APIBaseURL}/payment-details`, unwraps `payment_details`, preserves card/bank details and unknown types, and returns a non-nil empty slice for missing/null. | TS `payment-methods.ts`; tests | `TestPaymentMethodsListEndpointEnvelopeAndForwardCompatibility`; `TestPaymentMethodsListMissingNullAndEmptyEnvelopesReturnNonNilEmpty` | DONE |
| RES-02 | ShippingAddresses.List uses `/shipping_addresses`, unwraps the envelope, and preserves null versus present-empty fields. Missing/null arrays return non-nil empty slices. | TS `shipping-address.ts`; tests | `TestShippingAddressesListPreservesNullAndPresentEmptyValues`; `TestShippingAddressesListEmptyEnvelopeForms` | DONE |
| RES-03 | UserInfo.Retrieve uses `/userinfo`; present values decode exactly and missing/null fields become nil without conflating present empty strings. | TS `user-info.ts`; tests | `TestUserInfoRetrievePreservesMissingNullAndEmpty` | DONE |
| RES-04 | SignURL accepts only absolute HTTP(S) URLs with a hostname, POSTs the original URL to `/web_bot_auth/sign`, and rejects invalid/userinfo/non-HTTP URLs before token lookup or HTTP. | TS `web-bot-auth.ts`; Go URL-safety deviation | `TestWebBotAuthSignURLValidatesBeforeAuthentication`; `TestWebBotAuthSignURLExactRequestAndCanonicalHostnameCache` | DONE |
| RES-05 | SignURL returns a complete authority-bound unexpired web_bot_auth block, rejects missing/malformed blocks, and applies common API/transport errors. | TS `web-bot-auth.ts:163-186`; tests | `TestWebBotAuthSignURLValidatesCompleteBoundUnexpiredBlock`; `TestWebBotAuthSignURLAPITransportAndNoMutationReplay` | DONE |
| RES-06 | Web-bot signatures are cached by canonical hostname until 30 seconds before expiry. Different hosts do not share entries and returned pointers cannot mutate cached values. | TS cache behavior; Go defensive-copy safety | `TestWebBotAuthSignURLExactRequestAndCanonicalHostnameCache`; `TestWebBotAuthSignURLCacheExpiryBuffer`; `TestWebBotAuthSignURLDifferentHostsProceedConcurrently` | DONE |
| RES-07 | Same-host cache misses are single-flighted while different hosts proceed independently. A canceled waiter does not affect live waiters; when the last waiter leaves, web-bot work is canceled. Failed or malformed responses are not cached. | Go concurrency extension | `TestWebBotAuthSignURLSingleFlightSameHost`; `TestWebBotAuthSignURLDifferentHostsProceedConcurrently`; `TestWebBotAuthSignURLCanceledWaiterDoesNotCancelSharedWork`; `TestWebBotAuthSignURLCancelsWorkAfterLastWaiterLeaves`; `TestWebBotAuthSignURLAPITransportAndNoMutationReplay` | DONE |
| RES-08 | Reports.Create POSTs `/agent_observations`, preserves required/optional field presence and unknown tags, and decodes a complete report record. | TS `report.ts`; tests | `TestReportsCreateRequestPresenceAndCompleteResponse`; `TestReportsCreateOmitsOptionalFieldsButPreservesKnownValues`; `TestReportsCreatePreservesExplicitEmptyAndUnknownTags` | DONE |
| RES-09 | Reports.Create never replays its mutation after 401 and applies the common API/transport error contract, including nested and non-JSON errors. | TS report tests; Go no-mutation-replay deviation | `TestReportsCreateDoesNotBlindlyReplay401`; `TestReportsCreateAPIAndMalformedSuccessErrors`; `TestReportsCreatePreservesTransportError` | DONE |
| RES-10 | PaymentMethods, ShippingAddresses, and UserInfo each exercise safe-read 401 refresh and rebuild Authorization without defaulting response data. | TS resource tests | `TestPaymentMethodsListSafe401ReplayAndAPIError`; `TestShippingAddressesListSafe401ReplayAndErrors`; `TestUserInfoRetrieveSafe401ReplayAndErrors` | DONE |
| RES-11 | Response string-enum-like fields pass unknown values through unchanged; wire timestamps remain lossless strings except expiry fields that require validation. | TS types; Go forward compatibility | `TestSpendRequestsList`; `TestPaymentMethodsListEndpointEnvelopeAndForwardCompatibility`; `TestReportsCreatePreservesExplicitEmptyAndUnknownTags`; `TestWebBotAuthSignURLValidatesCompleteBoundUnexpiredBlock` | DONE |

## Slice 8 — production failure and safety gates

| ID | Observable behavior | Source | Evidence | Status |
|---|---|---|---|---|
| SAFE-01 | The full suite, including concurrent refresh/storage/cache/device-flow scenarios, passes repeatedly under the race detector and a stress count without goroutine leaks or deadlocks. | Go production gate | [Hosted CI run 29102801918](https://github.com/mackross/stripelink/actions/runs/29102801918) passed `go test -race ./... -count=10` for implementation commit `080b957`; targeted adversarial refresh/session and storage-cancellation tests passed repeated race/stress runs; `TestClientCancellationDrainsAllResourceWork` proves every blocked operation and transport drains under cancellation without sleeps or goroutine-count heuristics. | DONE |
| SAFE-02 | Fuzz tests cover shared-payment-token decoding, API error decoding/diagnostics, URL handling, and storage decoding with bounded allocation and credential-safe diagnostics. | Go production gate | `FuzzSharedPaymentTokenUnmarshal`; `FuzzExtractAPIErrorMessage`; `FuzzWebBotURLParsingDoesNotDiscloseSecrets`; `FuzzStorageStateDecode` | DONE |
| SAFE-03 | HTTP reads default to 4 MiB and storage reads to 1 MiB. Overflow returns an explicit error, closes resources, preserves storage, and excludes truncated bytes from logs/diagnostics. | Go denial-of-service safety; resolved size policy | `TestCoreDoBoundsAndClosesResponse`; `TestFileStorageRejectsUnsafeOrInvalidFiles`; `TestExtractAPIErrorMessageRedactsCredentialFieldsAndBoundsDiagnostics`; metadata-only log tests | DONE |
| SAFE-04 | Public methods reject nil contexts/required pointers without panic; nil/typed-nil custom dependencies are safely handled. | Go API robustness | `TestPublicResourceMethodsRejectNilContextAndUnconfiguredReceiver`; `TestSharedPaymentTokenUnmarshalRejectsNilReceiver`; `TestAuthNilContextsAndCredentialSafeErrors`; `TestReportsCreateNilContextAndZeroReceiver`; `TestSpendRequestsValidationBeforeHTTP`; `TestWebBotAuthSignURLValidatesBeforeAuthentication`; `TestNewClientRejectsTypedNilAuthStorage`; `TestNewClientRejectsTypedNilHTTPTransport` | DONE |
| SAFE-05 | The exact patched Go 1.26.5 Linux/macOS/Windows matrix passes formatting, no-diff `go fix`, vet, examples, tests, repeated race runs, all fuzz targets, Staticcheck v0.7.0, govulncheck v1.6.0, dependency inspection, and docs; tests make no external calls. Go 1.26.1 is prohibited because the scanner found nine reachable standard-library vulnerabilities fixed through 1.26.5. | Release gate; resolved toolchain policy | [Hosted CI run 29102801918](https://github.com/mackross/stripelink/actions/runs/29102801918) passed all nine jobs for implementation commit `080b957`: the exact Go 1.26.5 Linux/macOS/Windows matrix, repeated race count 10, all four fuzz targets, Staticcheck v0.7.0, govulncheck v1.6.0, formatting, no-diff `go fix`, vet, build, tests, examples, docs, and module inspection. | DONE |
| SAFE-06 | Package documentation covers credential handling, context/timeout ownership, retry limits, storage permissions/platform limits, logging, errors, and offline compiling auth/session and spend-retrieval examples. | Release gate | `README.md`; `doc.go`; `SECURITY.md`; `RELEASE.md`; `ExampleClient_deviceAuthentication`; `ExampleSpendRequestsResource_Retrieve` | DONE |

## Deliberate Go and safety deviations

These are normative, not parity bugs.

| Decision | Go contract | Upstream behavior |
|---|---|---|
| Retrieval absence | `ErrNotFound` supports `errors.Is`. | Spend retrieval returns `null`. |
| Poll state | Pending and slow_down remain matchable as pending but are distinguishable. | Both return `null`. |
| Cohesive session | Initiation/polling persists pending state/tokens; default clients transparently use storage. | Storage orchestration lives mostly in the CLI. |
| Poll convenience | Blocking polling is context-aware and uses an absolute expiry. | SDK exposes only one-shot polling; CLI loops. |
| Error inspection | Go uses `errors.Is`/`errors.As`, preserves causes and explicit bounded response fields, and makes implicit formatting credential-safe/bounded. | JavaScript uses class inheritance and may echo server-controlled detail. |
| Cancellation | Every I/O/wait accepts and obeys `context.Context`. | Fetch cancellation is not part of the SDK surface. |
| Logging | Bodies and credential-bearing values are never logged. | Several TypeScript resources log raw response/request bodies in verbose mode. |
| Storage ownership | Values are defensively copied; files are atomic, bounded, permission-checked, and symlinks rejected. | MemoryStorage returns references; file behavior relies on `conf`. |
| Concurrency | Token refresh is single-flight and generation-aware within one provider; per-host signature misses are single-flight within one client. | TypeScript does not coordinate concurrent calls. |
| Optional inputs | Presence-capable Go fields preserve omitted versus explicit zero/false/empty. | JavaScript gets this naturally from `undefined`. |
| URL safety | Bases are validated/normalized, IDs escaped, and SignURL accepts absolute HTTP(S) URLs only. | TypeScript largely concatenates strings and accepts any URL parsed by `URL`. |
| Invalid 2xx bodies | Required response bodies are validated and failures are explicit. | TypeScript commonly casts parsed data without runtime validation. |
| API surface | One idiomatic Go method/type name is exposed; TypeScript compatibility aliases are not copied. | JS exposes short/long aliases and `LinkClient`. |
| Defaults | Go's documented client name is package-specific rather than `Link CLI`. | TypeScript defaults to `Link CLI`. |

## Resolved parity and policy decisions

The eight former policy blockers are resolved as follows; `GUIDANCE.md` §10 is
the normative detailed record.

1. The default credential path is
   `os.UserConfigDir()/stripelink/auth.json`; there is no automatic link-cli
   discovery or migration.
2. Direct RefreshToken/RevokeToken calls do not mutate storage. Automatic
   refresh persists its complete result, and Logout revokes then clears only
   the SDK-owned persisted session.
3. Create-only optional scalars use zero values where zero means omission;
   update scalars use pointers where presence matters, and optional slices
   preserve nil versus explicit empty. Local validation covers structural and
   safety invariants, not changeable server business rules or unknown enums.
4. FileStorage uses an advisory cross-process lock and directory fsync on
   Darwin, DragonFly BSD, FreeBSD, Linux, NetBSD, and OpenBSD. Other platforms
   have per-instance coordination and a synced replacement file, but no
   portable cross-process lock or directory fsync; link-cli never honors the
   Go lock.
5. HTTP response reads default to 4 MiB; auth-file reads are fixed at 1 MiB.
6. There is no generic base error. Sentinels plus APIError and TransportError
   provide Go-native classification and structured inspection.
7. Structural spend IDs/fields, contexts, URL safety and required response
   structure are validated locally. Changeable report business rules remain
   server-owned, and forward-compatible values remain accepted.
8. Patched Go 1.26.5 is the security minimum and exact initial CI target. The
   minimum CI matrix and mandatory
   race/fuzz/vet/staticcheck/govulncheck/dependency/doc gates are defined in
   `RELEASE.md`.

## Production-readiness gates

Current evidence audit (2026-07-11): **73 DONE, 0 PENDING**. Hosted CI run
[29102801918](https://github.com/mackross/stripelink/actions/runs/29102801918)
closes the final platform, tooling, fuzz, and repeated-race evidence gates for
implementation commit `080b957`.

Release is allowed only when:

1. All 73 contract rows are DONE (or have an explicitly approved waiver).
2. All eight policy decisions above still match implementation, tests, and
   public documentation.
3. `go test -race ./...`, fuzz smoke runs, vet/static analysis, and supported-Go
   version CI pass from a clean checkout.
4. A security review specifically examines credential logs, token rotation,
   file permissions/links/atomicity, URL construction, response bounds, and
   cancellation races.
5. Public examples compile and a reviewer verifies every endpoint and wire name
   against the pinned upstream commit.
