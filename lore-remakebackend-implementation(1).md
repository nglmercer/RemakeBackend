# Implementation Brief: Lore Fork Embedded in RemakeBackend

> **Audience:** an LLM coding agent with access to the relevant repositories.
> **Language:** write code comments, public documentation, architectural decisions, and the implementation report in English.
> **Task:** implement the system described here. This is an implementation brief, not a request for another architecture proposal.

## 1. Approved architecture and intended outcome

Maintain a fork of [EpicGames/lore](https://github.com/EpicGames/lore) and integrate it directly into [nglmercer/RemakeBackend](https://github.com/nglmercer/RemakeBackend). Reuse the backend's existing [nglmercer/better-auth-rs](https://github.com/nglmercer/better-auth-rs) integration.

The result must provide one coherent versioning and synchronization foundation for plugin selections and settings, templates, automation definitions, profiles, portable OBS configuration, images, videos, and other binary assets. Applications must be able to use it through a versioned API, language SDKs, and a Git-like CLI.

The approved deployment is an embedded module in RemakeBackend. The reusable engine, contracts, and extension points belong in the Lore fork. Backend-specific identity, permissions, migrations, and product adapters belong in RemakeBackend. A third standalone platform repository or a separately deployed Lore service must not be a prerequisite.

The design should reduce future changes by stabilizing boundaries and documenting compatibility. Do not promise that a fork will eliminate maintenance or future migrations.

### Required ownership boundaries

| Area | Owner and responsibility |
| --- | --- |
| Immutable bytes, trees, revisions, branch references, engine merge operations | Lore, using its authoritative stores |
| Existing users, sessions, login, account lifecycle | The existing Better Auth integration in RemakeBackend |
| Tenant membership, repository permissions, quotas, publication policy | RemakeBackend, exposed through reusable interfaces |
| Upload sessions, operation receipts, migration mappings, rebuildable indexes | RemakeBackend persistence |
| Portable resource schemas and application behavior | Domain adapters |
| Remote client behavior | Shared public API and SDK contract |
| Local staging, offline commits, checkout and conflict state | A reusable workspace engine built on Lore |

PostgreSQL may contain a projection of a Lore revision or branch head for queries. It must not own an independently editable version graph or a competing authoritative HEAD.

## 2. Start from the real code

Read applicable repository instructions, inspect the working tree, preserve unrelated changes, and record the exact revisions used. Verify the following baseline against the checked-out code before changing it.

| Repository | Inspected baseline | Important observation |
| --- | --- | --- |
| EpicGames/lore | `e32aaac2b0b02ad9aa10723250b64ba86f125fe4`, branch `main` | Rust workspace; reusable revision/store APIs and server builders exist, but embedding and authentication need deliberate integration. |
| nglmercer/RemakeBackend | `6a69c99a3a134f3f76333316957d788f31d4f004`, branch `master` | Rust, Axum, Tokio, SQLx and PostgreSQL; existing sync, asset, library, publication and package workflows. |
| nglmercer/better-auth-rs | `d4bb1ff17400d424813fc0bd8800204faf088238`, branch `main` | Existing session extractors and optional JWT signing; this revision is the inspected backend dependency. |
| nglmercer/TikTools-app | `4187ef2c6b592ef17166c7a29b1beb3416fe5327`, branch `remake` | Existing Rust application core, cloud client, synchronization state and CLI integration. |

These are inspection references, not instructions to assume that a moving branch still has the same contents. Use a deliberately selected, pinned fork revision and record any differences that affect this brief.

### Inspect these areas first

- Lore: `lore/src/revision_tree/`, `lore/src/storage/`, `lore-revision/src/branch.rs`, `lore-server/src/server.rs`, `server_config.rs`, `authnz/`, `http/server.rs`, `grpc/server.rs`, `plugins/`, and the revision/storage protobuf definitions.
- RemakeBackend: `crates/cloud-api/src/main.rs`, `dual_auth.rs`, `workspace.rs`, `packages.rs`, `library.rs`, `assets.rs`, `overlays.rs`, `crates/cloud-contracts/src/portable.rs`, `crates/cloud-storage/`, and existing migrations.
- Better Auth: `session.rs`, `axum_integration.rs`, `jwt_signing.rs`, and `router.rs`.
- TikTools, when integrating its client: `crates/cloud-client/`, `crates/tiktools-cloud-sync/`, `crates/tiktools-core/src/cloud_sync.rs`, package installation, and the existing CLI/client interfaces.

The source references at the end support the baseline observations. Proposed names in this document are design suggestions, not claims that those APIs already exist.

## 3. Repository strategy and deliverables

Use an existing user-owned Lore fork if one is already present. Otherwise create the requested fork in the authorized account. Retain the upstream remote, history, license notices, and a documented upstream-update process.

Keep changes in three understandable groups:

1. Generic Lore improvements: embedding, configurable authorization, publication preconditions, and integration primitives.
2. Reusable modules: public contracts, remote SDKs, workspace/CLI integration, and adapter interfaces.
3. RemakeBackend implementation: existing-auth adapter, repository policy, routes, persistence, resource adapters, and migration.

Prefer small cohesive crates or modules whose names follow the repositories' conventions. An illustrative structure is:

~~~text
Lore fork
  existing Lore engine and server crates
  generic embedding and policy extension points
  integration contracts and shared workspace support
  SDK source/generation configuration
  CLI integration
  documentation and compatibility fixtures

RemakeBackend
  embedded versioning service
  Better Auth principal adapter
  repository policy and metadata persistence
  versioning HTTP routes
  domain adapters
  migration and reconciliation workers
~~~

Do not rename the entire upstream workspace or rewrite working engine components to make the fork look independent. Keep generic changes reviewable and easy to compare with upstream.

Deliver runnable code, schema migrations, focused verification, generated or reproducible SDK packages, examples, operational documentation, and a migration guide. Empty adapters, unimplemented handlers, and success responses backed only by mocks do not satisfy the task.

## 4. Embed Lore with an explicit lifecycle

The inspected `lore_server::server::server_main` is a process entry point. It parses configuration/arguments, owns runtime execution, installs process-level behavior, handles shutdown, and shuts down Lore runtimes. Calling it inside RemakeBackend's async main is not an embedding design. [L1]

Refactor or expose reusable initialization beneath that entry point:

- Accept typed configuration, stores, policy implementations, and host-provided dependencies.
- Return services, optional routers/listeners, health information, and an explicit lifecycle handle.
- Let RemakeBackend own process arguments, its tracing subscriber, operating-system signals, and top-level shutdown.
- Make ownership of Lore's internal runtimes, blocking work, and store locks explicit.
- Support cancellation and graceful draining of admitted operations.
- Stop admission, drain or persist recoverable work, flush storage, stop owned background tasks, and release locks in a defined order.
- Preserve standalone Lore behavior by making its entry point delegate to the same initialization layer.

Do not create a Tokio runtime for every request, block inside the host runtime with nested `block_on` calls, or shut down shared engine resources while another service still uses them.

Mount application-facing routes in the existing RemakeBackend application. Native Lore listeners are optional capabilities; enable them only when their authentication and authorization are implemented and tested.

## 5. Add reusable extension points, then implement adapters

Reuse existing interfaces before introducing new ones. The inspected fork baseline already exposes `RepositoryAuthorizer`, `RepositoryCatalog`, `GrpcServerBuilder::with_token_verification(...)`, and HTTP router construction with token verification and authorization in `ServerState`. Its `ServerConfig` supports plugins, hooks, and telemetry dependencies, but does not yet provide a general authentication factory. [L2]

Expose the necessary dependencies through the embedding configuration. Avoid copying the entire server startup implementation into RemakeBackend.

The following are proposed logical responsibilities; choose actual Rust names after inspecting the code:

| Extension point | Contract |
| --- | --- |
| Principal mapping | Convert an already verified host identity into a neutral principal. |
| Credential verification | Verify credentials for transports that authenticate independently. |
| Repository policy | Authorize an actor, repository and action using current policy. |
| Repository catalog | Resolve and list repositories visible to that actor. |
| Resource adapter | Export, validate, migrate and import a versioned resource type. |
| Storage integration | Configure supported Lore stores and their required mutable/reference facilities. |
| Transfer integration | Support persistent streaming upload/download workflows. |
| Event sink | Consume durable operation events with explicit retry and deduplication behavior. |

Keep Better Auth dependencies in the backend adapter or an optional adapter package. The generic engine must not import RemakeBackend's application state, query its user tables, or know TikTools collection names.

Provide a working third-party example host that implements the neutral interfaces without importing RemakeBackend. It may be a small example application within the fork; another production service is unnecessary.

## 6. Reuse Better Auth correctly

The normal in-process request path is:

1. Receive the existing cookie or native session.
2. Authenticate through the existing backend implementation.
3. Map the verified identity to a neutral principal.
4. Evaluate the repository policy.
5. Invoke the embedded versioning operation.

Reuse the existing `DualUser` / `AuthPrincipal` path where appropriate. The inspected backend selects explicit Bearer authentication when the Authorization header is present and otherwise uses the cookie path. Preserve that behavior and the existing cookie CSRF/origin checks. An invalid explicit Bearer token must not fall back to an ambient cookie. [B1, A1]

Represent identity with an issuer/provider and a stable subject. Tenant selection, account mappings, membership, and effective permissions must be validated server-side. A tenant ID, actor ID, role, or repository ID in request data is not proof of access.

Do not introduce a second user database, a second login screen, or a parallel password/session implementation.

### Distinguish session tokens from protocol tokens

Better Auth native sessions in the inspected implementation use opaque tokens. They are not JWTs. Better Auth also has optional JWT signing and JWKS support, but RemakeBackend's inspected authentication router does not enable that functionality, and the default token endpoint does not issue repository grants. [A2, B1]

In-process library calls do not need a JWT. If native Lore protocols or external service boundaries need JWTs, implement a separate, explicit credential bridge:

- Verify the existing session before issuing a protocol credential.
- Derive subject, tenant and permitted repository actions from trusted server state.
- Validate issuer, audience, allowed algorithms, key ID and expiration.
- Document token lifetime, refresh, key rotation and revocation latency.
- Decide whether each operation rechecks current ACLs or relies on bounded token grants.
- Keep signing keys and session secrets out of client SDKs and versioned content.
- Provide a noninteractive, narrowly scoped service identity path only when required.

JWT/JWKS support is not a complete OIDC provider. Do not invent discovery responses or advertise unsupported login/refresh grants.

The required product CLI can use the existing native-session flow or a documented bridge. Support for an unmodified upstream Lore CLI is a separate compatibility feature: if implemented, verify the complete advertised authentication flow end to end.

### Apply policy to every exposed path

Cover repository listing, trees, history, branches, uploads, raw content reads, downloads, ranges, signed URLs, and cross-repository references. If HTTP, gRPC or QUIC is enabled, it must use the same effective repository policy.

A content hash is an identifier, not authorization. Global grants across every repository are unsuitable as the default for isolated user workspaces. Signed URLs must have defined resource scope, expiry and revocation semantics.

## 7. Define one canonical versioning model

Use a stable application workspace ID mapped to a Lore repository. One workspace repository can atomically version related configuration files and references to its assets.

Model at least:

- Repository and workspace identity.
- Immutable revision and parent relationships.
- Tree entries and immutable content references.
- Branches and explicit tags or equivalent named references.
- Author identity, commit message, timestamps and operation identity.
- Resource schema version and logical resource identity.
- Provenance for imported legacy revisions.

Use opaque IDs at public boundaries. Do not require SDK users to understand Lore's internal hash encoding, chunk layout or storage keys.

Keep logical resource identity separate from its current path. Document path normalization, reserved paths, case handling, traversal prevention and symlink policy. Reject unsafe imports before materializing files on disk.

### Keep application state portable

Version templates, automation definitions, plugin selections/settings, profiles, and portable OBS descriptions through schemas and adapters. Keep machine-specific bindings and secrets outside portable history.

Examples include local device identifiers, absolute paths, OBS access tokens, stream keys and authentication credentials. Store explicit binding references where a portable definition needs local configuration.

For newly authored structured resources, use deterministic serialization where it improves meaningful diffs. When importing legacy data, preserve original bytes whenever a digest, signature or external reference binds those bytes.

Versioning a plugin selection does not install an executable package. Pulling an automation definition does not execute it. Import/apply behavior must use existing product validation, permissions and consent paths.

## 8. Make publication atomic and recoverable

A successful local commit is not proof that a change is durably published to the backend.

The inspected memory-store API creates local stores, and `remote_write` does not by itself prove remote publication when no effective remote is available. Do not open a fresh in-memory store per request, commit there and report cloud synchronization success. [L3]

The embedded service must operate against authoritative shared stores, or complete the validated publication path from a temporary/local revision into those stores.

### Expected-head preconditions

Every conditional branch mutation must enforce its expected head atomically within the authoritative publication operation.

The inspected branch-push protobuf has no literal `expectedHead` field. If the public contract requires one, map it to an existing equivalent operation or add a backward-compatible generic capability to the fork. Reuse the engine's validated branch publication and mutable-store CAS. [L4]

Do not implement:

~~~text
read HEAD -> compare in application code -> unconditional write
~~~

Two writers starting from the same head must not silently overwrite one another. Default to reporting divergence. Make merging and force updates explicit, separately authorized behavior.

### Idempotency and uncertain outcomes

For each retryable mutation, persist an operation identity, request fingerprint, authenticated scope, intended repository/ref, expected base, and recoverable publication state.

Implement a documented state machine such as:

~~~text
accepted -> preparing -> content-ready -> publishing -> published -> indexed
~~~

The exact names may differ, but each transition must have crash-recovery rules. In particular:

1. Persist the operation intent before a publish that may outlive the request.
2. Prepare content and a candidate revision without exposing partially prepared state.
3. Publish using the authoritative conditional operation.
4. Persist or reconcile the canonical publication receipt.
5. Update projections and enqueue downstream work through a durable process.
6. Return a completed publication receipt only when its documented durability conditions hold.

A repeated idempotency key with the same request must resolve to the same logical result. Reusing the key with a different request must fail. A timeout after publication must be recoverable through operation lookup, without creating a second commit.

Capture enough identity in the candidate revision/publication journal to recover a crash between Lore publication and SQL receipt creation. Do not rely only on the current branch head, because later commits may have advanced it. Prevent concurrent workers from independently publishing the same operation.

SQL and Lore do not share a database transaction. Describe reconciliation honestly; do not claim cross-store rollback or exactly-once delivery without implementing the necessary protocol.

### Preparation and event behavior

Use an operation-owned revision-tree handle. If a series of edits fails partway through preparation, discard or recover that private state; never publish a partially prepared batch.

Preserve structured conflict details from Lore, including the actual current head. Avoid parsing human-readable error strings.

Existing asynchronous post-hooks are not a durable outbox. Use a persistent journal/outbox and reconciliation for required delivery. Events must be deduplicable; consumers must tolerate retries. [L5]

## 9. Support large files through persistent streaming transfers

The inspected HTTP upload handler accepts buffered `Bytes` and returns a content address. It does not create a revision, and simply increasing its body-size limit is insufficient for video uploads. Existing download support also requires checking the exact range/validator behavior before advertising a broader contract. [L6]

Implement persistent resumable transfers, using a documented protocol such as tus or an explicitly specified upload-session API.

Required upload behavior:

- Create a scoped upload session with expected length, optional expected digest, expiry and quota reservation.
- Stream bytes with bounded memory and backpressure.
- Persist offsets or part identities and integrity information.
- Resume after both client interruption and backend restart.
- Detect wrong offsets, conflicting retries, truncated parts and digest mismatches.
- Bound parallel transfers, temporary disk use and abandoned-upload lifetime.
- Revalidate authorization and quota before final publication.
- Ingest completed data into Lore using its streaming/file ingestion and chunking facilities.
- Finalize idempotently and return a content receipt.
- Publish the selected content in a separate explicit commit, or through a documented combined operation with the same recovery guarantees.

Distinguish these results in API responses and SDKs:

| Result | Meaning |
| --- | --- |
| Upload accepted | A transfer session exists. |
| Content ready | Verified bytes are available for a commit. |
| Revision created locally | A local workspace has recorded a revision. |
| Revision published | The authoritative repository accepted the revision/ref update. |

Temporary upload data must not become a second permanent canonical asset store. Clean it up only when recovery and retention rules permit.

Downloads must support bounded streaming, cancellation and resumable reads. Specify implemented Range, Content-Length, ETag, conditional-request and cache semantics. Do not advertise multi-range or If-Range support merely because a single range implementation exists.

Preserve both application-level SHA-256 identities and internal Lore addresses where they serve different contracts. Do not assume a multipart storage ETag is the file's SHA-256.

Lore chunk deduplication can reduce storage and some transfers, but do not promise small deltas for arbitrary re-encoded videos. Media transcoding, thumbnails and delivery optimization may use adapters/background jobs; they are separate from version correctness.

## 10. Use supported durable storage

Make the initial deployment work with durable storage compatible with RemakeBackend's actual environment. Provide validated configuration and startup checks for the implemented providers.

For local storage, require persistent directories, recovery-safe writes, appropriate locking and an explicit backup path. Temporary directories and process-local memory are unsuitable as the production source of truth.

For object storage, inspect the selected Lore implementation's full requirements. Immutable objects alone are not enough: references, fragment associations, mutable metadata and locks must also work correctly. The stock binary does not automatically register every provider crate; derived configurations must register their chosen plugins. [L7]

Do not describe S3 as a drop-in complete backend without implementing or configuring the associated requirements. Conversely, do not impose AWS dependencies on a deployment that uses a valid local provider.

If multiple backend instances are supported, they must share the authoritative reference/locking facilities. Independently writable local HEAD stores are not a clustered implementation. Expose single-instance limitations explicitly until multi-instance correctness is verified.

Define retention and garbage collection around all relevant roots: branches, tags, pinned historical dependencies, active operations, uploads, and migration recovery points. A historical package pin must not break because an asset appears unused in the latest workspace tree.


## 11. Define a versioned public API

Introduce a separate namespace, for example `/api/versioning/v1`. Keep the legacy v2 sync contract intact. Choose final naming to fit the backend, then document it consistently.

Use one authoritative contract source. OpenAPI can describe the remote HTTP API, with generated schemas or generation from Rust definitions if that is the repository convention. Do not maintain unrelated handwritten definitions in every language.

At minimum, expose these capabilities:

| Capability | Required behavior |
| --- | --- |
| Capabilities/version | Advertise protocol versions, supported operations, limits and optional features. |
| Workspaces/repositories | Create, resolve and list authorized workspaces; expose stable mappings. |
| References | Read/list branches and tags; conditionally create, advance and delete permitted references. |
| Revision reads | Retrieve metadata, history, trees and exact historical content. |
| Diff | Report structured changes between explicit revisions. |
| Uploads | Create, inspect, append/upload parts, resume, finalize and cancel sessions. |
| Commits/publication | Apply a complete mutation set with expected-base and idempotency semantics. |
| Operation status | Resolve pending, failed and uncertain outcomes after reconnecting. |
| Downloads | Stream authorized content and resume supported ranges. |
| Change notifications | Provide a documented polling feed and optionally resumable events. |

Use opaque string IDs and cursors in the new API. Avoid exposing 64-bit counters as unsafe JavaScript numbers. Preserve existing numeric legacy fields through their compatibility contract.

Define stable machine-readable errors, including authentication failure, forbidden access, missing precondition, conflict, invalid content, expired upload/cursor, quota exhaustion, unsupported capability and temporary unavailability.

Specify pagination, cancellation, progress, rate-limit responses and retry behavior. Preserve request IDs and operation IDs in diagnostics without exposing credentials.

An illustrative publication request may contain:

~~~json
{
  "branch": "main",
  "expectedHead": "<opaque-revision-id>",
  "operationId": "<client-generated-operation-id>",
  "message": "Update streaming workspace",
  "changes": [
    {
      "type": "put",
      "path": "templates/welcome.json",
      "contentId": "<verified-content-id>"
    },
    {
      "type": "put",
      "path": "assets/intro.mp4",
      "uploadId": "<completed-upload-id>"
    }
  ]
}
~~~

The server must validate every content reference, path, size, scope and adapter rule before publication. Request fields must not let a caller choose an unverified author identity or bypass repository ownership.

Represent an initially absent branch with an explicit, documented precondition. Distinguish conflict, accepted/pending work, content completion, and publication completion in responses.

Protect application-managed branches with domain validation on every mutation path, including native protocols if enabled. Raw branch pushes must not bypass schemas or corrupt the legacy compatibility projection.

## 12. Implement real SDKs without duplicating the engine

Implement functioning remote SDKs for:

1. Rust, for RemakeBackend/TikTools integration.
2. TypeScript, with explicit browser and Node capabilities.
3. Python, for scripts and third-party automation.

Keep the API contract and generation workflow suitable for additional languages such as Kotlin/Java, C#, Go and Swift. Document how to add and validate a language target. Do not create empty packages and label them supported.

Each shipped SDK must provide:

- Configurable server URL and a supplied credential/token provider.
- Typed requests, responses and stable error mapping.
- Repositories, refs, revisions, diff and operation lookup.
- Bounded streaming uploads/downloads.
- Persistent or exportable resume information.
- Idempotency-key reuse across retries.
- Expected-head conflicts with structured details.
- Cancellation, progress and explicit retry policy.
- A runnable example against the real development backend.

The browser SDK must respect cookie/CSRF requirements or its documented Bearer flow. It must not require native Lore FFI or an embedded filesystem.

Generated transport code may be wrapped by handwritten conveniences. A generated REST client does not implement local staging, offline commits or merges.

### Shared local workspace support

Reuse Lore's Rust engine for local version-control behavior. Share that implementation with the CLI and native consumers instead of independently reimplementing Lore's storage/hash algorithms in each SDK.

Treat native bindings as an optional layer with a documented ABI/version policy. If using the C ABI, build and package the actual C API library and headers; building only the CLI does not provide those artifacts.

Remote API compatibility, native library compatibility and on-disk repository compatibility are separate version promises. Document each one.

### Connect the local graph to the remote service

Specify and implement the transport used by the product CLI for clone, fetch and push. Either adapt the local Lore workspace engine to the public API or expose the necessary authenticated native Lore protocols through the embedded host. A transport required by the CLI is mandatory in that deployment profile.

Transfer revision identities, parent relationships, references and required content correctly. Do not silently replace a sequence of offline commits with an unrelated server-created snapshot. If any canonicalization is unavoidable, specify its identity mapping and reconciliation rules before implementing it.

Record the verified publishing actor without silently rewriting immutable revision payloads. Distinguish verified publication identity from any client-supplied authorship metadata, and apply the same authorization and expected-head guarantees to this transport.

## 13. Provide Git-like commands with truthful semantics

Use the fork's existing CLI and workspace primitives where possible. A product wrapper is acceptable when it shares the same engine and API. It must not implement operations by parsing another CLI's human-readable output.

Choose the executable name once and document it. The examples below use the proposed placeholder `syncctl`, not an existing Lore command.

~~~sh
syncctl login
syncctl clone <repository-url> ./stream-workspace
syncctl status
syncctl diff
syncctl add templates/ automations/ obs/ assets/
syncctl commit -m "Update streaming workspace"
syncctl push
syncctl fetch
syncctl pull
syncctl log
syncctl branch experiment
syncctl switch experiment
syncctl restore --source <revision> -- assets/intro.mp4
syncctl revert <revision>
~~~

Required semantics:

- `clone` establishes a local repository, remote identity and credentials through the documented provider.
- `add` stages content; `commit` records a local revision.
- `push` publishes and reports authoritative acceptance or conflict.
- `fetch` updates remote knowledge without silently changing local application state.
- `pull` follows a documented merge policy and protects uncommitted edits.
- `restore` affects selected working-copy paths.
- `revert` records a new compensating revision rather than silently rewriting shared history.
- Binary conflicts preserve both alternatives until the user resolves them.
- Text/structured merge behavior is explicit; do not silently merge incompatible schema changes.
- Credentials, local bindings and ignored secrets are excluded from staging by policy.

Provide machine-readable output and stable exit codes for automation. Persist local operation and conflict state so a process interruption does not lose recovery information.

Do not claim Git wire-protocol compatibility, Git object compatibility, complete Git command parity, or compatibility with an unmodified Lore CLI unless those features are actually implemented and verified.

## 14. Integrate RemakeBackend's domains

Connect existing backend functionality through resource adapters and a common versioning service.

| Domain | Versioned representation and retained behavior |
| --- | --- |
| Plugin selections/settings | Portable selections and settings with exact package references; retain existing installation/trust rules. |
| Templates and profiles | Stable logical IDs, schema versions, exact retained revisions and publication metadata. |
| Automations | Portable definitions and referenced resources; execution remains an explicit product operation. |
| OBS-related content | Portable descriptions and referenced assets, with local bindings resolved by the application. |
| Images, video and binary assets | Immutable content references, media metadata, retained versions and streaming transfers. |
| Bundles/packages | Exact dependency pins, provenance, preflight and current publication/access policy. |

Do not assume that existing overlay storage already represents a complete OBS scene collection, or that every frontend automation panel already uploads its data. Inspect the real producers and consumers.

Preserve moderation, signed registry generations, publisher trust, package integrity verification, permission consent, withdrawal/yank behavior and client application journals. A Lore commit is neither catalog publication nor permission to install or execute content. [B3]

Existing explicitly consented automatic application may continue through its current product path. The generic versioning layer must not create new implicit side effects.

For pinned packages, resolve exact historical revisions where retained and currently authorized. Do not substitute the newest revision or bypass current access/revocation policy. The inspected package evaluator compares some pins with current/published revisions, so historical reproducibility needs explicit implementation rather than an assumption. [B3]

For TikTools, extend the existing cloud client and synchronization coordinator where necessary. Preserve durable outboxes, account/origin separation and conflict recovery. A frontend redesign or replacement of the application core is not a prerequisite for this backend implementation.

## 15. Preserve the legacy v2 synchronization contract

Current v2 records use `(user_id, collection, key)` and an account-wide cursor. They do not already have a workspace ID. Map each account's existing namespace to an explicit legacy/default workspace. Additional workspaces belong to the new API. [B2]

Do not split one account's legacy v2 namespace across partially migrated workspaces with different write authorities.

The existing v1 plugin-selection dataset has separate storage, cursors and routes. Preserve its behavior unless an explicit migration maps it into Lore. Do not silently merge v1 and v2 records or allow a v1 route to become an unfenced writer to a migrated v2 namespace. [B6]

Preserve:

- Existing record schemas and credential filtering.
- Numeric, monotonically increasing revisions and cursors.
- Strong per-record ETags and conditional create/update/delete behavior.
- Tombstones and tombstone recreation.
- No-op writes that do not produce a new revision/change event.
- Existing precondition/error semantics.
- Gap-free retained feed pages and snapshot recovery after cursor expiry.
- Write-epoch behavior.
- Existing quotas unless an explicitly versioned change replaces them.

Keep a durable mapping from compatibility revision/cursor to canonical Lore state. Do not replace a legacy numeric revision with a Lore hash.

The inspected fixed collection set is:

~~~text
plugin-selections
rule-templates
profiles
plugin-settings
preferences
~~~

`variables` is separately advertised as optional. Do not add videos, arbitrary files, OBS collections or new record kinds to old feeds. Some existing clients reject unknown collections even when capabilities are advertised. [B2]

After migration, v2 routes should act as a compatibility facade over Lore and its reconstructible projection. Return success only when the legacy state needed for subsequent reads is durably available or recovered.

Preserve per-record preconditions even though the underlying repository uses a branch-wide head. Unrelated concurrent record changes may require controlled retry/rebase or serialization; they must not weaken the requested record precondition or silently lose another record's change.

## 16. Implement a resumable migration and real write cutover

Build a dry-run inventory and an idempotent importer. Keep the old authority active until the chosen namespace is ready for an explicit cutover.

A possible migration state model is:

~~~text
legacy -> preparing -> sealed -> active
~~~

The state names are illustrative. Implement the following guarantees:

1. Inventory records, retained document/overlay revisions, assets, package pins, public IDs, digests, ownership and publication state.
2. Record source boundaries and deterministic ID/path mappings.
3. Import current state and available retained history into Lore.
4. Verify counts, bytes/digests, references, ownership and historical reads.
5. Fence every writer affecting the migrated namespace and drain or reject in-flight old-authority writes.
6. Capture/reconcile the final source state while the fence is effective.
7. Atomically switch the application's authority mapping.
8. Route subsequent legacy writes through the compatibility facade.
9. Reconcile projections, operation receipts and downstream indexes.
10. Retain a documented recovery point and old data until the migration is verified.

The existing write-epoch barrier is not a complete migration write lock. Some epoch enforcement is optional and other mutation routes may exist. Do not enable an irreversible client requirement merely to simulate a migration fence. [B2]

The existing account export can include sections captured at different instants. Do not treat it as a globally atomic source snapshot for all domains. Use a consistent final capture or verified watermarks under the real fence. [B4]

The old sync feed is bounded. Import what actually exists; do not fabricate historical commits or promise to reconstruct expired changes.

Preserve legacy UUIDs, numeric revision URLs, raw signed package bytes, asset bytes and the original public hash semantics. Record explicit legacy-to-Lore mappings. Backend assets in the inspected baseline include bytes stored in PostgreSQL, so do not assume all media already lives in object storage. [B5]

Avoid indefinite bidirectional dual writes. Before cutover, legacy storage owns the namespace. After cutover, Lore owns its canonical versioned content.

Recovery must account for writes accepted after cutover. Switching a flag back to old tables is not a valid rollback if that would discard new commits. Provide a tested forward-repair or reverse-migration procedure for the supported recovery window.

Account deletion, resource deletion, retention and existing publication removal must remain effective across both metadata and Lore-managed content.

## 17. Make the build and packaging reproducible

Pin all dependent Lore crates to a consistent fork revision, and retain lockfiles. The inspected source integration uses unpublished crates and workspace patches, including `quinn-proto` and `glob-match`. Cargo does not apply a dependency workspace's `[patch]` section to its consumer automatically. [L8]

Audit the resolved dependency graph and reproduce necessary overrides in the consuming workspace or use an equivalent controlled source layout. Do not treat an untested two-line Git dependency declaration as complete integration.

Verify Rust/toolchain, Axum, Tokio, SQLx, TLS and native-library compatibility at the selected revisions. Avoid duplicate incompatible versions of types crossing crate boundaries.

Expose the engine/fork revision in diagnostic version output. Document:

- Public API compatibility.
- SDK release and regeneration policy.
- Native library/ABI compatibility, when applicable.
- Repository/store format compatibility and upgrade procedure.
- Upstream update procedure and relevant fork modifications.

Keep generic fork changes separate enough to review for upstream contribution. Implement the authorized fork without waiting for upstream to accept those changes.

## 18. Operate and recover the integrated service

Document configuration, durable directories/stores, required database migrations, supported deployment topology, size limits and worker concurrency.

Provide health/readiness checks that distinguish initialization, writable storage, database availability, reconciliation backlog and shutdown. Do not report ready while the authoritative store cannot publish.

Use structured diagnostics for operation IDs, upload progress, conflicts, migration state and recovery. Avoid recording credentials, signed URLs or private file contents in routine logs.

Define backup and restore across Lore immutable/mutable stores and backend metadata. A backup of only the latest visible files is not a backup of the versioned system.

Document a consistency strategy for the backup boundary, and verify restoration of references, retained history, permissions, operation receipts and migration mappings.

Implement quotas and temporary-storage limits without race-prone check-then-write accounting. Explain how retained history, pending transfers and shared/deduplicated content count toward the product's limits.

Provide a local development setup that starts the actual integrated backend with persistent test storage. Keep optional native listeners and optional external providers disabled until configured correctly.

## 19. Verification gates

Use focused tests and end-to-end scenarios for the material failure modes. Reuse existing test infrastructure. Do not inflate the change with trivial tests that mirror private implementation details, and do not claim verification that was not run.

| Gate | Required evidence |
| --- | --- |
| Embedded lifecycle | Backend starts, serves, drains, stops and restarts without nested-runtime errors or leaked store locks; standalone Lore still works. |
| Identity reuse | Cookie and native-session routes identify the same account; invalid Bearer does not fall back to cookies. |
| Isolation | Another account cannot list, read by hash, download, mutate or finalize uploads for a repository it cannot access. |
| Transport parity | Every enabled HTTP/gRPC/QUIC path enforces the same effective repository policy. |
| Protocol credentials, when enabled | Wrong issuer/audience, expired tokens and unauthorized repository grants are rejected; key rotation and documented session/ACL revocation behavior work across enabled native transports. |
| Concurrent publication | Two writers with the same expected head cannot both overwrite the branch; the losing writer receives a recoverable conflict. |
| Operation recovery | Crash after Lore publication but before SQL receipt/response is recoverable without duplicate publication. |
| Video transfer | Interrupted large-file upload resumes after a server restart, verifies integrity and stays within a documented bounded-memory budget. |
| Historical content | Exact retained file/resource revisions and pinned dependencies resolve correctly under current policy. |
| Legacy compatibility | Existing create/update/delete/recreate, ETags, no-op writes, feed recovery and numeric revisions work before and after migration. |
| Migration fencing | A delayed legacy write cannot mutate the old authority after activation; interruption and retry preserve source bytes and IDs. |
| Product trust | Checkout/import does not bypass package verification, permissions, moderation or existing application-consent rules. |
| SDK consistency | Rust, TypeScript and Python perform the same upload/commit/conflict/download/retry scenario against the real API. |
| CLI synchronization | Clone from the real backend, create multiple commits offline, reconnect and push, then fetch and check out the exact revisions in a second working copy; verify ancestry, bytes, authentication and conflict handling. |
| Independent host | A non-TikTools example supplies its own verified identity/policy adapter and uses generic versioning without importing RemakeBackend. |
| Backup recovery | A restored development backup contains the expected refs, history, bytes, permissions and recovery metadata. |

Exercise failure boundaries deliberately, including cancellation and dropped responses. Test metadata/content mismatch and replay of an idempotency key with changed input.

Measure the large-file path with an input materially larger than the request buffer budget; document observed memory behavior and the test environment. Do not use a tiny fixture as proof of video scalability.

Once a gate resolves its concrete risk, stop redundant testing and proceed with implementation or delivery.

## 20. Implementation sequence and completion criteria

Work in coherent increments that build toward the complete architecture:

1. Audit and record chosen revisions, integration seams and existing contracts.
2. Establish the fork dependency/build layout.
3. Extract the embedded lifecycle while preserving standalone behavior.
4. Implement neutral identity/policy injection and the Better Auth host adapter.
5. Implement authoritative revision operations, atomic publication and operation recovery.
6. Add persistent resumable transfers and durable storage configuration.
7. Add the public API, capabilities and contract.
8. Implement the remote SDKs and Git-like workspace/CLI flow.
9. Connect backend domain adapters and exact historical resource resolution.
10. Implement the legacy compatibility facade and resumable migration/cutover.
11. Run the focused gates, document deployment/recovery, and deliver reviewable changes.

Do not stop at a design document, disconnected scaffolding or a series of unrelated patches. When a stage exposes a missing engine capability, add the smallest reusable capability that satisfies the architecture, then continue through the dependent integration.

Use existing repository and environment approval rules. Make ordinary implementation decisions from the code and this brief. If access or required credentials block one part, complete independent work and report the precise remaining blocker; do not claim the blocked acceptance gate passed.

### Definition of done

The delivered implementation must demonstrate this complete flow:

1. A user authenticates through the existing RemakeBackend Better Auth integration.
2. An authorized workspace resolves to its Lore repository.
3. A client uploads structured resources and a large binary asset with resumable transfer.
4. The client publishes one complete revision under an atomic expected-head condition.
5. Another client retrieves that exact revision through a different language SDK.
6. A concurrent edit produces a structured conflict without losing either client's work.
7. An interrupted publish is recovered using its original operation ID.
8. An existing v2 account migrates to its mapped default workspace and remains compatible.
9. A third-party example uses the generic interfaces without TikTools-specific dependencies.
10. The integrated service restarts with its history, permissions and operation state intact.
11. The CLI publishes multiple offline commits and another working copy retrieves their preserved history and content.

### Final implementation report

Report concrete outcomes in English:

- Repositories, branches and exact revisions used.
- What changed in Lore versus RemakeBackend versus client packages.
- Actual module names and key entry points.
- Authentication and authorization behavior.
- Public API and SDK usage examples.
- Migration/cutover and recovery procedures.
- Tests and end-to-end scenarios actually run, with results.
- Supported storage and deployment configurations.
- Remaining limitations or blocked gates, stated precisely.

Distinguish implemented features, validated behavior and future work. A limitation must not be presented as a working adapter.

## Source references for the inspected baseline

These links explain existing code observations. Requirements above remain the implementation target; the coding agent must verify actual APIs at the selected revision.

### Lore

- **[L1] Process lifecycle:** [server.rs](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/server.rs).
- **[L2] Extension seams:** [ServerConfig](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/server_config.rs), [gRPC builder](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/grpc/server.rs), [HTTP router](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/http/server.rs), [RepositoryAuthorizer](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/authnz/repository_authorizer.rs).
- **[L3] Local revision/store semantics:** [revision-tree module](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore/src/revision_tree/mod.rs), [commit](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore/src/revision_tree/commit.rs), [storage open](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore/src/storage/open.rs).
- **[L4] Publication/CAS:** [revision protocol](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-proto/proto/lore/revision/v1/revision.proto), [branch_push handler](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/grpc/handlers/branch_push.rs), [branch operations](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-revision/src/branch.rs).
- **[L5] Hook delivery semantics:** [hook traits](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/hooks/traits.rs).
- **[L6] Transfer implementation:** [HTTP content upload](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/http/repositories/repository/contents/put_repository_content.rs), [range handling](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/http/range.rs), [file ingestion](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore/src/storage/put_file.rs).
- **[L7] Storage integration:** [plugin traits](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/plugins/traits.rs), [AWS implementation](https://github.com/EpicGames/lore/tree/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-aws), [server configuration documentation](https://epicgames.github.io/lore/reference/lore-server-config/).
- **[L8] Workspace/build configuration:** [root Cargo.toml](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/Cargo.toml), [Lore manifest](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore/Cargo.toml), [server manifest](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/Cargo.toml).
- **Authentication discovery:** [OIDC implementation](https://github.com/EpicGames/lore/blob/e32aaac2b0b02ad9aa10723250b64ba86f125fe4/lore-server/src/auth/oidc.rs).

### RemakeBackend

- **[B1] Authentication/hosting:** [main.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/main.rs), [dual_auth.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/dual_auth.rs).
- **[B2] Legacy synchronization:** [workspace.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/workspace.rs), [portable contracts](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-contracts/src/portable.rs).
- **[B3] Product and publication behavior:** [packages.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/packages.rs), [library.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/library.rs), [cloud storage](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-storage/src/lib.rs).
- **[B4] Existing API/export contract:** [CLOUD-API-V2.md](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/docs/CLOUD-API-V2.md).
- **[B5] Existing asset/history behavior:** [assets.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/assets.rs), [overlays.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/overlays.rs).
- **[B6] Separate v1 synchronization:** [sync.rs](https://github.com/nglmercer/RemakeBackend/blob/6a69c99a3a134f3f76333316957d788f31d4f004/crates/cloud-api/src/sync.rs).

### Better Auth and the existing application

- **[A1] Session authentication:** [SessionService/AuthPrincipal](https://github.com/nglmercer/better-auth-rs/blob/d4bb1ff17400d424813fc0bd8800204faf088238/crates/better-auth/src/session.rs), [Axum extractors](https://github.com/nglmercer/better-auth-rs/blob/d4bb1ff17400d424813fc0bd8800204faf088238/crates/better-auth/src/axum_integration.rs).
- **[A2] Optional JWT integration:** [JWT signer](https://github.com/nglmercer/better-auth-rs/blob/d4bb1ff17400d424813fc0bd8800204faf088238/crates/better-auth/src/jwt_signing.rs), [authentication router](https://github.com/nglmercer/better-auth-rs/blob/d4bb1ff17400d424813fc0bd8800204faf088238/crates/better-auth/src/router.rs).
- **TikTools client integration:** [cloud client](https://github.com/nglmercer/TikTools-app/tree/4187ef2c6b592ef17166c7a29b1beb3416fe5327/crates/cloud-client), [synchronization core](https://github.com/nglmercer/TikTools-app/tree/4187ef2c6b592ef17166c7a29b1beb3416fe5327/crates/tiktools-cloud-sync), [application sync entry point](https://github.com/nglmercer/TikTools-app/blob/4187ef2c6b592ef17166c7a29b1beb3416fe5327/crates/tiktools-core/src/cloud_sync.rs).


