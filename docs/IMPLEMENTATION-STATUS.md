# Implementation status

The plan remains the source of scope; the project is not ready for deployment.

Foundation in this repository: Axum server, configuration validation, PostgreSQL adapter and secondary storage, explicit Better Auth migration command, health endpoints, Better Auth routes, cookie-protected `/api/v1/me`, optional Google provider, versioned Cloud migrations, pending publisher namespace requests and membership-scoped listing with an audit event, local PostgreSQL Compose file, and basic CI. Members may list their publisher membership; only an owner can add, change, or remove non-owner roles, with changes recorded in the audit table. Publisher namespace approval and a signing-key lifecycle are implemented; key enrollment and approval require session-bound step-up grants (password or Google reauthentication, single-use, five minutes, no bypass); ownership transfer uses a time-limited offer accepted by an existing member. The pinned auth library has sign-in second-factor challenges; a session-bound step-up integration for key enrollment remains unverified. Better Auth is pinned in the manifest and lockfile. Google provider token retention is not enabled.

Local checks on 2026-11-02: `cargo check --workspace`, `cargo test --workspace --locked` (one config test), and `cargo clippy --workspace --all-targets --locked -- -D warnings` passed. A fresh local PostgreSQL 18 database accepted `cloud-api migrate`; the running API returned 200 for liveness/readiness and 401 for anonymous `/me`. An additional PostgreSQL integration test exercises a local OAuth fixture through the Cloud router: PKCE initiation, state replay and unverified-email refusal, session restoration after reconstructing the app, CSRF rejection, cross-instance logout/revocation with and without cached cookies, and non-retention of provider tokens. It does not cover a real Google callback, an OS process restart, or the desktop flow. Docker Compose could not be exercised because the Compose plugin was unavailable. Better Auth declares Rust 1.89, while pinned TikTools packages require Rust 1.95.

Minimum compiler verification: `cargo +1.95.0 check --workspace --locked` and `cargo +1.89.0 check -p cloud-client --all-features --locked` both passed locally. CI repeats those declared minimum compiler checks. These were compile checks, not full test-suite runs under each compiler.

Still required include real Google OAuth E2E, process restart and native desktop client integration; static registry integration and signing; publisher authorization and audits; package upload, validation, moderation and publishing; opt-in sync and desktop integration; security/load testing, recovery drills, and independent review. See PLAN.md and ROADMAP.md for the full acceptance criteria. Migrations have no tested upgrade or rollback procedure beyond restoring a backup.

Publisher foundation verification: PostgreSQL integration tests passed for two users, including anonymous and cross-origin rejection, invalid and duplicate namespaces, membership isolation, pending status, and audit insertion. A fresh PostgreSQL database accepted the explicit Cloud migration. Key enrollment and approval require session-bound step-up grants; complete deletion handling remains unimplemented.

Membership verification: PostgreSQL integration tests exercised non-member isolation, owner-only role changes, cross-origin refusal, unknown users, owner protection, removal and redacted audit role transitions; a repeat role assignment produced no extra audit event. The test database was upgraded from the earlier publisher migration. Concurrent membership operations and account deletion have not been independently stress-tested.

Registry bootstrap verification: checked out TikTools PR #43 at `983a375c5b702681a791061ca863cea9c542528d`; its signed registry client round-trip, tampered/unknown-root rejection, and CLI scaffold/sign/publish tests passed locally. A separate disposable registry was generated using the pinned upstream CLI, and its output contained public registry documents and an archive, with no private key files. CI is configured to repeat these checks and generate a test artifact, but CI itself has not been run here. The generated artifact is now verified with the pinned TikTools registry client and its separately generated root pin, including signed index, archive digest, publisher signature, extraction, wrong-root, wrong-digest and tampered-index checks. A complete Desktop install has not been exercised. Official root provisioning, production signing, snapshot promotion and CDN rollback remain unimplemented; see REGISTRY-OPERATIONS.md.

OIDC verification: a local provider using Better Auth’s test-only HS256 validator exercised the Cloud callback over PostgreSQL. It accepted a valid ID token and rejected absent tokens, invalid signatures, missing or forged nonces, wrong audience, expired tokens, and state replay. A separate local OAuth collision test confirms a verified provider cannot attach to an unverified existing account, while the same provider email links to that account after local email verification; another test rejects an unverified provider email. The opt-in `google_jwks_live_refresh_smoke` test also fetched and parsed at least one current Google signing key through the pinned Better Auth provider. Run it with `cargo test --locked -p cloud-api google_jwks_live_refresh_smoke -- --ignored`; it uses placeholder OAuth client credentials and does not perform sign-in. CI skips this live-network check; run it separately. This proves initial endpoint reachability/key parsing only, not scheduled or unknown-key refresh, outage/staleness, a real callback, or Desktop behavior. Google JWKS policy remains configurable within bounded settings; changing it triggers synchronous reload because the upstream API replaces its cache.

Sync foundation: an experimental plugin-selection-only schema has per-user records, strong revision preconditions, tombstones, paged listing and a per-user ordered changes feed. PostgreSQL tests covered concurrent conflicting writes, stale edits, tombstones, account isolation and rejection of an unknown token field. Sync now limits records and retains at most the latest 10,000 changes after each write; expired cursors require a documented rebuild. Foreign keys delete sync state with the Better Auth user row. Desktop integration, full schema allowlists, complete Cloud account deletion/export, production abuse controls, secret-leakage review and the multi-device offline workflow remain outstanding; see SYNC.md.

Native transport foundation: `/api/v1/native/me` and native sync routes use Better Auth `NativeAuthUser` to accept bearer sessions without ambient cookies; browser sync remains cookie-only. PostgreSQL tests verified a native write, forged bearer rejection, separation of cookie and bearer routes, and bearer invalidation after account deletion. The backend now exposes a Better Auth single-use PKCE handoff; no Desktop UI, keychain integration, or actual Desktop client is yet wired.

Desktop handoff verification: local PostgreSQL and a Better Auth loopback receiver exercised CSRF and redirect refusal, wrong state, PKCE, single-use redemption, expiration and rate limiting. Redemption limits key per trusted client IP behind allowlisted proxies and fall back to the socket peer IP otherwise, with unit and PostgreSQL integration coverage for per-IP buckets and header stripping on untrusted peers; proxy deployment, real-browser testing, Google sign-in, real keychain use and independent security review remain outstanding. See DESKTOP-AUTH.md.

Proxy and authentication limits: Cloud strips supplied forwarding headers from untrusted peers and sets `X-Forwarded-For` to the socket IP. An allowlisted proxy may supply one valid client IP; malformed or multi-hop values fall back to the peer. Better Auth's built-in limiter uses shared secondary storage and a 10-attempt-per-minute budget per action and account/IP where available. Cloud separately limits GET social-login initiation to 10 per minute and OAuth callbacks to 60 per minute per IP, failing closed when identity or storage is unavailable. Local tests cover peer spoofing, IP/account isolation, social initiation and callback throttling across two API instances using PostgreSQL, a successful callback after exhausting the separate initiation budget, and the pinned Better Auth resolver. Configuration rejects invalid CIDRs and default routes; production firewall and proxy sanitization remain deployment checks.

Readiness verification: the PostgreSQL integration test checks missing, failed, changed and unknown Cloud migration records, absent auth/Cloud columns, and a closed pool. Liveness stays available. Readiness also checks required table privileges, but it does not verify column types, indexes, constraints, external services or successful application behavior; older binaries report unready when the database has newer Cloud migrations.

Publisher approval: Cloud roles can be granted or revoked by an explicit database operator command, with audited role changes. A non-member Cloud admin can approve a pending publisher, and the decision is audited; this does not confer signing trust. PostgreSQL tests covered self-approval refusal, CSRF, role revocation and audit events. Operator identity is a supplied label, role bootstrap is not production-hardened, and deleting a user can still remove the last admin. See PUBLISHER-APPROVAL.md.

Package verification: the standalone `cloud-verifier` crate copies and checks signed TikTools archives against independently supplied release metadata and a publisher key. Local tests exercised a valid upstream-generated package, forged or revoked/expired keys, digest/identity mismatch, content tampering, traversal and high expansion, plus the disposable CLI fixture. The one-shot worker now connects it to version-pinned uploads and approved-key records; an enforced worker sandbox and publication remain absent; the ClamAV adapter has simulated-protocol tests and a real-daemon smoke test with an artificial signature. See PACKAGE-VERIFICATION.md.

Step-up integration finding: in the pinned Better Auth revision, two-factor enrollment requires a password and the OAuth path refuses users with an enabled second factor rather than completing an OAuth second-factor challenge. Social-only users therefore cannot safely use this flow as-is; publisher key enrollment remains closed pending a suitable upstream integration.

Native sync client: the opt-in `cloud-client` library stages local plugin-selection edits, binds serialized state to origin and account, preserves pending edits on network errors and conflicts, supports cursor rebuilds and rejects HTTP redirects. Tests exercised two sessions against the Cloud API, conflict/rebase/delete, expired-cursor rebuild, offline preservation, account/origin isolation and token exclusion from serialized state. This is a reusable library, not a Desktop integration; keychain and local persistence adapters now exist, while UI integration, actual offline app behavior and broader schemas remain outstanding.

Local sync persistence: `StateStore` adds versioned, generation-checked state files with advisory locking, atomic replacement and Unix file/directory syncing. Tests covered stale local writers, invalid files, private directory handling and a local API reconnect after persisting an offline edit. This does not integrate with Desktop or an OS keychain; Windows ACLs and crash recovery remain unverified.

Desktop login client: the Cloud consent page resumes after the upstream Google callback, and `cloud-client` supplies PKCE generation, Better Auth loopback reception, optional system-browser opening and a bearer logout method. An optional OS keychain adapter uses platform backends directly. Local PostgreSQL tests exercised the native handoff and logout; JavaScript tests use DOM mocks and keychain tests use a mock credential. Real Google, system browser, OS keychains, cross-platform builds, and TikTools Desktop integration are not verified.

Object-storage foundation: `cloud-storage` can generate constrained S3 quarantine upload URLs, require bucket versioning, capture a version and stream it with a digest check. Local unit tests inspect signed headers; a disposable Moto smoke test exercised conditional PUT, version capture and digest checking. An API integration test exercises authorization and concurrent completion against a simulated S3 endpoint. The authenticated API now creates idempotent, publisher-authorized upload reservations and queues immutable versions; a one-shot worker now checks integrity once release metadata is attached; a ClamAV adapter is connected, while publication is not implemented. A moderation API records independent decisions and issues short-lived version-bound inspection URLs; an isolated inspection environment is not provided. Moto is not proof of real S3 signature/IAM behavior. A later disposable MinIO smoke test passed; see OBJECT-STORAGE.md.

Publisher signing-key lifecycle: challenge-based proof of possession, independent approval, scoped listing and irreversible revocation are implemented and exercised by integration tests. The server requires a session-bound step-up grant for challenge issuance, enrollment, and approval; revocation remains available. The integrity and initial-candidate workers read these records; no public registry is deployed. See PUBLISHER-KEYS.md.

Release submission and integrity worker: an authenticated request binds a quarantined upload to namespace-scoped metadata and an approved publisher key. A one-shot worker claims it with a fenced lease, downloads the recorded object version, verifies digest and package integrity, and rechecks key authorization before recording the result. ClamAV scanning is connected; the full worker is tested with a simulated scanner, and the adapter has a separate real-daemon smoke test; moderation decisions are implemented, but an isolated reviewer environment and publication remain absent, and the process sandbox and real storage still require validation. See RELEASE-VERIFICATION.md.

Moderation: reviewers with a Cloud admin or moderator role can list eligible, antivirus-passed releases and record one independent, audited decision. Approval rechecks publisher and key status; conflicts of interest, competing decisions, and decisions on yanked releases are refused. Reviewers can request short-lived version-bound inspection URLs, refused once a release is yanked; the service does not provide an isolated review environment, appeal or reversal, and does not publish an artifact. Independent reviewers can also permanently yank a release, which blocks publication requests, preparation, approval, and snapshot candidacy, and can record or replace a severity-graded security advisory, which the snapshot builder carries into candidate registry documents for the verifier to recheck. All yank, advisory, decision, and inspection actions are audited, and the release, review, and moderation-queue read APIs expose the yank and advisory state. See MODERATION.md.

Publication request: an independent moderator or admin can queue a reviewed release after rechecking publisher, key, antivirus and review state and refusing yanked releases. A one-shot preparer now reverifies, rescans, and stores a read-back-verified private object version with fenced leases. The response still reports end-to-end publication as unavailable. An initial-only candidate worker now signs and stages private files, but no public release or deployment worker exists yet; see REGISTRY-OPERATIONS.md.

Snapshot candidate builder: the standalone `cloud-snapshot` library checks independently pinned and root-signed trust material, verifies an explicitly supplied release inventory, and uses the pinned TikTools writer to produce and recheck a private signed candidate. A real TikTools client verified the local candidate in tests. An initial-candidate worker now reads every prepared job, checks its current authorization, rescans and builds a candidate, and records privately staged file versions after inventory rechecks. A yanked release fails the authorization check and blocks the candidate; recorded advisories are carried into the registry documents. It does not handle an existing published inventory, guarantee later authorization, or deploy. See REGISTRY-OPERATIONS.md.

Initial candidate worker: an operator command connects prepared jobs to the signed candidate builder, stores versioned private files and records an inventory digest. It is restricted to an empty initial seed, uses point-in-time checks, and has no promotion or cleanup. Simulated-storage tests cover authorization changes and corrupt read-back; real storage, scanner, KMS and deployment remain unverified.

Candidate export: an operator command reconstructs a private candidate from exact stored versions and checks hashes and a stable database manifest before writing a completion marker. Tests verify the reconstructed registry with the pinned TikTools client and reject corrupt data or a changing manifest. Export does not establish current authorization or deploy the candidate.

Candidate verification: an operator command reconstructs a private candidate and
checks its stored hashes, registry signatures against independently supplied public
pins, release links, current point-in-time authorization, and initial candidate
index and catalog completeness against that inventory. It also compares independently
supplied signed policy and rejects revoked digests. It reverifies package
signatures and rescans candidate artifacts, but does not authorize promotion;
changes can occur after it returns. Scanner integration is tested with a simulated
service, not a production ClamAV deployment. See REGISTRY-OPERATIONS.md.

Promotion readiness: an operator command runs the point-in-time candidate
verifier and records a `verified` or `blocked` decision with the operator
label, reason, the candidate's pinned inventory hash, and an audited event. A second operator command lists the recorded decisions for a candidate as JSON. Recording a decision performs no
deployment, changes no release status, and is not approval to deploy; a future
promotion process must still recheck inventory, authorization, trust, scanner
policy, and stored versions atomically. A PostgreSQL integration test covers
verified and blocked decisions, the audit events, and rejection of invalid
decisions, operator labels, reasons, and unknown candidates. See
REGISTRY-OPERATIONS.md.

Real ClamAV adapter smoke test: ClamAV 1.4.6 in a disposable local container,
with an isolated custom signature database, returned clean and detected results over
INSTREAM for the Rust adapter, including detection within a deflated ZIP archive.
This does not validate production signatures, other archive formats, scanner
configuration, or freshness; the test is opt-in.

MinIO smoke test: a disposable MinIO 2025-04-22 server enforced signed upload headers, checksum and conditional writes, and supported version-pinned quarantine and prepared-object readback. A privileged overwrite of the quarantine key produced a different current version while the captured version remained downloadable with the original bytes. This is local emulator evidence only; production S3, IAM and retention remain unverified. See OBJECT-STORAGE.md.

Sync export: authenticated browser and native endpoints return a bounded, consistent
snapshot of the current allowlisted sync records and tombstones. PostgreSQL tests
cover account isolation, authentication, cache headers, and fail-closed handling of
unexpected stored fields. It is not a complete account export or deletion workflow.

Account deletion guard: restrictive foreign keys prevent auth-user deletion while
Cloud roles or publisher memberships remain, requiring explicit role and membership
removal. Existing orphan memberships block migration for investigation. This is
not complete account deletion: social-only reauthentication,
audit retention, and user-facing error handling remain unfinished.

Publisher ownership transfer: the owner offers to an existing member, who must
accept a unique expiring offer. Role updates and audits are transactional; replaced,
expired, cancelled and replayed offers fail. This uses existing session/CSRF checks
and now provides session-bound step-up authentication (password and Google, single-use five-minute grants); a notification UI is still absent.

Publisher departure: a non-owner can leave their own publisher membership with an
audited, CSRF-protected request; an owner must transfer ownership first. Leaving
invalidates a pending offer to that member.

Deletion preparation: authenticated browser and native endpoints list the caller’s
Cloud roles and paginated publisher memberships. A CSRF-checked browser endpoint lets
users revoke their own Cloud roles before account deletion; it serializes with
operator role changes, protects the final admin and records an audit event. Together
with publisher departure and ownership transfer, this resolves Cloud authorization
blockers. Better Auth still requires its own account-deletion reauthentication;
social-only reauthentication, a user-facing deletion flow and audit retention policy
remain unfinished. A bounded Cloud account export now covers profile, roles,
memberships, user-requested publisher metadata, authored moderation/publication/audit
activity including recorded yanks and advisories, and current validated sync records.
It excludes credentials, tokens, signed
URLs, object keys and version IDs; it is not a full identity-provider or backup export.
The PostgreSQL 18
integration test passed with cross-origin refusal, successful self-revocation,
audit verification and final-admin protection coverage.

Regression verification: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, the workspace unit suites, all-feature Cloud client tests, desktop-login JavaScript tests, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps` all pass, as do the minimum-compiler gates (`cargo +1.95.0 check --workspace --locked`, `cargo +1.89.0 check -p cloud-client --all-features --locked`). The CI-selected ignored PostgreSQL suite passes 27/27 on a fresh disposable PostgreSQL 18 database, including migration 20, stale-manifest rejection, OAuth rate limits and the native client account-export path. It also covers candidate build/export/verification, promotion decisions and listing, yanks and advisories with pipeline enforcement and read-API visibility, migration upgrades with data preservation, and per-IP redemption limiting. The live Google JWKS and real-ClamAV smoke tests run separately as described above. CI itself was not run here.
A separate live smoke test ran the documented flow end to end on a fresh disposable
PostgreSQL 18 database: `cloud-api -- migrate` applied the 19 Cloud migrations then present,
and the serving binary returned 200 for liveness and readiness and 401 for
anonymous `/api/v1/me`.

Sync write throttling: browser and native writes share a 120-per-minute account
limit backed by Better Auth secondary storage. A PostgreSQL integration test checks
shared limits, account isolation, unchanged cursor on rejection, and preservation of
native pending edits. Separate per-account limits now cover sync reads and export;
deployment-wide abuse controls remain open.

Transient job recovery: operator commands can requeue failed verification and
publication-preparation jobs only when their result is `temporary_failure` and their
release remains in the expected state. Concurrent attempts produce one audit event;
workers recheck authorization and artifact integrity. Tests use PostgreSQL and
simulated storage/scanner services. Blocked, rejected and already prepared jobs are
not recovered by these commands, and the operator label is not authenticated.

Blocked publication recovery: a currently authorized independent moderator can
re-request a job blocked by an authorization change. The API rechecks current
release, upload, key and review state and assigns the new requester transactionally;
the worker rechecks it again. PostgreSQL tests cover revoked roles, revoked keys,
concurrent repeat requests, auditing and renewed worker fencing.

Migration and restore drill: a PostgreSQL 18 integration test applied Cloud
migrations through `20261102000014`, inserted existing memberships, and verified
that the next migrations reject orphan memberships and duplicate owners before
succeeding after correction. A second drill upgrades a populated database from
migration 16 to 19, verifies publishers, memberships, roles, keys, uploads,
releases, verification, moderation, publication, and candidate rows all survive,
checks the backfilled promotion-check inventory hashes, and exercises the new
yank, advisory, and promotion-check tables against the preserved rows. A separate disposable `pg_dump`/`pg_restore` drill
restored a test database with the same user, publisher, membership, audit and
migration counts and retained the owner-deletion foreign-key guard. This is a local
database-only drill; production-sized recovery, object versions, secrets, backup
retention and point-in-time recovery remain untested.

pgrust migration verification on 2026-11-03: dev, prod-overlay, and CI database
images moved to self-hosted `malisper/pgrust:v0.4-beta`; no external database
remains. A standalone pgrust container reported
`PostgreSQL 18.6 (pgrust 0.4-beta)`, accepted `cloud-api migrate` (Better Auth
migrations plus all 20 Cloud migrations), and passed the full workspace unit
suite plus the ignored disposable-database integration suite (27 passed,
0 failed). JWKS policy mapping and the default-policy startup-reload skip are
now covered by offline config tests; rotation, outage, and unknown-key refresh
remain upstream library behavior covered only by the ignored live-network
smoke test. The Compose file itself is still unexercised here because the
Compose plugin is unavailable; the container was started with equivalent
`docker run` settings.

Account deletion verification on 2026-11-03: `DELETE /api/v1/me` requires a
session and trusted origin, rejects empty passwords (400) and wrong passwords
(403) without writing anything, refuses social-only accounts without a password
credential (409) and blocked accounts with roles or memberships (409), then
removes the auth identity, sessions, sync records, and cursor, records one
`account.deleted` audit event, and clears the session cookie (204). Audit
events and shared pipeline rows are retained under the opaque user id. A
wrong-password attempt that previously recorded a deletion event before failing
was caught by the new test and fixed by verifying the password before any
Cloud-side mutation. The RESTRICT guards remain the backstop against a
concurrent membership or role racing the delete; that race reports 500.
Native (Bearer) deletion is not implemented because the library flow resolves
cookie sessions only.

Admin web foundation and read APIs: `GET /api/v1/admin/overview` (publisher/release/status counts, pending keys, audit total), `GET /api/v1/admin/publishers?status=&cursor=&limit=` (oldest-first keyset pages of id/namespace/status/createdAt, no user secrets), and `GET /api/v1/admin/audit?cursor=&limit=` (newest-first redacted projection: opaque IDs, actions, role names, links only) are Cloud-admin-gated with `no-store` on every route. PostgreSQL integration coverage asserts anonymous 401, non-admin 403, malicious filters/cursors/limits failing closed with 400, cursor pagination without repeats, exact audit key sets with no secret-bearing fields, and revocation taking effect immediately. `web/admin/` is a Vite + Vue 3 + TypeScript app (Vue Router, TanStack Query, Pinia for client-only UI state, ES/EN i18n) with `/login`, `/auth/callback`, `/app` (dashboard, publishers, moderation, audit, portal, account), `/403`, and `/logout`; cookie sessions only, CSRF via Better Auth endpoints, no tokens in web storage (asserted by a storage spy test), and key enrollment/approval reauthenticate through a step-up dialog (password or Google) before spending single-use grants. Frontend checks: `npm run build` (vue-tsc + vite), `npm test` (12 vitest cases), and a Playwright cookie/CSRF spec against the real server. Deployment hardening is documented in `docs/ADMIN-WEB-DEPLOYMENT.md` with an example single-origin nginx config in `deploy/admin-reverse-proxy.example.conf`. Real-browser E2E, real Google OAuth, production proxy deployment, and independent security review remain outstanding.

Publisher self-service portal verification on 2026-11-03:
`GET /api/v1/publishers/{id}/releases` lists a member publisher's releases
newest-first with keyset cursor pagination, joining upload digests/sizes,
key identity, yank/advisory state, moderation decisions, and verification job
status; non-members and members of other publishers get 404, unknown cursors
and out-of-range limits get 400, and every route carries `no-store`. The Vue
portal now requests namespaces, renders pending/approved/suspended states,
manages members (owner-only role changes and removals, self leave with an
owner-transfer guard), drives ownership offers/accepts/cancels, lists signing
keys with fingerprint and status plus confirmed revocation, and submits signed
releases through a validated wizard (approved publisher and key selection,
local ZIP/size/SHA-256 checks, idempotent reservation, direct-to-quarantine
PUT, version-pinned completion, metadata submission) with distinct
expired-URL, failure, and retry states in English and Spanish. New PostgreSQL
integration tests cover listing scope/pagination/composed fields, expired
reservation completion (410), and revoked-key submission refusal; new vitest
cases cover namespace validation, member/key management gating, release
rendering and pagination, and the full wizard order plus local validation and
expired-URL recovery. `cargo fmt`, `cargo clippy -- -D warnings`,
`cargo test --workspace --locked`, `npm ci`, `npm run typecheck`,
`npm test` (38 cases), and `npm run build` passed; new database tests ran
against a disposable local pgrust database. Real storage, real browser E2E,
and publication remain unverified here. See PUBLISHER-PORTAL.md.

Registry publication verification on 2026-11-03:
Persistent generations (`cloud_registry_generations`, `_releases`, `_files`,
`_promotions`) track published snapshots, immutable versioned artifacts,
candidate-to-generation mapping, manifest hashes, and promotion/rollback/GC
history with operator identity. `snapshot_publish::publish` promotes a
verified candidate to a new generation after rechecking manifest/inventory
hashes, publisher/key authorization, moderation, yanks, advisories,
signatures, object versions, digests, and the current root/delegated policy
under an advisory lock; the active pointer flips atomically and reruns are
idempotent. `rollback` restores only generations that revalidate against
current trust and security state and refuses compromised, revoked, yanked, or
stale targets. `gc` collects staged leftovers, redundant published candidate
files, and consumed staging originals with a per-run bound. Public routes
serve the registry without Cloud authentication (`/current` uncached,
generation files immutable with ETags). New pgrust integration tests
(`registry_tests`, 10 cases) cover initial and incremental publication,
concurrency, changed authorization, revoked keys, yanked releases and
advisories, corrupt and forged artifacts, interrupted-upload resume, atomic
switching and caches, restart recovery, safe/unsafe rollback, GC, and real
TikTools registry-client compatibility (refresh, discover, download, offline
signature verification, install, update, yank removal, wrong-root and
digest-mismatch rejection). `cargo fmt`, `cargo clippy -D warnings`,
`cargo test --workspace --locked` (excluding ignored), and the 10 ignored
database tests on a disposable local pgrust passed; web code is untouched by
this branch. Real S3/ClamAV, Cloud authentication for operator commands, and
production trust/deployment remain unverified. See REGISTRY-OPERATIONS.md.
