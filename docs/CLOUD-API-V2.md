# Cloud API v2

The product consumes one operator-configured RemakeBackend instance. All paths
below are relative to that origin. Requests cannot add a registry, select an
external source, upload root trust pins or change the instance URL. Operators
configure the origin, storage and signing material when deploying; the future
Desktop build must independently pin that instance and its trust roots.

The implementation plan and repository boundary are in
[CLOUD-REDESIGN.md](CLOUD-REDESIGN.md). This API does not change Desktop, the
local control protocol or LIVE collaboration.

## Authentication and transport

Public catalog and capability routes are anonymous. Library, workspace sync
and v2 account export accept a native Better Auth bearer session, or a browser
session cookie with the existing trusted-origin/CSRF checks. An Authorization
header selects native authentication; an invalid bearer never falls back to
an ambient cookie. Moderation routes remain cookie-only and require a live
`moderator` or `admin` role. Author approval is refused even for an admin.

All v2 responses use `Cache-Control: no-store`. Registry generation files
retain their existing immutable caching rules. The body limit is 256 KiB plus
1 KiB for the request envelope; each portable document itself must fit 256 KiB.
Malformed and unknown fields are rejected. This is additive to v1; none of the
existing cookie/native identity, publisher, upload or registry routes move.

## Instance discovery and plugins

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v2/capabilities` | API version, single-instance policy, relative routes, collections and limits |
| GET | `/api/v2/catalog/plugins` | Generation-scoped plugin listing |
| GET | `/api/v2/catalog/plugins/{id}` | Published versions, targets, sizes, digests and signed metadata path |
| GET | `/api/v2/catalog/pagination-capabilities` | Additive bounded-pagination routes and limits |
| GET | `/api/v2/catalog/plugin-summaries` | Byte-bounded plugin summaries |
| GET | `/api/v2/catalog/plugins/{id}/version-pages` | Byte-bounded version rows for one plugin |

Plugin queries accept `q` (at most 100 bytes, literal substring of the plugin
ID), `after` (plugin ID), `target`, and `generation` (positive integer).
Listings return at most 50 plugins, `nextCursor` and `generation`. Pass the
returned generation with the next page to keep the inventory stable across
publication. Without an active generation, listing returns an empty catalog
and `generation: null`; an unknown/unpublished requested generation or plugin
returns 404. Staged generations never appear.

Plugin IDs use ascending ASCII byte order for both listing and the exclusive
`after` cursor. These queries explicitly use PostgreSQL `COLLATE "C"`, so a
database's default locale does not change page order or cursor boundaries.
Catalog IDs follow the release manifest grammar: 2–128 ASCII bytes, starting
with a lowercase letter and followed by lowercase letters, digits, `.`, `_`
or `-`. V2 workspace plugin keys accept this grammar plus previously accepted
numeric-leading dotted keys; v1 sync retains its original separate grammar.
Official legacy release IDs include `hotkeys` and `textintel`, which have no dot.
For an ID whose second shard would be the literal `..` (for example `ab..c`),
new registry candidates use `index/ab..c.json` and its `.sig` sidecar instead
of an unsafe parent-directory component. Other IDs retain their prior paths.
Existing immutable generations are not rewritten by this change: audit them
and, where necessary, build and promote a new signed generation before relying
on the new path. Older clients also need the updated shard handling for these IDs.

Versions sort by semantic version. Release submission accepts canonical semantic
versions of at most 128 bytes; catalog clients must preserve the same bound.
`latestStableVersion` excludes prereleases,
yanked releases, revoked publisher keys and unapproved publishers. Current
yank, advisory and authorization state is read even when the inventory is
pinned to an older generation. `metadataPath` points to this instance's
existing signed index document; its `.sig` sidecar and package signatures
remain authoritative. Catalog JSON and its digests never replace independent
signature verification or root pins. Discovery searches plugin IDs; rich
display metadata remains in the signed package documents.

### Bounded plugin discovery

The additive bounded routes leave the original `/plugins` responses and the
closed `/api/v2/capabilities` object unchanged. They do not establish trust.
The separate pagination-capabilities route returns their paths, schema version,
maximum 50 items and 512 KiB serialized JSON per page.

`plugin-summaries` accepts `q`, `target`, `generation` and `cursor` and returns
`{generation,items,nextCursor}`. Each item has `id`, `metadataPath` and
`latestStableVersion`; the latter uses all matching versions and the current
yank/publisher/key state. `generation` is a decimal string in responses and
an integer query parameter. Without an active generation the first page is
empty and its generation is null. Pass the returned generation and the same
`q` and `target` with `nextCursor` on every continuation.

`plugins/{id}/version-pages` accepts `target`, `generation` and `cursor` and
returns `{generation,id,metadataPath,items,nextCursor}`. Items have the same
version metadata and current status fields as the old detail response, except
that `size` is a decimal string. Order is ascending ASCII byte order of the
`(version,target)` pair, not semantic-version precedence. The continuation is
exclusive; it binds the plugin ID, generation and target. Version membership
is pinned to the generation while yanks, advisories and authorization are
observed independently on each request and must be rechecked before install.

Both cursors are bounded, opaque base64url values. A cursor reused with another
generation or filter is rejected with 400; an unavailable generation or plugin
returns 404. A page never silently truncates a record: if a single row exceeds
the limit, the request returns 413. Empty final pages are possible after a valid
cursor; nextCursor is null on the last page.

## Private template and profile library

| Method | Path | Result |
| --- | --- | --- |
| GET, POST | `/api/v2/library/documents` | List own documents or create a private revision |
| GET, PUT, DELETE | `/api/v2/library/documents/{id}` | Read latest draft, append a revision or delete all revisions |
| GET | `/api/v2/library/documents/{id}/versions` | List own revision metadata |
| GET | `/api/v2/library/documents/{id}/versions/{revision}` | Read a specific own revision |
| POST | `/api/v2/library/documents/{id}/versions/{revision}/submit` | Submit a draft for independent review |
| POST | `/api/v2/library/documents/{id}/versions/{revision}/withdraw` | Author withdrawal with a reason |

Create takes `{"kind":"template","document":{...}}` or kind `profile`.
The `.tiktemplate.json` / `.tikprofile.json` v1 object is stored as JSONB in
`document`; the envelope is not itself an interchange document. PostgreSQL
normalizes numeric representations, so original upload bytes are not retained.
Duplicate
`(owner, kind, document.id)` creates return 409. Read responses contain `id`,
`kind`, `slug`, `revision`, `title`, `sha256`, `status` and `document`.

`sha256` is the lowercase SHA-256 of `serde_json::to_vec(document)` after
decoding the actual stored JSONB value, using the backend/SDK serde JSON
contract, including round-trip float parsing. It is not a hash of the upload
bytes or PostgreSQL's whitespace-bearing `jsonb::text`. Create and update hash
the `INSERT ... RETURNING document` value inside the transaction and revalidate
its portable limits before commit. A value such as `1e18` can become the integer
`1000000000000000000`; `-0.0` can become `0.0`. Readers validate the stored
identity before returning either metadata or content. A mismatched digest or
nonportable stored body returns 503; it is never silently repaired on read.

PUT takes `{"document":{...}}` and `If-Match: "N"`. The kind and interchange
document ID cannot change. Each edit appends a new immutable document revision
and leaves any public pointer untouched. DELETE also requires the current
revision's strong ETag and removes all versions. Missing preconditions return
428; stale revisions return 409. Cross-account access returns 404.

Lists accept `after` (UUID), `kind` and `q` (literal title substring), returning
50 items and `nextCursor`. Revision lists accept numeric `after`, returning
50 revision metadata entries. Content limits are 100 documents, 100 revisions
per document and 8 MiB of JSONB document text per account, including history.
Quota violations return 507. Private reads share the 300/minute read budget;
library writes allow 60/minute per account. Owners serialize quota checks in
the transaction, so concurrent creates cannot bypass quotas.

### Auditing and repairing legacy derived digests

Deployments created before stored-value hashing can contain a digest of the
pre-JSONB input. Migration `20261108000002` adds only a metadata repair audit
table; it does not rewrite existing digests, content, approvals or publication
pointers. Back up the database, apply the migration, deploy the corrected
binary, then use the explicit operator commands:

```sh
cloud-api audit-library-digests
cloud-api audit-library-digests AFTER_DOCUMENT_UUID AFTER_REVISION
cloud-api repair-library-digest DOCUMENT_UUID REVISION OLD_SHA256 NORMALIZED_SHA256 OPERATOR
```

The audit scans 100 revisions per page in document UUID/revision order and
prints mismatches as `items` plus `nextAfter`. Continue using the returned
cursor even when `items` is empty: the cursor tracks scanned rows, not just
invalid rows. Each item contains the document UUID, revision, status, stored
and normalized digests, and whether the stored document remains portable.
No document body, account credentials or secret values are printed. Audit is
read-only and is not a transactionally frozen global snapshot; repair checks
the reviewed tuple again under row locks.

Repair requires both exact hashes from a reviewed audit item and a nonempty
operator identifier of at most 200 bytes. It refuses changed hashes/source,
missing revisions, invalid arguments and nonportable documents. It updates
only `sha256` and atomically records old/new hashes, document UUID, revision,
operator and timestamp in `cloud_library_digest_repairs`. The document JSONB,
revision, review status, reviewer, reason and public pointer remain unchanged;
the operation never submits or republishes content. Repeating an already
applied old-hash tuple conflicts. Repair evidence survives document/account
deletion as metadata, consistent with the existing audit log.

The normalized digest restores the identity of the stored typed body. It
cannot reconstruct or authenticate original upload bytes that were never
retained. Until a mismatch is explicitly repaired, reads, exports, submission
and moderation decisions fail closed with 503. Withdrawal and deletion remain
available. A nonportable body requires withdrawal or a new valid revision;
changing a digest cannot make unsupported content acceptable.

## Public documents and moderation

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v2/catalog/documents` | Current independently published revisions |
| GET | `/api/v2/catalog/documents/{id}` | Current public revision and interchange object |
| GET | `/api/v2/catalog/documents/{id}/versions/{revision}` | A specific published revision |
| POST | `/api/v2/catalog/documents/{id}/fork` | Copy a published template/profile into the caller's private library (additive) |
| GET | `/api/v2/moderation/documents` | Pending documents from other authors, including content |
| POST | `/api/v2/moderation/documents/{id}/versions/{revision}/decision` | Independent approval or rejection |
| POST | `/api/v2/moderation/documents/{id}/versions/{revision}/withdraw` | Moderator withdrawal |

The state machine is `draft -> pending -> published | rejected`; any existing
revision can be withdrawn. Only drafts can be submitted; repeated submission
of a pending revision is idempotent. A rejected revision must be edited into
a new draft before resubmission. Decisions take
`{"decision":"approve","reason":"Reviewed actions and parameters"}` or
`reject`; withdrawal takes `{"reason":"Outdated instructions"}`. Reasons are
required and limited to 500 bytes. Decisions and withdrawals are audited.

Approval revalidates the stored document. Approving an older revision cannot
roll the public pointer back. Earlier approved revisions remain addressable
until individually withdrawn or the document/account is deleted. Withdrawing
the current revision clears its public pointer and never silently restores
older content. Public readers receive 404 for drafts, pending, rejected or
withdrawn revisions. A downloaded copy cannot be remotely recalled.

The review queue emits the oldest pending revision of each document, with
UUID pagination. Refresh from the first page after decisions to discover the
next pending revision of documents already processed. Its read budget is
300/minute; decisions and moderator withdrawals share 60/minute per reviewer.

### Forking a public document

`POST /api/v2/catalog/documents/{id}/fork` (session cookie or native bearer, like the
library) copies a template or profile that is **visible in the public catalog** into the
caller's own library as a new private draft. `{id}` is the public document id. The body is
empty, `null` or `{"revision": N}`; without `revision` the current published revision is
copied, with it any revision that is still `published` (the ones addressable through
`/catalog/documents/{id}/versions/{revision}`). Anything else in the body, and a
non-positive revision, is 400.

- `201` with `ETag: "1"` and the create acknowledgement plus provenance:
  `{"id":<new id>,"revision":1,"status":"draft","forkOf":{"documentId":<source>,"revision":N}}`.
- `404` when the document or revision is not published (draft, pending, rejected,
  withdrawn, unknown) or the id is not a template/profile; `401` without a session; `400`
  for a malformed id or body.
- `409` when the caller already owns a document of that kind with the same portable `id`
  (this includes forking the same document twice and forking your own published document).
  The copy keeps the source's `id`, as the validators require the slug to equal it; the
  portable value is copied byte for byte, so rename it with `PUT` afterwards if needed.
- `507` when the account already has 100 templates/profiles or 8 MiB of stored template
  and profile revisions (the same quotas as create, enforced under the same account lock);
  `429` over the 60/minute library-write limit. Responses are `no-store`.

**Provenance is row metadata, not part of the portable value.** It is stored in
`fork_of_document` / `fork_of_revision` on the library document row (migration
`20261111000003`) and returned as `forkOf` on the caller's own `GET`/`list`,
`versions`, `versions/{revision}` and `/api/v2/me/export` entries, only when present.
It never appears on public catalog responses and is not inside `document`, so the
template and profile validators and the `sha256` digest are unchanged and older clients
that read only `document` keep working. If the source revision or its document is later
deleted, `forkOf` is cleared (`ON DELETE SET NULL`) and the copy remains a normal draft.
Not done on purpose: profiles have no `parentId`, branch or lineage fields, and the
portable profile shape was not extended.

Compatibility: the `cloud-client` in this repository accepts `forkOf` on private
document metadata and refuses it on public documents. A client built before this change
validates library metadata with `deny_unknown_fields` and will report a protocol error
when it reads a forked document; roll such clients forward before enabling fork.

The v2 library routes and quotas now consider only templates and profiles. Overlays and
packages created through `/api/v3` live in the same table and previously made the v2 list
and export fail with 503; they are filtered out (see [CLOUD-API-V3.md](CLOUD-API-V3.md)).

The admin web panel links from release moderation to **Cloud document
moderation**. Reviewers can inspect the complete pending document and its
revision and digest before approving or rejecting it with a reason. The
published tab reads the exact displayed public revision before offering
withdrawal. The panel refreshes the queue after each attempt and does not
automatically retry an uncertain decision. Historical published revisions
remain addressable through the versioned API, but are not discoverable in this
panel. The server continues to enforce cookie authentication, current roles,
independent review and audit; a Cloud approval does not authorize local
execution. Component tests and a Chromium layout check use mocked HTTP. A
separate Playwright test exercised the built panel against a disposable local
PostgreSQL database and real cookie sessions: an author could not approve their
own revision, an independent moderator approved it, and the moderator then
withdrew the published revision. This does not establish a production
deployment or broader operational acceptance.

## Workspace synchronization

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v2/sync/head` | Current account cursor |
| GET | `/api/v2/sync/write-epoch` | Current account write epoch as a decimal string and whether it is required |
| POST | `/api/v2/sync/write-barrier` | Advance the account write epoch and return the new value |
| POST | `/api/v2/sync/require-write-epoch` | Irreversibly require fenced v2 writes for this account and advance its epoch |
| GET | `/api/v2/sync/collections/{collection}` | Key-paginated records, including tombstones |
| GET, PUT, DELETE | `/api/v2/sync/collections/{collection}/{key}` | Read or conditionally mutate one record |
| GET | `/api/v2/sync/changes?cursor=N` | Ordered incremental changes |
| GET | `/api/v2/sync/export` | Consistent bounded snapshot for rebuild/backup |

| Collection | Key | Value |
| --- | --- | --- |
| `plugin-selections` | plugin ID | `{schemaVersion:1,pluginId,version,enabled}`; semantic version up to 128 bytes |
| `rule-templates` | document ID | Original template v1 object |
| `profiles` | document ID | Original profile v1 object with inline templates |
| `plugin-settings` | plugin ID | `{schemaVersion:1,pluginId,settings:{...}}` |
| `preferences` | `desktop` | `{schemaVersion:1,theme?,locale?,reducedMotion?,updateChannel?}` |
| `variables` | variable name | `{schemaVersion:1,name,type,value}` with `type` one of `text`, `number`, `boolean`, `list` (see below) |

Preferences allow `system/light/dark`, a bounded locale identifier, a boolean
and `stable/beta`, respectively. Unknown preferences and collections fail
closed. Plugin/document IDs are validated by `cloud-contracts`.

### Variables collection

`variables` is a sixth, credential-free collection for the runtime variables ("globals") of
the desktop. It uses exactly the same routes, ETag / `If-Match` / `If-None-Match`
preconditions, tombstones, change feed, snapshot, write-epoch fence, 120/minute write limit
and 1,000-record / 8 MiB account quotas as the other collections; its records count toward
those totals. There is no parallel implementation: `cloud-contracts` validates it and the
existing `PUT`/`DELETE` path stores it. Migration `20261111000002` only widens the table's
`collection` CHECK.

| Part | Rule |
| --- | --- |
| Key | the variable name: `^[A-Za-z_][A-Za-z0-9_.-]{0,63}$` (the desktop's runtime-global key rule, `validate_key` in `tiktools-core`); case-sensitive |
| `name` | must equal the key |
| `schemaVersion` | `1` |
| `type` | `text`, `number`, `boolean` or `list`. **`secret` (and anything else) is rejected: secrets never sync** |
| `value` | `text`: string of at most 4,096 bytes (may be empty). `number`: a finite JSON number. `boolean`. `list`: at most 100 strings of at most 256 characters each |

Fields are closed: any other field, a missing field or a wrong value type is 400, and the
portable credential guards still apply to values (for example a `Bearer ...` string, a PEM
header or a URL with embedded credentials is refused). This cannot detect a secret typed
into an ordinary text variable; the type is the contract, and the desktop must keep secret
variables local.

**Discovery.** `sync.collections` in `GET /api/v2/capabilities` still lists only the five
original collections, because deployed clients require that list to match their own exactly.
`variables` is announced in `sync.optionalCollections` and in a top-level `variables` object
(`collection`, `path`, `schemaVersion`, `types`, `secretsSync:false`, size limits,
`available`). `cloud-client` exposes it as `WorkspaceSyncCapabilities::variables`
and accepts the collection in `workspace_collection/record/put/delete`; it ignores unknown
optional collections.

**Older clients.** A client built before this change validates every record it reads and
rejects `variables` in `GET /sync/export`, the collection and record routes and the change
feed with a protocol error, because it does not know the collection. The server cannot tell
clients apart and does not hide records (the change feed must stay contiguous). Do not
write variables from an account until every device that syncs it has the new contracts.

Create uses `If-None-Match: *`. Replace/delete use exactly one strong
`If-Match: "N"`. Missing preconditions return 428, malformed/weak/repeated
preconditions return 400 and a stale base returns 409. Delete requires an
existing revision and records a tombstone. A matching write with identical
content preserves its revision and emits no change. Numeric JSON values compare
by their exact decimal value, so JSONB normalization (`1e18` to its integer
form, or `-0.0` to zero) cannot create a spurious revision. PUT normalizes via
PostgreSQL and revalidates portable limits before writing; its acknowledgement
contains the stored value returned by GET, snapshot and feed. An equivalent
no-op returns the existing stored representation, including decimal/integer
distinctions that did not change its value. Repeating a request whose
first response was lost may conflict: read the current record before rebasing.
Neither the server nor SDK silently chooses a side of a conflict.

For clients that support the optional write barrier, GET `write-epoch` before
preparing a write, persist that account/origin-bound epoch alongside the exact
durable request, and send its canonical decimal value in a single
`X-Workspace-Write-Epoch` header on PUT or DELETE. The server compares the
epoch while holding the account workspace cursor lock, before checking record
preconditions or changing data. An old or future epoch returns 412. Missing
headers retain the legacy behavior until the account enables the required mode
described below. The value is a string because it spans
the nonnegative signed 64-bit range; negative, repeated, noncanonical or
out-of-range headers return 400.

When an outcome is unknown, a successful authenticated POST to `write-barrier`
increments the epoch under that same lock. A fenced write with an earlier epoch
has therefore either committed before the barrier or can no longer commit;
this includes a delayed request that has not yet entered the database. The
client can then read the record and explicitly review its outcome. The
barrier covers every v2 collection for the authenticated account, but not
other accounts, v1 writes, or legacy v2 writes that omit the epoch. A client
must not claim full recovery or clear local safety markers while any such
unfenced emitter may still write. Each barrier call consumes the normal write
rate limit. Retrying after a lost response advances the epoch again and is safe;
another device's later barrier can make a returned epoch stale before use, in
which case a subsequent write receives 412. The epoch survives server restarts
and never wraps; exhaustion returns 503. A GET by itself is not a barrier.
The Desktop client must persist the epoch before dispatch and perform the
barrier before publishing any uncertain-write recovery; the endpoint alone
does not enable that product workflow.

After explicit account-owner consent and migration of all v2 clients and
emitters, POST `require-write-epoch` permanently enables the required mode for
the authenticated account. Its response is
`{"writeEpoch":"N","epochRequired":true}`; GET `write-epoch` also returns
both fields, with `epochRequired:false` before activation. Each activation
attempt that succeeds advances the epoch, including repeated attempts after a
lost response. The flag and increment commit atomically under the same account
cursor lock as the writes. An unfenced request that already entered the
transaction completes before activation, while one reaching the lock later
fails with 428; stale fenced requests fail with 412. No endpoint turns this
mode off. Account deletion remains separate. This mode does not change or
reconcile v1: a v1 client can still write its distinct v1 dataset, which must
be handled by the migration and product reconciliation flow.

**Deployment prerequisite:** every backend instance serving this database
must run a version that enforces this policy before activation. Older backend
binaries ignore the flag and can accept unfenced writes even after activation;
this application-level guarantee does not fence noncooperating database
writers or rollbacks to old binaries. Do not enable the mode while such
instances or writes remain possible. The setting affects all v2 devices on the
account and is intentionally not enabled by the Desktop product yet.

Records are `{collection,key,revision,deleted,value}`. Snapshots are
`{schemaVersion:2,cursor,records}`. Change pages are
`{changes,cursor,has_more}` with at most 50 entries. Collection pages are
`{records,nextAfter}` and accept a key-valued `after`. Changes from all v2
collections share a monotonically increasing account cursor. Its allocation,
record mutation and feed append commit atomically under the account cursor
lock. Pagination and snapshot rebuilds never use another account's cursor.
List, point-read and change-feed responses revalidate stored record shape,
portable content and revision against the account cursor read in the same
database statement or locked transaction. Invalid stored data returns 500
without exposing the value or advancing a client cursor. A list also checks
its extra pagination sentinel: corruption there makes the preceding page
unavailable until repaired. Snapshot validation uses its consistent cursor.
Updates also validate the previous stored record against the locked account
cursor before evaluating the write; an invalid record cannot be silently
overwritten or cause a revision to be reused.

Collection keys also use ascending ASCII byte order and an exclusive `after`
cursor, with explicit `COLLATE "C"` for both comparison and ordering. UUID
document cursors and numeric revision/change cursors retain their own order.

The feed retains a suffix bounded by 10,000 changes and 16 MiB of JSONB text
plus a per-row allowance. A cursor older than that suffix returns 410; rebuild
from `/sync/export` and resume at the snapshot cursor. Negative/future cursors
return 400. The feed expiry check and page read hold a shared cursor lock to
prevent concurrent pruning from skipping changes. If retained history has a
missing or invalid cursor within a requested page, the server returns 500
instead of advancing the client past the missing change. A fully expired
prefix still returns 410. Operators must investigate damaged retained history;
the error does not silently repair it or detect a gap that the client has
already passed.

Each account allows 1,000 records (including tombstones) and 8 MiB of current
JSONB value text. Writes share 120/minute; reads share 300/minute; exports
allow 10/minute. A 429 response includes `Retry-After: 60`. A tombstone retains
its identity for conflict safety and counts toward the record quota. This
API does not execute, install, enable or download plugins automatically.

V2 has separate tables and cursors. V1 remains plugin-selection-only, including
its account export DTO. There is no implicit migration or double writing
between versions; the subsequent Desktop adapter must explicitly stage its
existing local selections once when enabling v2, then use one sync engine.

## Portable data and credentials

`cloud-contracts` is the shared backend-owned validator, used by the API and
`cloud-client`. It validates Desktop v1 interchange shapes, action/filter
counts, known fields, maximum depth, node counts and string sizes. It rejects
recognized credential fields with literal values, credentials in concrete
URLs and user-configurable registry fields. Sensitive configuration values
can use `{"secretRef":"local-key-name"}` or exact
`"{{ globals.localCredential }}"` references. Values are resolved on the
device; this backend never stores the referenced credential or executes a
template. Importing an action config with `secretRef` requires a Desktop
adapter that resolves it into the plugin's expected local type.

Generic plugin settings and free text cannot establish the absence of secrets
under arbitrary names or encodings. Authors must remove credentials before
uploading, and moderators must inspect public templates. This validator is
not a credential vault or a replacement for plugin-specific secret schemas.
Uploaded action URLs are data: the backend never fetches them.

## Export, deletion and operations

`GET /api/v2/me/export` returns
`{schemaVersion:2,account,workspaceSync,library}` with a 32 MiB response limit.
Each section has a consistent database snapshot; sections may reflect
different instants. This is an account privacy export, not an atomic restore
across all cloud domains. The existing password-confirmed browser
`DELETE /api/v1/me` cascades workspace records, cursors, feed entries and all
owned library versions. Existing publisher/role blockers and audit retention
still apply. Native/social-only account deletion retains its existing limits.

Apply `cloud-api migrate` explicitly before starting the upgraded API; readiness
checks require the new migration and tables. Older binaries become unready on
a newer schema. Rollback uses a pre-migration backup, not destructive down SQL.
No production database is migrated by this change.

Use `cloud-api run-workers` under a service manager for continuous verification
and publication preparation. It reuses the existing fenced workers, exits on
infrastructure errors for supervisor restart, and stops on SIGINT/SIGTERM.
Interrupted work is reclaimed after its existing lease expires. It requires
object storage and loopback ClamAV. Signature provisioning, independent package
review, candidate verification and `publish-generation` remain explicit
operator actions described in [REGISTRY-OPERATIONS.md](REGISTRY-OPERATIONS.md).
The daemon never signs or promotes snapshots automatically.

`cloud-client::CloudCatalog` provides anonymous discovery. Existing `Session`
adds validated workspace snapshots, change pages, conditional records,
library create/read/update/submit/withdraw and v2 account export. It retains
same-origin transport and redirect refusal. Offline persistence/application
of v2 conflicts in Desktop belongs to the later authorized integration.

## Application SDK integration fixture

An ignored cross-repository test runs the actual application `cloud-client`
against this backend over loopback HTTP and a disposable PostgreSQL database.
It creates synthetic accounts, passes their tokens only through a private child
process stdin, and deletes those accounts after the child completes or times
out. The database URL must use `127.0.0.1`, an explicit port and a database name
starting with `tiktools_sdk_epoch_`; provision that dedicated database before
running, then remove it afterward. The fixture applies migrations to it.

First, from the application checkout, run:

```sh
cargo test -p cloud-client --test real_backend_epoch --locked --offline --no-run
```

Set `CLOUD_V2_APP_SDK_TEST_BIN` to the **absolute executable path printed by
Cargo**, and `CLOUD_TEST_DATABASE_URL` to the dedicated loopback PostgreSQL
database. From the backend checkout run:

```sh
cargo test -p cloud-api --locked --offline actual_app_sdk_epoch_contract_against_postgres -- --ignored --nocapture
```

This verifies the pre-enforcement to required-epoch transition, rejection of
missing or stale epochs, a subsequent barrier, fenced writes and deletes,
account isolation, and an uncertain application workspace saved and reopened
with a newer local edit. It does not run the complete synchronization
coordinator, verify recovery after a barrier, or establish two-PC acceptance.


## Compiled headless CLI acceptance

The `native-cli-acceptance` feature includes `native-peer-acceptance` and provides the ignored
`native_cli_teams_end_to_end` fixture. It launches a separately compiled
`tiktools` CLI through the application's `scripts/headless-teams-e2e.ts`,
using this backend, private PostgreSQL data and native PKCE handoff accounts.
It adds no production routes or authentication bypass.

From the application checkout:

```sh
bun scripts/task.ts test headless-teams --binary /absolute/path/tiktools --backend /absolute/path/RemakeBackend --report /tmp/headless-teams.json
```

Install the backend's pgrust development tools first. The runner reuses those
binaries, creates its own cluster, confirms that the exact fixture is selected,
and requires a passing report with the current run identity. A zero-test run
or a report left from an earlier invocation cannot pass acceptance.

The CLI must include `cloud-auth`, `remote-client` and `remote-control`.
Development binaries accept the fixture origin at runtime. For a release
artifact, compile it with a private fixed loopback HTTPS origin and select that
port through `--cloud-port PORT`; production-pinned release binaries are refused
before authentication. The fixture uses only its synthetic identities in the OS
keychain and logs them out before stopping the server. The existing SDK-only
fixture continues to use memory-only credentials.

Coverage includes owner creation and host enrollment, nickname discovery,
recipient-bound invitation, explicit approval and native agent policy,
delegated reads and journalled writes, resource denial, restart and revocation.
The two processes run on one machine: this does not establish cross-NAT,
physical two-PC, TikTok or OBS acceptance.
