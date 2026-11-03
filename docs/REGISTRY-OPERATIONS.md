# Registry bootstrap and operations

The planned official registry uses the v1 static format and tooling from TikTools PR #43, pinned here for integration checks at `983a375c5b702681a791061ca863cea9c542528d`. The implementation and protocol are upstream in `crates/tiktools-plugin-registry`, `crates/tiktools-plugin-devkit`, and `docs/PLUGIN_REGISTRY_PROTOCOL.md`. Do not introduce a second signing format or let a Cloud login bypass client verification. An official domain, root public key, deployment environment, and authorized operators have not been selected.

## Test fixture

On a trusted development machine, check out that exact TikTools revision and run `scripts/build-registry-fixture.sh /path/to/TikTools-app /path/to/new-output`. The script builds the upstream `tiktools-plugin` CLI, creates disposable test keys in a temporary directory, uses the CLI to initialize, delegate, sign and publish a sample package, and copies only the resulting public registry tree to the output. A separate public root pin is saved as `<output>.root-pin.json`. It refuses an existing output directory and tracked changes to the checkout. These test keys and the generated root are never official trust anchors. Run `scripts/verify-registry-fixture.sh /path/to/TikTools-app /path/to/output /path/to/output.root-pin.json` to use the pinned TikTools registry client against this exact tree. It checks the independent root pin, signed index, downloaded archive digest, publisher signature and extraction, and rejects a wrong root, wrong digest and tampered index. CI runs that verification, upstream client and CLI tests, and uploads the disposable tree and public pin. This does not exercise a complete Desktop install.

## Production key lifecycle (not yet provisioned)

- Generate root keys offline with an audited ceremony, record public fingerprints through an independent channel, protect and back up the private keys offline, and pin the approved public root in Desktop releases. `root.json` is unsigned and cannot establish trust by itself. Never put a root private key in CI, Cloud, a CDN, logs, or a repository.
- Use root-signed `keys.json` to delegate index and namespace-scoped publisher public keys. Review namespace ownership, key identity, scopes and validity before delegation. A Cloud account or publisher membership alone confers no signing authority. Delegation changes require separate approval and the offline root ceremony.
- Keep the index key in a restricted signing environment backed by KMS/HSM where supported; the upstream CLI currently accepts a local key file, so a secure production signing integration remains to be built and audited. Limit who can invoke it, require approval, log signer identity and artifact digest, and rotate it via a root-signed delegation before expiration. Revoke compromised delegated keys and affected digests promptly; publish a new signed snapshot and notify clients.
- Root rotation requires a Desktop update with an independently authenticated new pin, an overlap and recovery plan, and coordinated retirement of the old root. Do not replace `root.json` and expect existing pinned clients to trust it. Test recovery and compromise procedures before launch.

## Snapshot publication and rollback

Generations are immutable full snapshots served at `GET
/api/v1/registry/generations/{generation}/files/{path}` with immutable
caching, and `GET /api/v1/registry/current` is the atomic pointer the v1
protocol lacks (never cached). Each new generation preserves the previously
published releases and adds newly prepared ones; generations are never rebuilt
as empty registries. Files are never published one by one into a live tree.
Promotion, rollback, GC, and listing run through operator-owned CLI commands
that take an explicit operator label (`publish-generation CANDIDATE_ID
OPERATOR`, `rollback-generation GENERATION OPERATOR`, `gc-registry-artifacts
LIMIT OPERATOR`, `list-generations`); every decision, failure, and recovery is
audited with that identity.

Promotion is fail-closed. A `verified` readiness record is evidence, never
authorization: promotion rechecks the exact manifest and inventory hashes,
current publisher/key authorization, moderation decisions, yanks, key
revocations, and advisories, revalidates signatures against the current root
and delegated policy, rescans and reverifies every artifact by pinned object
version, and serializes promoters on an advisory lock. Anything changed since
verification aborts with a `blocked` record; infrastructure failures record
`failed`. Concurrent promotions fail fast instead of interleaving, and the
active pointer flips in one transaction, so clients never observe a mixed
snapshot. Re-running promotion for the same candidate is idempotent: an
already-active generation returns as-is, and an interrupted staged generation
resumes instead of duplicating.

Rollback restores a previously live generation only after re-downloading every
file by pinned version, digest-checking it, revalidating the tree against the
current pins, rechecking current publisher/key authorization, yanks,
advisories, and revocations, and rescanning the packages. A target carrying a
compromised key, revoked digest, yanked release, or stale advisory is refused
with a `blocked` record; rebuild and promote a corrected generation instead.
Superseded generations stay readable as rollback targets and pinned clients
keep working; `gc-registry-artifacts` only collects staged leftovers older
than one hour, published candidates' redundant staging files, and consumed
staging originals, bounded per run.

Public downloads need no Cloud authentication and stay offline-verifiable:
clients pin the root, refresh, discover, download by digest, verify publisher
signatures, and install through the pinned TikTools client. The integration
suite proves this against the real served routes, including update discovery,
yank removal, wrong-root rejection, and digest-mismatch rejection.

## Staging registry runbook

Development uses disposable keys and a local staging registry; staging trust
material is never a production anchor. Generate a root, an index key, and a
publisher key on a trusted machine, build a seed directory with
`IndexWriter::init`, and pass it through `SNAPSHOT_SEED_DIR`,
`SNAPSHOT_ROOT_PIN_FILE`, and `SNAPSHOT_INDEX_KEY_FILE` (or the equivalent
`*_B64` variables) with the usual `CLOUD_*` storage and `CLAMAV_ADDR`
settings. Run `build-initial-candidate`, `verify-candidate`,
`check-promotion-readiness`, then `publish-generation`; confirm
`/api/v1/registry/current` advances and the files serve with immutable cache
headers. Serve the API over loopback HTTP and point the pinned TikTools client
at `/api/v1/registry/generations/{n}/files` to rehearse discovery, download,
verification, install, update, and yank removal. Production promotion stays
disabled until official trust material (offline root ceremony, KMS/HSM-backed
index key, independently authenticated client pins), authorized operators, and
the reviewed deployment infrastructure are provisioned; until then, staging
keys and local runs are the only supported path, and no staging artifact may
be presented as an official release.

## Publication requests

An independent Cloud moderator or admin can request publication of a reviewed release
with `POST /api/v1/plugins/releases/{releaseUuid}/publish`. The request checks current
publisher and signing-key approval, an antivirus-passed verification job, an approved
review, and the requester's role and conflicts of interest. It records one audited,
idempotent queue item and returns `202` with `status: "queued"` and
`processingAvailable: false`. Concurrent retries return the same job ID and current
preparation status. This flag means end-to-end snapshot publication is unavailable;
a preparation worker is available as described below. The release remains
`review_approved` and private. There is no public release status yet.

Run one preparation job in an isolated, resource-limited process with
`cargo run --locked -p cloud-api -- prepare-publication-once`, using the same database,
versioned quarantine storage and `CLAMAV_ADDR` settings as the verification worker.
It rechecks the requester's role and conflicts, publisher, key, review and verification
state, and that the release has not been yanked; fetches the captured object version; repeats package verification and scanning;
then writes a fresh private `prepared/{publisherUuid}/{leaseUuid}` object with a
conditional PUT. It reads back the exact returned version and checks its size and
SHA-256 before recording `prepared`. It rechecks authorization and the input metadata
under locks after network and scanning work. Ten-minute leases fence stale workers;
transient failures retry at most three times, while revoked authorization blocks the
job. A failed, blocked or superseded attempt can leave an unreferenced object version;
cleanup is not implemented; an operator may explicitly retry eligible transient failures as described below. The bucket must remain private and
its policies must preserve referenced versions through publication.

`prepared` is **not published** and does not imply that a snapshot exists. A future
promotion process must recheck current authorization and scanner policy, fetch and verify
the recorded prepared version, independently verify a signed snapshot, and atomically
promote it without mixing snapshot generations. The initial-candidate worker does not
implement that promotion. A queued or prepared
request is not authorization to skip these checks; revocation or suspension after
preparation must prevent publication. The integration test uses simulated S3 and ClamAV
servers; real provider signatures, checksums, IAM and failure behavior remain unverified.

Migration `20261102000012_publication_requests.sql` adds this queue;
`20261102000013_publication_preparation.sql` adds preparation leases and versioned
artifact references. Stop request
traffic and workers before rollback and preserve queued jobs and their audit history.
Restore a matching backup and reconcile any snapshot deployment separately; dropping
the table loses requests. The rollback and snapshot deployment remain untested.

## Private candidate builder

The `cloud-snapshot` library builds a temporary candidate tree with the pinned
TikTools v1 `IndexWriter`. Its caller supplies a **complete, independently authorized**
release inventory, current approved publisher keys, an independently obtained root
pin, a root-signed `keys.json`, an index-signed `config.json`, and a delegated index
signing key. The builder verifies the seed signatures and key validity, checks each
publisher delegation against the independently supplied key, re-verifies each package,
rejects duplicate identities, and preserves the caller-supplied yank and advisory
states. The pinned devkit keeps its publish-readiness helper private, so the builder
mirrors its non-changelog metadata checks; this compatibility code must be reviewed
when changing the upstream pin. It checks the generated signatures and artifact digests and returns a
short-lived private directory and per-file SHA-256 map. Candidate construction has
limits of 10,000 artifacts, 6,400 plugin IDs and 16 GiB of compressed artifacts.

The standalone library does **not** establish that the caller's inventory is complete
or still authorized, check scanner freshness, perform an independent review, or
promote/deploy a candidate. The experimental initial-candidate worker described below
connects it to prepared jobs and privately stores the resulting files. It reconstructs
release documents with the upstream writer, so callers must assess changes to
publication timestamps, metadata and distribution tags before use. Treat the file map
as evidence of the candidate at build time and reverify all contents and authorization
before any later use. Index signing currently requires an in-process local key; a
production KMS/HSM integration and key ceremony are still missing. Run builds only in
an isolated, resource-limited environment.

Tests build a two-plugin candidate and use the pinned TikTools client to verify its
root, signed index, package digest and publisher signature. They also exercise yank
and advisory fields, untrusted and expired keys, forged packages, duplicate versions,
tampered seed documents and tampered output. This is a local protocol test, not proof
of a complete inventory, real scanner, remote CDN behavior or atomic publication.

## Initial candidate worker

`cargo run --locked -p cloud-api -- build-initial-candidate` builds an **initial,
private** candidate from every publication job currently marked `prepared`. It refuses
an invalid prepared job rather than silently omitting it, checks current publisher,
key, review, verification and requester authorization, downloads each recorded
prepared version, and repeats the antivirus scan. It passes the complete captured set
to `cloud-snapshot`, compares the inventory again after building and before recording,
revalidates the candidate signatures and hashes, and stores each file as a separate
private versioned object with read-back digest checks. A database record contains the
file paths, hashes, sizes and version IDs and references each included prepared job.
The worker logs the non-secret candidate UUID for operators; the same UUID is recorded
in the audit event. The event uses a service-process label, not an authenticated human
operator identity. No public registry pointer or release status is changed.

Set `SNAPSHOT_SEED_DIR` to an empty initial registry containing the signed seed
documents, `SNAPSHOT_ROOT_PIN_FILE` to an independently authenticated root `TrustedKey`
JSON, and `SNAPSHOT_INDEX_KEY_FILE` to the delegated TikTools index private-key JSON.
The index key file must be a non-symlink regular file with no group or other access on
Unix; this file-based signer is disabled on platforms where those permissions cannot
be checked. The worker also requires the database, versioned private object storage,
and loopback `CLAMAV_ADDR` settings. Protect the signing host and key; production
KMS/HSM integration is not implemented.

This command accepts only a seed with no index, package or catalog tree and zero
catalog pages. Cloud does not yet model an existing published inventory, so it must
not be used to update an existing public registry. It assigns channels from versions,
carries moderator-recorded advisories into the registry documents, and refuses to
build when any prepared release is yanked. The database comparisons
are point-in-time checks; they do not freeze future changes or make a candidate safe
to deploy. A future promotion process must recheck the entire inventory, current
authorization, trust, scanner policy and all stored object versions after construction
and enforce consistent client access across snapshot generations. Candidate creation
is not idempotent, and failed or raced builds may leave unreferenced private objects;
operator retry and garbage collection are not implemented. The integration test uses
simulated S3 and ClamAV servers, not a real provider or production scanner.

Migration `20261102000014_snapshot_candidates.sql` adds private candidate, release and
file records. Stop candidate builders before rollback and preserve candidate metadata
and referenced object versions. Restoring a database backup requires reconciliation
with private objects; dropping these tables loses candidate references. Rollback has
not been rehearsed.

## Inspecting a private candidate

An operator can reconstruct a recorded candidate with
`cargo run --locked -p cloud-api -- export-candidate CANDIDATE_UUID NEW_OUTPUT_DIR`.
The output directory must not exist. On Unix it is created with private permissions;
other platforms fail closed until equivalent ACL checks are implemented. The command
reads each exact private object version, verifies its stored size and digest, checks
the database manifest again, and writes `.cloud-candidate.json` last. A failed export
may leave an incomplete directory without that marker; it never overwrites an
existing destination. Treat the marker as usable only when the command also exits
successfully. The marker describes the private candidate and does not assert
that it is approved or safe to deploy.

Independently verify the exported signed documents, root pin, package signatures and
current policy before review. The root fingerprint in the marker comes from the
database and is not an independent trust anchor. Export does not recheck current
publisher, reviewer, scanner or inventory authorization and does not promote the
candidate. The test reconstructs a candidate through simulated storage and verifies
its registry documents with the pinned TikTools client; actual provider behavior and
an isolated reviewer environment remain unverified.

### Point-in-time candidate checks

`cargo run --locked -p cloud-api -- verify-candidate CANDIDATE_UUID` uses the
configured private object store and database. Set `SNAPSHOT_ROOT_PIN_FILE` to an
independently supplied JSON `TrustedKey` for the root and
`SNAPSHOT_INDEX_PUBLIC_KEY_FILE` to the independently supplied JSON `PublicKey` for
the index signer. Set `SNAPSHOT_SEED_DIR` to the independently maintained current
signed policy seed. Set `CLAMAV_ADDR` to a loopback ClamAV INSTREAM service. No
signing key is needed. The command reconstructs the stored
versions in a temporary private directory, validates their hashes and registry
signatures, compares release links and the recorded inventory with current Cloud
authorization, checks every indexed artifact and catalog entry against that inventory, validates
release metadata and channel tags against signed packages, rejects yanked releases
and registry documents whose advisory differs from the recorded one,
compares current root-signed delegations and registry policy with the seed, rejects
revoked release digests, reverifies package signatures, rescans each exact package,
rechecks file hashes and
signatures, and repeats the database checks before returning. An infected result,
scanner failure, or digest mismatch fails verification.

A successful result is a point-in-time inspection, not approval to publish. It depends on the operator supplying the current policy seed; it cannot detect rollback
to an older valid seed or prevent changes
after the check. The inventory comparison applies only to initial candidates without
prior releases. Promotion must independently establish these properties and
fence authorization changes atomically. Storage and scanner production behavior,
review procedures, and promotion remain unverified.

For an initial candidate, all target variants of the latest release must carry the
same displayed package metadata. The verifier rejects divergent variants instead
of relying on the writer’s order-dependent choice.

## Recording promotion-readiness decisions

An operator can run the point-in-time verifier and record its outcome with
`cargo run --locked -p cloud-api -- check-promotion-readiness CANDIDATE_UUID OPERATOR`.
It uses the same database, private object storage, `SNAPSHOT_SEED_DIR`,
`SNAPSHOT_ROOT_PIN_FILE`, `SNAPSHOT_INDEX_PUBLIC_KEY_FILE`, and loopback
`CLAMAV_ADDR` settings as `verify-candidate`, then records a `verified` or
`blocked` row in `cloud_snapshot_promotion_checks` with an audited
`snapshot.candidate_verified` or `snapshot.candidate_verification_blocked`
event. A successful verification returns the candidate manifest it checked; the
ledger locks the candidate and its file rows, refuses success if the manifest
changed, and records its SHA-256 alongside the inventory hash. The digest covers
the root fingerprint, inventory hash, and path-sorted file paths, digests, sizes,
object keys and version IDs serialized as compact JSON; database row revisions
are used for the comparison but excluded from the digest. A blocked row records
the candidate inventory hash at the time of recording, without a manifest hash.
These checks do not freeze authorization, trust material, or stored files after
verification, so a future promotion process must recheck them. Operators can
review the recorded history with
`cargo run --locked -p cloud-api -- list-promotion-checks CANDIDATE_UUID`,
which prints the decisions as JSON, oldest first; unknown candidates list no
decisions. The operator label is self-supplied and must be correlated with
separately authenticated operator logs. A `blocked` outcome still records the
decision and exits nonzero with the failure reason.

A recorded decision is **not a promotion and not an approval to deploy**. It
only retains the decision history the design requires ("retain previous
immutable snapshots and record their hashes and approvals") so a future
promotion process can consult it before rechecking the entire inventory,
current authorization, trust material, scanner policy, and every stored object
version atomically. The command performs no deployment, changes no release
status, and cannot detect rollback to an older valid seed or changes made
after the check.

Migration `20261102000017_snapshot_promotion_checks.sql` adds the decision
table, migration `20261102000019_promotion_check_inventory.sql` adds the
pinned inventory hash, and migration `20261102000020_promotion_manifest_hash.sql`
adds a nullable manifest hash. Older checks remain null because their exact file
manifest cannot be reconstructed as evidence. Stop candidate builders before
rollback and preserve promotion-check
rows with their candidate metadata; dropping the table loses decision history.
Rollback has not been rehearsed.

## Recovering transient preparation failures

After fixing the cause, run `cargo run --locked -p cloud-api -- retry-publication
JOB_UUID OPERATOR`. Only a `failed` preparation job with `temporary_failure`, no
lease or prepared version, and a review-approved release can be requeued. The
worker repeats all authorization, package, scanner and storage checks. Blocked,
rejected, running and prepared jobs cannot be reset by this command. Each successful
requeue records an audit event; the operator label is self-supplied and must be
correlated with separately authenticated operator logs. Orphan object cleanup and
recovery from changed authorization remain separate operational work.

A publication job blocked by `authorization_changed` can be requested again through
`POST /api/v1/plugins/releases/{id}/publish` by a currently authorized, independent
moderator or admin. The request rechecks the publisher, key, quarantined upload,
antivirus result and approved review, then atomically assigns the new requester and
queues a fresh preparation attempt. Repeated requests for an already queued job do
not replace its requester or add another re-request audit event. Rejected jobs are
not reopened by this flow; transient `failed` jobs use the operator command above.
Preparation still performs its own checks and no public registry is changed.
