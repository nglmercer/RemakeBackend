# Versioning engine: build layout and integration status

This document records how RemakeBackend consumes the Lore versioning engine, the revisions used,
and what is and is not implemented. It is the working record for the implementation described in
`lore-remakebackend-implementation(1).md`; update it as stages land.

## Revisions

| Repository | Revision | Notes |
| --- | --- | --- |
| EpicGames/lore | `e32aaac2b0b02ad9aa10723250b64ba86f125fe4` (`main`) | Baseline named in the brief; verified present in the clone. Upstream `main` was two commits ahead (`d9a361fa`, `d0866da0`, both in `lore-revision`) when the clone was made. The fork branch `remake/embedding` starts at the baseline. |
| nglmercer/RemakeBackend | `6a69c99a3a134f3f76333316957d788f31d4f004` (`master`) | Working tree had unrelated uncommitted edits (README, `cloud-api` manifest and tests, `devtools-core`, two docs); they are preserved. |
| nglmercer/better-auth-rs | `d4bb1ff17400d424813fc0bd8800204faf088238` | The revision `cloud-api` already pins. Not modified. |

The fork is `https://github.com/nglmercer/lore`, branch `remake/embedding`, with the remote
`upstream` pointing at `EpicGames/lore` in the local checkout. RemakeBackend pins fork revision
`603fa111939fab8f560d0e6c97dd27a50f73474a` (the embedding commit, one commit above the baseline).

## Build layout

`crates/cloud-versioning` depends on the fork by git revision, and the root `Cargo.toml` repeats
Lore's two workspace patches from the same revision, because Cargo does not apply a dependency's
own `[patch]` section to its consumer:

```toml
lore-server = { git = "https://github.com/nglmercer/lore.git", rev = "0d64e1d4..." }

[patch.crates-io]
quinn-proto = { git = "https://github.com/nglmercer/lore.git", rev = "0d64e1d4..." }
glob-match = { git = "https://github.com/nglmercer/lore.git", rev = "0d64e1d4..." }
```

Cargo finds `lore-server` and the two vendored crates inside the repository by package name.
Builds work with `--locked` and need no sibling checkout. **To update the engine**, change the
three `rev` values together and re-resolve; a mismatch between the dependency and the patches
would mix two Lore revisions.

`.cargo/config.toml` sets `--cfg tokio_unstable --cfg uuid_unstable`, because Lore does not
compile without them (verified: without `uuid_unstable` the wire headers fail with
`Uuid: IntoBytes` unsatisfied, and without `tokio_unstable` the telemetry metrics type is
configured out). Cargo has no stable per-package rustflags, so the cfgs apply to the whole
workspace and the first build after the change recompiles every dependency.

Dependency impact, measured against the committed `Cargo.lock`: 120 packages added, no locked
version changed or removed, and five packages gained a second version (`aws-smithy-json`,
`aws-smithy-xml`, `system-configuration`, `toml`, `toml_datetime`).

## Upstream updates in the fork

`git fetch upstream && git rebase upstream/main` on `remake/embedding`, then run
`cargo test -p lore-server --test embedded_server` and the `lore-server` unit suite. The fork's
changes are confined to `lore-server/src/{server,server_config,settings}.rs`, one test file, one
ADR and one release note, so conflicts are expected only in `server.rs`. Upstream was two commits
ahead of the baseline (both in `lore-revision`) when the fork was made.

## What exists

Lore fork (`nglmercer/lore`, branch `remake/embedding`, commit `0d64e1d4`):

- `lore_server::server::EmbeddedServer`: starts the server inside a host runtime, leaves the
  tracing subscriber and process signals to the host, serves until stopped, and restarts in the
  same process. See `docs/developing/decisions/00037-embedded-server-with-host-owned-process-concerns.md`.
- `ServerConfig::{repository_authorizer, repository_catalog}`: host-supplied repository policy
  that replaces the configured authorizer on every enabled transport.
- `Settings::from_overrides`: typed settings without environment, disk or printing.
- `[server.grpc] enabled` is now honoured; it was ignored.
- Tests: `lore-server/tests/embedded_server.rs` (3), the existing `lore-server` unit suite
  (1709 passing), clippy and nightly rustfmt clean.

RemakeBackend:

- `crates/cloud-versioning`: `VersioningHost` starts the engine over durable local stores under a
  data directory, with every native listener off, takes an exclusive `host.lock` so a second host
  on the directory does not start, reports health, exposes the stores, and stops. 3 tests.

## What does not exist yet

Everything past the embedded lifecycle: the Better Auth principal adapter and repository policy
tables, authoritative publication with expected-head and operation recovery, resumable transfers,
the `/api/versioning/v1` routes and OpenAPI contract, the Rust/TypeScript/Python SDKs, the
workspace engine and CLI, domain adapters, the legacy v2 facade and migration, backup/restore
procedures, and the independent third-party example host. None of the acceptance gates other
than "Embedded lifecycle" has been run.

## Findings that shape the remaining stages

1. **Lore's runtimes are process-wide and their shutdown is terminal.** `EmbeddedServer::stop`
   therefore never shuts them down; they end with the host process.
2. **Branch heads already have a real compare-and-swap.** `lore_revision::branch::store_latest`
   writes through `mutable_try_store` against the expected previous tip and returns
   `BranchError::BranchAdvanced` otherwise, and the server's `branch_push` handler rejects a push
   whose parent is not the current head with `FailedPrecondition`. An application-level
   `expectedHead` can map onto that without a new engine capability.
3. **The `lore` crate is a client API** (C-ABI argument structs and event callbacks over
   process-global handles). The validated server-side publication path is the `branch_push`
   handler. The planned publication route is therefore: build the revision with the revision-tree
   API in a private store, then publish it through the same native push the CLI uses, to the
   embedded server over an authenticated loopback listener. That makes the CLI transport and the
   backend publication path one path with one set of guarantees. This is a design decision to
   confirm when that stage starts, because it makes the native listener mandatory for that
   deployment profile.
4. **Lore's local store claim coordinates processes that share a directory; it does not exclude
   them.** The host's `host.lock` is what enforces a single instance.
5. **A server with no endpoint exits immediately** in stock Lore; the embedded mode holds until
   stopped so that a host can use the stores and authorization alone.
6. **`Settings::load` prints the whole configuration** to stdout, which can include credentials,
   so the embedded path does not use it.
7. **Builds regenerate tracked files** under `lore-proto/src/grpc/` (extra
   `#[allow(clippy::all)]`). They are not part of this work; restore them with
   `git checkout -- lore-proto` before committing.
8. **Commit policy differs between the repositories.** Lore's `lore-development` skill forbids
   authorship/tool attribution lines and requires DCO sign-off, so the fork commit is signed off
   and carries no attribution. RemakeBackend has no such rule.

## Viability spike (Lore CLI against the embedded engine)

Run with `crates/cloud-versioning/examples/serve*.rs` and the Lore CLI, over loopback, in a debug
build. Results:

| Check | Result |
| --- | --- |
| create, stage, commit, push, clone in a second copy | Works over QUIC (`lore://`); bytes identical. |
| Two writers from the same head | The second push fails with `Branch has diverged`; neither side loses work. |
| Restart with history | Survives a graceful stop. |
| `SIGKILL` right after an acknowledged push | **Lost** with Lore's default flush delay; survives after the `[server] durable_publication = true` fork change (2/2). Survives a kill 14 s later without it. |
| 1 GiB file | Push 5 s, clone 19 s, SHA-256 identical. Server peak RSS 327 MB (push) and 824 MB (clone) against a 253 MB baseline; the clone figure may include mapped store pages and needs a proper measurement before promising a memory budget. |
| Authenticated native endpoints, creation | Works: `repository create` with a bridge token passed as `--identity-token` succeeds. The token must go in `--identity-token` (the flags are mutually exclusive with `--identity`): `--access-token` alone sends no authentication token, and the unscoped create service refuses that. |
| Lore transport fixes (`0d64e1d4`, `73319125`) | Two client paths dropped a supplied credential: the connection's exchange (no identity named) and the storage session against a server with no authentication endpoint. The storage session then sent no token and the server answered `MissingToken`, reported as not authorized. Both are fixed with tests; the transport unit suite passes (395/395). |
| Owner push and clone, by name and by id | Works. Alice's push succeeds and both clones match the pushed bytes (`--identity-token` and `--access-token` both set to the bridge token). |
| Isolation | Works. A foreign account gets `Repository not found` (no existence leak) on clone; a missing token and a tampered signature are refused; a read-only token clones but its push fails with `Not authorized to access repository`. |

Verdict: the embedded engine is viable for native authenticated access through the Lore CLI, for
the behaviours checked above. Limits that remain: the bridge is a loopback evaluation harness with
an unauthenticated mint endpoint, not a production credential service; tokens are minted with a
fixed 300 s lifetime and no revocation; and the engine runs in a debug build with ephemeral
certificates. Tracked separately: the memory measurement of large clones, and the verbosity of the
identity/access token flags (they are documented as unsafe for secrets on the command line).

Not started: the Better Auth session to token minting, the v2 migration, the SDKs and the
`/api/versioning/v1` routes. These are the remaining stages of the migration; the native-path
viability question above is the one this spike answers.

## Backend credential issue (Better Auth to native token)

Implemented in `crates/cloud-api/src/versioning.rs`, with migration
`migrations/20261114000001_versioning_workspaces.sql`:

- `GET /api/versioning/v1/jwks.json`: the public Ed25519 key set the engine verifies against. No
  private material is published (tested).
- `POST /api/versioning/v1/native-credentials`: authenticated by the existing `DualUser` extractor
  (Bearer or cookie, with the same CSRF and origin rules as other routes). It reads the account's
  live `versioning_workspaces` rows and returns a token valid for 300 seconds, carrying `read` and
  `write` only on the repositories that account owns. The subject is the Better Auth user id.
  Rate-limited by the existing upload limiter.
- Ownership is written only by server-side code (`register_workspace`, `revoke_workspace`). No
  request can claim a repository. Repository ids are constrained to 32 lowercase hex characters.

Tests (`crates/cloud-api/src/versioning_tests.rs`, six, against real PostgreSQL with real
Better Auth sessions): unauthenticated requests are refused; the key set is public without a
private scalar; an owner's token verifies against the published key and carries exactly their
grant; another account gets no grant on that repository; revocation takes effect on the next
issue; malformed ids are refused by the table.

Full `cloud-api` run against PostgreSQL 18: the 96 default tests and 113 of the 115 database-gated
tests pass. The two that fail need environment this machine lacks (a ClamAV daemon and the staging
package set) and fail on a missing variable, not on behavior.

Not done: the workspace creation flow (the engine is not yet started inside `cloud-api`, so a
repository cannot be created through the backend); the engine's JWKS fetch from this route; a
persistent or shared signing key for several instances; revocation of already-issued tokens;
the v2 migration; the `/api/versioning/v1` repository, reference and commit routes; the SDKs.

Local test database used for the above: a system PostgreSQL 18 cluster started with a short
socket directory (`-k /tmp/...`, since the default path exceeds the Unix socket length limit
under a long scratch path), reached with `CLOUD_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:<port>/postgres`.
