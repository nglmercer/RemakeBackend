# TikTools Cloud

TikTools cloud backend for identity, signed plugin publication, reviewed
templates/profiles and optional workspace sync. **Not production-ready:**
production trust, scanner operations, deployment and release gates still need
validation. Desktop v2 integration is a separate authorized step.
Per-surface status and limits are in the [feature matrix](docs/FEATURE-MATRIX.md);
verified evidence in [implementation status](docs/IMPLEMENTATION-STATUS.md).
The current cloud redesign and v2 API are in [CLOUD-REDESIGN.md](docs/CLOUD-REDESIGN.md) and [CLOUD-API-V2.md](docs/CLOUD-API-V2.md).
The original plan, specification, and roadmap are [here](docs/PLAN.md),
[here](docs/SPECS.md), and [here](docs/ROADMAP.md). All design docs are
indexed in [docs/README.md](docs/README.md).

## Requirements

- Rust 1.95 or newer (pinned TikTools package crates require it). Minimums
  are verified with `cargo +1.95.0 check --workspace --locked` and
  `cargo +1.89.0 check -p cloud-client --all-features --locked`; CI repeats
  both checks.
- A PostgreSQL-compatible database. Local development uses pgrust; a fresh
  PostgreSQL 18 database also passes the migration and upload-authorization
  smoke tests. The complete suite has not yet been validated on every provider.
- Better Auth is pinned to `c6940517155ff9a123221789b1efc89ef48cb19c`
  with only `axum` and `sqlx` features; provider token retention is not
  enabled. Google credentials are optional and must be set together. Google
  JWKS loads at startup using the library's refresh policy (defaults: one
  hour refresh, 24-hour max stale, one-minute minimum retry; invalid
  settings stop startup). Production setup and independent security review
  remain necessary.

## Quickstart (local development)

```sh
docker compose up -d            # provides only the database
cp .env.example .env            # then fill in private values
export $(grep -v '^#' .env | xargs)
cargo run -p cloud-api -- migrate   # Better Auth + versioned Cloud migrations
cargo run -p cloud-api
```

With object storage and ClamAV configured, run `cargo run -p cloud-api --
run-workers` in a separate supervised process to continuously verify and
prepare plugin publications. Signing and generation promotion remain explicit
operator operations. See [Cloud API v2](docs/CLOUD-API-V2.md) for the complete
single-instance contract and subsequent Desktop integration boundary.

Without Docker on Linux/macOS: `cargo run -p devtools -- db install` once, then
`cargo run -p devtools -- db up` — the `remake-dev` CLI installs pgrust a single time and then only
runs it. See the [local development guide](docs/LOCAL-PGRUST.md).

Migrations are explicit and never run on server startup. Back up the
database before migrating; there is no automatic rollback, so restore the
backup to roll back. Never use example credentials outside local
development, and never log database URLs, auth secrets, cookies, or OAuth
credentials.

Health and identity:

- `GET /health/live` — process liveness.
- `GET /health/ready` — database access, Cloud migration versions and
  checksums, required auth/Cloud columns. Returns 503 when the database is
  unavailable, a migration is missing/failed/changed/unknown, or required
  columns/CRUD permissions are absent. It does not prove indexes,
  constraints, data, providers, or operations healthy, and newer migrations
  make an older binary unready — account for that when rolling versions.
- `GET /api/v1/me` — requires a Better Auth session cookie. Auth routes
  live under `/api/auth/*`.

## What the API covers

- **Publishers** — `POST /api/v1/publishers` requests a pending namespace
  (grants no publishing or signing authority); `GET /api/v1/publishers`
  lists your own. Owners manage members via
  `PUT/DELETE /api/v1/publishers/{id}/members/{user_id}` (`admin`,
  `publisher`, `viewer`); only the owner changes membership, ownership
  transfers by recipient-accepted expiring offer, and a non-owner can leave.
  Membership never bypasses pending status or grants signing keys.
  Approval and Cloud role management: [publisher approval](docs/PUBLISHER-APPROVAL.md).
- **Uploads and releases** — S3 or single-instance private-volume quarantine uploads ([object storage](docs/OBJECT-STORAGE.md)),
  integrity verification with ClamAV ([package verification](docs/PACKAGE-VERIFICATION.md),
  [release verification](docs/RELEASE-VERIFICATION.md)). Uploaded objects
  can be reviewed and prepared for signed registry publication.
- **Moderation** — independent review decisions, release yanks, and
  security advisories ([moderation](docs/MODERATION.md)). Publisher keys
  enroll via challenge-based proof of possession with session-bound step-up
  ([publisher keys](docs/PUBLISHER-KEYS.md)).
- **Registry** — signed generation publication, serving and rollback, plus a
  v2 product catalog over the published inventory. Operators provision trust
  material; disposable fixtures never establish official trust
  ([registry operations](docs/REGISTRY-OPERATIONS.md)).
- **Templates and profiles** — private versioned library, independent review,
  public discovery and withdrawal ([v2 API](docs/CLOUD-API-V2.md)).
- **Sync and desktop** — v1 plugin selections remain compatible; separate v2
  workspace sync covers templates, profiles, portable settings and preferences.
  Desktop v2 integration is a separate authorized step. Native sign-in remains
  experimental ([desktop authentication](docs/DESKTOP-AUTH.md)).
- **Admin web app** — `web/admin` (login, review dashboard, moderation,
  publisher portal) with read-only admin APIs ([admin web plan](docs/ADMIN-WEB-PLAN.md),
  [deployment hardening](docs/ADMIN-WEB-DEPLOYMENT.md)).

## Optional Docker-free database

For local Linux/macOS development without Docker, use the `remake-dev` CLI (`cargo run -p devtools -- db up`) after configuring `.env`. See the [local development guide](docs/LOCAL-PGRUST.md) for installation, the isolated test database, security limits and shutdown.

For Railway staging, the repository includes a multi-stage image and same-origin
admin hosting. See [Railway staging](docs/RAILWAY-STAGING.md) for configuration,
migration and current storage limitations. The publication system remains
staging-only until its production gates have been verified.

## Tests

```sh
cargo test --workspace --locked   # no external services needed
```

For the database tests, point `CLOUD_TEST_DATABASE_URL` at a disposable
PostgreSQL (or pgrust) server and run them in parallel:

```sh
CLOUD_TEST_DATABASE_URL=postgres://user@127.0.0.1:5432/cloud_test cargo test --workspace --locked -- --include-ignored --skip google_jwks_live_refresh_smoke --skip staging_official_packages_install_with_pinned_client --skip real_clamav_scans_staging_packages
```

or let `cargo run -p devtools -- test --integration` provision everything.
`--test-threads=1` is no longer needed: every test gets a private database,
cloned from a template that already holds all migrations (`CREATE DATABASE …
TEMPLATE …`, dropped when the test ends). The role needs `CREATEDB`. The
template is rebuilt by itself when the migrations, `Cargo.lock` or the template
builder (`crates/cloud-api/src/test_support.rs`) change, and clones left behind
by a killed run are swept on the next one. Set `CLOUD_TEST_ISOLATE=0` to use
the database in the URL directly instead (shared, so run with
`--test-threads=1`). `CLOUD_TEST_FAST_HASH=1` (set by `remake-dev test`, off by default) switches the
fixtures to negligible scrypt parameters and cuts the suite by about a third; CI keeps
the real ones. Password hashing is compiled with optimizations in the dev
profile (`[profile.dev.package.scrypt]` and friends); without it a debug build
spends seconds on every sign-up.

The tests apply Better Auth migrations and insert fixture records — never
point them at production. CI provisions a separate pgrust service. The
fixture is not a substitute for a real Google or desktop end-to-end test.
The skipped network and staging tests require separate services and inputs;
see [Railway staging](docs/RAILWAY-STAGING.md) for the staging tests.
The cross-repository application SDK fixture additionally requires
`--features app-sdk-acceptance` and its separately built executable; see
[the SDK acceptance procedure](docs/CLOUD-API-V2.md#application-sdk-integration-fixture).
