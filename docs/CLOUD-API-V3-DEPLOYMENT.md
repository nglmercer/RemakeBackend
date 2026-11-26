# Cloud API v3: deployment and operations

This guide covers what an operator provisions for the v3 surfaces: the visual
catalog, managed assets, overlays and packages, the remote-control relay, and
the signed webhook integration. The contract itself is in
[CLOUD-API-V3.md](CLOUD-API-V3.md). Nothing here is a secret. Values shown in
examples are placeholders and must be replaced with values from your own secret
store.

## What the app never configures

The desktop app takes one Cloud origin, provisioned by the operator. It does not
hold relay addresses, database credentials, integration keys or host names. Every
value below lives on the server.

## Prerequisites

- PostgreSQL, reachable from every API replica. The v3 suite was run against PostgreSQL 18. Use a dedicated
  database; v3 writes to `cloud_remote_*`, `cloud_integration_*`, `cloud_relay_*`
  and `cloud_library_*` tables that the v2 workers also read. Operators who
  prefer a managed service can use [Neon](https://neon.tech) (serverless
  PostgreSQL): create a project, copy the connection details into the libpq
  variables below, and apply the migrations as usual. Validate against a
  disposable Neon branch first — compatibility is expected from PostgreSQL
  wire compatibility, not from a validated run of this suite.
- A TLS terminator in front of the API. The relay is a WebSocket upgrade at
  `/api/v3/remote/socket`; the terminator must forward `Upgrade` and `Connection`
  headers and allow idle connections of at least 60 seconds (the relay closes an
  idle socket after 45 seconds of silence).
- The API reads its existing v2 configuration unchanged. v3 adds the variables
  below and nothing else is required.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD` | yes | Database connection (standard libpq names). |
| `PGCONNECT_TIMEOUT` | no | Seconds to wait for a database connection. |
| `APP_ORIGIN` | yes | Public origin of the API, for example `https://cloud.example`. Used to bind the relay to trusted origins. |
| `BIND_ADDR`, `PORT` | no | Listen address and port, as in v2. |
| `INTEGRATION_SECRET_KEY` | for webhooks | 32 random bytes, base64 encoded. Seals webhook secrets with AES-256-GCM. Without it the webhook provider is not published and connecting answers `misconfigured`. |
| `RELAY_NODE_ID` | recommended with several replicas | A stable name for this process, such as `relay-a`. If unset, a random id is used. That is correct, but leases taken by a previous process expire only after their lease time. |

Generate the integration key once and store it in your secret manager:

```sh
openssl rand -base64 32
```

This release has no tool to re-seal webhook secrets under a new key. Do not
change `INTEGRATION_SECRET_KEY` on a deployment with existing webhook connections:
their sealed secrets can no longer be opened, so their deliveries cannot be
verified. Store the key in a secret manager with its own backup, and treat a
rotation as a planned change that requires creating new connections.

## Migrations

v3 adds eight migrations, applied in order by the normal migrator
(`readiness::MIGRATOR`) at startup:

1. `20261110000001_plugin_presentation.sql`: display fields on plugin releases.
   Releases verified before this migration show their identifier as title until
   they are verified again.
2. `20261110000002_remote_control.sql`: devices, teams, invitations, requests,
   grants, sessions and commands.
3. `20261110000003_media_overlays_packages.sql`: assets, overlays and packages.
4. `20261110000004_relay_coordination.sql`: leases and the cross-node frame queue
   used when several replicas serve the relay.
5. `20261110000005_integrations.sql`: integration connections and events.
6. `20261111000001_assets_overlays_lifecycle.sql`: nullable `cloud_assets.label` and
   the keyset-order indexes for assets and for the owner's library documents. No row
   is rewritten.
7. `20261111000002_variables_collection.sql`: widens the `collection` CHECK on
   `cloud_workspace_records` to include `variables`. The table is scanned once to
   validate the new constraint; existing rows already satisfy it.
8. `20261111000003_library_fork_provenance.sql`: nullable `fork_of_document` /
   `fork_of_revision` on `cloud_library_documents`, a both-or-neither CHECK and a
   composite foreign key to `cloud_library_versions` with `ON DELETE SET NULL`.

**Rolling versions:** a binary older than migration 6-8 reports unready on a migrated
database (readiness compares migration versions), and migration 7 means an older
binary would reject `variables` rows it reads. Migrate, then roll the new binary; do
not run old and new binaries against one database for long.

Migrations are additive. They create tables and columns; they do not rewrite v2
data. Take a database backup before the first start of a release that contains
them, as for any schema change.

## Replicas and the relay

Several API replicas may serve the relay. Each replica runs a background task
that drains cross-node frames every 200 ms, renews its leases every 10 seconds
and reaps expired leases every 60 seconds. Each host has one owning node at a
time, and the lease carries a fencing token: a replica that lost its lease cannot
deliver frames.

Operational rules:

- Give every replica its own `RELAY_NODE_ID`.
- A replica that crashes leaves its leases to expire after their lease time.
  Commands in flight on the lost connection become `unknown` with
  `hostDisconnected` and are not resent by the relay.

## Verifying a deployment

Run these checks against the deployed origin. None of them changes state except
where noted.

1. `GET /api/v3/integrations/providers` lists `webhook` only when
   `INTEGRATION_SECRET_KEY` is set.
2. `GET /api/v3/catalog/items?limit=1` answers `200` with `dataState` set to
   `ready` or `noActiveGeneration`. `noActiveGeneration` is an empty registry, not
   an outage.
3. `POST /api/v3/remote/challenges` without a session answers `401`.
4. Each v3 response carries an `x-request-id` header.

The backend's own suite exercises the full v3 contract against a disposable
PostgreSQL database and must not run against production:

```sh
CLOUD_TEST_DATABASE_URL=postgres://user:pass@host:5432/cloud_v3_disposable \
  cargo test -p cloud-api v3_tests -- --ignored --test-threads=1
```

## Recovery

- **Webhook deliveries are refused after a key change**: restore the previous
  `INTEGRATION_SECRET_KEY`. Connections sealed under a lost key must be deleted and
  created again; there is no re-sealing tool in this release.
- **A host shows `unknown` commands**: the relay did not learn their outcome. Read
  the command receipt (`GET /api/v3/remote/hosts/{hostId}/commands/{commandId}`)
  before retrying anything. Retrying a mutation without reading the receipt can
  repeat an action.
- **A grant is stuck in `pendingHost`**: the host has not confirmed the revision.
  Start the host link on the PC; it confirms pending grants at connect and on
  `grants.changed`. Revoking and approving again creates a new revision.
- **A controller still reaches a host after revocation**: revocation is applied
  through the database, so every replica must point at the same database. Check
  that the replicas share `PGHOST` and `PGDATABASE`, then read the session list for
  the host.

## Limits in this release

- The only integration provider is the signed webhook. OAuth-based services and
  host-side connectors need their own credentials and contracts.
- Operations on integrations (`…/operations/{id}`) answer `unsupported`.
- Overlay rendering and the package apply journal run in the app. The backend
  stores and checks overlays and packages but never applies them.
