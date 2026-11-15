# Local development with `remake-dev` (pgrust, no Docker)

`remake-dev` is one native CLI (crates `devtools` and `devtools-core`) that replaces
`scripts/dev-admin.sh` and the old `pgrust-local` launcher. It installs a local
[pgrust](https://github.com/nglmercer/pgrust) once, runs it, runs the backend against it and
runs the tests. It is a development tool: nothing in `cloud-api` depends on it, and the
production image still builds only `-p cloud-api`.

```bash
git submodule update --init --recursive      # vendor/pgrust (your fork, see below)
cargo run -p devtools -- setup               # .devtools/, devtools.toml, .gitignore entry
cargo run -p devtools -- db install          # builds pgrust ONCE and installs it
cargo run -p devtools -- db up               # starts it (or reuses the running one)
cargo run -p devtools -- dev --ui            # migrations, backend, admin UI, restart on change
cargo run -p devtools -- test                # unit tests
cargo run -p devtools -- test --integration  # database tests on an isolated database
cargo run -p devtools -- report              # JSON report
```

`cargo remake <args>` is the same thing (`.cargo/config.toml` defines the alias), and
`cargo install --path crates/devtools` installs the `remake-dev` binary.

## The one rule: pgrust is compiled only when you ask

| Command | Compiles pgrust? |
| --- | --- |
| `db install --source <checkout>` (default `vendor/pgrust`), `db upgrade --source` | **Yes**, explicitly |
| `db install --prebuilt <dir>` | No: copies a finished build |
| `db up`, `db down`, `db restart`, `db status`, `db logs`, `db reset` | No |
| `dev`, `build`, `check`, `test`, `doctor`, `report`, `clean` | No |

The build runs with pgrust's own release profile and pinned toolchain, in
`vendor/pgrust/target`, never in this repository's `target/`. The result is copied to
`.devtools/bin/pgrust/` (`postgres`, `initdb`, `share/`, `manifest.json`), so editing the backend
cannot invalidate it. `manifest.json` records the real `postgres --version`, the source commit,
the sha256 of the binary and of the whole tree, and when it was installed; `db up` refuses a
binary that no longer matches it. A failed install or upgrade leaves the previous one in place.

A build of `main_main/full` is what ships (CJK conversions, `pgcrypto`, Snappy/Brotli Parquet
codecs). `db install` uses it automatically when the checkout defines it; `--slim` builds without
it for a faster, smaller server.

## The database

* `db up` starts `.devtools/bin/pgrust/postgres` on `127.0.0.1:<port>` (loopback only), creating
  the cluster with the installed `initdb` the first time. A healthy instance it started earlier is
  reused as is. The check is a real SQL round trip, and `version()` must identify as pgrust.
* A port held by anything `remake-dev` did not start is never reused and never signalled: `db up`
  stops with an error. Pid files are checked against the real executable before any signal.
* `db down` stops it and keeps the data. `db logs` tails `.devtools/logs/pgrust.log`.
* `db reset --yes` recreates only the isolated test database (`cloud_test`); it cannot name the
  development database.
* `db upgrade` refuses to change the server version over an existing cluster unless you pass
  `--accept-data-risk`: pgrust data is not guaranteed to carry across versions, so `pg_dump` first.

### Configuration

`DATABASE_URL` (environment, then `.env`) stays the single source of truth for the connection
(user, password, database, port); only loopback hosts are accepted. Without it, `devtools.toml`
supplies host, port, database and user, and the password must come from `REMAKE_DEV_DB_PASSWORD`.
Passwords are never read from `devtools.toml`. Other settings: `database.data_dir`,
`database.binary_dir`, `database.test_database`, `development.debounce_ms`, `tests.*`, `reports.*`.
`database.auto_build = true` is rejected.

An existing cluster, for example the one the old launcher kept in
`~/.local/share/remakebackend/pgrust/data`, can be reused without copying it:
`REMAKE_DEV_DATA_DIR=~/.local/share/remakebackend/pgrust/data`.

## Tests

* `test` / `test --unit`: `cargo test --workspace`. The database tests are `#[ignore]`d, so this
  never starts pgrust.
* `test --integration`: reuses the installed pgrust, recreates `cloud_test`, exports it as
  `CLOUD_TEST_DATABASE_URL` and runs exactly the tests marked
  `#[ignore = "... CLOUD_TEST_DATABASE_URL"]`. Each test gets a private database cloned from a migrated
  template, so with `tests.parallel = true` (the default) they run on several threads;
  `parallel = false` runs one at a time. A test whose reason names another variable (for
  example `CLOUD_V2_APP_SDK_TEST_BIN`, a separately built SDK binary) is reported `skipped` with the
  missing variable named, unless you export it. The development database is not touched.
* The cross-repository SDK epoch fixture is compiled only with
  `--features app-sdk-acceptance`; follow [its dedicated procedure](CLOUD-API-V2.md#application-sdk-integration-fixture).
* `test --all`: unit, integration and a reported-as-`unsupported` e2e slot.

Any failure makes the command exit non-zero. A run that executed no test is reported `skipped`,
never `passed`; the statuses are `passed`, `failed`, `skipped`, `not_run` and `unsupported`.
`--json` prints one JSON document on stdout (cargo's output goes to stderr).

## `dev`

`dev` reuses or starts pgrust, builds `cloud-api`, applies migrations, starts the backend and, with
`--ui`, Vite on `127.0.0.1:5173`. It watches the backend crates and `migrations/`, rebuilds after a
short debounce and restarts only the backend; a failed build keeps the previous backend running.
pgrust is never rebuilt or restarted by a code change, and keeps running when you stop `dev`.

## Build tools stay yours

`remake-dev` never sets, clears or edits `RUSTFLAGS`, `RUSTC_WRAPPER`, `CARGO_TARGET_DIR`, the
linker or any cache. mold, kache and sccache are used only if you configure them yourself.
`remake-dev doctor` reports what in your environment, your cargo config or your scripts changes
Cargo's fingerprints, so a surprising rebuild can be explained. (The old `dev-admin.sh` exported
`RUSTC_WRAPPER` and `RUSTFLAGS` by itself depending on which tools it found, which made the same
command fingerprint differently from one shell to the next.)

## Reports

`report --format json|markdown` writes `.devtools/reports/latest.*` and prints it. The JSON has
`schema_version: 1`: commit, platform, Rust versions, the real server version, database state,
the last recorded test and build results, and diagnostics. With nothing recorded the status is
`not_run`, not a zero-count success. `doctor` checks the toolchain, the install and its hash,
`initdb` and `share/`, the data directory permissions, the instance, SQL connectivity, port
ownership, pending migrations and the build-cache factors above.

## The fork

`vendor/pgrust` is a Git submodule of `https://github.com/nglmercer/pgrust.git`. Moving to a newer
fork commit is `git -C vendor/pgrust fetch && git -C vendor/pgrust checkout <commit>`, committing the
submodule pointer, then `remake-dev db down && remake-dev db upgrade`. The tracked
`patches/pgrust-mimalloc-glibc-2.44.patch` is applied only to a checkout that lacks that fix.
The submodule is pinned at a commit that already has that fix, so the patch only matters for an
older checkout passed with `--source`.

`db install --source` builds with `main_main/full` when the checkout defines it (a plain pgrust
build leaves out pgcrypto, the CJK conversions, the Snappy/Brotli Parquet codecs, the non-English
Snowball stemmers and 46 contrib extensions such as hstore, ltree and postgres_fdw). A `--prebuilt`
directory is used as it is, so build it with `--features main_main/full` if the backend needs those.

pgrust is beta software and is not production-ready; keep PostgreSQL for data that matters.
Requirements to build it: Git, a C/C++ toolchain, pkg-config and the RE2 development files (see
the submodule README). Windows is not supported (use WSL2). Licence: `vendor/pgrust/LICENSE`.
