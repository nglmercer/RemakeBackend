mod account;
mod admin;
mod admin_static;
mod api_error;
mod assets;
mod catalog_pages;
mod catalog_v3;
mod cloud_v2;
mod config;
mod desktop;
mod dual_auth;
mod integrations;
mod library;
mod library_digest_repair;
mod local_backup;
mod local_objects;
mod media;
mod moderation;
mod overlays;
mod packages;
mod paging;
mod portable;
mod publication;
mod publication_worker;
mod publisher_keys;
mod publisher_releases;
mod publishers;
mod readiness;
mod recovery;
mod releases;
mod remote;
mod scanner;
mod security_headers;
mod snapshot_export;
mod snapshot_promotion;
mod snapshot_publish;
mod snapshot_trust;
mod snapshot_verify;
mod snapshot_worker;
mod step_up;
mod sync;
mod temporary_log_approval;
mod uploads;
mod versioning;
#[cfg(test)]
mod versioning_tests;
mod web;
mod worker;
mod worker_daemon;
mod workspace;

use axum::{
    extract::{FromRef, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use better_auth::{
    axum_integration::{auth_routes, AuthUser, NativeAuthUser},
    context::AuthContext,
    database::{SqlxDbAdapter, SqlxSecondaryStorage},
    http_oauth::HttpOAuthProvider,
    router::AuthRouter,
    JwksRefreshPolicy,
};
use better_auth_core::{
    migration::SqlDialect,
    options::{AuthOptions, BaseUrl},
};
use config::Config;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{error::Error, sync::Arc};

#[derive(Clone)]
struct AppState {
    /// Native credentials and the engine this process runs. See `versioning`.
    versioning: Arc<versioning::Versioning>,
    peer: remote::peers::PeerConfig,
    auth: AuthContext,
    pool: PgPool,
    object_storage: Option<cloud_storage::QuarantineStore>,
    /// OAuth material for the step-up flow. `None` when Google sign-in is not
    /// configured; password step-up still works, Google step-up answers 503.
    step_up_oauth: Option<step_up::StepUpOAuth>,
    temporary_log_approvals: bool,
    /// Live relay routing for remote control. Single-process by design.
    remote: std::sync::Arc<remote::relay::Hub>,
}

fn proxy_auth_options(enabled: bool) -> better_auth_core::options::AdvancedOptions {
    better_auth_core::options::AdvancedOptions {
        trusted_proxy_headers: enabled,
        trusted_ip_headers: if enabled {
            vec!["x-forwarded-for".to_owned()]
        } else {
            Vec::new()
        },
    }
}

fn configured_auth_router(context: AuthContext) -> better_auth_core::error::Result<AuthRouter> {
    let storage = context.secondary_storage.clone().ok_or_else(|| {
        better_auth_core::error::AuthError::InvalidConfiguration(
            "auth rate limiting requires secondary storage".into(),
        )
    })?;
    let policy = better_auth::rate_limit::RateLimitPolicy::new(
        "auth",
        10,
        std::time::Duration::from_secs(60),
    )?;
    Ok(AuthRouter::new(context)?.with_sign_in_rate_limit(
        better_auth::rate_limit::RateLimiter::new(storage, "cloud:auth"),
        policy,
    ))
}
impl FromRef<AppState> for AuthContext {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

async fn me(
    AuthUser(principal): AuthUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let roles = admin::roles(&state.pool, &principal.user.id).await?;
    Ok(Json(
        serde_json::json!({ "id": principal.user.id, "email": principal.user.email, "name": principal.user.name, "roles": roles }),
    ))
}
async fn native_me(
    NativeAuthUser(principal): NativeAuthUser,
    state: State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    me(AuthUser(principal), state).await
}

async fn native_logout(
    NativeAuthUser(principal): NativeAuthUser,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    let sessions = better_auth::session::SessionService::new(state.auth)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    sessions
        .discard(&principal.session.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() > max_bytes {
        let mut end = max_bytes;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
}

/// The role this process plays, logged once at startup so deploy logs show it.
/// `rejected` covers arguments the usage check refuses before the listener starts.
fn startup_mode(args: &[String]) -> &'static str {
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => "server",
        ["migrate"] => "migrate",
        ["verify-once"]
        | ["prepare-publication-once"]
        | ["build-initial-candidate"]
        | ["run-workers"] => "worker",
        [command, ..]
            if matches!(
                *command,
                "backup-local"
                    | "restore-local"
                    | "verify-local-backup"
                    | "export-candidate"
                    | "verify-candidate"
                    | "list-promotion-checks"
                    | "check-promotion-readiness"
                    | "publish-generation"
                    | "rollback-generation"
                    | "list-generations"
                    | "gc-registry-artifacts"
                    | "retry-verification"
                    | "retry-publication"
                    | "grant-role"
                    | "revoke-role"
                    | "audit-library-digests"
                    | "repair-library-digest"
            ) =>
        {
            "maintenance"
        }
        _ => "rejected",
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cloud_api=info".into()),
        )
        .init();
    let startup_args: Vec<_> = std::env::args().skip(1).collect();
    if let [command, path] = startup_args.as_slice() {
        if command == "verify-local-backup" {
            local_backup::verify(std::path::Path::new(path))?;
            return Ok(());
        }
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            // The message names the variable at fault and never prints its value.
            tracing::error!(%error, "startup configuration rejected");
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, error).into());
        }
    };
    // Logs never include DATABASE_URL, AUTH_SECRET or other credentials.
    tracing::info!(railway = config.railway, bind = %config.bind, "configuration validated");
    tracing::info!(mode = startup_mode(&startup_args), "startup mode");
    if let [command, path] = startup_args.as_slice() {
        if command == "backup-local" {
            local_backup::backup(
                config
                    .object_storage
                    .ok_or("STORAGE_LOCAL_DIR is required")?,
                &config.database_url,
                std::path::Path::new(path),
            )
            .await?;
            return Ok(());
        }
        if command == "restore-local" {
            local_backup::restore(
                config
                    .object_storage
                    .ok_or("STORAGE_LOCAL_DIR is required")?,
                &config.database_url,
                std::path::Path::new(path),
            )
            .await?;
            return Ok(());
        }
    }
    // Every command that can touch this database holds the volume's shared
    // lock when local storage is configured. Offline backups require the
    // exclusive lock and therefore refuse to race API and worker commands.
    let _local_volume_guard = match &config.object_storage {
        Some(config::StorageConfig::Local { root, .. }) => {
            Some(cloud_storage::local::LocalStore::open(root)?)
        }
        _ => None,
    };
    let adapter = Arc::new(SqlxDbAdapter::postgres(&config.database_url).await?);
    let storage = Arc::new(SqlxSecondaryStorage::postgres(&config.database_url).await?);
    tracing::info!("database connection established");
    let context = AuthContext::new(
        AuthOptions {
            secret: config.auth_secret,
            base_url: Some(BaseUrl::Static(config.origin.clone())),
            trusted_origins: vec![config.origin.clone()],
            // The boundary below replaces untrusted forwarded IPs with the socket peer.
            advanced: proxy_auth_options(true),
            ..AuthOptions::default()
        },
        adapter.clone(),
        Some(storage.clone()),
        // Username sign-in: set a username after email sign-up, then sign in
        // with it. Google OAuth stays last and remains unconfigured here.
        vec![Arc::new(better_auth::UsernamePlugin)],
    )?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["migrate"] {
        adapter
            .apply_migrations(&context.migration_plan(), SqlDialect::Postgres)
            .await?;
        storage.migrate().await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&config.database_url)
            .await?;
        readiness::MIGRATOR.run(&pool).await?;
        // One-shot completion: the process exits 0 here and never binds the HTTP listener.
        tracing::info!("migrations applied; exiting without starting the HTTP server");
        return Ok(());
    }
    if args == ["audit-library-digests"]
        || matches!(args.as_slice(), [command, _, _] if command == "audit-library-digests")
    {
        let after = match args.as_slice() {
            [_, document, revision] => Some(library_digest_repair::AuditCursor {
                document_id: uuid::Uuid::parse_str(document)?,
                revision: revision.parse()?,
            }),
            _ => None,
        };
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&config.database_url)
            .await?;
        let page = library_digest_repair::audit(&pool, after, 100).await?;
        println!("{}", serde_json::to_string_pretty(&page)?);
        return Ok(());
    }
    if let [command, document, revision, old, normalized, operator] = args.as_slice() {
        if command == "repair-library-digest" {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database_url)
                .await?;
            let receipt = library_digest_repair::repair(
                &pool,
                uuid::Uuid::parse_str(document)?,
                revision.parse()?,
                old,
                normalized,
                operator,
            )
            .await?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
            return Ok(());
        }
    }
    if let [command, candidate] = args.as_slice() {
        if command == "verify-candidate" {
            let id = uuid::Uuid::parse_str(candidate)?;
            let store = config
                .object_storage
                .ok_or("object storage must be configured")?
                .build()?;
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&config.database_url)
                .await?;
            let root: tiktools_plugin_package::TrustedKey =
                serde_json::from_slice(&snapshot_worker::read_file(
                    std::path::Path::new(&std::env::var("SNAPSHOT_ROOT_PIN_FILE")?),
                    false,
                    16384,
                )?)?;
            let index: tiktools_plugin_package::PublicKey =
                serde_json::from_slice(&snapshot_worker::read_file(
                    std::path::Path::new(&std::env::var("SNAPSHOT_INDEX_PUBLIC_KEY_FILE")?),
                    false,
                    16384,
                )?)?;
            let scanner = scanner::ClamAv::new(
                config
                    .clamav_addr
                    .ok_or("CLAMAV_ADDR must be configured for verification")?,
            );
            let seed = std::path::PathBuf::from(std::env::var("SNAPSHOT_SEED_DIR")?);
            snapshot_trust::require_trust(&root, index.key_id.as_str())
                .map_err(|refused| format!("snapshot trust refused: {refused}"))?;
            snapshot_verify::verify(&pool, &store, &scanner, &seed, id, &root, &index).await?;
            tracing::info!(candidate_id=%id, "private candidate checks passed; not approved for deployment");
            return Ok(());
        }
        if command == "list-promotion-checks" {
            let id = uuid::Uuid::parse_str(candidate)?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database_url)
                .await?;
            let checks = snapshot_promotion::list_checks(&pool, id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&checks).map_err(|e| e.to_string())?
            );
            return Ok(());
        }
    }
    if let [command, candidate, operator] = args.as_slice() {
        if command == "check-promotion-readiness" {
            let id = uuid::Uuid::parse_str(candidate)?;
            let store = config
                .object_storage
                .ok_or("object storage must be configured")?
                .build()?;
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&config.database_url)
                .await?;
            let root: tiktools_plugin_package::TrustedKey =
                serde_json::from_slice(&snapshot_worker::read_file(
                    std::path::Path::new(&std::env::var("SNAPSHOT_ROOT_PIN_FILE")?),
                    false,
                    16384,
                )?)?;
            let index: tiktools_plugin_package::PublicKey =
                serde_json::from_slice(&snapshot_worker::read_file(
                    std::path::Path::new(&std::env::var("SNAPSHOT_INDEX_PUBLIC_KEY_FILE")?),
                    false,
                    16384,
                )?)?;
            let scanner = scanner::ClamAv::new(
                config
                    .clamav_addr
                    .ok_or("CLAMAV_ADDR must be configured for verification")?,
            );
            let seed = std::path::PathBuf::from(std::env::var("SNAPSHOT_SEED_DIR")?);
            snapshot_trust::require_trust(&root, index.key_id.as_str())
                .map_err(|refused| format!("snapshot trust refused: {refused}"))?;
            let outcome =
                snapshot_verify::verify(&pool, &store, &scanner, &seed, id, &root, &index).await;
            let (decision, reason) = match &outcome {
                Ok(_) => (
                    "verified",
                    "point-in-time verification passed; not deployed".to_owned(),
                ),
                Err(e) => {
                    let mut reason = format!("verification failed: {e}");
                    truncate_utf8(&mut reason, 1024);
                    ("blocked", reason)
                }
            };
            let check = match &outcome {
                Ok(inventory) => {
                    snapshot_promotion::record_verified(&pool, id, inventory, operator, &reason)
                        .await?
                }
                Err(_) => {
                    snapshot_promotion::record_decision(&pool, id, decision, operator, &reason)
                        .await?
                }
            };
            tracing::info!(candidate_id=%id, check_id=%check, decision, "promotion readiness recorded; not deployed");
            if outcome.is_err() {
                return Err(reason.into());
            }
            return Ok(());
        }
    }
    if let [command, job, operator] = args.as_slice() {
        let kind = match command.as_str() {
            "retry-verification" => Some(recovery::Kind::Verification),
            "retry-publication" => Some(recovery::Kind::Publication),
            _ => None,
        };
        if let Some(kind) = kind {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database_url)
                .await?;
            let changed =
                recovery::retry(&pool, kind, uuid::Uuid::parse_str(job)?, operator).await?;
            if !changed {
                return Err("job is not an eligible transient failure".into());
            }
            tracing::info!("transient job requeued");
            return Ok(());
        }
    }
    if args == ["list-generations"] {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&config.database_url)
            .await?;
        let generations = snapshot_publish::list(&pool).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&generations).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if let [command, candidate, operator] = args.as_slice() {
        if command == "publish-generation" {
            let id = uuid::Uuid::parse_str(candidate)?;
            let storage_config = config
                .object_storage
                .ok_or("object storage must be configured")?;
            let store = storage_config.build()?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&config.database_url)
                .await?;
            let scanner = scanner::ClamAv::new(
                config
                    .clamav_addr
                    .ok_or("CLAMAV_ADDR must be configured for publication")?,
            );
            let inputs = snapshot_worker::inputs_from_env()?;
            let published =
                snapshot_publish::publish(&pool, &store, &scanner, &inputs, id, operator).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": published.id,
                    "generation": published.generation,
                    "manifestSha256": published.manifest_sha256,
                    "releaseCount": published.release_count,
                    "fileCount": published.file_count,
                    "dropped": published.dropped,
                }))
                .map_err(|e| e.to_string())?
            );
            tracing::info!(candidate_id=%id, generation = published.generation, "registry generation promoted and activated");
            return Ok(());
        }
        if command == "rollback-generation" {
            let generation: i64 = candidate
                .parse()
                .map_err(|_| "generation must be a positive integer")?;
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(&config.database_url)
                .await?;
            let storage_config = config
                .object_storage
                .ok_or("object storage must be configured")?;
            let store = storage_config.build()?;
            let scanner = scanner::ClamAv::new(
                config
                    .clamav_addr
                    .ok_or("CLAMAV_ADDR must be configured for rollback")?,
            );
            let inputs = snapshot_worker::inputs_from_env()?;
            let index_pub = inputs.index.public_key();
            let seed = inputs.seed.clone();
            let root = inputs.root.clone();
            let rolled = snapshot_publish::rollback(
                &pool, &store, &scanner, &seed, &root, &index_pub, generation, operator,
            )
            .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": rolled.id,
                    "generation": rolled.generation,
                    "previous": rolled.previous,
                }))
                .map_err(|e| e.to_string())?
            );
            tracing::info!(
                generation = rolled.generation,
                previous = rolled.previous,
                "registry generation restored"
            );
            return Ok(());
        }
    }
    if let [command, limit, operator] = args.as_slice() {
        if command == "gc-registry-artifacts" {
            let limit: i64 = limit
                .parse()
                .map_err(|_| "gc limit must be an integer between 1 and 1000")?;
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&config.database_url)
                .await?;
            let storage_config = config
                .object_storage
                .ok_or("object storage must be configured")?;
            let store = storage_config.build()?;
            let report = snapshot_publish::gc(&pool, &store, limit, operator).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "deletedFiles": report.deleted_files,
                    "deletedGenerations": report.deleted_generations,
                    "deletedCandidateFiles": report.deleted_candidate_files,
                    "deletedPrepared": report.deleted_prepared,
                }))
                .map_err(|e| e.to_string())?
            );
            tracing::info!("registry gc completed");
            return Ok(());
        }
    }
    if let [command, candidate, destination] = args.as_slice() {
        if command == "export-candidate" {
            let id = uuid::Uuid::parse_str(candidate)?;
            let storage_config = config
                .object_storage
                .ok_or("object storage must be configured")?;
            let store = storage_config.build()?;
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&config.database_url)
                .await?;
            snapshot_export::export(&pool, &store, id, std::path::Path::new(destination)).await?;
            tracing::info!(candidate_id=%id,"private snapshot candidate exported");
            return Ok(());
        }
    }
    if let [command, user, role, operator] = args.as_slice() {
        if command == "grant-role" || command == "revoke-role" {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect(&config.database_url)
                .await?;
            let changed =
                admin::change_role(&pool, command == "grant-role", user, role, operator).await?;
            tracing::info!(changed, "role command completed");
            return Ok(());
        }
    }
    if args == ["verify-once"]
        || args == ["prepare-publication-once"]
        || args == ["build-initial-candidate"]
        || args == ["run-workers"]
    {
        let storage_config = config
            .object_storage
            .ok_or("object storage must be configured")?;
        let store = storage_config.build()?;
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&config.database_url)
            .await?;
        let scanner = scanner::ClamAv::new(
            config
                .clamav_addr
                .ok_or("CLAMAV_ADDR must be configured for verification")?,
        );
        if args == ["run-workers"] {
            tracing::info!("processing verification and publication preparation queues");
            return worker_daemon::run(&pool, &store, &scanner).await;
        }
        let worked = if args == ["verify-once"] {
            worker::once(&pool, &store, &scanner).await?
        } else if args == ["prepare-publication-once"] {
            publication_worker::once(&pool, &store, &scanner).await?
        } else {
            let inputs = snapshot_worker::inputs_from_env()?;
            let candidate = snapshot_worker::build(&pool, &store, &scanner, inputs).await?;
            if let Some(id) = candidate {
                tracing::info!(candidate_id=%id,"private snapshot candidate staged");
            }
            candidate.is_some()
        };
        tracing::info!(worked, "worker finished");
        return Ok(());
    }
    if !args.is_empty() {
        return Err("usage: cloud-api [migrate | backup-local NEW_DIR | verify-local-backup DIR | restore-local DIR | run-workers | verify-once | prepare-publication-once | build-initial-candidate | export-candidate ID OUTPUT_DIR | verify-candidate ID | list-promotion-checks ID | check-promotion-readiness ID OPERATOR | publish-generation CANDIDATE_ID OPERATOR | rollback-generation GENERATION OPERATOR | list-generations | gc-registry-artifacts LIMIT OPERATOR | retry-verification UPLOAD_ID OPERATOR | retry-publication JOB_ID OPERATOR | grant-role USER ROLE OPERATOR | revoke-role USER ROLE OPERATOR | audit-library-digests [AFTER_DOCUMENT AFTER_REVISION] | repair-library-digest DOCUMENT REVISION OLD_SHA NORMALIZED_SHA OPERATOR]".into());
    }
    let mut auth = configured_auth_router(context.clone())?;
    let mut step_up_oauth = None;
    if let Some((id, secret)) = config.google.clone() {
        let mut google = HttpOAuthProvider::google_with_jwks(id.clone(), secret.clone()).await?;
        if config.jwks_policy != JwksRefreshPolicy::default() {
            // Changing policy rebuilds the upstream cache. Reload immediately to
            // preserve fail-closed startup rather than starting with an empty cache.
            google = google.with_jwks_policy(config.jwks_policy)?;
            google
                .refresh_oidc_jwks(url::Url::parse(
                    "https://www.googleapis.com/oauth2/v3/certs",
                )?)
                .await?;
        }
        auth = auth.with_social_providers(vec![google])?;
        // Separate step-up material with its own verified JWKS cache. Startup
        // fails closed when Google's keys are unreachable.
        step_up_oauth = Some(
            step_up::StepUpOAuth::google(id, secret, &config.origin)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotConnected, e))?,
        );
    }
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    let object_storage = config
        .object_storage
        .map(config::StorageConfig::build)
        .transpose()?;
    let hsts = config.origin.starts_with("https://");
    // The versioning engine runs in this process only when its data directory is configured.
    // Native listeners stay off: the backend's routes are the public surface.
    let versioning_engine = match std::env::var("REMAKE_VERSIONING_DATA_DIR") {
        Ok(dir) if !dir.is_empty() => Some(Arc::new(
            cloud_versioning::VersioningHost::start(cloud_versioning::VersioningConfig {
                data_dir: dir.into(),
                native_listen: None,
                native_auth: None,
            })
            .await
            .map_err(|error| std::io::Error::other(format!("{error:#}")))?,
        )),
        _ => None,
    };
    let mut app = app_inner(
        context,
        pool,
        auth,
        object_storage,
        RouterFlags {
            engine: versioning_engine,
            peer: config.peer,
            trusted_proxy_cidrs: config.trusted_proxy_cidrs,
            step_up_oauth,
            hsts,
            temporary_log_approvals: config.temporary_log_approvals,
            social_limit_enabled: true,
        },
    );
    if let Some(dist) = config.admin_dist_dir {
        app = admin_static::mount(app, &dist, hsts)?;
    }
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, railway = config.railway, "HTTP listener bound; cloud API listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        shutdown_signal().await;
        tracing::info!("shutdown signal received; draining in-flight requests");
    })
    .await?;
    tracing::info!("HTTP server stopped");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
fn app(context: AuthContext, pool: PgPool, auth: AuthRouter) -> Router {
    app_with_storage(context, pool, auth, None)
}

#[cfg(test)]
fn app_with_peer(
    context: AuthContext,
    pool: PgPool,
    auth: AuthRouter,
    peer: remote::peers::PeerConfig,
) -> Router {
    app_inner(
        context,
        pool,
        auth,
        None,
        RouterFlags {
            engine: None,
            peer,
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: None,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: false,
        },
    )
}

/// The router with a versioning engine attached, for tests of workspace creation.
#[cfg(test)]
fn app_with_engine(
    context: AuthContext,
    pool: PgPool,
    auth: AuthRouter,
    engine: Option<Arc<cloud_versioning::VersioningHost>>,
) -> Router {
    app_inner(
        context,
        pool,
        auth,
        None,
        RouterFlags {
            engine,
            peer: remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: None,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: false,
        },
    )
}

#[cfg(test)]
fn app_with_storage(
    context: AuthContext,
    pool: PgPool,
    auth: AuthRouter,
    object_storage: Option<cloud_storage::QuarantineStore>,
) -> Router {
    app_inner(
        context,
        pool,
        auth,
        object_storage,
        RouterFlags {
            engine: None,
            peer: remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: None,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: false,
        },
    )
}

struct RouterFlags {
    /// The versioning engine this process runs, when it is configured. `None` answers workspace
    /// creation with 503 rather than writing ownership the engine does not hold.
    engine: Option<Arc<cloud_versioning::VersioningHost>>,
    peer: remote::peers::PeerConfig,
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    step_up_oauth: Option<step_up::StepUpOAuth>,
    social_limit_enabled: bool,
    hsts: bool,
    temporary_log_approvals: bool,
}

// Keep the established deployment/auth-test constructor while RouterFlags
// remains the internal configuration boundary.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn app_with_proxies(
    context: AuthContext,
    pool: PgPool,
    auth: AuthRouter,
    object_storage: Option<cloud_storage::QuarantineStore>,
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    step_up_oauth: Option<step_up::StepUpOAuth>,
    hsts: bool,
    temporary_log_approvals: bool,
) -> Router {
    app_inner(
        context,
        pool,
        auth,
        object_storage,
        RouterFlags {
            engine: None,
            peer: remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs,
            step_up_oauth,
            social_limit_enabled: true,
            hsts,
            temporary_log_approvals,
        },
    )
}

// Normal key enrollment and approval require fresh step-up grants. The
// separately audited temporary log-code override is opt-in.
/// Product API v3. Every route carries a backend-generated request id and
/// answers failures with the shared error envelope.
fn v3_routes() -> Router<AppState> {
    Router::new()
        .merge(catalog_v3::routes())
        .merge(integrations::routes())
        .merge(remote::routes())
        .merge(assets::routes())
        .merge(overlays::routes())
        .merge(packages::routes())
        .layer(axum::middleware::from_fn(api_error::request_id))
}

fn app_inner(
    context: AuthContext,
    pool: PgPool,
    auth: AuthRouter,
    object_storage: Option<cloud_storage::QuarantineStore>,
    flags: RouterFlags,
) -> Router {
    // One hub per app instance; the sweeper and the relay share it so expiries reach live controllers.
    let remote_hub = std::sync::Arc::new(remote::relay::Hub::new(relay_node_id()));
    remote::relay::spawn_background(pool.clone(), remote_hub.clone());
    let social_limiter = context
        .secondary_storage
        .clone()
        .map(|storage| better_auth::rate_limit::RateLimiter::new(storage, "cloud:auth-social-get"));
    let router = Router::new()
        .route(
            "/api/v1/local-objects/quarantine/{publisher}/{upload}",
            axum::routing::put(local_objects::upload),
        )
        .route(
            "/api/v1/local-inspection/quarantine/{publisher}/{upload}",
            get(local_objects::inspection),
        )
        .route("/", get(web::page))
        .route("/desktop/login", get(web::page))
        .route("/desktop/login.js", get(web::script))
        .route("/desktop/login.css", get(web::style))
        .route("/health/live", get(|| async { StatusCode::OK }))
        .route("/health/ready", get(readiness::ready))
        .route(
            "/api/v1/me/deletion-blockers",
            get(account::blockers).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/me/export",
            get(account::export).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/me/roles/{role}",
            axum::routing::delete(account::leave_role)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/me/deletion-blockers",
            get(account::native_blockers).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/me/export",
            get(account::native_export).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/me",
            get(me)
                .delete(account::delete_me)
                .layer(axum::extract::DefaultBodyLimit::max(2048))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route("/api/v1/auth/providers", get(account::auth_providers))
        .route(
            "/api/v1/me/providers",
            get(account::providers).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/me/providers/unlink",
            axum::routing::post(account::unlink_provider)
                .layer(axum::extract::DefaultBodyLimit::max(2048))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/publishers/{id}/approve",
            axum::routing::post(admin::approve)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/overview",
            get(admin::overview).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/publishers",
            get(admin::publishers).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/audit",
            get(admin::audit).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/moderation/releases",
            get(moderation::queue).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/moderation/releases/{id}/inspection",
            axum::routing::post(moderation::inspection)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/moderation/releases/{id}/decision",
            axum::routing::post(moderation::decide)
                .layer(axum::extract::DefaultBodyLimit::max(2048))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/moderation/releases/{id}/yank",
            axum::routing::post(moderation::yank)
                .layer(axum::extract::DefaultBodyLimit::max(2048))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/moderation/releases/{id}/advisory",
            axum::routing::post(moderation::advisory)
                .layer(axum::extract::DefaultBodyLimit::max(2048))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/releases",
            axum::routing::post(releases::submit)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/releases/{id}",
            get(releases::get).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/releases/{id}/publish",
            axum::routing::post(publication::request)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/releases/{id}/review",
            get(releases::review).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/releases/{id}/revocation",
            get(releases::revocation_status).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/uploads",
            axum::routing::post(uploads::create)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/plugins/uploads/{id}/complete",
            axum::routing::post(uploads::complete)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/registry/current",
            get(snapshot_publish::current).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/registry/generations/{generation}/files/{*path}",
            get(snapshot_publish::file),
        )
        .route(
            "/api/v1/publishers",
            get(publishers::list)
                .post(publishers::create)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/keys/challenges",
            axum::routing::post(publisher_keys::challenge)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/keys",
            get(publisher_keys::list)
                .post(publisher_keys::request_key)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/keys/{key_id}/revoke",
            axum::routing::post(publisher_keys::revoke)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/publishers/{id}/keys",
            get(publisher_keys::admin_list).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/publishers/{id}/keys/{key_id}/approve",
            axum::routing::post(publisher_keys::approve)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/publishers/{id}/keys/{key_id}/revoke",
            axum::routing::post(publisher_keys::admin_revoke)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}",
            axum::routing::delete(publishers::delete)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/transfer",
            get(publishers::current_transfer)
                .post(publishers::offer_transfer)
                .delete(publishers::cancel_transfer)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/transfer/{transfer_id}/accept",
            axum::routing::post(publishers::accept_transfer)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/membership",
            axum::routing::delete(publishers::leave)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route("/api/v1/publishers/{id}/members", get(publishers::members))
        .route(
            "/api/v1/publishers/{id}/releases",
            get(publisher_releases::list).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/publishers/{id}/members/{user_id}",
            axum::routing::put(publishers::set_member).delete(publishers::remove_member),
        )
        .route(
            "/api/v1/sync/collections/{name}",
            get(sync::list).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/sync/collections/{name}/{key}",
            axum::routing::put(sync::put)
                .delete(sync::delete)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/sync/changes",
            get(sync::changes).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/sync/export",
            get(sync::export).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/sync/head",
            get(sync::head).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/desktop/handoff",
            axum::routing::post(desktop::issue)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/handoff/redeem",
            axum::routing::post(desktop::redeem)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/logout",
            axum::routing::post(native_logout)
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/me",
            get(native_me).layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/native/sync/collections/{name}",
            get(sync::native_list).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/native/sync/collections/{name}/{key}",
            axum::routing::put(sync::native_put)
                .delete(sync::native_delete)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/native/sync/changes",
            get(sync::native_changes).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/native/sync/export",
            get(sync::native_export).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/native/sync/head",
            get(sync::native_head).layer(axum::middleware::map_response(sync::sync_response)),
        )
        .route(
            "/api/v1/step-up/password",
            axum::routing::post(step_up::password)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/step-up/oauth/start",
            axum::routing::post(step_up::oauth_start)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/temporary-log-approvals",
            get(temporary_log_approval::availability)
                .post(temporary_log_approval::start)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/admin/temporary-log-approvals/{id}/confirm",
            axum::routing::post(temporary_log_approval::confirm)
                .layer(axum::extract::DefaultBodyLimit::max(4096))
                .layer(axum::middleware::map_response(sync::no_store)),
        )
        .route(
            "/api/v1/step-up/oauth/callback",
            axum::routing::get(step_up::oauth_callback),
        )
        .merge(cloud_v2::routes())
        .merge(v3_routes())
        .merge(versioning::routes())
        .with_state(AppState {
            versioning: Arc::new(
                versioning::Versioning::new(flags.engine).expect("the versioning credential key"),
            ),
            peer: flags.peer,
            auth: context,
            pool,
            object_storage,
            step_up_oauth: flags.step_up_oauth,
            temporary_log_approvals: flags.temporary_log_approvals,
            remote: remote_hub,
        })
        .merge(auth_routes(auth));
    let router = if flags.social_limit_enabled {
        router.layer(axum::middleware::from_fn_with_state(
            social_limiter,
            limit_oauth_get,
        ))
    } else {
        router
    };
    router
        .layer(axum::middleware::from_fn_with_state(
            flags.trusted_proxy_cidrs,
            proxy_boundary,
        ))
        .layer(axum::middleware::from_fn_with_state(
            flags.hsts,
            security_headers::apply,
        ))
}

async fn limit_oauth_get(
    State(limiter): State<Option<better_auth::rate_limit::RateLimiter>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path();
    let budget = if request.method() != axum::http::Method::GET {
        None
    } else if path.starts_with("/api/auth/sign-in/social/") {
        Some(("social-get", 10))
    } else if path.starts_with("/api/auth/callback/") {
        Some(("callback-get", 60))
    } else {
        None
    };
    if let Some((action, limit)) = budget {
        let ip = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<std::net::IpAddr>().ok());
        let (Some(limiter), Some(ip)) = (limiter, ip) else {
            return auth_limit_error(StatusCode::SERVICE_UNAVAILABLE);
        };
        let policy = match better_auth::rate_limit::RateLimitPolicy::new(
            action,
            limit,
            std::time::Duration::from_secs(60),
        ) {
            Ok(policy) => policy,
            Err(_) => return auth_limit_error(StatusCode::INTERNAL_SERVER_ERROR),
        };
        if let Err(error) = limiter.enforce(&policy, &ip.to_string()).await {
            let status = match error {
                better_auth_core::error::AuthError::RateLimited { .. } => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            return auth_limit_error(status);
        }
    }
    next.run(request).await
}

fn auth_limit_error(status: StatusCode) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut response = status.into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::TOO_MANY_REQUESTS {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("60"),
        );
    }
    response
}

async fn proxy_boundary(
    State(trusted): State<Vec<ipnet::IpNet>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let peer = request
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip());
    let trusted_peer =
        peer.is_some_and(|peer| trusted.iter().any(|network| network.contains(&peer)));
    if !trusted_peer {
        for name in [
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-real-ip",
        ] {
            request.headers_mut().remove(name);
        }
    }
    if let Some(peer) = peer {
        let forwarded = if trusted_peer {
            let values: Vec<_> = request
                .headers()
                .get_all("x-forwarded-for")
                .iter()
                .collect();
            match values.as_slice() {
                [value] => value
                    .to_str()
                    .ok()
                    .and_then(|value| value.trim().parse::<std::net::IpAddr>().ok()),
                _ => None,
            }
        } else {
            None
        };
        let client = forwarded.unwrap_or(peer).to_string();
        if let Ok(value) = client.parse() {
            request.headers_mut().insert("x-forwarded-for", value);
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod cloud_v2_tests;
#[cfg(test)]
mod portal_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod schema_v2_recovery_tests;
#[cfg(test)]
mod step_up_tests;
#[cfg(test)]
mod test_db;
#[cfg(test)]
mod test_support;
#[cfg(test)]
mod v3_tests;

/// Identifies this relay node. Set `RELAY_NODE_ID` to a stable name per process;
/// a random id is used otherwise, which is correct but changes on restart.
fn relay_node_id() -> String {
    std::env::var("RELAY_NODE_ID")
        .ok()
        .filter(|id| !id.trim().is_empty())
        .unwrap_or_else(|| format!("relay-{}", uuid::Uuid::new_v4()))
}
