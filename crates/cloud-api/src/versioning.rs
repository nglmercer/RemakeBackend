//! Native credentials for the versioning engine, issued to accounts that Better Auth has
//! authenticated.
//!
//! Browser and SDK requests keep using the in-process path: the session cookie or Bearer token
//! is verified by [`DualUser`], and the backend's own ownership table decides what the account
//! may reach. A native Lore client (the Lore CLI) authenticates on its own transport, so this
//! module turns a verified account into a short-lived signed token that the engine verifies from
//! the key set published here.
//!
//! Scope of this module: it issues credentials for repositories the backend already records as
//! owned by the account. It does not create repositories, and it has no route by which a request
//! can claim one.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use cloud_versioning::bridge::{CredentialBridge, RepositoryGrant};
use serde::Serialize;
use sqlx::{PgPool, Row};
use std::sync::Arc;

use crate::dual_auth::DualUser;
use crate::AppState;

/// The issuer every native token carries. The engine is configured to require it.
pub const ISSUER: &str = "remake-backend";
/// The audience every native token carries. The engine is configured to require it.
pub const AUDIENCE: &str = "remake-native";
/// How long an issued token is valid. A grant revoked in the backend stays usable until this
/// lifetime ends, which bounds the revocation latency of native access.
pub const LIFETIME_SECONDS: u64 = 300;

/// The actions a workspace owner holds on their own repository. Administrative actions stay
/// out of user credentials.
const OWNER_ACTIONS: [&str; 2] = ["read", "write"];

/// The versioning state of this process: the key that signs native tokens, and the engine once it
/// has started.
///
/// The engine starts after the HTTP listener is serving, because it fetches its verification keys
/// from this process's own key set at startup. Until it is set, workspace creation answers 503.
pub struct Versioning {
    pub bridge: Arc<CredentialBridge>,
    /// Revocation cutoffs the engine consults. Shared with the engine, so a revocation here takes
    /// effect there at once.
    pub revocations: Arc<cloud_versioning::revocation::RevocationList>,
    engine: std::sync::Mutex<Option<Arc<cloud_versioning::VersioningHost>>>,
}

impl Versioning {
    /// State with the given key and no engine yet.
    pub fn new(bridge: Arc<CredentialBridge>) -> Self {
        Self {
            bridge,
            revocations: Arc::new(cloud_versioning::revocation::RevocationList::new()),
            engine: std::sync::Mutex::new(None),
        }
    }

    /// The running engine, when one has been set.
    pub fn engine(&self) -> Option<Arc<cloud_versioning::VersioningHost>> {
        self.engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records the engine once it has started.
    pub fn set_engine(&self, host: Arc<cloud_versioning::VersioningHost>) {
        *self
            .engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(host);
    }

    /// Removes the engine so that it can be stopped at shutdown.
    pub fn take_engine(&self) -> Option<Arc<cloud_versioning::VersioningHost>> {
        self.engine
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// Test state: a fresh key and the given engine, if any.
#[cfg(test)]
pub fn for_tests(
    engine: Option<Arc<cloud_versioning::VersioningHost>>,
) -> Result<Arc<Versioning>, String> {
    let state = Versioning::new(bridge()?);
    if let Some(engine) = engine {
        state.set_engine(engine);
    }
    Ok(Arc::new(state))
}

/// The state of a process that runs no engine. Workspace creation answers 503 and nothing is
/// recorded.
#[cfg(test)]
pub fn unconfigured() -> Arc<Versioning> {
    for_tests(None).expect("the versioning credential key")
}

/// How the engine accepts native clients, read from the environment through `lookup`.
///
/// `REMAKE_VERSIONING_NATIVE_LISTEN` names the address the engine's native endpoints bind. It is
/// off when unset. When it is set, `REMAKE_VERSIONING_JWKS_URL` must name the backend's own key
/// set, because a native listener that cannot verify tokens would accept every caller. The engine
/// is configured to require the issuer and audience of `bridge`.
pub fn native_settings(
    bridge: &CredentialBridge,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<
    (
        Option<std::net::SocketAddr>,
        Option<cloud_versioning::bridge::NativeAuth>,
    ),
    String,
> {
    let listen = match lookup("REMAKE_VERSIONING_NATIVE_LISTEN").filter(|v| !v.trim().is_empty()) {
        None => return Ok((None, None)),
        Some(value) => value
            .parse::<std::net::SocketAddr>()
            .map_err(|_| "REMAKE_VERSIONING_NATIVE_LISTEN must be an address:port".to_string())?,
    };
    let jwks_url = lookup("REMAKE_VERSIONING_JWKS_URL")
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            "REMAKE_VERSIONING_JWKS_URL is required when the native listener is enabled".to_string()
        })?;
    Ok((
        Some(listen),
        Some(cloud_versioning::bridge::NativeAuth {
            issuer: bridge.issuer().to_string(),
            audience: bridge.audience().to_string(),
            jwks_url,
        }),
    ))
}

#[cfg(test)]
mod config_tests {
    use super::*;

    fn lookup(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn the_native_listener_is_off_unless_configured() {
        let bridge = bridge().unwrap();
        let (listen, auth) = native_settings(&bridge, lookup(&[])).unwrap();
        assert!(listen.is_none() && auth.is_none());
    }

    #[test]
    fn a_native_listener_requires_the_key_set_it_verifies_against() {
        let bridge = bridge().unwrap();
        let error = native_settings(
            &bridge,
            lookup(&[("REMAKE_VERSIONING_NATIVE_LISTEN", "127.0.0.1:41337")]),
        )
        .unwrap_err();
        assert!(error.contains("REMAKE_VERSIONING_JWKS_URL"));
    }

    #[test]
    fn a_native_listener_verifies_the_bridge_issuer_and_audience() {
        let bridge = bridge().unwrap();
        let (listen, auth) = native_settings(
            &bridge,
            lookup(&[
                ("REMAKE_VERSIONING_NATIVE_LISTEN", "127.0.0.1:41337"),
                (
                    "REMAKE_VERSIONING_JWKS_URL",
                    "http://127.0.0.1:3000/api/versioning/v1/jwks.json",
                ),
            ]),
        )
        .unwrap();
        assert_eq!(listen.unwrap().port(), 41337);
        let auth = auth.unwrap();
        assert_eq!(auth.issuer, ISSUER);
        assert_eq!(auth.audience, AUDIENCE);
    }

    /// A key file is created on first use and reloaded afterwards, so the public key set, and
    /// with it every token issued before a restart, is unchanged.
    #[test]
    fn a_signing_key_file_is_created_once_and_reloaded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing.der");
        let path_text = path.to_str().unwrap().to_string();
        let first = bridge_from_env(|key| {
            (key == "REMAKE_VERSIONING_SIGNING_KEY_FILE").then(|| path_text.clone())
        })
        .unwrap();
        assert!(path.exists(), "the key file is created");
        let second = bridge_from_env(|key| {
            (key == "REMAKE_VERSIONING_SIGNING_KEY_FILE").then(|| path_text.clone())
        })
        .unwrap();
        assert_eq!(first.jwks_json(), second.jwks_json());
    }

    #[cfg(unix)]
    #[test]
    fn a_signing_key_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signing.der");
        let path_text = path.to_str().unwrap().to_string();
        bridge_from_env(|key| {
            (key == "REMAKE_VERSIONING_SIGNING_KEY_FILE").then(|| path_text.clone())
        })
        .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn without_a_key_file_the_key_is_generated_per_process() {
        let first = bridge_from_env(|_| None).unwrap();
        let second = bridge_from_env(|_| None).unwrap();
        assert_ne!(first.jwks_json(), second.jwks_json());
    }

    #[test]
    fn a_malformed_listen_address_is_refused() {
        let bridge = bridge().unwrap();
        assert!(native_settings(
            &bridge,
            lookup(&[("REMAKE_VERSIONING_NATIVE_LISTEN", "not an address")]),
        )
        .is_err());
    }
}

/// Builds the bridge for this process from the environment.
///
/// `REMAKE_VERSIONING_SIGNING_KEY_FILE` names a file holding the PKCS#8 Ed25519 key. When the
/// file exists it is loaded, so a restart and every process that shares it verify the same tokens.
/// When it does not exist a key is generated and written there with owner-only permissions. When
/// the variable is unset the key is generated for this process only, which is the default.
pub fn bridge_from_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Arc<CredentialBridge>, String> {
    let Some(path) = lookup("REMAKE_VERSIONING_SIGNING_KEY_FILE").filter(|p| !p.trim().is_empty())
    else {
        return bridge();
    };
    let path = std::path::PathBuf::from(path);
    if path.exists() {
        let der =
            std::fs::read(&path).map_err(|error| format!("reading the signing key: {error}"))?;
        return CredentialBridge::from_pkcs8_der(&der, ISSUER, AUDIENCE)
            .map(Arc::new)
            .map_err(|error| format!("{error:#}"));
    }
    let generated =
        CredentialBridge::generate(ISSUER, AUDIENCE).map_err(|error| format!("{error:#}"))?;
    write_owner_only(&path, generated.pkcs8_der())?;
    Ok(Arc::new(generated))
}

/// Creates `path` exclusively with owner-only permissions and writes `bytes` into it.
fn write_owner_only(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("creating the signing key file: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("writing the signing key file: {error}"))
}

/// Builds the bridge that signs native tokens for this process.
///
/// The key is generated at startup and not stored. A restart invalidates every outstanding
/// token, which is the right default for credentials that last minutes. Several backend
/// instances would need one shared key, which is not implemented.
pub fn bridge() -> Result<Arc<CredentialBridge>, String> {
    CredentialBridge::generate(ISSUER, AUDIENCE)
        .map(Arc::new)
        .map_err(|error| format!("{error:#}"))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeCredential {
    token: String,
    expires_in_seconds: u64,
    repositories: Vec<String>,
}

/// The public key set the engine fetches to verify native tokens. Carries no private material.
pub async fn jwks(State(state): State<AppState>) -> Response {
    let mut response = state.versioning.bridge.jwks_json().into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

/// Issues a native credential for the calling account, carrying the owner actions on each
/// repository the account owns and nothing else.
pub async fn issue(
    DualUser(user): DualUser,
    State(state): State<AppState>,
) -> Result<Json<NativeCredential>, StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "native-credential").await?;
    let rows = sqlx::query(
        "SELECT lore_repository_id FROM versioning_workspaces \
         WHERE owner_user_id = $1 AND revoked_at IS NULL AND state = 'active' \
         ORDER BY created_at, id",
    )
    .bind(&user.user.id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let repositories: Vec<String> = rows
        .iter()
        .map(|row| row.get::<String, _>("lore_repository_id"))
        .collect();
    let grants: Vec<RepositoryGrant> = repositories
        .iter()
        .map(|id| RepositoryGrant {
            repository_id: Some(id.clone()),
            actions: OWNER_ACTIONS.iter().map(|a| a.to_string()).collect(),
        })
        .collect();
    let token = state
        .versioning
        .bridge
        .mint(&user.user.id, &grants, LIFETIME_SECONDS)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(NativeCredential {
        token,
        expires_in_seconds: LIFETIME_SECONDS,
        repositories,
    }))
}

/// Records that `owner_user_id` owns the Lore repository `lore_repository_id`.
///
/// Server-side only: the caller must already have verified the repository exists in the engine
/// and that the account may own it. No HTTP route calls this yet.
// Used by the tests until the workspace creation flow calls them.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn register_workspace(
    pool: &sqlx::PgPool,
    owner_user_id: &str,
    lore_repository_id: &str,
    name: &str,
) -> Result<uuid::Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO versioning_workspaces (owner_user_id, lore_repository_id, name) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(owner_user_id)
    .bind(lore_repository_id)
    .bind(name)
    .fetch_one(pool)
    .await
}

/// Ends a workspace's ownership when `owner_user_id` owns it and it is active. Returns whether a
/// workspace was ended. The owner check is part of the same statement, so another account's
/// workspace is never changed.
pub async fn revoke_owned_workspace(
    pool: &sqlx::PgPool,
    id: uuid::Uuid,
    owner_user_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE versioning_workspaces SET revoked_at = now() \
         WHERE id = $1 AND owner_user_id = $2 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(owner_user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// The request that creates a workspace.
#[derive(serde::Deserialize)]
pub struct WorkspaceRequest {
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    id: uuid::Uuid,
    repository_id: String,
    name: String,
}

/// The engine's name for a workspace's repository. It is derived from the unique id, so it never
/// collides with another workspace.
fn engine_name(repository_id: &str) -> String {
    format!("ws-{repository_id}")
}

/// Creates a workspace in two steps the reconciliation pass can always finish.
///
/// 1. The workspace is recorded as `pending`, committed on its own, before the engine is touched.
/// 2. The engine creates the repository.
/// 3. The row becomes `active`, and only then can credentials name it.
///
/// A refused engine create removes the pending row. If that removal fails, or the activation fails
/// after the engine created the repository, the row stays pending and [`reconcile`] completes it.
/// So the engine never holds a repository without a row that records its owner.
pub async fn create_workspace(
    DualUser(user): DualUser,
    State(state): State<AppState>,
    Json(input): Json<WorkspaceRequest>,
) -> Result<(StatusCode, Json<Workspace>), StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "workspace-create").await?;
    let name = input.name.trim();
    if name.is_empty()
        || name.chars().count() > 120
        || name.chars().any(|character| character.is_control())
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let engine = state
        .versioning
        .engine()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;

    let id_bytes: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
    let repository_id = hex::encode(id_bytes);
    let workspace_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO versioning_workspaces (owner_user_id, lore_repository_id, name, state) \
         VALUES ($1, $2, $3, 'pending') RETURNING id",
    )
    .bind(&user.user.id)
    .bind(&repository_id)
    .bind(name)
    .fetch_one(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Err(status) = engine
        .create_repository(id_bytes, &engine_name(&repository_id), &user.user.id)
        .await
    {
        // A refused create leaves no workspace. If the removal itself fails, the row stays pending
        // and reconciliation retries the create, which for a refused name is a permanent refusal
        // that removes it.
        let _ = sqlx::query("DELETE FROM versioning_workspaces WHERE id = $1")
            .bind(workspace_id)
            .execute(&state.pool)
            .await;
        return Err(match status.code() {
            cloud_versioning::tonic::Code::AlreadyExists => StatusCode::CONFLICT,
            cloud_versioning::tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
            cloud_versioning::tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        });
    }
    // The engine holds the repository. Until this succeeds the row stays pending, and the caller
    // gets an error that says the workspace is not usable yet.
    sqlx::query("UPDATE versioning_workspaces SET state = 'active' WHERE id = $1")
        .bind(workspace_id)
        .execute(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((
        StatusCode::CREATED,
        Json(Workspace {
            id: workspace_id,
            repository_id,
            name: name.to_string(),
        }),
    ))
}

/// Completes workspaces left pending by a failed step of [`create_workspace`].
///
/// For each pending row the engine create is repeated. It is idempotent for the same id and name,
/// so a repository the engine already holds is simply confirmed. A row the engine refuses as
/// invalid is removed. Other failures leave the row pending for the next pass.
///
/// Returns how many workspaces became active and how many remain pending.
pub async fn reconcile(
    pool: &PgPool,
    engine: &cloud_versioning::VersioningHost,
) -> Result<(usize, usize), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, owner_user_id, lore_repository_id FROM versioning_workspaces \
         WHERE state = 'pending' ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    let (mut activated, mut remaining) = (0, 0);
    for row in rows {
        let id: uuid::Uuid = row.get("id");
        let owner: String = row.get("owner_user_id");
        let repository_id: String = row.get("lore_repository_id");
        let Ok(bytes) = hex::decode(&repository_id) else {
            remaining += 1;
            continue;
        };
        let Ok(id_bytes) = <[u8; 16]>::try_from(bytes.as_slice()) else {
            remaining += 1;
            continue;
        };
        match engine
            .create_repository(id_bytes, &engine_name(&repository_id), &owner)
            .await
        {
            Ok(()) => {
                sqlx::query("UPDATE versioning_workspaces SET state = 'active' WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await?;
                activated += 1;
            }
            Err(status) if status.code() == cloud_versioning::tonic::Code::InvalidArgument => {
                sqlx::query("DELETE FROM versioning_workspaces WHERE id = $1")
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
            Err(status) => {
                tracing::warn!(
                    workspace = %id,
                    code = ?status.code(),
                    "a pending workspace could not be completed; it stays pending"
                );
                remaining += 1;
            }
        }
    }
    Ok((activated, remaining))
}

/// One workspace the caller owns.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSummary {
    id: uuid::Uuid,
    repository_id: String,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// The caller's active workspaces, oldest first. Pending and revoked workspaces are not listed.
pub async fn list_workspaces(
    DualUser(user): DualUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<WorkspaceSummary>>, StatusCode> {
    let rows = sqlx::query(
        "SELECT id, lore_repository_id, name, created_at FROM versioning_workspaces \
         WHERE owner_user_id = $1 AND revoked_at IS NULL AND state = 'active' \
         ORDER BY created_at, id",
    )
    .bind(&user.user.id)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(
        rows.iter()
            .map(|row| WorkspaceSummary {
                id: row.get("id"),
                repository_id: row.get("lore_repository_id"),
                name: row.get("name"),
                created_at: row.get("created_at"),
            })
            .collect(),
    ))
}

/// The response for a branch head.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchHead {
    branch: String,
    /// The revision the branch points at, or `null` when it has none or does not exist.
    revision: Option<String>,
}

/// The branch names a caller may ask for: the characters Lore accepts in a branch name, bounded.
fn valid_branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 120
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
}

/// The head of one branch of a workspace the caller owns. A workspace the caller does not own is
/// reported as not found, the same as one that does not exist, so the answer does not reveal
/// which repositories exist.
pub async fn branch_head(
    DualUser(user): DualUser,
    State(state): State<AppState>,
    axum::extract::Path((workspace, branch)): axum::extract::Path<(uuid::Uuid, String)>,
) -> Result<Json<BranchHead>, StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "branch-head").await?;
    if !valid_branch_name(&branch) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let row = sqlx::query(
        "SELECT lore_repository_id FROM versioning_workspaces \
         WHERE id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND state = 'active'",
    )
    .bind(workspace)
    .bind(&user.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;
    let repository_id: String = row.get("lore_repository_id");
    let engine = state
        .versioning
        .engine()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let bytes: [u8; 16] = hex::decode(&repository_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let revision =
        engine
            .branch_head(bytes, &branch)
            .await
            .map_err(|status| match status.code() {
                cloud_versioning::tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            })?;
    Ok(Json(BranchHead { branch, revision }))
}

/// Loads the revocation cutoffs recorded by earlier processes into `revocations`, so that a
/// revocation survives a restart. Returns how many accounts have a cutoff.
pub async fn load_cutoffs(
    pool: &PgPool,
    revocations: &cloud_versioning::revocation::RevocationList,
) -> Result<usize, sqlx::Error> {
    let rows = sqlx::query("SELECT subject, revoked_before_ms FROM versioning_token_cutoffs")
        .fetch_all(pool)
        .await?;
    for row in &rows {
        let subject: String = row.get("subject");
        let at_ms: i64 = row.get("revoked_before_ms");
        revocations.revoke_before(&subject, at_ms.max(0) as u64);
    }
    Ok(rows.len())
}

/// Records and applies a cutoff for `subject`, so that every credential of the account issued so
/// far is refused. A later cutoff never weakens an earlier one, in the database or in memory.
async fn cut_off(state: &AppState, subject: &str) -> Result<(), StatusCode> {
    let at_ms = cloud_versioning::revocation::now_ms();
    sqlx::query(
        "INSERT INTO versioning_token_cutoffs (subject, revoked_before_ms) VALUES ($1, $2) \
         ON CONFLICT (subject) DO UPDATE SET revoked_before_ms = \
         GREATEST(versioning_token_cutoffs.revoked_before_ms, EXCLUDED.revoked_before_ms)",
    )
    .bind(subject)
    .bind(at_ms as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state.versioning.revocations.revoke_before(subject, at_ms);
    Ok(())
}

/// Refuses every credential the caller holds. The caller then issues a new one, which carries
/// the current grants. Credentials already in use stop working on their next check.
pub async fn revoke_credentials(
    DualUser(user): DualUser,
    State(state): State<AppState>,
) -> Result<StatusCode, StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "credential-revoke").await?;
    cut_off(&state, &user.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ends a workspace the caller owns. Its repository is no longer granted, and the caller's
/// credentials are refused, so the next credential names only the remaining workspaces. A
/// workspace the caller does not own is not found.
pub async fn end_workspace(
    DualUser(user): DualUser,
    State(state): State<AppState>,
    axum::extract::Path(workspace): axum::extract::Path<uuid::Uuid>,
) -> Result<StatusCode, StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "workspace-end").await?;
    if !revoke_owned_workspace(&state.pool, workspace, &user.user.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(StatusCode::NOT_FOUND);
    }
    cut_off(&state, &user.user.id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The query of a history request.
#[derive(serde::Deserialize)]
pub struct HistoryQuery {
    #[serde(default)]
    limit: Option<u32>,
}

/// The most revisions one history request returns.
const HISTORY_LIMIT_MAX: u32 = 200;
/// The revisions a history request returns when it names no limit.
const HISTORY_LIMIT_DEFAULT: u32 = 50;

/// The recent history of one branch of a workspace the caller owns, newest first. Revisions are
/// reported by their hexadecimal ids; a parent is given only when the engine records one.
pub async fn branch_history(
    DualUser(user): DualUser,
    State(state): State<AppState>,
    axum::extract::Path((workspace, branch)): axum::extract::Path<(uuid::Uuid, String)>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    crate::uploads::limit(&state, &user.user.id, "branch-history").await?;
    if !valid_branch_name(&branch) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let limit = query.limit.unwrap_or(HISTORY_LIMIT_DEFAULT);
    if limit == 0 || limit > HISTORY_LIMIT_MAX {
        return Err(StatusCode::BAD_REQUEST);
    }
    let row = sqlx::query(
        "SELECT lore_repository_id FROM versioning_workspaces \
         WHERE id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND state = 'active'",
    )
    .bind(workspace)
    .bind(&user.user.id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    .ok_or(StatusCode::NOT_FOUND)?;
    let repository_id: String = row.get("lore_repository_id");
    let bytes: [u8; 16] = hex::decode(&repository_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let engine = state
        .versioning
        .engine()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let (revisions, has_more) =
        engine
            .branch_history(bytes, &branch, limit)
            .await
            .map_err(|status| match status.code() {
                cloud_versioning::tonic::Code::NotFound => StatusCode::NOT_FOUND,
                cloud_versioning::tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            })?;
    let revisions: Vec<serde_json::Value> = revisions
        .iter()
        .map(|revision| {
            serde_json::json!({
                "id": hex::encode(&revision.id),
                "message": revision.commit_message,
                "timestamp": revision.timestamp,
                "createdBy": revision.created_by,
                "committedBy": revision.committed_by,
                "number": revision.number,
                "parent": revision.parent_self.as_ref().map(hex::encode),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "branch": branch,
        "revisions": revisions,
        "hasMore": has_more,
    })))
}

/// The versioning routes: the public key set, native credential issue, and workspace creation.
pub fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/versioning/v1/jwks.json", get(jwks))
        .route(
            "/api/versioning/v1/native-credentials",
            post(issue).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
        .route(
            "/api/versioning/v1/workspaces",
            post(create_workspace)
                .get(list_workspaces)
                .layer(axum::middleware::map_response(crate::sync::no_store)),
        )
        .route(
            "/api/versioning/v1/native-credentials/revoke",
            post(revoke_credentials).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
        .route(
            "/api/versioning/v1/workspaces/{id}",
            axum::routing::delete(end_workspace)
                .layer(axum::middleware::map_response(crate::sync::no_store)),
        )
        .route(
            "/api/versioning/v1/workspaces/{id}/branches/{branch}",
            get(branch_head).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
        .route(
            "/api/versioning/v1/workspaces/{id}/branches/{branch}/revisions",
            get(branch_history).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
}
