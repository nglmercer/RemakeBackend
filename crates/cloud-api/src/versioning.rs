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
use sqlx::Row;
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
    engine: std::sync::Mutex<Option<Arc<cloud_versioning::VersioningHost>>>,
}

impl Versioning {
    /// State with the given key and no engine yet.
    pub fn new(bridge: Arc<CredentialBridge>) -> Self {
        Self {
            bridge,
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
         WHERE owner_user_id = $1 AND revoked_at IS NULL \
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

/// Ends a workspace's ownership, so its repository is no longer granted to the owner.
// Used by the tests until the workspace creation flow calls them.
#[cfg_attr(not(test), allow(dead_code))]
pub async fn revoke_workspace(pool: &sqlx::PgPool, id: uuid::Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE versioning_workspaces SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
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

/// Creates a repository in the engine and records the caller as its owner.
///
/// The ownership row is written in a transaction that the engine create runs inside. If the
/// engine refuses, nothing is recorded. If the commit fails after the engine created the
/// repository, the repository exists with no owner row, so no credential can reach it; a
/// reconciliation pass can remove such repositories later.
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
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let workspace_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO versioning_workspaces (owner_user_id, lore_repository_id, name) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&user.user.id)
    .bind(&repository_id)
    .bind(name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // The engine's own name for the repository, which never collides with another workspace
    // because it is derived from the unique id.
    let engine_name = format!("ws-{repository_id}");
    if let Err(status) = engine
        .create_repository(id_bytes, &engine_name, &user.user.id)
        .await
    {
        // Dropping the transaction rolls the ownership row back.
        return Err(match status.code() {
            cloud_versioning::tonic::Code::AlreadyExists => StatusCode::CONFLICT,
            cloud_versioning::tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
            cloud_versioning::tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        });
    }
    tx.commit()
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
            post(create_workspace).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
}
