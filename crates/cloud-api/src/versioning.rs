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
    let mut response = state.versioning.jwks_json().into_response();
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

/// The versioning routes: the public key set, and native credential issue.
pub fn routes() -> axum::Router<AppState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/versioning/v1/jwks.json", get(jwks))
        .route(
            "/api/versioning/v1/native-credentials",
            post(issue).layer(axum::middleware::map_response(crate::sync::no_store)),
        )
}
