//! Real PostgreSQL coverage for native credential issue: who receives which repository grant,
//! that revocation takes effect for the next issue, and that the published key verifies what is
//! issued.
use super::*;
use axum::{
    body::Body,
    http::{header, HeaderMap, Request},
};
use better_auth::email_password::{EmailPasswordService, SignUpInput};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};
use tower::ServiceExt;

const ORIGIN: &str = "https://cloud.example.test";
const PASSWORD: &str = "test password with enough characters";
const OWNER_REPOSITORY: &str = "00112233445566778899aabbccddeeff";
const OTHER_REPOSITORY: &str = "ffeeddccbbaa99887766554433221100";

struct User {
    id: String,
    cookie: String,
}

struct Fixture {
    router: Router,
    pool: PgPool,
    users: Vec<User>,
}

async fn fixture(users_wanted: usize) -> Fixture {
    let database = crate::test_support::migrated_url();
    let adapter = Arc::new(SqlxDbAdapter::postgres(&database).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&database).await.unwrap());
    let context = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![Arc::new(better_auth::UsernamePlugin)],
    )
    .unwrap();
    adapter
        .apply_migrations(&context.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    secondary.migrate().await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database)
        .await
        .unwrap();
    readiness::MIGRATOR.run(&pool).await.unwrap();
    let mut users = Vec::new();
    for _ in 0..users_wanted {
        let user = EmailPasswordService::new(context.clone())
            .unwrap()
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Versioning Test".into(),
                    password: PASSWORD.into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push(User {
            id: user.user.id,
            cookie: format!("{}={}", user.cookie.name, user.cookie.value),
        });
    }
    let router = crate::app_with_peer(
        context.clone(),
        pool.clone(),
        AuthRouter::new(context.clone()).unwrap(),
        crate::remote::peers::PeerConfig::default(),
    );
    Fixture {
        router,
        pool,
        users,
    }
}

async fn call(
    f: &Fixture,
    user: Option<usize>,
    method: &str,
    path: &str,
) -> (StatusCode, HeaderMap, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(user) = user {
        request = request
            .header(header::COOKIE, &f.users[user].cookie)
            .header(header::ORIGIN, ORIGIN);
    }
    let response = f
        .router
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

/// The public key the backend publishes, as the engine would fetch it.
async fn published_key(f: &Fixture) -> DecodingKey {
    let (status, _, jwks) = call(f, None, "GET", "/api/versioning/v1/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    let x = jwks["keys"][0]["x"]
        .as_str()
        .expect("the Ed25519 public key");
    DecodingKey::from_ed_components(x).expect("a usable Ed25519 key")
}

fn native_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&[versioning::ISSUER]);
    validation.set_audience(&[versioning::AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation
}

#[derive(serde::Deserialize)]
struct Issued {
    token: String,
    repositories: Vec<String>,
    #[serde(rename = "expiresInSeconds")]
    expires_in_seconds: u64,
}

async fn issue(f: &Fixture, user: usize) -> Issued {
    let (status, _, body) = call(
        f,
        Some(user),
        "POST",
        "/api/versioning/v1/native-credentials",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "issue for user {user}: {body}");
    serde_json::from_value(body).expect("the credential document")
}

#[tokio::test]
async fn issuing_requires_an_authenticated_account() {
    let f = fixture(1).await;
    let (status, _, _) = call(&f, None, "POST", "/api/versioning/v1/native-credentials").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_published_key_set_is_public_and_holds_no_private_key() {
    let f = fixture(1).await;
    let (status, headers, jwks) = call(&f, None, "GET", "/api/versioning/v1/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/json");
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert!(
        key.get("d").is_none(),
        "the private scalar is never published"
    );
}

#[tokio::test]
async fn an_owner_receives_a_verifiable_token_for_their_repository_only() {
    let f = fixture(2).await;
    register_workspace_for(&f, 0, OWNER_REPOSITORY).await;
    register_workspace_for(&f, 1, OTHER_REPOSITORY).await;

    let issued = issue(&f, 0).await;
    assert_eq!(issued.repositories, vec![OWNER_REPOSITORY.to_string()]);
    assert_eq!(issued.expires_in_seconds, versioning::LIFETIME_SECONDS);

    let key = published_key(&f).await;
    let claims = jsonwebtoken::decode::<Value>(&issued.token, &key, &native_validation())
        .expect("the token verifies against the published key")
        .claims;
    assert_eq!(claims["sub"], f.users[0].id);
    assert_eq!(
        claims["resources"],
        json!([{ "resource_id": format!("urc-{OWNER_REPOSITORY}"), "permission": ["read", "write"] }])
    );
}

#[tokio::test]
async fn an_account_receives_no_grant_for_a_repository_it_does_not_own() {
    let f = fixture(2).await;
    register_workspace_for(&f, 0, OWNER_REPOSITORY).await;

    let issued = issue(&f, 1).await;
    assert!(issued.repositories.is_empty());

    let key = published_key(&f).await;
    let claims = jsonwebtoken::decode::<Value>(&issued.token, &key, &native_validation())
        .expect("a token with no grants still verifies")
        .claims;
    assert_eq!(claims["resources"], json!([]));
}

#[tokio::test]
async fn revoking_a_workspace_removes_its_grant_on_the_next_issue() {
    let f = fixture(1).await;
    let id = register_workspace_for(&f, 0, OWNER_REPOSITORY).await;
    assert_eq!(issue(&f, 0).await.repositories.len(), 1);

    assert!(versioning::revoke_workspace(&f.pool, id).await.unwrap());
    assert!(issue(&f, 0).await.repositories.is_empty());
    assert!(
        !versioning::revoke_workspace(&f.pool, id).await.unwrap(),
        "a second revoke changes nothing"
    );
}

#[tokio::test]
async fn ownership_rows_only_accept_well_formed_repository_ids() {
    let f = fixture(1).await;
    let owner = f.users[0].id.clone();
    let uppercase =
        versioning::register_workspace(&f.pool, &owner, "00112233445566778899AABBCCDDEEFF", "bad")
            .await;
    assert!(
        uppercase.is_err(),
        "an uppercase id is not the engine's form"
    );
    let short = versioning::register_workspace(&f.pool, &owner, "abc", "bad").await;
    assert!(short.is_err(), "a short id is refused by the table");
}

async fn register_workspace_for(f: &Fixture, user: usize, repository: &str) -> uuid::Uuid {
    versioning::register_workspace(&f.pool, &f.users[user].id, repository, "Workspace")
        .await
        .expect("a well-formed ownership row")
}
