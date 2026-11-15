//! Real PostgreSQL coverage for native credential issue: who receives which repository grant,
//! that revocation takes effect for the next issue, and that the published key verifies what is
//! issued.
use super::*;
use axum::{
    body::Body,
    http::{header, HeaderMap, Request},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    /// The engine this fixture's router serves, when it was given one.
    engine: Option<Arc<cloud_versioning::VersioningHost>>,
    /// Keeps the engine's data directory alive for the fixture's lifetime.
    _data: Option<tempfile::TempDir>,
    /// The versioning state the router serves, including the revocation list.
    versioning: Arc<versioning::Versioning>,
}

async fn fixture(users_wanted: usize) -> Fixture {
    fixture_with(users_wanted, true).await
}

async fn fixture_with(users_wanted: usize, with_engine: bool) -> Fixture {
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
    // The engine and the application share one revocation list, as they do in the process.
    let versioning = versioning::for_tests(None).unwrap();
    let (engine, data) = if with_engine {
        let data = tempfile::tempdir().unwrap();
        let engine = cloud_versioning::VersioningHost::start_with_revocations(
            cloud_versioning::VersioningConfig {
                data_dir: data.path().to_path_buf(),
                native_listen: None,
                native_auth: None,
            },
            versioning.revocations.clone(),
        )
        .await
        .unwrap();
        let engine = Arc::new(engine);
        versioning.set_engine(engine.clone());
        (Some(engine), Some(data))
    } else {
        (None, None)
    };
    let router = crate::app_with_engine(
        context.clone(),
        pool.clone(),
        AuthRouter::new(context.clone()).unwrap(),
        versioning.clone(),
    );
    Fixture {
        router,
        pool,
        users,
        engine,
        _data: data,
        versioning,
    }
}

async fn call(
    f: &Fixture,
    user: Option<usize>,
    method: &str,
    path: &str,
) -> (StatusCode, HeaderMap, Value) {
    call_with_body(f, user, method, path, None).await
}

async fn call_with_body(
    f: &Fixture,
    user: Option<usize>,
    method: &str,
    path: &str,
    body: Option<Value>,
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
    let body = match body {
        Some(value) => Body::from(value.to_string()),
        None => Body::empty(),
    };
    let response = f
        .router
        .clone()
        .oneshot(request.body(body).unwrap())
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

    assert!(
        versioning::revoke_owned_workspace(&f.pool, id, &f.users[0].id)
            .await
            .unwrap()
    );
    assert!(issue(&f, 0).await.repositories.is_empty());
    assert!(
        !versioning::revoke_owned_workspace(&f.pool, id, &f.users[0].id)
            .await
            .unwrap(),
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

/// Creates a workspace as the given user, returning the status and the response document.
async fn create_workspace(f: &Fixture, user: usize, name: &str) -> (StatusCode, Value) {
    let (status, _, body) = call_with_body(
        f,
        Some(user),
        "POST",
        "/api/versioning/v1/workspaces",
        Some(json!({ "name": name })),
    )
    .await;
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_a_workspace_requires_an_authenticated_account() {
    let f = fixture(1).await;
    let (status, _, _) = call_with_body(
        &f,
        None,
        "POST",
        "/api/versioning/v1/workspaces",
        Some(json!({ "name": "stream" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workspace_is_created_in_the_engine_and_owned_by_its_creator() {
    let f = fixture(2).await;
    let (status, created) = create_workspace(&f, 0, "  Stream overlays  ").await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let repository_id = created["repositoryId"].as_str().unwrap().to_string();
    assert_eq!(repository_id.len(), 32);
    assert!(repository_id
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(created["name"], "Stream overlays", "the name is trimmed");

    // The engine holds the repository under the name the backend derived from its id: a create
    // with that name succeeds as an early success, and another name is refused as taken.
    let engine = f.engine.clone().expect("the fixture has an engine");
    let id: [u8; 16] = hex::decode(&repository_id).unwrap().try_into().unwrap();
    engine
        .create_repository(id, &format!("ws-{repository_id}"), &f.users[0].id)
        .await
        .expect("the engine holds the repository under the derived name");
    let taken = engine
        .create_repository(id, "some-other-name", &f.users[0].id)
        .await
        .expect_err("the id is taken by the workspace's repository");
    assert_eq!(taken.code(), cloud_versioning::tonic::Code::AlreadyExists);

    // The owner's credential now names the repository, with the owner actions on it only.
    let issued = issue(&f, 0).await;
    assert_eq!(issued.repositories, vec![repository_id.clone()]);
    let key = published_key(&f).await;
    let claims = jsonwebtoken::decode::<Value>(&issued.token, &key, &native_validation())
        .unwrap()
        .claims;
    assert_eq!(
        claims["resources"],
        json!([{ "resource_id": format!("urc-{repository_id}"), "permission": ["read", "write"] }])
    );
    // The other account holds no grant on it.
    assert!(issue(&f, 1).await.repositories.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_workspace_gets_its_own_repository() {
    let f = fixture(1).await;
    let (_, first) = create_workspace(&f, 0, "first").await;
    let (_, second) = create_workspace(&f, 0, "second").await;
    assert_ne!(first["repositoryId"], second["repositoryId"]);
    assert_eq!(issue(&f, 0).await.repositories.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workspace_name_is_checked_before_anything_is_written() {
    let f = fixture(1).await;
    for name in ["", "   ", "tab\there", &"x".repeat(121)] {
        let (status, _) = create_workspace(&f, 0, name).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "name {name:?}");
    }
    assert!(
        issue(&f, 0).await.repositories.is_empty(),
        "no ownership was recorded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workspace_creation_is_unavailable_without_an_engine() {
    let f = fixture_with(1, false).await;
    let (status, _) = create_workspace(&f, 0, "stream").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        issue(&f, 0).await.repositories.is_empty(),
        "nothing was recorded without an engine"
    );
}

async fn list(f: &Fixture, user: usize) -> Vec<Value> {
    let (status, _, body) = call(f, Some(user), "GET", "/api/versioning/v1/workspaces").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body.as_array().cloned().expect("a list")
}

/// Records a pending workspace the way a create that stopped after its first step leaves one.
async fn insert_pending(f: &Fixture, user: usize) -> String {
    let repository_id = hex::encode(uuid::Uuid::new_v4().as_bytes());
    sqlx::query(
        "INSERT INTO versioning_workspaces (owner_user_id, lore_repository_id, name, state) \
         VALUES ($1, $2, 'pending stream', 'pending')",
    )
    .bind(&f.users[user].id)
    .bind(&repository_id)
    .execute(&f.pool)
    .await
    .unwrap();
    repository_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_workspace_grants_nothing_until_reconciliation_completes_it() {
    let f = fixture(1).await;
    let pending = insert_pending(&f, 0).await;

    assert!(
        issue(&f, 0).await.repositories.is_empty(),
        "pending is not granted"
    );
    assert!(list(&f, 0).await.is_empty(), "pending is not listed");

    let engine = f.engine.clone().expect("the fixture has an engine");
    let (activated, remaining) = versioning::reconcile(&f.pool, &engine).await.unwrap();
    assert_eq!((activated, remaining), (1, 0));

    assert_eq!(issue(&f, 0).await.repositories, vec![pending.clone()]);
    // The engine holds it under the derived name: the create is an early success with that name.
    let id: [u8; 16] = hex::decode(&pending).unwrap().try_into().unwrap();
    engine
        .create_repository(id, &format!("ws-{pending}"), &f.users[0].id)
        .await
        .expect("the reconciled repository exists in the engine");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_workspace_list_shows_only_the_callers_active_workspaces() {
    let f = fixture(2).await;
    let (_, first) = create_workspace(&f, 0, "first").await;
    let (_, second) = create_workspace(&f, 0, "second").await;
    let (_, other) = create_workspace(&f, 1, "theirs").await;

    let mine = list(&f, 0).await;
    assert_eq!(mine.len(), 2);
    assert_eq!(mine[0]["id"], first["id"]);
    assert_eq!(mine[1]["id"], second["id"]);
    assert!(mine.iter().all(|w| w["id"] != other["id"]));
    assert!(
        mine[0]["createdAt"].is_string(),
        "creation time is reported"
    );

    let theirs = list(&f, 1).await;
    assert_eq!(theirs.len(), 1);
    assert_eq!(theirs[0]["id"], other["id"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_workspace_is_not_listed() {
    let f = fixture(1).await;
    let (_, created) = create_workspace(&f, 0, "stream").await;
    let id: uuid::Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert!(
        versioning::revoke_owned_workspace(&f.pool, id, &f.users[0].id)
            .await
            .unwrap()
    );
    assert!(list(&f, 0).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_branch_head_is_read_for_the_owner_and_hidden_from_others() {
    let f = fixture(2).await;
    let (_, created) = create_workspace(&f, 0, "heads").await;
    let id = created["id"].as_str().unwrap().to_string();
    let path = format!("/api/versioning/v1/workspaces/{id}/branches/main");

    // A new workspace's main branch has no revision yet.
    let (status, _, body) = call(&f, Some(0), "GET", &path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["branch"], "main");
    assert!(body["revision"].is_null());

    // Another account gets the same answer as for a workspace that does not exist.
    let (other, _, _) = call(&f, Some(1), "GET", &path).await;
    let (missing, _, _) = call(
        &f,
        Some(0),
        "GET",
        "/api/versioning/v1/workspaces/00000000-0000-0000-0000-000000000000/branches/main",
    )
    .await;
    assert_eq!(other, StatusCode::NOT_FOUND);
    assert_eq!(missing, StatusCode::NOT_FOUND);

    let (status, _, _) = call(
        &f,
        Some(0),
        "GET",
        &format!("/api/versioning/v1/workspaces/{id}/branches/bad%20name"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The issue time, in milliseconds, that a native credential carries.
fn issued_ms(token: &str) -> u64 {
    use base64::Engine as _;
    let payload = token.split('.').nth(1).expect("a compact JWT");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    let claims: Value = serde_json::from_slice(&bytes).expect("JSON claims");
    claims["iat_ms"]
        .as_u64()
        .expect("the issue time in milliseconds")
}

/// A short pause, so that a credential issued after a revocation carries a later millisecond.
async fn tick() {
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_credentials_refuses_the_issued_ones_and_a_new_one_works() {
    let f = fixture(1).await;
    register_workspace_for(&f, 0, OWNER_REPOSITORY).await;
    let before = issue(&f, 0).await;
    tick().await;

    let (status, _, _) = call(
        &f,
        Some(0),
        "POST",
        "/api/versioning/v1/native-credentials/revoke",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let owner = f.users[0].id.clone();
    assert!(f
        .versioning
        .revocations
        .is_revoked(&owner, Some(issued_ms(&before.token))));

    tick().await;
    let after = issue(&f, 0).await;
    assert!(!f
        .versioning
        .revocations
        .is_revoked(&owner, Some(issued_ms(&after.token))));
    assert_eq!(after.repositories, vec![OWNER_REPOSITORY.to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_credentials_requires_an_account() {
    let f = fixture(1).await;
    let (status, _, _) = call(
        &f,
        None,
        "POST",
        "/api/versioning/v1/native-credentials/revoke",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cutoffs_are_recorded_and_survive_a_restart() {
    let f = fixture(1).await;
    register_workspace_for(&f, 0, OWNER_REPOSITORY).await;
    let before = issue(&f, 0).await;
    tick().await;
    let (status, _, _) = call(
        &f,
        Some(0),
        "POST",
        "/api/versioning/v1/native-credentials/revoke",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A fresh process starts with no memory of the revocation and loads it from the database.
    let restarted = cloud_versioning::revocation::RevocationList::new();
    let loaded = versioning::load_cutoffs(&f.pool, &restarted).await.unwrap();
    assert_eq!(loaded, 1);
    assert!(restarted.is_revoked(&f.users[0].id, Some(issued_ms(&before.token))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ending_a_workspace_removes_it_and_refuses_the_owners_earlier_credentials() {
    let f = fixture(2).await;
    let (_, created) = create_workspace(&f, 0, "ending").await;
    let id = created["id"].as_str().unwrap().to_string();
    let before = issue(&f, 0).await;
    assert_eq!(before.repositories.len(), 1);
    tick().await;

    let path = format!("/api/versioning/v1/workspaces/{id}");
    let (other, _, _) = call(&f, Some(1), "DELETE", &path).await;
    assert_eq!(
        other,
        StatusCode::NOT_FOUND,
        "another account cannot end it"
    );

    let (status, _, _) = call(&f, Some(0), "DELETE", &path).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(list(&f, 0).await.is_empty());
    let owner = f.users[0].id.clone();
    assert!(f
        .versioning
        .revocations
        .is_revoked(&owner, Some(issued_ms(&before.token))));

    let (again, _, _) = call(&f, Some(0), "DELETE", &path).await;
    assert_eq!(again, StatusCode::NOT_FOUND, "a workspace ends once");
    tick().await;
    assert!(issue(&f, 0).await.repositories.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_workspace_has_an_empty_history_and_others_cannot_read_it() {
    let f = fixture(2).await;
    let (_, created) = create_workspace(&f, 0, "history").await;
    let id = created["id"].as_str().unwrap().to_string();
    let path = format!("/api/versioning/v1/workspaces/{id}/branches/main/revisions");

    let (status, _, body) = call(&f, Some(0), "GET", &path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["branch"], "main");
    assert_eq!(body["revisions"], json!([]));
    assert_eq!(body["hasMore"], false);

    let (other, _, _) = call(&f, Some(1), "GET", &path).await;
    assert_eq!(other, StatusCode::NOT_FOUND);
    let (bad_limit, _, _) = call(
        &f,
        Some(0),
        "GET",
        &format!("/api/versioning/v1/workspaces/{id}/branches/main/revisions?limit=0"),
    )
    .await;
    assert_eq!(bad_limit, StatusCode::BAD_REQUEST);
    let (missing_branch, _, _) = call(
        &f,
        Some(0),
        "GET",
        &format!("/api/versioning/v1/workspaces/{id}/branches/nope/revisions"),
    )
    .await;
    assert_eq!(missing_branch, StatusCode::NOT_FOUND);
}
