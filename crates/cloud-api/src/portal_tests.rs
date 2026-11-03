//! Publisher self-service portal coverage: the publisher-scoped release
//! listing, upload-expiry handling, and session boundaries for the new read
//! API. Run explicitly with CLOUD_TEST_DATABASE_URL; the test applies
//! upstream migrations.
//!
//! Release submission basics (duplicate and concurrent submits, cross-user
//! rejection, metadata validation) are covered in `auth_tests`; tampered and
//! forged packages are covered by the verification/worker tests there and in
//! `cloud-verifier`.
use super::*;
use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use tower::ServiceExt;

const ORIGIN: &str = "https://cloud.example.test";

async fn context(database_url: &str) -> (AuthContext, PgPool) {
    use better_auth::database::{SqlxDbAdapter, SqlxSecondaryStorage};
    use better_auth_core::{
        migration::SqlDialect,
        options::{AuthOptions, BaseUrl},
    };
    let adapter = Arc::new(SqlxDbAdapter::postgres(database_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(database_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
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
    let mut attempts = 0;
    loop {
        attempts += 1;
        let auth_result = adapter
            .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
            .await;
        let secondary_result = match &auth_result {
            Ok(()) => secondary.migrate().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        if secondary_result.is_ok() {
            break;
        }
        assert!(
            attempts < 20,
            "auth migrations did not converge: {}",
            secondary_result.unwrap_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await
        .unwrap();
    let mut attempts = 0;
    loop {
        attempts += 1;
        match readiness::MIGRATOR.run(&pool).await {
            Ok(()) => break,
            Err(e) if attempts < 20 => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => panic!("cloud migrations did not converge: {e}"),
        }
    }
    (ctx, pool)
}

async fn user(ctx: &AuthContext) -> (String, String) {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let result = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Portal Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    (
        result.user.id,
        format!("{}={}", result.cookie.name, result.cookie.value),
    )
}

fn app_router(ctx: AuthContext, pool: PgPool) -> Router {
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    app(ctx, pool, auth)
}

async fn get(app: &Router, path: &str, cookie: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

/// An approved publisher with one approved key; returns (publisher, key_row).
async fn publisher_with_key(pool: &PgPool, owner: &str) -> (uuid::Uuid, uuid::Uuid) {
    use tiktools_plugin_package::{KeyId, SigningKey};
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("p{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers (id, namespace, status) VALUES ($1, $2, 'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id, user_id, role) VALUES ($1, $2, 'owner')")
        .bind(publisher)
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap()
    .public_key();
    let key_row = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id, publisher_id, key_id, public_key, fingerprint, status, requested_by) VALUES ($1, $2, $3, $4, $5, 'approved', $6)")
        .bind(key_row)
        .bind(publisher)
        .bind(key.key_id.as_str())
        .bind(&key.public_key)
        .bind(key.fingerprint().unwrap().to_string())
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    (publisher, key_row)
}

/// A quarantined upload plus a release in `status`; returns (upload, release).
async fn release(
    pool: &PgPool,
    publisher: uuid::Uuid,
    key_row: uuid::Uuid,
    owner: &str,
    plugin: &str,
    version: &str,
    status: &str,
) -> (uuid::Uuid, uuid::Uuid) {
    let upload = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id, publisher_id, requested_by, idempotency_key, expected_size, expected_sha256, object_key, status, expires_at, version_id) VALUES ($1, $2, $3, $4, 5, $5, $6, 'quarantined', now() + interval '5 minutes', 'version')")
        .bind(upload)
        .bind(publisher)
        .bind(owner)
        .bind(format!("key{}", upload.simple()))
        .bind("a".repeat(64))
        .bind(format!("quarantine/{publisher}/{upload}"))
        .execute(pool)
        .await
        .unwrap();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_plugin_releases (id, publisher_id, upload_id, publisher_key_id, plugin_id, version, target, status, requested_by) VALUES ($1, $2, $3, $4, $5, $6, 'any', $7, $8)")
        .bind(release)
        .bind(publisher)
        .bind(upload)
        .bind(key_row)
        .bind(plugin)
        .bind(version)
        .bind(status)
        .bind(owner)
        .execute(pool)
        .await
        .unwrap();
    (upload, release)
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_release_listing_scopes_by_membership_and_paginates() {
    let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
    let (ctx, pool) = context(&database_url).await;
    let owner = user(&ctx).await;
    let outsider = user(&ctx).await;
    let other_owner = user(&ctx).await;
    let (publisher, key) = publisher_with_key(&pool, &owner.0).await;
    let (other, other_key) = publisher_with_key(&pool, &other_owner.0).await;
    let namespace: String =
        sqlx::query_scalar("SELECT namespace FROM cloud_publishers WHERE id = $1")
            .bind(publisher)
            .fetch_one(&pool)
            .await
            .unwrap();
    for version in ["1.0.0", "1.1.0", "2.0.0"] {
        release(
            &pool,
            publisher,
            key,
            &owner.0,
            &format!("{namespace}.plugin"),
            version,
            "awaiting_verification",
        )
        .await;
    }
    let other_namespace: String =
        sqlx::query_scalar("SELECT namespace FROM cloud_publishers WHERE id = $1")
            .bind(other)
            .fetch_one(&pool)
            .await
            .unwrap();
    release(
        &pool,
        other,
        other_key,
        &other_owner.0,
        &format!("{other_namespace}.plugin"),
        "1.0.0",
        "awaiting_verification",
    )
    .await;
    let app = app_router(ctx, pool);
    let path = format!("/api/v1/publishers/{publisher}/releases");

    // Anonymous sessions are rejected before any membership check.
    assert_eq!(get(&app, &path, None).await.0, StatusCode::UNAUTHORIZED);
    // Non-members and members of another publisher learn nothing: 404, not 403.
    assert_eq!(
        get(&app, &path, Some(&outsider.1)).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, &path, Some(&other_owner.1)).await.0,
        StatusCode::NOT_FOUND
    );
    // Unknown publishers are also 404.
    assert_eq!(
        get(
            &app,
            &format!("/api/v1/publishers/{}/releases", uuid::Uuid::new_v4()),
            Some(&owner.1)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let (status, body) = get(&app, &path, Some(&owner.1)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
    assert!(body["nextCursor"].is_null());
    // Newest first: the last inserted release sorts first.
    assert_eq!(body["items"][0]["version"], "2.0.0");
    assert_eq!(body["items"][0]["pluginId"], format!("{namespace}.plugin"));
    assert_eq!(body["items"][0]["target"], "any");
    assert_eq!(body["items"][0]["status"], "awaiting_verification");
    assert_eq!(body["items"][0]["sha256"], "a".repeat(64));
    assert_eq!(body["items"][0]["size"], 5);
    // No moderation or verification rows exist yet: explicit nulls, not absence.
    assert!(body["items"][0]["moderation"].is_null());
    assert!(body["items"][0]["verification"].is_null());
    assert_eq!(body["items"][0]["yanked"], false);

    // Keyset pagination walks the whole list without overlap or gaps.
    let (status, first) = get(&app, &format!("{path}?limit=2"), Some(&owner.1)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["nextCursor"].as_str().unwrap().to_owned();
    let (status, second) = get(
        &app,
        &format!("{path}?limit=2&cursor={cursor}"),
        Some(&owner.1),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert!(second["nextCursor"].is_null());
    assert_ne!(first["items"][1]["id"], second["items"][0]["id"]);

    // Broken page references fail instead of silently returning wrong data.
    assert_eq!(
        get(
            &app,
            &format!("{path}?cursor={}", uuid::Uuid::new_v4()),
            Some(&owner.1)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&app, &format!("{path}?limit=0"), Some(&owner.1))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        get(&app, &format!("{path}?limit=101"), Some(&owner.1))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_release_listing_reports_verification_moderation_and_revocation() {
    let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
    let (ctx, pool) = context(&database_url).await;
    let owner = user(&ctx).await;
    let reviewer = user(&ctx).await;
    sqlx::query("INSERT INTO cloud_account_roles (user_id, role) VALUES ($1, 'moderator')")
        .bind(&reviewer.0)
        .execute(&pool)
        .await
        .unwrap();
    let (publisher, key) = publisher_with_key(&pool, &owner.0).await;
    let namespace: String =
        sqlx::query_scalar("SELECT namespace FROM cloud_publishers WHERE id = $1")
            .bind(publisher)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (upload, approved) = release(
        &pool,
        publisher,
        key,
        &owner.0,
        &format!("{namespace}.plugin"),
        "1.0.0",
        "review_approved",
    )
    .await;
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id, release_id, status, result_class) VALUES ($1, $2, 'antivirus_passed', 'antivirus_passed')")
        .bind(upload)
        .bind(approved)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id, release_id, actor_user_id, decision, reason_code) VALUES ($1, $2, $3, 'approve', 'policy_reviewed')")
        .bind(uuid::Uuid::new_v4())
        .bind(approved)
        .bind(&reviewer.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_release_yanks (release_id, yanked_by, reason) VALUES ($1, $2, 'compromised upstream')")
        .bind(approved)
        .bind(&reviewer.0)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_release_advisories (release_id, severity, message, url, created_by) VALUES ($1, 'high', 'upgrade immediately', NULL, $2)")
        .bind(approved)
        .bind(&reviewer.0)
        .execute(&pool)
        .await
        .unwrap();
    let app = app_router(ctx, pool);
    let path = format!("/api/v1/publishers/{publisher}/releases");
    let (status, body) = get(&app, &path, Some(&owner.1)).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item["moderation"]["decision"], "approve");
    assert_eq!(item["moderation"]["reasonCode"], "policy_reviewed");
    assert_eq!(item["verification"]["status"], "antivirus_passed");
    assert_eq!(item["verification"]["resultClass"], "antivirus_passed");
    assert_eq!(item["yanked"], true);
    assert_eq!(item["yankReason"], "compromised upstream");
    assert_eq!(item["advisory"]["severity"], "high");
    assert_eq!(item["advisory"]["message"], "upgrade immediately");
    assert!(item["advisory"]["url"].is_null());
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn upload_complete_rejects_expired_reservations_and_outsiders() {
    let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
    let (ctx, pool) = context(&database_url).await;
    let owner = user(&ctx).await;
    let outsider = user(&ctx).await;
    let (publisher, _) = publisher_with_key(&pool, &owner.0).await;
    let expired = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id, publisher_id, requested_by, idempotency_key, expected_size, expected_sha256, object_key, status, expires_at) VALUES ($1, $2, $3, $4, 5, $5, $6, 'pending', now() - interval '1 minute')")
        .bind(expired)
        .bind(publisher)
        .bind(&owner.0)
        .bind(format!("key{}", expired.simple()))
        .bind("b".repeat(64))
        .bind(format!("quarantine/{publisher}/{expired}"))
        .execute(&pool)
        .await
        .unwrap();
    use axum::{
        http::{Method, Uri},
        response::IntoResponse,
    };
    async fn fake_s3(method: Method, uri: Uri) -> axum::response::Response {
        if method == Method::GET && uri.query().is_some_and(|q| q.contains("versioning")) {
            return ([(header::CONTENT_TYPE, "application/xml")], "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>").into_response();
        }
        if method == Method::HEAD {
            return (
                [
                    (header::CONTENT_LENGTH, "5"),
                    (
                        header::HeaderName::from_static("x-amz-version-id"),
                        "fixture-version",
                    ),
                ],
                "",
            )
                .into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(fake_s3))
            .await
            .unwrap();
    });
    let store = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app_with_storage(ctx, pool, auth, Some(store));
    let path = format!("/api/v1/plugins/uploads/{expired}/complete");
    async fn complete(app: &Router, path: &str, cookie: Option<&str>) -> StatusCode {
        let mut req = Request::builder().method("POST").uri(path);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }
    assert_eq!(complete(&app, &path, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        complete(&app, &path, Some(&outsider.1)).await,
        StatusCode::NOT_FOUND
    );
    // The reservation lapsed: the client must reserve again, not retry completion.
    assert_eq!(
        complete(&app, &path, Some(&owner.1)).await,
        StatusCode::GONE
    );
    assert_eq!(
        complete(
            &app,
            &format!("/api/v1/plugins/uploads/{}/complete", uuid::Uuid::new_v4()),
            Some(&owner.1)
        )
        .await,
        StatusCode::NOT_FOUND
    );
    server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn release_submit_rejects_revoked_keys() {
    let database_url = std::env::var("CLOUD_TEST_DATABASE_URL").unwrap();
    let (ctx, pool) = context(&database_url).await;
    let owner = user(&ctx).await;
    let (publisher, key) = publisher_with_key(&pool, &owner.0).await;
    sqlx::query("UPDATE cloud_publisher_keys SET status = 'revoked' WHERE id = $1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let namespace: String =
        sqlx::query_scalar("SELECT namespace FROM cloud_publishers WHERE id = $1")
            .bind(publisher)
            .fetch_one(&pool)
            .await
            .unwrap();
    let (upload, _) = release(
        &pool,
        publisher,
        key,
        &owner.0,
        &format!("{namespace}.plugin"),
        "9.9.9",
        "awaiting_verification",
    )
    .await;
    // The fixture release above already binds this upload; a resubmit with the
    // same metadata is idempotent, but a fresh upload against a revoked key
    // must conflict instead of queuing verification work.
    let fresh = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id, publisher_id, requested_by, idempotency_key, expected_size, expected_sha256, object_key, status, expires_at, version_id) VALUES ($1, $2, $3, $4, 5, $5, $6, 'quarantined', now() + interval '5 minutes', 'version')")
        .bind(fresh)
        .bind(publisher)
        .bind(&owner.0)
        .bind(format!("key{}", fresh.simple()))
        .bind("c".repeat(64))
        .bind(format!("quarantine/{publisher}/{fresh}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id, status) VALUES ($1, 'queued')")
        .bind(fresh)
        .execute(&pool)
        .await
        .unwrap();
    let app = app_router(ctx, pool);
    let body = serde_json::json!({
        "uploadId": fresh,
        "publisherKeyId": key,
        "pluginId": format!("{namespace}.plugin"),
        "version": "1.0.0",
        "target": "any",
    });
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/plugins/releases")
                .header(header::COOKIE, &owner.1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let _ = upload;
}
