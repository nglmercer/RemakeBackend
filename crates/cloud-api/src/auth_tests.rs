//! Exercises the actual Cloud router and Better Auth against an isolated PostgreSQL database.
//! Run explicitly with CLOUD_TEST_DATABASE_URL; the test applies upstream migrations.
use super::*;
use axum::{
    body::Body,
    extract::Path,
    http::{header, HeaderMap, Request},
    routing::post,
};
use better_auth_core::options::SessionOptions;
use serde_json::json;
use tower::ServiceExt;
use url::Url;

const ORIGIN: &str = "https://cloud.example.test";

#[test]
fn readiness_reason_truncation_preserves_utf8() {
    let mut reason = format!("{}é", "x".repeat(1023));
    super::truncate_utf8(&mut reason, 1024);
    assert_eq!(reason.len(), 1023);
    assert!(reason.chars().all(|c| c == 'x'));
    let mut short = "é".to_owned();
    super::truncate_utf8(&mut short, 1024);
    assert_eq!(short, "é");
}

#[test]
fn better_auth_resolves_forwarded_ip_only_when_proxy_trust_is_enabled() {
    let make_context = |enabled| {
        AuthContext::builder(AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            advanced: super::proxy_auth_options(enabled),
            ..Default::default()
        })
        .build()
        .unwrap()
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
    let request = better_auth::context::RequestMetadata::new(
        axum::http::Method::GET,
        "/".parse().unwrap(),
        headers,
    );
    assert_eq!(
        make_context(false)
            .resolve_request(&request)
            .unwrap()
            .client_ip,
        None
    );
    assert_eq!(
        make_context(true)
            .resolve_request(&request)
            .unwrap()
            .client_ip,
        Some("203.0.113.8".parse().unwrap())
    );
}

#[tokio::test]
async fn forwarded_headers_require_an_allowlisted_proxy_peer() {
    let app = Router::new()
        .route(
            "/",
            axum::routing::get(|headers: HeaderMap| async move {
                headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("missing")
                    .to_owned()
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            vec!["127.0.0.1/32".parse::<ipnet::IpNet>().unwrap()],
            super::proxy_boundary,
        ));
    let untrusted = Request::builder()
        .uri("/")
        .header("x-forwarded-for", "203.0.113.8")
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(untrusted).await.unwrap();
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "missing"
    );
    let trusted = Request::builder()
        .uri("/")
        .header("x-forwarded-for", "203.0.113.8")
        .extension(axum::extract::connect_info::ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(trusted).await.unwrap();
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "203.0.113.8"
    );
    let spoofed = Request::builder()
        .uri("/")
        .header("x-forwarded-for", "203.0.113.99")
        .extension(axum::extract::connect_info::ConnectInfo(
            "192.0.2.4:43210".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(spoofed).await.unwrap();
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "192.0.2.4"
    );
    let ambiguous = Request::builder()
        .uri("/")
        .header("x-forwarded-for", "203.0.113.8, 192.0.2.99")
        .extension(axum::extract::connect_info::ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(ambiguous).await.unwrap();
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
        "127.0.0.1"
    );
}

#[tokio::test]
async fn auth_sign_in_limiter_uses_peer_and_account_budgets() {
    use better_auth_core::adapter::memory::{MemoryDb, MemorySecondaryStorage};
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            advanced: super::proxy_auth_options(true),
            ..Default::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![],
    )
    .unwrap();
    let app = auth_routes(super::configured_auth_router(ctx).unwrap()).layer(
        axum::middleware::from_fn_with_state(Vec::<ipnet::IpNet>::new(), super::proxy_boundary),
    );
    async fn attempt(app: &Router, peer: &str, email: &str) -> StatusCode {
        let request = Request::builder()
            .method("POST")
            .uri("/api/auth/sign-in/email")
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-forwarded-for", "203.0.113.99")
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::from(
                json!({"email":email,"password":"incorrect password"}).to_string(),
            ))
            .unwrap();
        app.clone().oneshot(request).await.unwrap().status()
    }
    for _ in 0..10 {
        assert_eq!(
            attempt(&app, "192.0.2.1:1234", "victim@example.test").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        attempt(&app, "192.0.2.1:1234", "other@example.test").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        attempt(&app, "192.0.2.2:1234", "victim@example.test").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        attempt(&app, "192.0.2.3:1234", "other@example.test").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn social_get_limiter_uses_sanitized_peer_and_fails_closed() {
    use better_auth::rate_limit::RateLimiter;
    use better_auth_core::adapter::memory::MemorySecondaryStorage;
    let limiter = Some(RateLimiter::new(
        Arc::new(MemorySecondaryStorage::default()),
        "test-social-get",
    ));
    let app = Router::new()
        .route(
            "/api/auth/sign-in/social/{provider}",
            get(|| async { StatusCode::OK }),
        )
        .route(
            "/api/auth/callback/{provider}",
            get(|| async { StatusCode::OK }),
        )
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            super::limit_oauth_get,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Vec::<ipnet::IpNet>::new(),
            super::proxy_boundary,
        ));
    let attempt = |peer: Option<&str>| {
        let mut builder = Request::builder()
            .uri("/api/auth/sign-in/social/fixture")
            .header("x-forwarded-for", "203.0.113.99");
        if let Some(peer) = peer {
            builder = builder.extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ));
        }
        builder.body(Body::empty()).unwrap()
    };
    assert_eq!(
        app.clone().oneshot(attempt(None)).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    for _ in 0..10 {
        assert_eq!(
            app.clone()
                .oneshot(attempt(Some("192.0.2.1:1234")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let response = app
        .clone()
        .oneshot(attempt(Some("192.0.2.1:1234")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        app.clone()
            .oneshot(attempt(Some("192.0.2.2:1234")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let callback = || {
        Request::builder()
            .uri("/api/auth/callback/fixture?code=invalid&state=invalid")
            .extension(axum::extract::ConnectInfo(
                "192.0.2.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    };
    for _ in 0..60 {
        assert_eq!(
            app.clone().oneshot(callback()).await.unwrap().status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        app.oneshot(callback()).await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let unavailable = Router::new()
        .route(
            "/api/auth/sign-in/social/{provider}",
            get(|| async { StatusCode::OK }),
        )
        .layer(axum::middleware::from_fn_with_state(
            None::<RateLimiter>,
            super::limit_oauth_get,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Vec::<ipnet::IpNet>::new(),
            super::proxy_boundary,
        ));
    assert_eq!(
        unavailable
            .oneshot(attempt(Some("192.0.2.3:1234")))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
#[ignore = "requires outbound network access to Google's JWKS endpoint"]
async fn google_jwks_live_refresh_smoke() {
    let mut provider = better_auth::http_oauth::HttpOAuthProvider::google(
        "jwks-smoke-client",
        "jwks-smoke-secret",
    )
    .unwrap();
    let count = provider
        .refresh_oidc_jwks(Url::parse("https://www.googleapis.com/oauth2/v3/certs").unwrap())
        .await
        .unwrap();
    assert!(count > 0, "Google returned no supported signing keys");
}

async fn fixture() -> (String, tokio::task::JoinHandle<()>) {
    async fn token(
        axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        assert_eq!(form.get("code").map(String::as_str), Some("fixture-code"));
        assert!(form.get("code_verifier").is_some_and(|v| v.len() >= 43));
        Json(json!({"access_token":"fixture-token", "token_type":"Bearer", "expires_in":3600}))
    }
    async fn userinfo(Path(verified): Path<String>) -> Json<serde_json::Value> {
        Json(
            json!({"sub":format!("cloud-test-{verified}"), "email":"cloud-fixture@example.test", "email_verified":verified == "verified", "name":"Fixture"}),
        )
    }
    let router = Router::new()
        .route("/token", post(token))
        .route("/userinfo/{verified}", get(userinfo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

fn provider(base: &str, id: &str, variant: &str) -> HttpOAuthProvider {
    HttpOAuthProvider::insecure_for_testing(
        id,
        "client-id",
        "client-secret",
        Url::parse(&format!("{base}/authorize")).unwrap(),
        Url::parse(&format!("{base}/token")).unwrap(),
        Url::parse(&format!("{base}/userinfo/{variant}")).unwrap(),
        ["openid", "email"],
    )
}

async fn context(database_url: &str, cache: bool) -> (AuthContext, PgPool) {
    let adapter = Arc::new(SqlxDbAdapter::postgres(database_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(database_url).await.unwrap());
    let mut session = SessionOptions::default();
    session.cookie_cache.enabled = cache;
    session.cookie_cache.max_age_seconds = 3600;
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            session,
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![Arc::new(better_auth::UsernamePlugin)],
    )
    .unwrap();
    // The ignored suite shares one database across parallel tests, so a
    // concurrent first-time setup may be halfway through the same migrations;
    // retry until they converge instead of failing on a unique violation for
    // an object the other setup is creating.
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
    let pool = PgPoolOptions::new()
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

fn router(ctx: AuthContext, pool: PgPool, base: &str) -> Router {
    let auth = AuthRouter::new(ctx.clone())
        .unwrap()
        .with_social_providers(vec![
            provider(base, "fixture", "verified"),
            provider(base, "unverified", "unverified"),
        ])
        .unwrap();
    app(ctx, pool, auth)
}

async fn request(
    app: &Router,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    app.clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn begin(app: &Router, provider: &str) -> String {
    let response = request(
        app,
        "GET",
        &format!("/api/auth/sign-in/social/{provider}"),
        None,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let pairs: Vec<_> = location.query_pairs().collect();
    assert!(pairs
        .iter()
        .any(|(key, value)| key == "code_challenge_method" && value == "S256"));
    pairs
        .iter()
        .find(|(key, _)| key == "state")
        .unwrap()
        .1
        .to_string()
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn social_get_rate_limit_applies_to_real_auth_router() {
    let url = crate::test_support::migrated_url();
    let (existing, pool) = context(&url, false).await;
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            advanced: super::proxy_auth_options(true),
            ..Default::default()
        },
        existing.adapter.clone(),
        existing.secondary_storage.clone(),
        vec![],
    )
    .unwrap();
    let (base, fixture_handle) = fixture().await;
    let auth = super::configured_auth_router(ctx.clone())
        .unwrap()
        .with_social_providers(vec![provider(&base, "fixture", "verified")])
        .unwrap();
    let second_auth = super::configured_auth_router(ctx.clone())
        .unwrap()
        .with_social_providers(vec![provider(&base, "fixture", "verified")])
        .unwrap();
    let app = app_with_proxies(
        ctx.clone(),
        pool.clone(),
        auth,
        None,
        Vec::new(),
        None,
        false,
        false,
    );
    let second_app = app_with_proxies(ctx, pool, second_auth, None, Vec::new(), None, false, false);
    let attempt = |peer: &str| {
        Request::builder()
            .uri("/api/auth/sign-in/social/fixture")
            .header("x-forwarded-for", "203.0.113.99")
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    };
    let mut callback_state = None;
    for i in 0..10 {
        let instance = if i % 2 == 0 { &app } else { &second_app };
        let response = instance
            .clone()
            .oneshot(attempt("198.18.0.1:1234"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FOUND);
        if callback_state.is_none() {
            let location =
                Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
            callback_state = location
                .query_pairs()
                .find(|(name, _)| name == "state")
                .map(|(_, value)| value.into_owned());
        }
    }
    assert_eq!(
        second_app
            .clone()
            .oneshot(attempt("198.18.0.1:1234"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let callback = Request::builder()
        .uri(format!(
            "/api/auth/callback/fixture?code=fixture-code&state={}",
            callback_state.unwrap()
        ))
        .extension(axum::extract::ConnectInfo(
            "198.18.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        second_app.clone().oneshot(callback).await.unwrap().status(),
        StatusCode::FOUND
    );
    let invalid_callback = |peer: &str| {
        Request::builder()
            .uri("/api/auth/callback/fixture?code=fixture-code&state=invalid")
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::empty())
            .unwrap()
    };
    for i in 0..59 {
        let instance = if i % 2 == 0 { &app } else { &second_app };
        assert_ne!(
            instance
                .clone()
                .oneshot(invalid_callback("198.18.0.1:1234"))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        second_app
            .clone()
            .oneshot(invalid_callback("198.18.0.1:1234"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        second_app
            .clone()
            .oneshot(invalid_callback("198.18.0.2:1234"))
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.oneshot(attempt("198.18.0.2:1234"))
            .await
            .unwrap()
            .status(),
        StatusCode::FOUND
    );
    fixture_handle.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_email_collision_requires_both_accounts_verified() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let url = crate::test_support::migrated_url();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("link_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&control)
        .await
        .unwrap();
    let mut isolated = Url::parse(&url).unwrap();
    isolated
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let (ctx, pool) = context(isolated.as_str(), false).await;
    let local = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: "cloud-fixture@example.test".into(),
                name: "Existing user".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let (base, fixture_handle) = fixture().await;
    let app = router(ctx, pool.clone(), &base);
    let state = begin(&app, "fixture").await;
    let callback = format!("/api/auth/callback/fixture?code=fixture-code&state={state}");
    assert_eq!(
        request(&app, "GET", &callback, None, None).await.status(),
        StatusCode::FORBIDDEN
    );
    let linked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM account WHERE provider_id='fixture'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked, 0, "unverified local account must not be linked");
    sqlx::query("UPDATE \"user\" SET email_verified=true WHERE id=$1")
        .bind(&local.user.id)
        .execute(&pool)
        .await
        .unwrap();
    let state = begin(&app, "fixture").await;
    let callback = format!("/api/auth/callback/fixture?code=fixture-code&state={state}");
    assert_eq!(
        request(&app, "GET", &callback, None, None).await.status(),
        StatusCode::FOUND
    );
    let linked_user: String =
        sqlx::query_scalar("SELECT user_id FROM account WHERE provider_id='fixture'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked_user, local.user.id);
    fixture_handle.abort();
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&control)
        .await
        .unwrap();
}

/// PR B exit: a Cloud admin can review publishers and audit events through the
/// read-only admin APIs; anonymous callers get 401 and non-admins get 403
/// without enumerating anything. Malicious filters fail closed with 400.
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn admin_read_apis_authorize_paginate_and_redact() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut cookies = Vec::new();
    let mut user_ids = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Admin Read".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        user_ids.push(result.user.id.clone());
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    async fn get(app: &Router, path: &str, cookie: Option<&str>) -> axum::response::Response {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }
    async fn body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap(),
        )
        .unwrap()
    }
    // Anonymous callers are rejected before any data access.
    for path in [
        "/api/v1/admin/overview",
        "/api/v1/admin/publishers",
        "/api/v1/admin/audit",
    ] {
        assert_eq!(
            get(&app, path, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    // Ordinary users cannot enumerate administrative data.
    for path in [
        "/api/v1/admin/overview",
        "/api/v1/admin/publishers?status=pending",
        "/api/v1/admin/audit",
    ] {
        assert_eq!(
            get(&app, path, Some(&cookies[0])).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    // Malicious filters fail closed even for callers who would otherwise pass
    // the role gate; unknown query fields are rejected by deny_unknown_fields.
    assert!(
        admin::change_role(&pool, true, &user_ids[0], "admin", "test-operator")
            .await
            .unwrap()
    );
    for path in [
        "/api/v1/admin/publishers?status=approved%2Cpending",
        "/api/v1/admin/publishers?status=",
        "/api/v1/admin/publishers?status=PENDING",
        "/api/v1/admin/publishers?limit=0",
        "/api/v1/admin/publishers?limit=101",
        "/api/v1/admin/publishers?limit=-1",
        "/api/v1/admin/publishers?cursor=00000000-0000-0000-0000-000000000000",
        "/api/v1/admin/publishers?cursor=not-a-uuid",
        "/api/v1/admin/publishers?order=desc",
        "/api/v1/admin/audit?limit=1000",
        "/api/v1/admin/audit?cursor=00000000-0000-0000-0000-000000000000",
        "/api/v1/admin/audit?select=*",
    ] {
        assert_eq!(
            get(&app, path, Some(&cookies[0])).await.status(),
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    // Seed two pending publishers owned by the non-admin user.
    let baseline: i64 = body(get(&app, "/api/v1/admin/overview", Some(&cookies[0])).await).await
        ["publishers"]["pending"]
        .as_i64()
        .unwrap();
    let mut seeded = Vec::new();
    for _ in 0..2 {
        let namespace = format!("adm{}", uuid::Uuid::new_v4().simple());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/publishers")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::COOKIE, &cookies[1])
                    .body(Body::from(json!({"namespace": namespace}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        seeded.push(body(response).await["id"].as_str().unwrap().to_owned());
    }
    // The dedicated test database is shared by the suite, so assert deltas
    // against the pre-seed baseline instead of absolute counts.
    let overview = get(&app, "/api/v1/admin/overview", Some(&cookies[0])).await;
    assert_eq!(overview.status(), StatusCode::OK);
    assert_eq!(overview.headers()[header::CACHE_CONTROL], "no-store");
    // Every admin read carries no-store: administrative data must never sit
    // in a browser or proxy cache.
    for path in [
        "/api/v1/admin/publishers?status=pending&limit=1",
        "/api/v1/admin/audit?limit=1",
    ] {
        let response = get(&app, path, Some(&cookies[0])).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store",
            "{path}"
        );
    }
    let overview = body(overview).await;
    assert_eq!(overview["contractVersion"], 1);
    assert_eq!(overview["publishers"]["pending"], baseline + 2);
    let publishers = get(
        &app,
        "/api/v1/admin/publishers?status=pending&limit=1",
        Some(&cookies[0]),
    )
    .await;
    assert_eq!(publishers.status(), StatusCode::OK);
    let publishers = body(publishers).await;
    assert_eq!(publishers["contractVersion"], 1);
    assert_eq!(publishers["items"].as_array().unwrap().len(), 1);
    // The projection carries namespaces and statuses only: no user secrets.
    let raw_publishers = publishers.to_string().to_lowercase();
    for leaked in [
        "email",
        "members",
        "userid",
        "user_id",
        "requested_by",
        "fingerprint",
    ] {
        assert!(
            !raw_publishers.contains(leaked),
            "admin publishers projection leaks {leaked}"
        );
    }
    let first = &publishers["items"][0];
    assert!(
        first.get("namespace").is_some()
            && first.get("status").is_some()
            && first.get("createdAt").is_some()
    );
    assert!(
        first.get("userId").is_none()
            && first.get("email").is_none()
            && first.get("members").is_none()
    );
    let cursor = publishers["nextCursor"].as_str().unwrap();
    let second = body(
        get(
            &app,
            &format!("/api/v1/admin/publishers?status=pending&limit=1&cursor={cursor}"),
            Some(&cookies[0]),
        )
        .await,
    )
    .await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_ne!(second["items"][0]["id"], first["id"]);
    // Other suite tests may leave pending publishers behind; pages only need
    // to advance without repeating the cursor row.
    let seen_first = second["items"][0]["id"].as_str().unwrap().to_owned();
    let mut seen = std::collections::BTreeSet::from([
        first["id"].as_str().unwrap().to_owned(),
        seen_first.clone(),
    ]);
    let mut cursor = second["nextCursor"].as_str().map(str::to_owned);
    while let Some(c) = cursor {
        let page = body(
            get(
                &app,
                &format!("/api/v1/admin/publishers?status=pending&limit=1&cursor={c}"),
                Some(&cookies[0]),
            )
            .await,
        )
        .await;
        for item in page["items"].as_array().unwrap() {
            assert!(
                seen.insert(item["id"].as_str().unwrap().to_owned()),
                "publisher page repeated an id"
            );
        }
        cursor = page["nextCursor"].as_str().map(str::to_owned);
    }
    assert!(seen.len() >= 2);
    // A revoked admin loses read access immediately. Revocation needs a second
    // admin standing: the last admin role is protected by design.
    assert!(
        admin::change_role(&pool, true, &user_ids[1], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert!(
        admin::change_role(&pool, false, &user_ids[0], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert_eq!(
        get(&app, "/api/v1/admin/overview", Some(&cookies[0]))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    // Re-grant the first admin and drop the second; the audit trail stays redacted.
    assert!(
        admin::change_role(&pool, true, &user_ids[0], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert!(
        admin::change_role(&pool, false, &user_ids[1], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert!(
        seen.contains(&seeded[0]) && seen.contains(&seeded[1]),
        "seeded publishers must be pageable"
    );
    let approve = format!("/api/v1/admin/publishers/{}/approve", seeded[1]);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&approve)
                .header(header::COOKIE, &cookies[0])
                .header(header::ORIGIN, ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let audit = body(get(&app, "/api/v1/admin/audit?limit=50", Some(&cookies[0])).await).await;
    assert_eq!(audit["contractVersion"], 1);
    assert!(!audit["events"].as_array().unwrap().is_empty());
    // Find our approval event instead of assuming it is the global newest:
    // the shared test database accumulates rows from other tests.
    let newest = audit["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["action"] == "publisher.approved"
                && e["publisherId"].as_str() == Some(seeded[1].as_str())
        })
        .expect("approval audit event must be listed")
        .clone();
    // Redaction: exact key set, no secret-bearing fields anywhere in the page.
    let mut keys: Vec<&str> = newest
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "action",
            "actorUserId",
            "createdAt",
            "id",
            "newRole",
            "oldRole",
            "publisherId",
            "subjectId",
            "targetUserId"
        ]
    );
    let raw = audit.to_string().to_lowercase();
    for leaked in [
        "email",
        "token",
        "secret",
        "password",
        "object_key",
        "version_id",
        "digest",
        "cookie",
        "@example.test",
    ] {
        assert!(!raw.contains(leaked), "admin audit page leaks {leaked}");
    }
    let newest_id = newest["id"].as_str().unwrap();
    let older = body(
        get(
            &app,
            &format!("/api/v1/admin/audit?limit=50&cursor={newest_id}"),
            Some(&cookies[0]),
        )
        .await,
    )
    .await;
    assert!(older["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["id"].as_str().unwrap() != newest_id));
    // The second user never gained admin: still forbidden after real data exists.
    assert_eq!(
        get(&app, "/api/v1/admin/audit", Some(&cookies[1]))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_session_restart_replay_and_revocation() {
    let database_url = crate::test_support::migrated_url();
    let (base, fixture_handle) = fixture().await;
    for cache in [false, true] {
        let (ctx, pool) = context(&database_url, cache).await;
        let app = router(ctx, pool.clone(), &base);
        let state = begin(&app, "fixture").await;
        let callback = format!("/api/auth/callback/fixture?code=fixture-code&state={state}");
        let response = request(&app, "GET", &callback, None, None).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let retained: Option<String> = sqlx::query_scalar(
            "SELECT token_envelope FROM account WHERE provider_id = $1 AND account_id = $2",
        )
        .bind("fixture")
        .bind("cloud-test-verified")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(retained.is_none(), "provider tokens must not be retained");
        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(!cookies.is_empty());
        assert_eq!(
            request(&app, "GET", "/api/v1/me", Some(&cookies), None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(&app, "GET", &callback, None, None).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let state = begin(&app, "unverified").await;
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("/api/auth/callback/unverified?code=fixture-code&state={state}"),
                None,
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let (ctx, pool) = context(&database_url, cache).await;
        let restarted = router(ctx, pool, &base);
        assert_eq!(
            request(&restarted, "GET", "/api/v1/me", Some(&cookies), None)
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            request(
                &restarted,
                "POST",
                "/api/auth/sign-out",
                Some(&cookies),
                Some("https://evil.example.test")
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(request(
            &restarted,
            "POST",
            "/api/auth/sign-out",
            Some(&cookies),
            Some(ORIGIN)
        )
        .await
        .status()
        .is_success());
        assert_eq!(
            request(&app, "GET", "/api/v1/me", Some(&cookies), None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    fixture_handle.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_requests_are_isolated_and_audited() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut cookies = Vec::new();
    let mut user_ids = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        user_ids.push(result.user.id.clone());
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let namespace = format!("pub{}", uuid::Uuid::new_v4().simple());
    async fn create(
        app: &Router,
        cookie: Option<&str>,
        origin: &str,
        namespace: &str,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/publishers")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, origin);
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(
                builder
                    .body(Body::from(json!({"namespace":namespace}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    assert_eq!(
        create(&app, None, ORIGIN, &namespace).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        create(
            &app,
            Some(&cookies[0]),
            "https://evil.example.test",
            &namespace
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        create(&app, Some(&cookies[0]), ORIGIN, "bad/name")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = create(&app, Some(&cookies[0]), ORIGIN, &namespace).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["status"], "pending");
    assert_eq!(data["role"], "owner");
    assert_eq!(
        create(&app, Some(&cookies[1]), ORIGIN, &namespace)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    for (cookie, expected) in [(&cookies[0], 1), (&cookies[1], 0)] {
        let response = request(&app, "GET", "/api/v1/publishers", Some(cookie), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let data: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data.as_array().unwrap().len(), expected);
    }
    let publisher_id = data["id"].as_str().unwrap();
    let member_path = format!("/api/v1/publishers/{publisher_id}/members/{}", user_ids[1]);
    let members_path = format!("/api/v1/publishers/{publisher_id}/members");
    async fn change(
        app: &Router,
        method: &str,
        path: &str,
        cookie: &str,
        role: &str,
        origin: &str,
    ) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, origin)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"role": role}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    assert_eq!(
        request(&app, "GET", &members_path, Some(&cookies[1]), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[1], "admin", ORIGIN).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        change(
            &app,
            "PUT",
            &member_path,
            &cookies[0],
            "admin",
            "https://evil.example.test"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[0], "owner", ORIGIN).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[0], "viewer", ORIGIN).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[0], "viewer", ORIGIN).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "GET", &members_path, Some(&cookies[1]), None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[1], "admin", ORIGIN).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        change(&app, "PUT", &member_path, &cookies[0], "publisher", ORIGIN).await,
        StatusCode::NO_CONTENT
    );
    let unknown_path = format!("/api/v1/publishers/{publisher_id}/members/nonexistent-user");
    assert_eq!(
        change(&app, "PUT", &unknown_path, &cookies[0], "viewer", ORIGIN).await,
        StatusCode::NOT_FOUND
    );
    let owner_path = format!("/api/v1/publishers/{publisher_id}/members/{}", user_ids[0]);
    assert_eq!(
        change(&app, "DELETE", &owner_path, &cookies[0], "", ORIGIN).await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        change(&app, "DELETE", &member_path, &cookies[0], "", ORIGIN).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&app, "GET", &members_path, Some(&cookies[1]), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let changes: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id = $1 AND action = 'publisher.membership_changed' AND target_user_id = $2")
        .bind(uuid::Uuid::parse_str(publisher_id).unwrap()).bind(&user_ids[1]).fetch_one(&pool).await.unwrap();
    assert_eq!(changes, 3);
    let audit: Vec<(Option<String>, Option<String>)> = sqlx::query_as("SELECT old_role, new_role FROM cloud_audit_events WHERE publisher_id = $1 AND action = 'publisher.membership_changed' AND target_user_id = $2 ORDER BY created_at, id")
        .bind(uuid::Uuid::parse_str(publisher_id).unwrap()).bind(&user_ids[1]).fetch_all(&pool).await.unwrap();
    assert_eq!(
        audit,
        vec![
            (None, Some("viewer".into())),
            (Some("viewer".into()), Some("publisher".into())),
            (Some("publisher".into()), None)
        ]
    );
    let approve_path = format!("/api/v1/admin/publishers/{publisher_id}/approve");
    assert_eq!(
        change(&app, "POST", &approve_path, &cookies[1], "", ORIGIN).await,
        StatusCode::FORBIDDEN
    );
    assert!(
        admin::change_role(&pool, true, &user_ids[0], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert!(
        !admin::change_role(&pool, true, &user_ids[0], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert_eq!(
        change(&app, "POST", &approve_path, &cookies[0], "", ORIGIN).await,
        StatusCode::FORBIDDEN,
        "a publisher member must not self-approve"
    );
    assert!(
        admin::change_role(&pool, true, &user_ids[1], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert_eq!(
        change(
            &app,
            "POST",
            &approve_path,
            &cookies[1],
            "",
            "https://evil.example.test"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    let profile = request(&app, "GET", "/api/v1/me", Some(&cookies[1]), None).await;
    let profile: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(profile.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(profile["roles"], json!(["admin"]));
    assert_eq!(
        change(&app, "POST", &approve_path, &cookies[1], "", ORIGIN).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        change(&app, "POST", &approve_path, &cookies[1], "", ORIGIN).await,
        StatusCode::CONFLICT
    );
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_publishers WHERE id=$1")
        .bind(uuid::Uuid::parse_str(publisher_id).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "approved");
    let approvals: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id=$1 AND action='publisher.approved' AND actor_user_id=$2").bind(uuid::Uuid::parse_str(publisher_id).unwrap()).bind(&user_ids[1]).fetch_one(&pool).await.unwrap();
    assert_eq!(approvals, 1);
    assert!(
        admin::change_role(&pool, false, &user_ids[1], "admin", "test-operator")
            .await
            .unwrap()
    );
    assert_eq!(
        change(&app, "POST", &approve_path, &cookies[1], "", ORIGIN).await,
        StatusCode::FORBIDDEN
    );
    assert!(
        admin::change_role(&pool, true, "unknown-test-user", "admin", "test-operator")
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id = $1 AND action = 'publisher.requested'").bind(uuid::Uuid::parse_str(data["id"].as_str().unwrap()).unwrap()).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
}

/// Native Bearer tokens reach the publisher surface exactly like browser
/// cookies do; unknown tokens and missing credentials still fail closed.
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_surface_accepts_native_bearer_tokens() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let result = service
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Bearer".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let bearer = result.session_token.clone();
    let cookie = format!("{}={}", result.cookie.name, result.cookie.value);
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let namespace = format!("pub{}", uuid::Uuid::new_v4().simple());

    async fn bearer_call(
        app: &Router,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, ORIGIN);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(
                builder
                    .body(Body::from(
                        body.unwrap_or(serde_json::Value::Null).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    // No credential at all fails closed.
    assert_eq!(
        bearer_call(&app, "GET", "/api/v1/publishers", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // A forged token fails closed without touching the database.
    assert_eq!(
        bearer_call(
            &app,
            "GET",
            "/api/v1/publishers",
            Some("forged-token"),
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // The native token lists (empty) and creates exactly like the cookie.
    let list = bearer_call(&app, "GET", "/api/v1/publishers", Some(&bearer), None).await;
    assert_eq!(list.status(), StatusCode::OK);
    let list: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(list.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(list.as_array().unwrap().len(), 0);
    let created = bearer_call(
        &app,
        "POST",
        "/api/v1/publishers",
        Some(&bearer),
        Some(json!({ "namespace": namespace })),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    // The cookie flow sees the namespace the Bearer flow created.
    let listed = request(&app, "GET", "/api/v1/publishers", Some(&cookie), None).await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(listed.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["status"], "pending");
}

/// A local OIDC provider validates the real callback wiring, not Google's live service.
/// HS256 is supported only by Better Auth's test-utils feature and is never enabled in production.
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oidc_callback_rejects_missing_forged_and_expired_claims() {
    use better_auth::oidc::OidcIdTokenValidator;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};
    const TEST_KEY: &[u8] = b"test-only-oidc-signing-key-never-production";
    const ISSUER: &str = "https://fixture-issuer.example.test";

    async fn token(
        axum::Form(form): axum::Form<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        let code = form.get("code").unwrap();
        let (variant, nonce) = code.split_once('-').unwrap();
        if variant == "noidtoken" {
            return Json(json!({"access_token":"fixture-token", "token_type":"Bearer"}));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut claims = json!({"iss":ISSUER, "aud":if variant == "audience" { "wrong-client" } else { "client-id" }, "sub":"oidc-fixture", "exp":if variant == "expired" { now - 120 } else { now + 3600 }, "iat":now});
        if variant != "missing" {
            claims["nonce"] = json!(if variant == "forged" {
                "wrong-nonce"
            } else {
                nonce
            });
        }
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("fixture-key".into());
        let signing_key = if variant == "signature" {
            b"wrong-secret".as_slice()
        } else {
            TEST_KEY
        };
        let id_token = encode(&header, &claims, &EncodingKey::from_secret(signing_key)).unwrap();
        Json(json!({"access_token":"fixture-token", "token_type":"Bearer", "id_token":id_token}))
    }
    async fn userinfo() -> Json<serde_json::Value> {
        Json(
            json!({"sub":"oidc-fixture", "email":"oidc-fixture@example.test", "email_verified":true, "name":"OIDC"}),
        )
    }
    let fixture = Router::new()
        .route("/token", post(token))
        .route("/userinfo", get(userinfo));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fixture_handle = tokio::spawn(async move { axum::serve(listener, fixture).await.unwrap() });
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let validator =
        OidcIdTokenValidator::new(ISSUER, "client-id").add_test_hs_key("fixture-key", TEST_KEY);
    let provider = HttpOAuthProvider::insecure_for_testing(
        "oidc",
        "client-id",
        "client-secret",
        Url::parse(&format!("{base}/authorize")).unwrap(),
        Url::parse(&format!("{base}/token")).unwrap(),
        Url::parse(&format!("{base}/userinfo")).unwrap(),
        ["openid", "email"],
    )
    .with_oidc_validator(validator);
    let auth = AuthRouter::new(ctx.clone())
        .unwrap()
        .with_social_providers(vec![provider])
        .unwrap();
    let app = app(ctx, pool, auth);
    for (variant, expected) in [
        ("noidtoken", StatusCode::UNAUTHORIZED),
        ("signature", StatusCode::UNAUTHORIZED),
        ("missing", StatusCode::UNAUTHORIZED),
        ("forged", StatusCode::UNAUTHORIZED),
        ("audience", StatusCode::UNAUTHORIZED),
        ("expired", StatusCode::UNAUTHORIZED),
        ("valid", StatusCode::FOUND),
    ] {
        let response = request(&app, "GET", "/api/auth/sign-in/social/oidc", None, None).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let url = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let pairs: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let callback = format!(
            "/api/auth/callback/oidc?code={variant}-{}&state={}",
            pairs["nonce"], pairs["state"]
        );
        let result = request(&app, "GET", &callback, None, None).await;
        assert_eq!(result.status(), expected, "{variant} token");
        if variant == "valid" {
            assert!(result.headers().contains_key(header::SET_COOKIE));
        }
        assert_eq!(
            request(&app, "GET", &callback, None, None).await.status(),
            StatusCode::UNAUTHORIZED,
            "{variant} state must be single-use"
        );
    }
    fixture_handle.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn sync_conflicts_tombstones_and_user_isolation() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut cookies = Vec::new();
    let mut bearers = Vec::new();
    let mut user_ids = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Sync Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        bearers.push(result.session_token.clone());
        user_ids.push(result.user.id.clone());
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let publisher_id = uuid::Uuid::new_v4();
    let namespace = format!("p{}", publisher_id.simple());
    sqlx::query("INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,$2,'pending')")
        .bind(publisher_id)
        .bind(namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(publisher_id)
    .bind(&user_ids[0])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'moderator')")
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();
    let path = "/api/v1/sync/collections/plugin-selections/acme.plugin";
    let value =
        json!({"schemaVersion":1,"pluginId":"acme.plugin","version":"1.0.0","enabled":true});
    async fn write(
        app: &Router,
        cookie: &str,
        method: &str,
        path: &str,
        precondition: Option<(&str, &str)>,
        value: serde_json::Value,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::COOKIE, cookie)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((name, value)) = precondition {
            builder = builder.header(name, value);
        }
        app.clone()
            .oneshot(builder.body(Body::from(value.to_string())).unwrap())
            .await
            .unwrap()
    }
    assert_eq!(
        write(&app, &cookies[0], "PUT", path, None, value.clone())
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let mut secret = value.clone();
    secret["token"] = json!("must-not-sync");
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-none-match", "*")),
            secret
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let created = write(
        &app,
        &cookies[0],
        "PUT",
        path,
        Some(("if-none-match", "*")),
        value.clone(),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
    let first = created.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_string();
    let mut updated = value.clone();
    updated["version"] = json!("1.1.0");
    let (left, right) = tokio::join!(
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-match", &first)),
            updated.clone()
        ),
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-match", &first)),
            updated
        )
    );
    assert!(
        (left.status() == StatusCode::OK && right.status() == StatusCode::CONFLICT)
            || (right.status() == StatusCode::OK && left.status() == StatusCode::CONFLICT)
    );
    let saved = if left.status() == StatusCode::OK {
        left
    } else {
        right
    };
    let second = saved.headers()[header::ETAG].to_str().unwrap().to_string();
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-match", &first)),
            value.clone()
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "DELETE",
            path,
            Some(("if-match", &first)),
            json!(null)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "DELETE",
            path,
            Some(("if-match", &second)),
            json!(null)
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-none-match", "*")),
            value
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    // The export is scoped to the authenticated account, includes tombstones,
    // and never returns unexpected stored fields.
    assert_eq!(
        request(&app, "GET", "/api/v1/sync/export", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (cookie, expected_cursor, expected_records) in [(&cookies[0], 3, 1), (&cookies[1], 0, 0)] {
        let response = request(&app, "GET", "/api/v1/sync/export", Some(cookie), None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let data: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["schemaVersion"], 1);
        assert_eq!(data["cursor"], expected_cursor);
        assert_eq!(data["records"].as_array().unwrap().len(), expected_records);
        if expected_records == 1 {
            assert_eq!(data["records"][0]["deleted"], true);
            assert!(data["records"][0]["value"].is_null());
        }
    }
    let account_export = request(&app, "GET", "/api/v1/me/export", Some(&cookies[0]), None).await;
    assert_eq!(account_export.status(), StatusCode::OK);
    assert_eq!(account_export.headers()[header::CACHE_CONTROL], "no-store");
    let account_data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(account_export.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(account_data["profile"]["id"], user_ids[0]);
    assert_eq!(account_data["cloudRoles"][0], "moderator");
    assert_eq!(
        account_data["publisherMemberships"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(account_data["sync"]["cursor"], 3);
    assert_eq!(account_data["sync"]["records"][0]["deleted"], true);
    assert!(account_data.get("sessionToken").is_none());
    let other_export = request(&app, "GET", "/api/v1/me/export", Some(&cookies[1]), None).await;
    assert_eq!(other_export.status(), StatusCode::OK);
    let other_data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(other_export.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(other_data["sync"]["records"].as_array().unwrap().len(), 0);
    assert!(other_data["cloudRoles"].as_array().unwrap().is_empty());
    assert!(other_data["publisherMemberships"]
        .as_array()
        .unwrap()
        .is_empty());
    let native = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/native/sync/export")
                .header(header::AUTHORIZATION, format!("Bearer {}", bearers[0]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(native.status(), StatusCode::OK);
    assert_eq!(native.headers()[header::CACHE_CONTROL], "no-store");
    let native_account = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/native/me/export")
                .header(header::AUTHORIZATION, format!("Bearer {}", bearers[0]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(native_account.status(), StatusCode::OK);
    assert_eq!(native_account.headers()[header::CACHE_CONTROL], "no-store");
    sqlx::query("UPDATE cloud_sync_records SET deleted=false,value=$2 WHERE user_id=$1").bind(&user_ids[0]).bind(json!({"schemaVersion":1,"pluginId":"acme.plugin","version":"1.0.0","enabled":true,"token":"secret"})).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/api/v1/sync/export", Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/me/export", Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    sqlx::query("UPDATE cloud_sync_records SET deleted=true,value=NULL WHERE user_id=$1")
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();
    for (cookie, expected) in [(&cookies[0], 3), (&cookies[1], 0)] {
        let response = request(
            &app,
            "GET",
            "/api/v1/sync/changes?cursor=0",
            Some(cookie),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let data: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(data["changes"].as_array().unwrap().len(), expected);
        if expected == 3 {
            assert_eq!(data["changes"][2]["deleted"], true);
            assert_eq!(data["changes"][2]["value"], serde_json::Value::Null);
        }
    }
    let since = request(
        &app,
        "GET",
        "/api/v1/sync/changes?cursor=1",
        Some(&cookies[0]),
        None,
    )
    .await;
    let page: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(since.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(page["changes"].as_array().unwrap().len(), 2);
    assert_eq!(page["cursor"], 3);
    let list = request(
        &app,
        "GET",
        "/api/v1/sync/collections/plugin-selections",
        Some(&cookies[1]),
        None,
    )
    .await;
    let page: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(list.into_body(), 8192).await.unwrap())
            .unwrap();
    assert!(page["records"].as_array().unwrap().is_empty());
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/sync/changes?cursor=99999",
            Some(&cookies[0]),
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/sync/collections/plugin-selections",
            None,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Simulate a lagging client at the retention boundary, then verify the
    // head endpoint and the pruning path during a real write.
    sqlx::query("UPDATE cloud_sync_cursors SET cursor = 10001 WHERE user_id=$1")
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();
    // Preserve the invariant of an unbroken retained suffix while advancing
    // the synthetic cursor: the real writer appends one row per revision.
    sqlx::query("INSERT INTO cloud_sync_changes(user_id,cursor,collection,key,value,deleted) SELECT $1,n,'plugin-selections','acme.plugin',NULL,true FROM generate_series(4,10001) n")
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();
    let new_value =
        json!({"schemaVersion":1,"pluginId":"acme.plugin","version":"1.2.0","enabled":true});
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "PUT",
            path,
            Some(("if-match", "\"3\"")),
            new_value.clone()
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/sync/changes?cursor=0",
            Some(&cookies[0]),
            None
        )
        .await
        .status(),
        StatusCode::GONE
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/sync/changes?cursor=2",
            Some(&cookies[0]),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    let head = request(&app, "GET", "/api/v1/sync/head", Some(&cookies[0]), None).await;
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(head.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(body["cursor"], 10002);
    let native_path = "/api/v1/native/sync/collections/plugin-selections/acme.plugin";
    let native_request = |bearer: &str| {
        Request::builder()
            .method("PUT")
            .uri(native_path)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::IF_NONE_MATCH, "*")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(new_value.to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(native_request("forged-token"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(native_request(&bearers[1]))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/native/sync/head",
            Some(&cookies[1]),
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let browser_with_bearer = Request::builder()
        .uri("/api/v1/sync/head")
        .header(header::AUTHORIZATION, format!("Bearer {}", bearers[1]))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(browser_with_bearer)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let native_me = |bearer: &str| {
        Request::builder()
            .uri("/api/v1/native/me")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(native_me(&bearers[0]))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    sqlx::query("INSERT INTO cloud_sync_records (user_id, collection, key, revision, value, deleted) SELECT $1, 'plugin-selections', 'test.p' || i, 1, NULL, true FROM generate_series(1, 999) i")
        .bind(&user_ids[0]).execute(&pool).await.unwrap();
    let extra_path = "/api/v1/sync/collections/plugin-selections/other.plugin";
    let extra_value =
        json!({"schemaVersion":1,"pluginId":"other.plugin","version":"1.0.0","enabled":true});
    assert_eq!(
        write(
            &app,
            &cookies[0],
            "PUT",
            extra_path,
            Some(("if-none-match", "*")),
            extra_value
        )
        .await
        .status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM cloud_sync_cursors WHERE user_id=$1")
        .bind(&user_ids[0])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, 10002, "quota rejection must not advance the cursor");

    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id=$2")
        .bind(publisher_id)
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cloud_account_roles WHERE user_id=$1")
        .bind(&user_ids[0])
        .execute(&pool)
        .await
        .unwrap();

    // Better Auth rechecks the password and deletes the user; FK cascades must
    // remove only that user's sync state, including historical changes.
    let delete = |password: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/auth/delete-user")
            .header(header::COOKIE, &cookies[0])
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"password":password}).to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(delete("wrong password"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.clone()
            .oneshot(delete("test password with enough characters"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(native_me(&bearers[0]))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for table in [
        "cloud_sync_cursors",
        "cloud_sync_records",
        "cloud_sync_changes",
    ] {
        let query = format!("SELECT count(*) FROM {table} WHERE user_id=$1");
        let gone: i64 = sqlx::query_scalar(&query)
            .bind(&user_ids[0])
            .fetch_one(&pool)
            .await
            .unwrap();
        let kept: i64 = sqlx::query_scalar(&query)
            .bind(&user_ids[1])
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(gone, 0, "{table} retains deleted user data");
        assert!(kept > 0, "{table} removed another user's data");
    }
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn desktop_handoff_is_pkce_bound_single_use_and_loopback_only() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use better_auth::{
        desktop::LoopbackCallbackReceiver,
        email_password::{EmailPasswordService, SignUpInput},
    };
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let user = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Desktop Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let cookie = format!("{}={}", user.cookie.name, user.cookie.value);
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let verifier = "a".repeat(64);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = "test-state-at-least-16-characters";
    let receiver = LoopbackCallbackReceiver::bind("/callback", state)
        .await
        .unwrap();
    let redirect = receiver.redirect_uri();
    let issue_body =
        |redirect: &str| json!({"redirectUri":redirect,"codeChallenge":challenge,"state":state});
    async fn issue(
        app: &Router,
        cookie: Option<&str>,
        origin: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/desktop/handoff")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    assert_eq!(
        issue(&app, None, ORIGIN, issue_body(&redirect))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        issue(
            &app,
            Some(&cookie),
            "https://evil.example.test",
            issue_body(&redirect)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        issue(
            &app,
            Some(&cookie),
            ORIGIN,
            issue_body("https://evil.example.test/callback")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = issue(&app, Some(&cookie), ORIGIN, issue_body(&redirect)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let callback = Url::parse(body["callbackUrl"].as_str().unwrap()).unwrap();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let waiting = tokio::spawn(receiver.receive(std::time::Duration::from_secs(5), cancel_rx));
    let forged_target = format!("{}?{}", callback.path(), callback.query().unwrap())
        .replace(state, "wrong-state-0123456789");
    let mut forged = tokio::net::TcpStream::connect(("127.0.0.1", callback.port().unwrap()))
        .await
        .unwrap();
    forged
        .write_all(
            format!(
                "GET {forged_target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                callback.port().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut forged_response = Vec::new();
    forged.read_to_end(&mut forged_response).await.unwrap();
    assert!(String::from_utf8_lossy(&forged_response).starts_with("HTTP/1.1 400"));
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", callback.port().unwrap()))
        .await
        .unwrap();
    let target = format!("{}?{}", callback.path(), callback.query().unwrap());
    stream
        .write_all(
            format!(
                "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                callback.port().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut result = Vec::new();
    stream.read_to_end(&mut result).await.unwrap();
    assert!(String::from_utf8_lossy(&result).starts_with("HTTP/1.1 200"));
    let code = waiting.await.unwrap().unwrap();
    drop(cancel_tx);
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let peer = std::net::SocketAddr::from(([127, bytes[0], bytes[1], bytes[2]], 50000));
    async fn redeem(
        app: &Router,
        peer: std::net::SocketAddr,
        code: &str,
        redirect: &str,
        verifier: &str,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/native/handoff/redeem")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(axum::extract::ConnectInfo(peer))
                    .body(Body::from(
                        json!({"code":code,"redirectUri":redirect,"codeVerifier":verifier})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    let redeemed = redeem(&app, peer, &code, &redirect, &verifier).await;
    assert_eq!(redeemed.status(), StatusCode::OK);
    assert_eq!(redeemed.headers()[header::CACHE_CONTROL], "no-store");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(redeemed.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let bearer = body["sessionToken"].as_str().unwrap();
    let native = Request::builder()
        .uri("/api/v1/native/me")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(native).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        redeem(&app, peer, &code, &redirect, &verifier)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let another = issue(&app, Some(&cookie), ORIGIN, issue_body(&redirect)).await;
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(another.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let callback = Url::parse(body["callbackUrl"].as_str().unwrap()).unwrap();
    let code = callback
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(
        redeem(&app, peer, &code, &redirect, &"b".repeat(64))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        redeem(&app, peer, &code, &redirect, &verifier)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let expired = issue(&app, Some(&cookie), ORIGIN, issue_body(&redirect)).await;
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(expired.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let url = Url::parse(body["callbackUrl"].as_str().unwrap()).unwrap();
    let expired_code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let digest = Sha256::digest(expired_code.as_bytes());
    let key = format!(
        "desktop:handoff:{}",
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    assert_eq!(
        sqlx::query("UPDATE _better_auth_kv SET expires_at = 1 WHERE storage_key = $1")
            .bind(key)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    assert_eq!(
        redeem(&app, peer, &expired_code, &redirect, &verifier)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let mut limited = false;
    for _ in 0..65 {
        if redeem(&app, peer, "not-a-code", &redirect, &verifier)
            .await
            .status()
            == StatusCode::TOO_MANY_REQUESTS
        {
            limited = true;
            break;
        }
    }
    assert!(limited, "redemption must be rate limited");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn desktop_redeem_rate_limit_keys_trusted_client_ip() {
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app_with_proxies(
        ctx,
        pool,
        auth,
        None,
        vec!["127.0.0.1/32".parse::<ipnet::IpNet>().unwrap()],
        None,
        false,
        false,
    );
    async fn attempt(app: &Router, peer: &str, forwarded_for: Option<&str>) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/native/handoff/redeem")
            .header(header::CONTENT_TYPE, "application/json")
            .extension(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>().unwrap(),
            ));
        if let Some(xff) = forwarded_for {
            req = req.header("x-forwarded-for", xff);
        }
        let req = req
            .body(Body::from(
                json!({"code":"not-a-code","redirectUri":"http://127.0.0.1:9/cb","codeVerifier":"x"})
                    .to_string(),
            ))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }
    // Behind a trusted proxy each client IP gets its own redemption bucket.
    for _ in 0..60 {
        assert_ne!(
            attempt(&app, "127.0.0.1:50000", Some("203.0.113.7")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        attempt(&app, "127.0.0.1:50000", Some("203.0.113.7")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        attempt(&app, "127.0.0.1:50000", Some("203.0.113.8")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Behind an untrusted peer the boundary strips forwarded headers, so all
    // clients share the socket-peer bucket and a spoofed header changes nothing.
    for _ in 0..60 {
        assert_ne!(
            attempt(&app, "10.9.9.9:50000", Some("203.0.113.7")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    assert_eq!(
        attempt(&app, "10.9.9.9:50000", Some("203.0.113.99")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn readiness_refuses_missing_or_incompatible_schema() {
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    readiness::MIGRATOR.run(&pool).await.unwrap();
    let schema = format!("health_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    let isolated = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}, public"))
        .execute(&isolated)
        .await
        .unwrap();
    // Shadow the real migration table, while reading real auth and Cloud tables.
    sqlx::query(
        "CREATE TABLE _sqlx_migrations AS SELECT * FROM public._sqlx_migrations WHERE false",
    )
    .execute(&isolated)
    .await
    .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, isolated.clone(), auth);
    assert_eq!(
        request(&app, "GET", "/health/live", None, None)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("INSERT INTO _sqlx_migrations SELECT * FROM public._sqlx_migrations")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::OK
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum = decode('00', 'hex') WHERE version = (SELECT min(version) FROM _sqlx_migrations)").execute(&isolated).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&isolated)
        .await
        .unwrap();
    sqlx::query("INSERT INTO _sqlx_migrations SELECT * FROM public._sqlx_migrations")
        .execute(&isolated)
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = (SELECT min(version) FROM _sqlx_migrations)").execute(&isolated).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("UPDATE _sqlx_migrations SET success = true")
        .execute(&isolated)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE \"user\" (id TEXT PRIMARY KEY)")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("DROP TABLE \"user\"")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::OK
    );
    // A schema can have the migration marker but still lack the write fence
    // column; readiness must not announce a usable workspace in that state.
    sqlx::query("CREATE TABLE cloud_workspace_cursors (user_id TEXT, cursor BIGINT)")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("ALTER TABLE cloud_workspace_cursors ADD COLUMN write_epoch BIGINT")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("DROP TABLE cloud_workspace_cursors")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::OK
    );
    sqlx::query("INSERT INTO _sqlx_migrations SELECT 99999999999999, 'unknown', now(), true, decode('00', 'hex'), 0").execute(&isolated).await.unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 99999999999999")
        .execute(&isolated)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE cloud_sync_records (dummy TEXT)")
        .execute(&isolated)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    isolated.close().await;
    assert_eq!(
        request(&app, "GET", "/health/ready", None, None)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&app, "GET", "/health/live", None, None)
            .await
            .status(),
        StatusCode::OK
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn role_bootstrap_protects_last_admin_and_audits_changes() {
    let url = crate::test_support::migrated_url();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("role_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("SET search_path TO {schema}"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE \"user\" (id TEXT PRIMARY KEY); CREATE TABLE cloud_account_roles (user_id TEXT NOT NULL REFERENCES \"user\"(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY(user_id,role)); CREATE TABLE cloud_audit_events (id UUID PRIMARY KEY, actor_user_id TEXT NOT NULL, action TEXT NOT NULL, target_user_id TEXT, old_role TEXT, new_role TEXT); INSERT INTO \"user\" (id) VALUES ('one'), ('two');").execute(&pool).await.unwrap();
    assert!(admin::change_role(&pool, true, "one", "admin", "operator")
        .await
        .unwrap());
    assert!(!admin::change_role(&pool, true, "one", "admin", "operator")
        .await
        .unwrap());
    assert!(admin::change_role(&pool, false, "one", "admin", "operator")
        .await
        .is_err());
    assert!(admin::change_role(&pool, true, "two", "admin", "operator")
        .await
        .unwrap());
    assert!(admin::change_role(&pool, false, "one", "admin", "operator")
        .await
        .unwrap());
    assert!(admin::change_role(&pool, false, "two", "admin", "operator")
        .await
        .is_err());
    assert!(
        admin::change_role(&pool, true, "missing", "admin", "operator")
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 3);
    sqlx::query("SET search_path TO public")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn upgrade_guards_preserve_existing_data_and_reject_inconsistent_state() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use std::borrow::Cow;
    let url = crate::test_support::migrated_url();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("upgrade_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&control)
        .await
        .unwrap();
    let mut schema_url = Url::parse(&url).unwrap();
    schema_url
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let schema_url = schema_url.to_string();
    let adapter = Arc::new(SqlxDbAdapter::postgres(&schema_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&schema_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![],
    )
    .unwrap();
    adapter
        .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    secondary.migrate().await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&schema_url)
        .await
        .unwrap();
    let migrations = |last: i64| sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            readiness::MIGRATOR
                .iter()
                .filter(|m| m.version <= last)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: false,
        no_tx: false,
    };
    migrations(20261102000014).run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx).unwrap();
    let mut users = Vec::new();
    for _ in 0..2 {
        users.push(
            service
                .sign_up(
                    SignUpInput {
                        email: format!("{}@example.test", uuid::Uuid::new_v4()),
                        name: "Upgrade Test".into(),
                        password: "test password with enough characters".into(),
                    },
                    true,
                )
                .await
                .unwrap()
                .user
                .id,
        );
    }
    let publisher = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,'upgrade-fixture','approved')",
    )
    .bind(publisher)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES ($1,$2,'owner'),($1,'missing-user','viewer')").bind(publisher).bind(&users[0]).execute(&pool).await.unwrap();
    assert!(
        migrations(20261102000015).run(&pool).await.is_err(),
        "orphan membership must stop the upgrade"
    );
    sqlx::query(
        "DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id='missing-user'",
    )
    .bind(publisher)
    .execute(&pool)
    .await
    .unwrap();
    migrations(20261102000015).run(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES($1,$2,'owner')",
    )
    .bind(publisher)
    .bind(&users[1])
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        migrations(20261102000016).run(&pool).await.is_err(),
        "duplicate owners must stop the upgrade"
    );
    sqlx::query(
        "UPDATE cloud_publisher_memberships SET role='viewer' WHERE publisher_id=$1 AND user_id=$2",
    )
    .bind(publisher)
    .bind(&users[1])
    .execute(&pool)
    .await
    .unwrap();
    migrations(20261102000016).run(&pool).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_publisher_memberships WHERE publisher_id=$1",
    )
    .bind(publisher)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 2);
    let versions: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(versions, 16);
    assert!(sqlx::query("DELETE FROM \"user\" WHERE id=$1")
        .bind(&users[0])
        .execute(&pool)
        .await
        .is_err());
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&control)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn migration_upgrade_preserves_data_through_revocation_tables() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use std::borrow::Cow;
    let url = crate::test_support::migrated_url();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("drill_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&control)
        .await
        .unwrap();
    let mut schema_url = Url::parse(&url).unwrap();
    schema_url
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let schema_url = schema_url.to_string();
    let adapter = Arc::new(SqlxDbAdapter::postgres(&schema_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&schema_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![],
    )
    .unwrap();
    adapter
        .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    secondary.migrate().await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&schema_url)
        .await
        .unwrap();
    let migrations = |last: i64| sqlx::migrate::Migrator {
        migrations: Cow::Owned(
            readiness::MIGRATOR
                .iter()
                .filter(|m| m.version <= last)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: false,
        no_tx: false,
    };
    migrations(20261102000016).run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx).unwrap();
    let mut users = Vec::new();
    for _ in 0..2 {
        users.push(
            service
                .sign_up(
                    SignUpInput {
                        email: format!("{}@example.test", uuid::Uuid::new_v4()),
                        name: "Drill".into(),
                        password: "test password with enough characters".into(),
                    },
                    true,
                )
                .await
                .unwrap()
                .user
                .id,
        );
    }
    let publisher = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,'drill','approved')",
    )
    .bind(publisher)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&users[0]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_account_roles (user_id,role) VALUES ($1,'admin')")
        .bind(&users[1])
        .execute(&pool)
        .await
        .unwrap();
    let key_row = uuid::Uuid::new_v4();
    // Random per run: the ignored suite shares one disposable database, so a
    // fixed key_id would collide with earlier runs.
    let key_name = format!("k{}", uuid::Uuid::new_v4().simple());
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,'cGtleQ',$4,'approved',$5)").bind(key_row).bind(publisher).bind(&key_name).bind("f".repeat(64)).bind(&users[0]).execute(&pool).await.unwrap();
    let upload = uuid::Uuid::new_v4();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,'quarantine/drill','quarantined',now(),'version')").bind(upload).bind(publisher).bind(&users[0]).bind(format!("drill{}", upload.simple())).bind("a".repeat(64)).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,'drill.plugin','1.0.0','any','review_approved',$5)").bind(release).bind(publisher).bind(upload).bind(key_row).bind(&users[0]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,'antivirus_passed',1,'antivirus_passed')").bind(upload).bind(release).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id,release_id,actor_user_id,decision,reason_code) VALUES ($1,$2,$3,'approve','policy_reviewed')").bind(uuid::Uuid::new_v4()).bind(release).bind(&users[1]).execute(&pool).await.unwrap();
    let job = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publication_jobs (id,release_id,requested_by,status) VALUES ($1,$2,$3,'queued')").bind(job).bind(release).bind(&users[1]).execute(&pool).await.unwrap();
    let candidate = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_snapshot_candidates (id,status,root_fingerprint,inventory_sha256,release_count,file_count) VALUES ($1,'candidate',$2,$3,1,1)").bind(candidate).bind("b".repeat(64)).bind("c".repeat(64)).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_snapshot_candidate_files (candidate_id,path,sha256,size,object_key,version_id) VALUES ($1,'root.json',$2,1,'drill-object','v1')").bind(candidate).bind("d".repeat(64)).execute(&pool).await.unwrap();
    // Migrations 17 and 18 add tables without backfills or new guards.
    migrations(20261102000017).run(&pool).await.unwrap();
    // A check recorded before migration 19 carries no inventory hash; the
    // upgrade must backfill it from the referenced candidate.
    let legacy_check = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_snapshot_promotion_checks (id,candidate_id,decision,operator,reason) VALUES ($1,$2,'verified','drill','pre-upgrade')").bind(legacy_check).bind(candidate).execute(&pool).await.unwrap();
    migrations(20261102000019).run(&pool).await.unwrap();
    let backfilled: String = sqlx::query_scalar(
        "SELECT inventory_sha256 FROM cloud_snapshot_promotion_checks WHERE id=$1",
    )
    .bind(legacy_check)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        backfilled,
        "c".repeat(64),
        "upgrade backfills the check inventory"
    );
    migrations(20261102000020).run(&pool).await.unwrap();
    let legacy_manifest: Option<String> = sqlx::query_scalar(
        "SELECT manifest_sha256 FROM cloud_snapshot_promotion_checks WHERE id=$1",
    )
    .bind(legacy_check)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        legacy_manifest.is_none(),
        "legacy checks cannot claim a verified manifest"
    );
    for (table, expected) in [
        ("cloud_publishers", 1),
        ("cloud_publisher_memberships", 1),
        ("cloud_account_roles", 1),
        ("cloud_publisher_keys", 1),
        ("cloud_upload_sessions", 1),
        ("cloud_plugin_releases", 1),
        ("cloud_verification_jobs", 1),
        ("cloud_moderation_events", 1),
        ("cloud_publication_jobs", 1),
        ("cloud_snapshot_candidates", 1),
        ("cloud_snapshot_candidate_files", 1),
        // Only the legacy pre-upgrade check exists at this point; the
        // decision recorded below brings the total to two.
        ("cloud_snapshot_promotion_checks", 1),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, expected, "upgrade must preserve {table}");
    }
    // The new tables reference the preserved rows.
    sqlx::query(
        "INSERT INTO cloud_release_yanks (release_id,yanked_by,reason) VALUES ($1,$2,'drill')",
    )
    .bind(release)
    .bind(&users[1])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_release_advisories (release_id,severity,message,url,created_by) VALUES ($1,'high','drill',NULL,$2)").bind(release).bind(&users[1]).execute(&pool).await.unwrap();
    snapshot_promotion::record_decision(&pool, candidate, "blocked", "drill", "upgrade drill")
        .await
        .unwrap();
    let checks: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_promotion_checks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(checks, 2, "legacy check plus the new decision");
    for table in ["cloud_release_yanks", "cloud_release_advisories"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "missing row in {table}");
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE action='snapshot.candidate_verification_blocked'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1, "missing promotion-check audit event");
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&control)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn promotion_checks_record_audited_verified_and_blocked_decisions() {
    let url = crate::test_support::migrated_url();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("promotion_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&control)
        .await
        .unwrap();
    let mut schema_url = Url::parse(&url).unwrap();
    schema_url.query_pairs_mut().append_pair(
        "options",
        &format!("-csearch_path={schema} -ctimezone=America/Lima"),
    );
    let schema_url = schema_url.to_string();
    let adapter = Arc::new(SqlxDbAdapter::postgres(&schema_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&schema_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![],
    )
    .unwrap();
    adapter
        .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    secondary.migrate().await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&schema_url)
        .await
        .unwrap();
    readiness::MIGRATOR.run(&pool).await.unwrap();
    let candidate = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cloud_snapshot_candidates(id,status,root_fingerprint,inventory_sha256,release_count,file_count) VALUES($1,'candidate',$2,$3,1,5)",
    )
    .bind(candidate)
    .bind("a".repeat(64))
    .bind("b".repeat(64))
    .execute(&pool)
    .await
    .unwrap();
    for path in [
        "root.json",
        "keys.json",
        "keys.json.sig",
        "config.json",
        "config.json.sig",
    ] {
        sqlx::query("INSERT INTO cloud_snapshot_candidate_files(candidate_id,path,sha256,size,object_key,version_id) VALUES($1,$2,$3,1,$4,'v1')")
            .bind(candidate).bind(path).bind("d".repeat(64))
            .bind(format!("prepared/{candidate}/{}", uuid::Uuid::new_v4()))
            .execute(&pool).await.unwrap();
    }
    let stale_manifest = snapshot_export::current(&pool, candidate).await.unwrap();
    sqlx::query("UPDATE cloud_snapshot_candidate_files SET sha256=$2 WHERE candidate_id=$1 AND path='root.json'")
        .bind(candidate).bind("e".repeat(64)).execute(&pool).await.unwrap();
    assert!(snapshot_promotion::record_verified(
        &pool,
        candidate,
        &stale_manifest,
        "test-op",
        "stale manifest"
    )
    .await
    .is_err());
    let manifest = snapshot_export::current(&pool, candidate).await.unwrap();
    let expected_manifest_sha =
        tiktools_plugin_package::Sha256Digest::of_bytes(&serde_json::to_vec(&manifest).unwrap())
            .to_string();
    let verified = snapshot_promotion::record_verified(
        &pool,
        candidate,
        &manifest,
        "test-op",
        "point-in-time verification passed; not deployed",
    )
    .await
    .unwrap();
    let row: (String, String, String, String) = sqlx::query_as(
        "SELECT decision,operator,reason,inventory_sha256 FROM cloud_snapshot_promotion_checks WHERE id=$1",
    )
    .bind(verified)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "verified");
    assert_eq!(row.1, "test-op");
    assert_eq!(
        row.3,
        "b".repeat(64),
        "decision pins the candidate inventory"
    );
    let audit: (String, String) = sqlx::query_as(
        "SELECT actor_user_id,action FROM cloud_audit_events WHERE subject_id=$1 AND action='snapshot.candidate_verified'",
    )
    .bind(candidate)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit.0, "operator:test-op");
    assert_eq!(audit.1, "snapshot.candidate_verified");
    let blocked = snapshot_promotion::record_decision(
        &pool,
        candidate,
        "blocked",
        "test-op",
        "verification failed: candidate changed during verification",
    )
    .await
    .unwrap();
    assert_ne!(verified, blocked);
    sqlx::query("UPDATE cloud_snapshot_promotion_checks SET created_at='2026-01-02 03:04:05+00' WHERE id=$1")
        .bind(verified)
        .execute(&pool)
        .await
        .unwrap();
    let checks = snapshot_promotion::list_checks(&pool, candidate)
        .await
        .unwrap();
    assert_eq!(checks.len(), 2, "verified and blocked decisions are listed");
    assert_eq!(
        checks
            .iter()
            .find(|check| check.id == verified)
            .unwrap()
            .manifest_sha256
            .as_deref(),
        Some(expected_manifest_sha.as_str())
    );
    assert_eq!(
        checks
            .iter()
            .find(|check| check.id == verified)
            .unwrap()
            .created_at,
        "2026-01-02T03:04:05.000Z"
    );
    let decisions: Vec<&str> = checks.iter().map(|c| c.decision.as_str()).collect();
    assert!(decisions.contains(&"verified") && decisions.contains(&"blocked"));
    for check in &checks {
        assert_eq!(check.candidate_id, candidate);
        assert_eq!(check.inventory_sha256, "b".repeat(64));
        assert!(!check.created_at.is_empty());
        assert_eq!(check.manifest_sha256.is_some(), check.id == verified);
    }
    assert!(
        snapshot_promotion::list_checks(&pool, uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_empty(),
        "unknown candidates list no decisions"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='snapshot.candidate_verification_blocked'",
    )
    .bind(candidate)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    assert!(
        snapshot_promotion::record_decision(&pool, candidate, "deployed", "test-op", "x",)
            .await
            .is_err(),
        "unknown decisions are rejected"
    );
    assert!(
        snapshot_promotion::record_decision(&pool, candidate, "blocked", "bad operator!", "x",)
            .await
            .is_err(),
        "operator labels are constrained"
    );
    assert!(
        snapshot_promotion::record_decision(&pool, candidate, "blocked", "test-op", "",)
            .await
            .is_err(),
        "empty reasons are rejected"
    );
    assert!(
        snapshot_promotion::record_decision(
            &pool,
            uuid::Uuid::new_v4(),
            "blocked",
            "test-op",
            "x",
        )
        .await
        .is_err(),
        "unknown candidates are rejected"
    );
    assert!(
        snapshot_promotion::record_decision(&pool, candidate, "verified", "test-op", "x")
            .await
            .is_err()
    );
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&control)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn snapshot_capture_blocks_yanks_and_carries_advisories() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use tiktools_plugin_package::{KeyId, SigningKey};
    let url = crate::test_support::migrated_url();
    let control = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("yankcap_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&control)
        .await
        .unwrap();
    let mut schema_url = Url::parse(&url).unwrap();
    schema_url
        .query_pairs_mut()
        .append_pair("options", &format!("-csearch_path={schema}"));
    let schema_url = schema_url.to_string();
    let adapter = Arc::new(SqlxDbAdapter::postgres(&schema_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(&schema_url).await.unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        adapter.clone(),
        Some(secondary.clone()),
        vec![],
    )
    .unwrap();
    adapter
        .apply_migrations(&ctx.migration_plan(), SqlDialect::Postgres)
        .await
        .unwrap();
    secondary.migrate().await.unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&schema_url)
        .await
        .unwrap();
    readiness::MIGRATOR.run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx).unwrap();
    let mut users = Vec::new();
    for _ in 0..2 {
        users.push(
            service
                .sign_up(
                    SignUpInput {
                        email: format!("{}@example.test", uuid::Uuid::new_v4()),
                        name: "Yank Cap".into(),
                        password: "test password with enough characters".into(),
                    },
                    true,
                )
                .await
                .unwrap()
                .user
                .id,
        );
    }
    sqlx::query("INSERT INTO cloud_account_roles (user_id,role) VALUES ($1,'admin')")
        .bind(&users[1])
        .execute(&pool)
        .await
        .unwrap();
    let publisher = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,'yankcap','approved')",
    )
    .bind(publisher)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&users[0]).execute(&pool).await.unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap()
    .public_key();
    let key_row = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved',$6)").bind(key_row).bind(publisher).bind(key.key_id.as_str()).bind(&key.public_key).bind(key.fingerprint().unwrap().to_string()).bind(&users[0]).execute(&pool).await.unwrap();
    let upload = uuid::Uuid::new_v4();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,'quarantine/yankcap','quarantined',now(),'version')").bind(upload).bind(publisher).bind(&users[0]).bind(format!("yankcap{}", upload.simple())).bind("a".repeat(64)).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,'yankcap.plugin','1.0.0','any','review_approved',$5)").bind(release).bind(publisher).bind(upload).bind(key_row).bind(&users[0]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,'antivirus_passed',1,'antivirus_passed')").bind(upload).bind(release).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id,release_id,actor_user_id,decision,reason_code) VALUES ($1,$2,$3,'approve','policy_reviewed')").bind(uuid::Uuid::new_v4()).bind(release).bind(&users[1]).execute(&pool).await.unwrap();
    let job = uuid::Uuid::new_v4();
    let prepared_version = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO cloud_publication_jobs (id,release_id,requested_by,status,result_class,prepared_key,prepared_version_id) VALUES ($1,$2,$3,'prepared','prepared',$4,$5)").bind(job).bind(release).bind(&users[1]).bind(format!("prepared/{publisher}/{}", uuid::Uuid::new_v4())).bind(&prepared_version).execute(&pool).await.unwrap();
    let items = {
        let mut conn = pool.acquire().await.unwrap();
        snapshot_worker::capture(&mut conn).await.unwrap()
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].advisory, None);
    sqlx::query("INSERT INTO cloud_release_advisories (release_id,severity,message,url,created_by) VALUES ($1,'high','upgrade now','https://example.test/a',$2)").bind(release).bind(&users[1]).execute(&pool).await.unwrap();
    let items = {
        let mut conn = pool.acquire().await.unwrap();
        snapshot_worker::capture(&mut conn).await.unwrap()
    };
    let advisory = items[0].advisory.as_ref().expect("advisory is captured");
    assert_eq!(advisory.severity, "high");
    assert_eq!(advisory.message, "upgrade now");
    assert_eq!(advisory.url.as_deref(), Some("https://example.test/a"));
    assert_eq!(
        items[0]
            .advisory
            .as_ref()
            .unwrap()
            .registry()
            .unwrap()
            .severity,
        tiktools_plugin_registry::AdvisorySeverity::High
    );
    sqlx::query(
        "INSERT INTO cloud_release_yanks (release_id,yanked_by,reason) VALUES ($1,$2,'malware')",
    )
    .bind(release)
    .bind(&users[1])
    .execute(&pool)
    .await
    .unwrap();
    let blocked = {
        let mut conn = pool.acquire().await.unwrap();
        snapshot_worker::capture(&mut conn).await.is_err()
    };
    assert!(
        blocked,
        "a yanked release blocks candidacy instead of being silently omitted"
    );
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&control)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn release_yanks_and_advisories_are_moderated_and_block_publication() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..4 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push((
            result.user.id,
            format!("{}={}", result.cookie.name, result.cookie.value),
        ));
    }
    for user in [&users[1].0, &users[2].0] {
        admin::change_role(&pool, true, user, "moderator", "test")
            .await
            .unwrap();
    }
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("yank{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&users[0].0).execute(&pool).await.unwrap();
    let key_id = uuid::Uuid::new_v4();
    // Random per run: the ignored suite shares one disposable database, so a
    // fixed key_id would collide with earlier runs.
    let key_name = format!("k{}", uuid::Uuid::new_v4().simple());
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,'cGtleQ',$4,'approved',$5)").bind(key_id).bind(publisher).bind(&key_name).bind("f".repeat(64)).bind(&users[0].0).execute(&pool).await.unwrap();
    async fn release(
        pool: &PgPool,
        publisher: uuid::Uuid,
        key: uuid::Uuid,
        namespace: &str,
        requester: &str,
        version: &str,
        status: &str,
    ) -> uuid::Uuid {
        let upload = uuid::Uuid::new_v4();
        let id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,$6,'quarantined',now(),'version')").bind(upload).bind(publisher).bind(requester).bind(format!("yank{upload}")).bind("a".repeat(64)).bind(format!("quarantine/{publisher}/{upload}")).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,$6,'any',$7,$8)").bind(id).bind(publisher).bind(upload).bind(key).bind(format!("{namespace}.plugin")).bind(version).bind(status).bind(requester).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,'antivirus_passed',1,'antivirus_passed')").bind(upload).bind(id).execute(pool).await.unwrap();
        id
    }
    let approved = release(
        &pool,
        publisher,
        key_id,
        &namespace,
        &users[0].0,
        "1.0.0",
        "review_approved",
    )
    .await;
    sqlx::query("INSERT INTO cloud_moderation_events (id,release_id,actor_user_id,decision,reason_code) VALUES ($1,$2,$3,'approve','policy_reviewed')").bind(uuid::Uuid::new_v4()).bind(approved).bind(&users[1].0).execute(&pool).await.unwrap();
    let pending = release(
        &pool,
        publisher,
        key_id,
        &namespace,
        &users[0].0,
        "2.0.0",
        "antivirus_passed",
    )
    .await;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    async fn post_json(
        app: &Router,
        path: &str,
        cookie: Option<&str>,
        origin: Option<&str>,
        body: serde_json::Value,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        let req = req
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }
    let yank_path = format!("/api/v1/moderation/releases/{approved}/yank");
    let yank_body = || serde_json::json!({"reason": "malware found in 1.0.0"});
    assert_eq!(
        post_json(&app, &yank_path, None, Some(ORIGIN), yank_body()).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[3].1),
            Some(ORIGIN),
            yank_body()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[0].1),
            Some(ORIGIN),
            yank_body()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[1].1),
            Some("https://evil.test"),
            yank_body()
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[1].1),
            Some(ORIGIN),
            serde_json::json!({"reason": ""})
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[1].1),
            Some(ORIGIN),
            yank_body()
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_json(
            &app,
            &yank_path,
            Some(&users[1].1),
            Some(ORIGIN),
            yank_body()
        )
        .await,
        StatusCode::CONFLICT
    );
    let missing = format!("/api/v1/moderation/releases/{}/yank", uuid::Uuid::new_v4());
    assert_eq!(
        post_json(&app, &missing, Some(&users[1].1), Some(ORIGIN), yank_body()).await,
        StatusCode::NOT_FOUND
    );
    let advisory_path = format!("/api/v1/moderation/releases/{approved}/advisory");
    let advisory_body = |severity: &str, message: &str, url: Option<&str>| {
        let mut value = serde_json::json!({"severity": severity, "message": message});
        if let Some(url) = url {
            value["url"] = serde_json::json!(url);
        }
        value
    };
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[2].1),
            Some(ORIGIN),
            advisory_body("medium", "use 2.x", None)
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[2].1),
            Some(ORIGIN),
            advisory_body("high", "use 2.x", Some("http://example.test/a"))
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[2].1),
            Some(ORIGIN),
            advisory_body("high", "use\x072.x", None)
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[0].1),
            Some(ORIGIN),
            advisory_body("high", "use 2.x", None)
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[2].1),
            Some(ORIGIN),
            advisory_body("high", "use 2.x", Some("https://example.test/a"))
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_json(
            &app,
            &advisory_path,
            Some(&users[2].1),
            Some(ORIGIN),
            advisory_body("critical", "upgrade now", None)
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT severity,message,url FROM cloud_release_advisories WHERE release_id=$1",
    )
    .bind(approved)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, "critical");
    assert_eq!(row.1, "upgrade now");
    assert_eq!(row.2, None);
    let yank_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.yanked'",
    )
    .bind(approved)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(yank_count, 1);
    let advisory_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.advisory_recorded'",
    )
    .bind(approved)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(advisory_count, 2);
    // Publishers see the yank and advisory on the release and its review.
    let release_path = format!("/api/v1/plugins/releases/{approved}");
    let response = request(&app, "GET", &release_path, Some(&users[0].1), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["yanked"], true);
    assert_eq!(body["yankReason"], "malware found in 1.0.0");
    assert_eq!(body["advisory"]["severity"], "critical");
    assert_eq!(body["advisory"]["message"], "upgrade now");
    assert!(body["advisory"].get("url").is_none_or(|u| u.is_null()));
    let review_path = format!("/api/v1/plugins/releases/{approved}/review");
    let response = request(&app, "GET", &review_path, Some(&users[0].1), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let review: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(review["yanked"], true);
    assert_eq!(review["advisory"]["severity"], "critical");
    // A yanked release cannot enter or re-enter the publication queue.
    let publish_path = format!("/api/v1/plugins/releases/{approved}/publish");
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[2].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // A yanked release cannot be approved after the fact.
    let pending_yank = format!("/api/v1/moderation/releases/{pending}/yank");
    assert_eq!(
        post_json(
            &app,
            &pending_yank,
            Some(&users[1].1),
            Some(ORIGIN),
            yank_body()
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let pending_decision = format!("/api/v1/moderation/releases/{pending}/decision");
    assert_eq!(
        post_json(
            &app,
            &pending_decision,
            Some(&users[2].1),
            Some(ORIGIN),
            serde_json::json!({"decision": "approve", "reasonCode": "policy_reviewed"})
        )
        .await,
        StatusCode::CONFLICT
    );
    // Inspection URLs are refused for yanked releases, like every other
    // pipeline action.
    let inspect_path = format!("/api/v1/moderation/releases/{pending}/inspection");
    assert_eq!(
        request(&app, "POST", &inspect_path, Some(&users[2].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // Moderator authorship of yanks and advisories shows up in account export.
    let export = request(&app, "GET", "/api/v1/me/export", Some(&users[1].1), None).await;
    assert_eq!(export.status(), StatusCode::OK);
    let exported: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(export.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(exported["yanksRecorded"].as_array().unwrap().len(), 2);
    assert!(exported["advisoriesRecorded"]
        .as_array()
        .unwrap()
        .is_empty());
    let advisor_export = request(&app, "GET", "/api/v1/me/export", Some(&users[2].1), None).await;
    assert_eq!(advisor_export.status(), StatusCode::OK);
    let advisor_data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(advisor_export.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(advisor_data["yanksRecorded"].as_array().unwrap().is_empty());
    assert_eq!(
        advisor_data["advisoriesRecorded"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        advisor_data["advisoriesRecorded"][0]["severity"],
        "critical"
    );
    let owner_export = request(&app, "GET", "/api/v1/me/export", Some(&users[0].1), None).await;
    assert_eq!(owner_export.status(), StatusCode::OK);
    let owner_data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(owner_export.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(owner_data["yanksRecorded"].as_array().unwrap().is_empty());
    assert!(owner_data["advisoriesRecorded"]
        .as_array()
        .unwrap()
        .is_empty());
    // Reviewers see the yank in the moderation queue; the release stays listed.
    let queue_response = request(
        &app,
        "GET",
        "/api/v1/moderation/releases",
        Some(&users[2].1),
        None,
    )
    .await;
    assert_eq!(queue_response.status(), StatusCode::OK);
    let queue: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(queue_response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let pending_item = queue["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == pending.to_string())
        .expect("yanked pending release is still listed");
    assert_eq!(pending_item["yanked"], true);
    assert_eq!(pending_item["yankReason"], "malware found in 1.0.0");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_request_limits_serialize_and_rate_limit() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    let mut cookies = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Quota Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push(result.user.id);
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let prefix = format!("p{}", uuid::Uuid::new_v4().simple());
    sqlx::query("WITH created AS (INSERT INTO cloud_publishers(id,namespace,status) SELECT gen_random_uuid(),$2 || n::text,'pending' FROM generate_series(1,9) AS n RETURNING id) INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) SELECT id,$1,'owner' FROM created").bind(&users[0]).bind(&prefix).execute(&pool).await.unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    async fn create(app: &Router, cookie: &str, namespace: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/publishers")
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, ORIGIN)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"namespace":namespace}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    let a = format!("p{}", uuid::Uuid::new_v4().simple());
    let b = format!("p{}", uuid::Uuid::new_v4().simple());
    let (x, y) = tokio::join!(create(&app, &cookies[0], &a), create(&app, &cookies[0], &b));
    assert!(
        (x == StatusCode::CREATED && y == StatusCode::TOO_MANY_REQUESTS)
            || (y == StatusCode::CREATED && x == StatusCode::TOO_MANY_REQUESTS)
    );
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_publisher_memberships m JOIN cloud_publishers p ON p.id=m.publisher_id WHERE m.user_id=$1 AND m.role='owner' AND p.status='pending'").bind(&users[0]).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 10);
    let duplicate = format!("p{}", uuid::Uuid::new_v4().simple());
    assert_eq!(
        create(&app, &cookies[1], &duplicate).await,
        StatusCode::CREATED
    );
    for _ in 0..19 {
        assert_eq!(
            create(&app, &cookies[1], &duplicate).await,
            StatusCode::CONFLICT
        );
    }
    assert_eq!(
        create(&app, &cookies[1], &duplicate).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    let full: uuid::Uuid = sqlx::query_scalar("SELECT id FROM cloud_publishers WHERE namespace=$1")
        .bind(&duplicate)
        .fetch_one(&pool)
        .await
        .unwrap();
    let fake_prefix = format!("quota-{}-", uuid::Uuid::new_v4());
    sqlx::query("INSERT INTO \"user\"(id,email,email_verified,name) SELECT $1||n::text,$1||n::text||'@example.test',false,'Fixture' FROM generate_series(1,999) n").bind(&fake_prefix).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) SELECT $1,id,'viewer' FROM \"user\" WHERE id LIKE $2").bind(full).bind(format!("{fake_prefix}%")).execute(&pool).await.unwrap();
    let member_path = format!("/api/v1/publishers/{full}/members/{}", users[0]);
    let result = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(&member_path)
                .header(header::COOKIE, &cookies[1])
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"role":"viewer"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::INSUFFICIENT_STORAGE);
    sqlx::query(
        "DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id LIKE $2",
    )
    .bind(full)
    .bind(format!("{fake_prefix}%"))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM \"user\" WHERE id LIKE $1")
        .bind(format!("{fake_prefix}%"))
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn unused_publisher_deletion_requires_owner_and_preserves_audit() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    let mut cookies = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Deletion Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push(result.user.id);
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,$2,'pending')")
        .bind(id)
        .bind(format!("p{}", id.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')")
        .bind(id).bind(&users[0]).bind(&users[1]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_audit_events(id,actor_user_id,publisher_id,action) VALUES($1,$2,$3,'publisher.requested')")
        .bind(uuid::Uuid::new_v4()).bind(&users[0]).bind(id).execute(&pool).await.unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let path = format!("/api/v1/publishers/{id}");
    assert_eq!(
        request(&app, "DELETE", &path, None, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[1]), None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id=$2")
        .bind(id)
        .bind(&users[1])
        .execute(&pool)
        .await
        .unwrap();
    let challenge = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_key_challenges(id,publisher_id,actor_user_id,nonce,expires_at) VALUES($1,$2,$3,$4,now()+interval '1 minute')")
        .bind(challenge).bind(id).bind(&users[0]).bind("a".repeat(64)).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_publisher_key_challenges WHERE id=$1")
        .bind(challenge)
        .execute(&pool)
        .await
        .unwrap();
    let grant = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_step_up_grants(id,user_id,session_id,action,publisher_id,method,expires_at) VALUES($1,$2,'test-session','publisher.key.enroll',$3,'password',now()-interval '1 minute')")
        .bind(grant).bind(&users[0]).bind(id).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_step_up_grants WHERE id=$1")
        .bind(grant)
        .execute(&pool)
        .await
        .unwrap();
    let key = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys(id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES($1,$2,$3,'test',$4,'revoked',$5)")
        .bind(key).bind(id).bind(format!("key-{}", key.simple())).bind(format!("{}{}", key.simple(), key.simple())).bind(&users[0]).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_publisher_keys WHERE id=$1")
        .bind(key)
        .execute(&pool)
        .await
        .unwrap();
    let upload = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions(id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at) VALUES($1,$2,$3,$4,1,$5,$6,'pending',now()-interval '1 minute')")
        .bind(upload).bind(id).bind(&users[0]).bind(upload.to_string()).bind("b".repeat(64)).bind(upload.to_string()).execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_upload_sessions WHERE id=$1")
        .bind(upload)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE deleted_publisher_id=$1 AND publisher_id IS NULL")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 2);
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'admin')")
        .bind(&users[0])
        .execute(&pool)
        .await
        .unwrap();
    let response = request(
        &app,
        "GET",
        "/api/v1/admin/audit?limit=50",
        Some(&cookies[0]),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let audit: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(audit["events"].as_array().unwrap().iter().any(|event| {
        event["action"] == "publisher.deleted" && event["publisherId"] == id.to_string()
    }));
    assert_eq!(
        request(&app, "DELETE", &path, Some(&cookies[0]), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_transfer_requires_owner_offer_and_recipient_acceptance() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    let mut cookies = Vec::new();
    let mut bearers = Vec::new();
    for _ in 0..3 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Transfer Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        bearers.push(result.session_token.clone());
        users.push(result.user.id);
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
    }
    let publisher = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,$2,'approved')")
        .bind(publisher)
        .bind(format!("p{}", publisher.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')").bind(publisher).bind(&users[0]).bind(&users[1]).execute(&pool).await.unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_app = app.clone();
    let client_server = tokio::spawn(async move {
        axum::serve(
            listener,
            server_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let native_client =
        cloud_client::Session::connect(&format!("http://{address}"), bearers[0].clone())
            .await
            .unwrap();
    let client_blockers = native_client.deletion_blockers(None).await.unwrap();
    assert_eq!(client_blockers.memberships.len(), 1);
    assert_eq!(client_blockers.memberships[0].publisher_id, publisher);
    assert_eq!(client_blockers.memberships[0].role, "owner");
    let blockers = "/api/v1/me/deletion-blockers";
    assert_eq!(
        request(&app, "GET", blockers, None, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = request(&app, "GET", blockers, Some(&cookies[0]), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["memberships"][0]["publisherId"], publisher.to_string());
    assert_eq!(data["memberships"][0]["role"], "owner");
    assert!(data["cloudRoles"].as_array().unwrap().is_empty());
    admin::change_role(&pool, true, &users[2], "moderator", "test")
        .await
        .unwrap();
    let native = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/native/me/deletion-blockers")
                .header(header::AUTHORIZATION, format!("Bearer {}", bearers[2]))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(native.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["cloudRoles"], json!(["moderator"]));
    assert!(data["memberships"].as_array().unwrap().is_empty());
    let page_prefix = format!("p{}", uuid::Uuid::new_v4().simple());
    sqlx::query("WITH created AS (INSERT INTO cloud_publishers(id,namespace,status) SELECT gen_random_uuid(),$2 || n::text,'pending' FROM generate_series(1,101) AS n RETURNING id) INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) SELECT id,$1,'viewer' FROM created").bind(&users[2]).bind(&page_prefix).execute(&pool).await.unwrap();
    let first_page = request(&app, "GET", blockers, Some(&cookies[2]), None).await;
    let first_page: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(first_page.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(first_page["memberships"].as_array().unwrap().len(), 100);
    let next_page = format!(
        "{blockers}?after={}",
        first_page["nextAfter"].as_str().unwrap()
    );
    let next_page = request(&app, "GET", &next_page, Some(&cookies[2]), None).await;
    let next_page: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(next_page.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(next_page["memberships"].as_array().unwrap().len(), 1);
    assert!(next_page["nextAfter"].is_null());
    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE user_id=$1")
        .bind(&users[2])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM cloud_publishers WHERE namespace LIKE $1")
        .bind(format!("{page_prefix}%"))
        .execute(&pool)
        .await
        .unwrap();
    let bad = request(
        &app,
        "GET",
        "/api/v1/me/deletion-blockers?after=bad",
        Some(&cookies[0]),
        None,
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
    let path = format!("/api/v1/publishers/{publisher}/transfer");
    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        cookie: &str,
        origin: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::COOKIE, cookie)
                    .header(header::ORIGIN, origin)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
    // A departing recipient invalidates an outstanding transfer atomically.
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES ($1,$2,'viewer')").bind(publisher).bind(&users[2]).execute(&pool).await.unwrap();
    let departure_offer = call(
        &app,
        "POST",
        &path,
        &cookies[0],
        ORIGIN,
        json!({"recipientUserId":users[2]}),
    )
    .await;
    let departure_offer: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(departure_offer.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let leave_path = format!("/api/v1/publishers/{publisher}/membership");
    assert_eq!(
        call(&app, "DELETE", &leave_path, &cookies[2], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let invalid_accept = format!("{path}/{}/accept", departure_offer["id"].as_str().unwrap());
    assert_eq!(
        call(
            &app,
            "POST",
            &invalid_accept,
            &cookies[2],
            ORIGIN,
            json!({})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let offer = json!({"recipientUserId":users[1]});
    assert_eq!(
        call(
            &app,
            "POST",
            &path,
            &cookies[1],
            ORIGIN,
            json!({"recipientUserId":users[2]})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &path,
            &cookies[0],
            "https://evil.example.test",
            offer.clone()
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let first = call(&app, "POST", &path, &cookies[0], ORIGIN, offer.clone()).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(first.into_body(), 8192).await.unwrap())
            .unwrap();
    sqlx::query("UPDATE cloud_publisher_transfers SET expires_at=now()-interval '1 second' WHERE publisher_id=$1").bind(publisher).execute(&pool).await.unwrap();
    let expired = format!("{path}/{}/accept", first["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "POST", &expired, &cookies[1], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "DELETE", &path, &cookies[1], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "DELETE", &path, &cookies[0], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    let next = call(&app, "POST", &path, &cookies[0], ORIGIN, offer).await;
    let next: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(next.into_body(), 8192).await.unwrap())
            .unwrap();
    assert_eq!(
        call(&app, "GET", &path, &cookies[1], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "GET", &path, &cookies[2], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let stale = format!("{path}/{}/accept", first["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "POST", &stale, &cookies[1], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let accept = format!("{path}/{}/accept", next["id"].as_str().unwrap());
    assert_eq!(
        call(&app, "POST", &accept, &cookies[0], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let (a, b) = tokio::join!(
        call(&app, "POST", &accept, &cookies[1], ORIGIN, json!({})),
        call(&app, "POST", &accept, &cookies[1], ORIGIN, json!({}))
    );
    assert!(
        (a.status() == StatusCode::NO_CONTENT && b.status() == StatusCode::NOT_FOUND)
            || (b.status() == StatusCode::NO_CONTENT && a.status() == StatusCode::NOT_FOUND)
    );
    let roles:Vec<(String,String)>=sqlx::query_as("SELECT user_id,role FROM cloud_publisher_memberships WHERE publisher_id=$1 ORDER BY user_id").bind(publisher).fetch_all(&pool).await.unwrap();
    assert!(roles.contains(&(users[0].clone(), "admin".into())));
    assert!(roles.contains(&(users[1].clone(), "owner".into())));
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id=$1 AND action='publisher.transfer_accepted'").bind(publisher).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    let leave = format!("/api/v1/publishers/{publisher}/membership");
    assert_eq!(
        call(&app, "DELETE", &leave, &cookies[1], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &app,
            "DELETE",
            &leave,
            &cookies[0],
            "https://evil.example.test",
            json!({})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let response = call(&app, "DELETE", &leave, &cookies[0], ORIGIN, json!({})).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        call(&app, "DELETE", &leave, &cookies[0], ORIGIN, json!({}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let response = request(&app, "GET", blockers, Some(&cookies[0]), None).await;
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(data["memberships"].as_array().unwrap().is_empty());
    assert!(native_client
        .deletion_blockers(None)
        .await
        .unwrap()
        .memberships
        .is_empty());
    client_server.abort();
    let left: i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id=$1 AND actor_user_id=$2 AND target_user_id=$2 AND action='publisher.membership_changed' AND old_role='admin' AND new_role IS NULL").bind(publisher).bind(&users[0]).fetch_one(&pool).await.unwrap();
    assert_eq!(left, 1);
    assert_eq!(
        sqlx::query("DELETE FROM \"user\" WHERE id=$1")
            .bind(&users[0])
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn user_deletion_cannot_bypass_cloud_memberships_or_roles() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut cookies = Vec::new();
    let mut users = Vec::new();
    for _ in 0..3 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Deletion Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        cookies.push(format!("{}={}", result.cookie.name, result.cookie.value));
        users.push(result.user.id);
    }
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("p{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers(id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships(publisher_id,user_id,role) VALUES ($1,$2,'owner'),($1,$3,'viewer')").bind(publisher).bind(&users[0]).bind(&users[1]).execute(&pool).await.unwrap();
    admin::change_role(&pool, true, &users[2], "admin", "test")
        .await
        .unwrap();
    // This suite reuses a dedicated database, so establish an isolated
    // last-admin scenario regardless of roles left by earlier integration cases.
    sqlx::query("DELETE FROM cloud_account_roles WHERE role='admin' AND user_id<>$1")
        .bind(&users[2])
        .execute(&pool)
        .await
        .unwrap();
    admin::change_role(&pool, true, &users[1], "moderator", "test")
        .await
        .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let refuse_role_delete = Request::builder()
        .method("DELETE")
        .uri("/api/v1/me/roles/moderator")
        .header(header::COOKIE, &cookies[1])
        .header(header::ORIGIN, "https://evil.example.test")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(refuse_role_delete)
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let leave_moderator = Request::builder()
        .method("DELETE")
        .uri("/api/v1/me/roles/moderator")
        .header(header::COOKIE, &cookies[1])
        .header(header::ORIGIN, ORIGIN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(leave_moderator).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let last_admin = Request::builder()
        .method("DELETE")
        .uri("/api/v1/me/roles/admin")
        .header(header::COOKIE, &cookies[2])
        .header(header::ORIGIN, ORIGIN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(last_admin).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    let self_revocation_audit: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE actor_user_id=$1 AND target_user_id=$1 AND action='account.role_self_revoked' AND old_role='moderator' AND new_role IS NULL")
        .bind(&users[1])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(self_revocation_audit, 1);
    sqlx::query("INSERT INTO cloud_sync_cursors(user_id,cursor) VALUES ($1,1)")
        .bind(&users[0])
        .execute(&pool)
        .await
        .unwrap();
    for index in [0, 2] {
        let delete = Request::builder()
            .method("POST")
            .uri("/api/auth/delete-user")
            .header(header::COOKIE, &cookies[index])
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({"password":"test password with enough characters"}).to_string(),
            ))
            .unwrap();
        let response = app.clone().oneshot(delete).await.unwrap();
        assert!(!response.status().is_success(), "deletion must be blocked");
        assert_eq!(
            request(&app, "GET", "/api/v1/me", Some(&cookies[index]), None)
                .await
                .status(),
            StatusCode::OK,
            "blocked delete must preserve session"
        );
        let accounts: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE user_id=$1")
            .bind(&users[index])
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(accounts, 1, "blocked delete must preserve credentials");
    }
    let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM cloud_sync_cursors WHERE user_id=$1")
        .bind(&users[0])
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, 1, "blocked delete must preserve sync state");
    for user in &users {
        let err = sqlx::query("DELETE FROM \"user\" WHERE id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap_err();
        assert!(
            err.as_database_error()
                .is_some_and(|e| matches!(e.code().as_deref(), Some("23001" | "23503"))),
            "unexpected deletion error: {err}"
        );
    }
    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id=$2")
        .bind(publisher)
        .bind(&users[1])
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query("DELETE FROM \"user\" WHERE id=$1")
            .bind(&users[1])
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    // Ownership remains protected even after an unrelated account is deleted.
    assert!(sqlx::query("DELETE FROM \"user\" WHERE id=$1")
        .bind(&users[0])
        .execute(&pool)
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn sync_write_rate_limit_is_shared_and_preserves_pending_edits() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use cloud_client::{Edit, PluginSelection, Session, SyncError};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..2 {
        users.push(
            service
                .sign_up(
                    SignUpInput {
                        email: format!("{}@example.test", uuid::Uuid::new_v4()),
                        name: "Rate Test".into(),
                        password: "test password with enough characters".into(),
                    },
                    true,
                )
                .await
                .unwrap(),
        );
    }
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let cookie = format!("{}={}", users[0].cookie.name, users[0].cookie.value);
    let value = json!({"schemaVersion":1,"pluginId":"acme.limit","version":"1.0.0","enabled":true});
    for i in 0..120 {
        let native = i % 2 == 1;
        let path = if native {
            "/api/v1/native/sync/collections/plugin-selections/acme.limit"
        } else {
            "/api/v1/sync/collections/plugin-selections/acme.limit"
        };
        let mut req = Request::builder()
            .method("PUT")
            .uri(path)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::IF_NONE_MATCH, "*");
        req = if native {
            req.header(
                header::AUTHORIZATION,
                format!("Bearer {}", users[0].session_token),
            )
        } else {
            req.header(header::COOKIE, &cookie)
        };
        let response = app
            .clone()
            .oneshot(req.body(Body::from(value.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if i == 0 {
                StatusCode::CREATED
            } else {
                StatusCode::CONFLICT
            }
        );
    }
    // Browser and bearer reads draw from the same per-account budgets. Export
    // has its own stricter budget and cannot exhaust ordinary read capacity.
    for i in 0..31 {
        let native = i % 2 == 1;
        let path = if native {
            "/api/v1/native/sync/export"
        } else {
            "/api/v1/sync/export"
        };
        let req = Request::builder().uri(path);
        let req = if native {
            req.header(
                header::AUTHORIZATION,
                format!("Bearer {}", users[0].session_token),
            )
        } else {
            req.header(header::COOKIE, &cookie)
        };
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if i < 30 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        if i == 30 {
            assert_eq!(response.headers()[header::RETRY_AFTER], "60");
        }
    }
    for i in 0..301 {
        let native = i % 2 == 1;
        let path = if native {
            "/api/v1/native/sync/head"
        } else {
            "/api/v1/sync/changes?cursor=0"
        };
        let req = Request::builder().uri(path);
        let req = if native {
            req.header(
                header::AUTHORIZATION,
                format!("Bearer {}", users[0].session_token),
            )
        } else {
            req.header(header::COOKIE, &cookie)
        };
        let response = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if i < 300 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    let other_cookie = format!("{}={}", users[1].cookie.name, users[1].cookie.value);
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/sync/export",
            Some(&other_cookie),
            None
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/sync/head", Some(&other_cookie), None)
            .await
            .status(),
        StatusCode::OK
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let client = Session::connect(&format!("http://{address}"), users[0].session_token.clone())
        .await
        .unwrap();
    let mut state = client.new_state();
    state
        .stage(
            "acme.other".into(),
            Edit::Put(PluginSelection {
                schema_version: 1,
                plugin_id: "acme.other".into(),
                version: "1.0.0".into(),
                enabled: true,
            }),
        )
        .unwrap();
    assert!(matches!(
        client.push(&mut state, "acme.other").await,
        Err(SyncError::RateLimited {
            retry_after_seconds: Some(60)
        })
    ));
    assert!(state.entries["acme.other"].pending.is_some());
    let cursor: i64 = sqlx::query_scalar("SELECT cursor FROM cloud_sync_cursors WHERE user_id=$1")
        .bind(&users[0].user.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, 1);
    let other = Session::connect(&format!("http://{address}"), users[1].session_token.clone())
        .await
        .unwrap();
    let mut other_state = other.new_state();
    other_state
        .stage(
            "acme.other".into(),
            Edit::Put(PluginSelection {
                schema_version: 1,
                plugin_id: "acme.other".into(),
                version: "1.0.0".into(),
                enabled: true,
            }),
        )
        .unwrap();
    other.push(&mut other_state, "acme.other").await.unwrap();
    server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn native_sync_client_preserves_offline_edits_and_conflicts() {
    use better_auth::{
        email_password::{EmailPasswordService, SignUpInput},
        session::SessionService,
    };
    use cloud_client::{Edit, PluginSelection, Session, StateStore, SyncError, SyncState};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let signed_in = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Client Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let second = SessionService::new(ctx.clone())
        .unwrap()
        .create(signed_in.user.clone(), true)
        .await
        .unwrap();
    let user_id = signed_in.user.id.clone();
    let token1 = signed_in.session_token;
    let token2 = second.session_token;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let origin = format!("http://{address}");
    let app_on_reconnect = app.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    assert!(matches!(
        Session::connect("http://example.com", token1.clone()).await,
        Err(SyncError::Configuration)
    ));
    let device1 = Session::connect(&origin, token1.clone()).await.unwrap();
    let device2 = Session::connect(&origin, token2.clone()).await.unwrap();
    let mut first = device1.new_state();
    let mut second = device2.new_state();
    let key = "acme.plugin";
    let selection = |version: &str| PluginSelection {
        schema_version: 1,
        plugin_id: key.into(),
        version: version.into(),
        enabled: true,
    };
    first
        .stage(key.into(), Edit::Put(selection("1.0.0")))
        .unwrap();
    device1.push(&mut first, key).await.unwrap();
    let snapshot = device2.export_sync().await.unwrap();
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.cursor, 1);
    assert_eq!(snapshot.records.len(), 1);
    assert_eq!(snapshot.records[0].value.as_ref().unwrap().version, "1.0.0");
    let account_export = device2.export_account().await.unwrap();
    assert_eq!(account_export.profile.id, user_id);
    assert_eq!(account_export.sync.schema_version, 1);
    assert_eq!(account_export.sync.cursor, 1);
    assert_eq!(account_export.sync.records, snapshot.records);
    let mut unseen = device2.new_state();
    unseen.stage(key.into(), Edit::Delete).unwrap();
    assert!(matches!(
        device2.push(&mut unseen, key).await,
        Err(SyncError::Conflict)
    ));
    assert!(unseen.entries[key].pending.as_ref().unwrap().conflict);
    assert!(!device1.pull_page(&mut first).await.unwrap());
    second
        .stage(key.into(), Edit::Put(selection("2.0.0")))
        .unwrap();
    device2.rebuild(&mut second).await.unwrap();
    assert!(second.entries[key].pending.as_ref().unwrap().conflict);
    assert!(matches!(
        device2.push(&mut second, key).await,
        Err(SyncError::Conflict)
    ));
    second.rebase(key).unwrap();
    device2.push(&mut second, key).await.unwrap();
    first
        .stage(key.into(), Edit::Put(selection("3.0.0")))
        .unwrap();
    assert!(matches!(
        device1.push(&mut first, key).await,
        Err(SyncError::Conflict)
    ));
    assert!(first.entries[key].pending.as_ref().unwrap().conflict);
    assert!(!device1.pull_page(&mut first).await.unwrap());
    assert!(first.entries[key].pending.as_ref().unwrap().conflict);
    first.discard(key).unwrap();
    first.stage(key.into(), Edit::Delete).unwrap();
    device1.push(&mut first, key).await.unwrap();
    assert!(!device2.pull_page(&mut second).await.unwrap());
    assert!(second.entries[key].remote.as_ref().unwrap().deleted);
    let snapshot = device1.export_sync().await.unwrap();
    assert_eq!(snapshot.cursor, 3);
    assert!(snapshot.records[0].deleted && snapshot.records[0].value.is_none());
    let mut wrong = SyncState::new(origin.clone(), "another-user".into());
    assert!(matches!(
        device1.pull_page(&mut wrong).await,
        Err(SyncError::WrongAccount)
    ));
    let mut wrong_origin =
        SyncState::new("https://other.example".into(), device1.account_id().into());
    assert!(matches!(
        device1.pull_page(&mut wrong_origin).await,
        Err(SyncError::WrongAccount)
    ));
    first
        .stage(key.into(), Edit::Put(selection("3.0.0")))
        .unwrap();
    sqlx::query("UPDATE cloud_sync_cursors SET cursor=20004 WHERE user_id=$1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        device1.pull_page(&mut first).await,
        Err(SyncError::CursorExpired)
    ));
    device1.rebuild(&mut first).await.unwrap();
    assert!(first.entries[key].pending.is_some());
    assert!(!first.entries[key].pending.as_ref().unwrap().conflict);
    server.abort();
    assert!(matches!(
        device1.push(&mut first, key).await,
        Err(SyncError::Network)
    ));
    assert!(first.entries[key].pending.is_some());
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::open(directory.path().join("sync-state")).unwrap();
    let persisted = store.save(None, &first).unwrap();
    let saved =
        std::fs::read_to_string(directory.path().join("sync-state/sync-state.json")).unwrap();
    assert!(!saved.contains(&token1) && !saved.contains(&token2));
    let mut restored = store.load().unwrap().unwrap();
    assert_eq!(restored.state, first);
    assert_eq!(restored.generation, persisted.generation);
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let restarted = tokio::spawn(async move {
        axum::serve(
            listener,
            app_on_reconnect.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    device1.push(&mut restored.state, key).await.unwrap();
    assert!(restored.state.entries[key].pending.is_none());
    let saved = store
        .save(Some(restored.generation), &restored.state)
        .unwrap();
    assert_eq!(store.load().unwrap().unwrap().generation, saved.generation);
    restarted.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn native_login_client_completes_loopback_handoff() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use cloud_client::{LoginAttempt, SyncError};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let url = crate::test_support::migrated_url();
    let (base_context, pool) = context(&url, false).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let ctx = AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(origin.clone())),
            trusted_origins: vec![origin.clone()],
            ..Default::default()
        },
        base_context.adapter.clone(),
        base_context.secondary_storage.clone(),
        vec![],
    )
    .unwrap();
    let signed_in = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Native login".into(),
                password: "test password with enough characters".into(),
            },
            false,
        )
        .await
        .unwrap();
    let expected_user = signed_in.user.id.clone();
    let cookie = format!("{}={}", signed_in.cookie.name, signed_in.cookie.value);
    let app = app(ctx.clone(), pool, AuthRouter::new(ctx).unwrap());
    let server_app = app.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            server_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let attempt = LoginAttempt::begin(&origin).await.unwrap();
    let browser = attempt.browser_url().clone();
    assert_eq!(browser.path(), "/desktop/login");
    let params: std::collections::HashMap<_, _> = browser.query_pairs().into_owned().collect();
    assert_eq!(params.len(), 3);
    assert!(!browser.as_str().contains("codeVerifier"));
    let page = request(&app, "GET", browser.path(), None, None).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(page.headers()[header::REFERRER_POLICY], "no-referrer");
    assert!(page.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    let issue = Request::builder().method("POST").uri("/api/v1/desktop/handoff").header(header::COOKIE, cookie).header(header::ORIGIN, &origin).header(header::CONTENT_TYPE, "application/json").body(Body::from(json!({"redirectUri":params["redirectUri"],"codeChallenge":params["codeChallenge"],"state":params["state"]}).to_string())).unwrap();
    let response = app.clone().oneshot(issue).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let callback = Url::parse(body["callbackUrl"].as_str().unwrap()).unwrap();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let wait = tokio::spawn(attempt.complete(std::time::Duration::from_secs(5), cancel_rx));
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", callback.port().unwrap()))
        .await
        .unwrap();
    stream
        .write_all(
            format!(
                "GET {}?{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
                callback.path(),
                callback.query().unwrap(),
                callback.port().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    let result = wait.await.unwrap().unwrap();
    assert_eq!(result.session.account_id(), expected_user);
    result.session.logout().await.unwrap();
    assert!(matches!(
        result.session.logout().await,
        Err(SyncError::Unauthorized)
    ));
    drop(cancel_tx);
    let cancelled = LoginAttempt::begin(&origin).await.unwrap();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    cancel_tx.send(()).unwrap();
    assert!(matches!(
        cancelled
            .complete(std::time::Duration::from_secs(5), cancel_rx)
            .await,
        Err(SyncError::LoginCancelled)
    ));
    server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn upload_authorization_idempotency_and_quarantine() {
    use axum::{
        http::{Method, Uri},
        response::IntoResponse,
    };
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
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
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..2 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push((
            result.user.id,
            format!("{}={}", result.cookie.name, result.cookie.value),
        ));
    }
    let publisher = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'pending')")
        .bind(publisher)
        .bind(format!("pub{}", publisher.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner'),($1,$3,'viewer')").bind(publisher).bind(&users[0].0).bind(&users[1].0).execute(&pool).await.unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let storage = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let app = app_with_storage(ctx, pool.clone(), auth, Some(storage));
    async fn reserve(
        app: &Router,
        cookie: Option<&str>,
        origin: &str,
        publisher: uuid::Uuid,
        size: i64,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/plugins/uploads")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", "fixture-key-00000001");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(
                req.body(Body::from(
                    json!({"publisherId":publisher,"size":size,"sha256":"a".repeat(64)})
                        .to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap()
    }
    assert_eq!(
        reserve(&app, None, ORIGIN, publisher, 5).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        reserve(&app, Some(&users[0].1), "https://evil.test", publisher, 5)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        reserve(&app, Some(&users[0].1), ORIGIN, publisher, 5)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE cloud_publishers SET status='approved' WHERE id=$1")
        .bind(publisher)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        reserve(&app, Some(&users[1].1), ORIGIN, publisher, 5)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = reserve(&app, Some(&users[0].1), ORIGIN, publisher, 5).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap();
    let id = data["id"].as_str().unwrap();
    assert_eq!(data["headers"]["if-none-match"], "*");
    let retry = reserve(&app, Some(&users[0].1), ORIGIN, publisher, 5).await;
    let retry: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(retry.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(retry["id"], id);
    assert_eq!(
        reserve(&app, Some(&users[0].1), ORIGIN, publisher, 6)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let path = format!("/api/v1/plugins/uploads/{id}/complete");
    assert_eq!(
        request(&app, "POST", &path, Some(&users[1].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let (a, b) = tokio::join!(
        request(&app, "POST", &path, Some(&users[0].1), Some(ORIGIN)),
        request(&app, "POST", &path, Some(&users[0].1), Some(ORIGIN))
    );
    assert_eq!(a.status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::OK);
    let id = uuid::Uuid::parse_str(id).unwrap();
    let row = sqlx::query("SELECT status,version_id FROM cloud_upload_sessions WHERE id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    use sqlx::Row;
    assert_eq!(row.get::<String, _>("status"), "quarantined");
    assert_eq!(row.get::<String, _>("version_id"), "fixture-version");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_verification_jobs WHERE upload_id=$1 AND status='queued'",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publisher_signing_keys_require_proof_and_independent_approval() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use tiktools_plugin_package::{KeyId, SigningKey};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..3 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push((
            result.user.id,
            format!("{}={}", result.cookie.name, result.cookie.value),
            "test password with enough characters".to_string(),
        ));
    }
    let publisher = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(format!("pub{}", publisher.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner'),($1,$3,'viewer')").bind(publisher).bind(&users[0].0).bind(&users[1].0).execute(&pool).await.unwrap();
    admin::change_role(&pool, true, &users[0].0, "admin", "test")
        .await
        .unwrap();
    admin::change_role(&pool, true, &users[2].0, "admin", "test")
        .await
        .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let base = format!("/api/v1/publishers/{publisher}/keys");
    // Password step-up mints an action-scoped grant for the caller's current
    // session; the cookie passed here selects that session.
    async fn grant(
        app: &Router,
        cookie: &str,
        action: &str,
        publisher: &uuid::Uuid,
        key_id: Option<&str>,
        password: &str,
    ) -> uuid::Uuid {
        let body = serde_json::json!({"action":action,"publisherId":publisher,"keyId":key_id,"password":password});
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/step-up/password")
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, cookie)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        uuid::Uuid::parse_str(data["grantId"].as_str().unwrap()).unwrap()
    }
    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        origin: &str,
        body: Option<serde_json::Value>,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, origin);
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        let body = if let Some(body) = body {
            req = req.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        app.clone().oneshot(req.body(body).unwrap()).await.unwrap()
    }
    let challenge_path = format!("{base}/challenges");
    // Without a grant the endpoints refuse with a machine-readable
    // requirement instead of performing any key operation.
    let forged_grant = uuid::Uuid::new_v4();
    let forged_body = Some(serde_json::json!({"stepUpGrant": forged_grant}));
    let forged = call(
        &app,
        "POST",
        &challenge_path,
        Some(&users[0].1),
        ORIGIN,
        forged_body,
    )
    .await;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        forged
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        call(&app, "POST", &challenge_path, None, ORIGIN, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &challenge_path,
            Some(&users[0].1),
            "https://evil.test",
            None
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // A viewer with a valid grant is still forbidden: step-up proves
    // identity, not the publisher role.
    let viewer_grant = grant(
        &app,
        &users[1].1,
        "publisher.key.enroll",
        &publisher,
        None,
        &users[1].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &challenge_path,
            Some(&users[1].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": viewer_grant}))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "GET", &base, Some(&users[2].1), ORIGIN, None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let enroll_grant = grant(
        &app,
        &users[0].1,
        "publisher.key.enroll",
        &publisher,
        None,
        &users[0].2,
    )
    .await;
    let response = call(
        &app,
        "POST",
        &challenge_path,
        Some(&users[0].1),
        ORIGIN,
        Some(serde_json::json!({"stepUpGrant": enroll_grant})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    let challenge_id = uuid::Uuid::parse_str(challenge["challengeId"].as_str().unwrap()).unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap();
    let public = key.public_key();
    let message = publisher_keys::proof_message(
        publisher,
        challenge_id,
        nonce,
        public.key_id.as_str(),
        &public.public_key,
    );
    let proof = json!({"challengeId":challenge_id,"keyId":public.key_id,"publicKey":public.public_key,"signature":STANDARD.encode(key.sign(message.as_bytes())),"stepUpGrant":enroll_grant});
    // A caller authenticated in a different session cannot spend this grant.
    let mut cross_session = proof.clone();
    cross_session["stepUpGrant"] = json!(
        grant(
            &app,
            &users[1].1,
            "publisher.key.enroll",
            &publisher,
            None,
            &users[1].2
        )
        .await
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &base,
            Some(&users[0].1),
            ORIGIN,
            Some(cross_session)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let mut forged = proof.clone();
    forged["signature"] = json!(STANDARD.encode([0u8; 64]));
    assert_eq!(
        call(&app, "POST", &base, Some(&users[0].1), ORIGIN, Some(forged))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let response = call(
        &app,
        "POST",
        &base,
        Some(&users[0].1),
        ORIGIN,
        Some(proof.clone()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["status"], "pending");
    let key_row = data["id"].as_str().unwrap();
    assert_eq!(
        call(&app, "POST", &base, Some(&users[0].1), ORIGIN, Some(proof))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let admin_base = format!("/api/v1/admin/publishers/{publisher}/keys");
    let approve = format!("{admin_base}/{key_row}/approve");
    // Approval without a grant fails even for an independent admin.
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[2].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": uuid::Uuid::new_v4()}))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // Re-grant: another suite case deletes all other admin roles to build its
    // own last-admin scenario, so the role is re-established at the point of use.
    admin::change_role(&pool, true, &users[2].0, "admin", "test")
        .await
        .unwrap();
    assert_eq!(
        call(&app, "GET", &admin_base, Some(&users[2].1), ORIGIN, None)
            .await
            .status(),
        StatusCode::OK
    );
    // A publisher member cannot approve their own key even with a grant.
    let self_grant = grant(
        &app,
        &users[0].1,
        "publisher.key.approve",
        &publisher,
        Some(key_row),
        &users[0].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[0].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": self_grant}))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let viewer_grant = grant(
        &app,
        &users[1].1,
        "publisher.key.approve",
        &publisher,
        Some(key_row),
        &users[1].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[1].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": viewer_grant}))
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    admin::change_role(&pool, true, &users[2].0, "admin", "test")
        .await
        .unwrap();
    let approve_grant = grant(
        &app,
        &users[2].1,
        "publisher.key.approve",
        &publisher,
        Some(key_row),
        &users[2].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[2].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": approve_grant}))
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    // The key is no longer pending, so even the already-spent grant and a
    // fresh grant both fail on state before any grant is consumed.
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[2].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": approve_grant}))
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let stale_grant = grant(
        &app,
        &users[2].1,
        "publisher.key.approve",
        &publisher,
        Some(key_row),
        &users[2].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[2].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": stale_grant}))
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let revoke = format!("{base}/{key_row}/revoke");
    assert_eq!(
        call(&app, "POST", &revoke, Some(&users[1].1), ORIGIN, None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "POST", &revoke, Some(&users[0].1), ORIGIN, None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "POST", &revoke, Some(&users[0].1), ORIGIN, None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    // A revoked key is no longer pending, with or without a fresh grant.
    admin::change_role(&pool, true, &users[2].0, "admin", "test")
        .await
        .unwrap();
    let revoked_grant = grant(
        &app,
        &users[2].1,
        "publisher.key.approve",
        &publisher,
        Some(key_row),
        &users[2].2,
    )
    .await;
    assert_eq!(
        call(
            &app,
            "POST",
            &approve,
            Some(&users[2].1),
            ORIGIN,
            Some(serde_json::json!({"stepUpGrant": revoked_grant}))
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    // A fresh challenge cannot re-enroll revoked key material under a different ID.
    let reenroll_grant = grant(
        &app,
        &users[0].1,
        "publisher.key.enroll",
        &publisher,
        None,
        &users[0].2,
    )
    .await;
    let response = call(
        &app,
        "POST",
        &challenge_path,
        Some(&users[0].1),
        ORIGIN,
        Some(serde_json::json!({"stepUpGrant": reenroll_grant})),
    )
    .await;
    let challenge: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    let fresh = uuid::Uuid::parse_str(challenge["challengeId"].as_str().unwrap()).unwrap();
    let alternate_id = format!("alt-{}", uuid::Uuid::new_v4().simple());
    let message = publisher_keys::proof_message(
        publisher,
        fresh,
        challenge["nonce"].as_str().unwrap(),
        &alternate_id,
        &public.public_key,
    );
    let duplicate = json!({"challengeId":fresh,"keyId":alternate_id,"publicKey":public.public_key,"signature":STANDARD.encode(key.sign(message.as_bytes())),"stepUpGrant":reenroll_grant});
    assert_eq!(
        call(
            &app,
            "POST",
            &base,
            Some(&users[0].1),
            ORIGIN,
            Some(duplicate.clone())
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE cloud_publisher_key_challenges SET expires_at=now()-interval '1 second' WHERE id=$1").bind(fresh).execute(&pool).await.unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            &base,
            Some(&users[0].1),
            ORIGIN,
            Some(duplicate)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let id = uuid::Uuid::parse_str(key_row).unwrap();
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM cloud_audit_events WHERE subject_id=$1 ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "publisher_key.requested",
            "publisher_key.approved",
            "publisher_key.revoked"
        ]
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn release_submission_binds_tenant_key_upload_and_version() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use tiktools_plugin_package::{KeyId, SigningKey};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..3 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push((
            result.user.id,
            format!("{}={}", result.cookie.name, result.cookie.value),
        ));
    }
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("pub{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner'),($1,$3,'viewer')").bind(publisher).bind(&users[0].0).bind(&users[1].0).execute(&pool).await.unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap()
    .public_key();
    let key_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved',$6)")
        .bind(key_id).bind(publisher).bind(key.key_id.as_str()).bind(&key.public_key).bind(key.fingerprint().unwrap().to_string()).bind(&users[0].0).execute(&pool).await.unwrap();
    async fn create_upload(pool: &PgPool, publisher: uuid::Uuid, user: &str) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,$6,'quarantined',now()+interval '5 minutes','version')")
            .bind(id).bind(publisher).bind(user).bind(format!("key{}",id.simple())).bind("a".repeat(64)).bind(format!("quarantine/{publisher}/{id}")).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,status) VALUES ($1,'queued')")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
        id
    }
    let upload = create_upload(&pool, publisher, &users[0].0).await;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let input = json!({"uploadId":upload,"publisherKeyId":key_id,"pluginId":format!("{namespace}.plugin"),"version":"1.2.3","target":"any"});
    async fn submit(
        app: &Router,
        cookie: Option<&str>,
        origin: &str,
        input: serde_json::Value,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/v1/plugins/releases")
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(req.body(Body::from(input.to_string())).unwrap())
            .await
            .unwrap()
    }
    assert_eq!(
        submit(&app, None, ORIGIN, input.clone()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        submit(&app, Some(&users[0].1), "https://evil.test", input.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        submit(&app, Some(&users[2].1), ORIGIN, input.clone())
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        submit(&app, Some(&users[1].1), ORIGIN, input.clone())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut invalid = input.clone();
    invalid["pluginId"] = json!("other.plugin");
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut invalid = input.clone();
    invalid["version"] = json!("01.2.3");
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut invalid = input.clone();
    invalid["target"] = json!("../invalid");
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, invalid)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let mut invalid = input.clone();
    invalid["publisherKeyId"] = json!(uuid::Uuid::new_v4());
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, invalid)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let (a, b) = tokio::join!(
        submit(&app, Some(&users[0].1), ORIGIN, input.clone()),
        submit(&app, Some(&users[0].1), ORIGIN, input.clone())
    );
    let statuses = [a.status(), b.status()];
    assert!(statuses.contains(&StatusCode::CREATED));
    assert!(statuses.contains(&StatusCode::OK));
    let data: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(a.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(data["status"], "awaiting_verification");
    let id = data["id"].as_str().unwrap();
    let path = format!("/api/v1/plugins/releases/{id}");
    assert_eq!(
        request(&app, "GET", &path, None, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "GET", &path, Some(&users[2].1), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let response = request(&app, "GET", &path, Some(&users[1].1), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let linked: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT release_id FROM cloud_verification_jobs WHERE upload_id=$1")
            .bind(upload)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(linked.unwrap().to_string(), id);
    let mut different = input.clone();
    different["version"] = json!("2.0.0");
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, different)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let other = create_upload(&pool, publisher, &users[0].0).await;
    let mut duplicate = input.clone();
    duplicate["uploadId"] = json!(other);
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, duplicate)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut revoked = input;
    revoked["uploadId"] = json!(other);
    revoked["version"] = json!("2.0.0");
    assert_eq!(
        submit(&app, Some(&users[0].1), ORIGIN, revoked)
            .await
            .status(),
        StatusCode::CONFLICT
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn integrity_worker_verifies_exact_version_and_fences_retries() {
    use axum::{
        extract::State,
        http::{Method, Uri},
        response::IntoResponse,
    };
    use std::future::IntoFuture;
    use tiktools_plugin_package::{
        pack, sign_archive, KeyId, PackRequest, Sha256Digest, SigningKey,
    };
    let database_url = crate::test_support::migrated_url();
    let (_ctx, pool) = context(&database_url, false).await;
    // Isolate the queue from other integration tests in the shared disposable database.
    sqlx::query("UPDATE cloud_verification_jobs SET status='failed', lease_id=NULL, lease_expires_at=NULL, result_class='temporary_failure' WHERE status IN ('queued','running') AND release_id IS NOT NULL").execute(&pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("pub{}", publisher.simple());
    let plugin_id = format!("{namespace}.plugin");
    let manifest = dir.path().join("plugin.json");
    std::fs::write(&manifest,serde_json::to_vec(&json!({"schemaVersion":2,"id":plugin_id,"name":"Test","version":"1.0.0","runtime":"process","entry":"index.js","protocolVersion":1,"publisher":namespace})).unwrap()).unwrap();
    let entry = dir.path().join("entry");
    std::fs::write(&entry, b"valid plugin bytes").unwrap();
    let package = dir.path().join("package.plugin");
    pack(&PackRequest {
        manifest,
        entry: Some(entry),
        output: package.clone(),
        target: None,
    })
    .unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        Some(namespace.clone()),
    )
    .unwrap();
    sign_archive(&package, &key).unwrap();
    let public = key.public_key();
    let digest = Sha256Digest::of_file(&package).unwrap().to_string();
    let bytes = std::fs::read(&package).unwrap();
    let size = bytes.len() as i64;
    async fn s3(
        State(bytes): State<Arc<Vec<u8>>>,
        method: Method,
        uri: Uri,
    ) -> axum::response::Response {
        assert_eq!(method, Method::GET);
        assert!(uri
            .query()
            .is_some_and(|q| q.contains("versionId=fixture-version")));
        (
            [(
                header::HeaderName::from_static("x-amz-version-id"),
                "fixture-version",
            )],
            bytes.as_ref().clone(),
        )
            .into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let bytes = Arc::new(bytes);
    let scan_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scanner = crate::scanner::ClamAv::new(scan_listener.local_addr().unwrap());
    let scan_bytes = bytes.clone();
    let infected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scanner_infected = infected.clone();
    let scan_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut socket, _) = scan_listener.accept().await.unwrap();
            let expected = scan_bytes.clone();
            let infected = scanner_infected.clone();
            tokio::spawn(async move {
                let mut command = [0_u8; 10];
                socket.read_exact(&mut command).await.unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut data = Vec::new();
                loop {
                    let mut len = [0_u8; 4];
                    socket.read_exact(&mut len).await.unwrap();
                    let len = u32::from_be_bytes(len) as usize;
                    if len == 0 {
                        break;
                    }
                    let start = data.len();
                    data.resize(start + len, 0);
                    socket.read_exact(&mut data[start..]).await.unwrap();
                }
                assert_eq!(&data, expected.as_ref());
                let response: &[u8] = if infected.load(std::sync::atomic::Ordering::SeqCst) {
                    b"stream: fixture FOUND\0"
                } else {
                    b"stream: OK\0"
                };
                socket.write_all(response).await.unwrap();
            });
        }
    });
    let served_bytes = bytes.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(s3).with_state(served_bytes),
        )
        .await
        .unwrap();
    });
    let storage = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    let key_row = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved','fixture')").bind(key_row).bind(publisher).bind(public.key_id.as_str()).bind(&public.public_key).bind(public.fingerprint().unwrap().to_string()).execute(&pool).await.unwrap();
    async fn queued(
        pool: &PgPool,
        publisher: uuid::Uuid,
        key_row: uuid::Uuid,
        plugin: &str,
        digest: &str,
        size: i64,
        version: &str,
    ) -> (uuid::Uuid, uuid::Uuid) {
        let upload = uuid::Uuid::new_v4();
        let release = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,'fixture',$3,$4,$5,$6,'quarantined',now(),'fixture-version')").bind(upload).bind(publisher).bind(format!("key{}",upload.simple())).bind(size).bind(digest).bind(format!("quarantine/{publisher}/{upload}")).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,$6,'any','awaiting_verification','fixture')").bind(release).bind(publisher).bind(upload).bind(key_row).bind(plugin).bind(version).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status) VALUES ($1,$2,'queued')").bind(upload).bind(release).execute(pool).await.unwrap();
        (upload, release)
    }
    let (upload, release) = queued(
        &pool, publisher, key_row, &plugin_id, &digest, size, "1.0.0",
    )
    .await;
    assert!(
        !recovery::retry(&pool, recovery::Kind::Verification, upload, "test")
            .await
            .unwrap()
    );
    sqlx::query("UPDATE cloud_verification_jobs SET status='failed',attempts=3,result_class='temporary_failure' WHERE upload_id=$1").bind(upload).execute(&pool).await.unwrap();
    assert!(
        recovery::retry(&pool, recovery::Kind::Verification, upload, "bad operator!")
            .await
            .is_err()
    );
    let (a, b) = tokio::join!(
        recovery::retry(&pool, recovery::Kind::Verification, upload, "test"),
        recovery::retry(&pool, recovery::Kind::Verification, upload, "test")
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let audit:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='verification.retry_requested'").bind(upload).fetch_one(&pool).await.unwrap();
    assert_eq!(audit, 1);
    assert!(worker::once(&pool, &storage, &scanner).await.unwrap());
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(release)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "antivirus_passed");
    let result: (String, i32) =
        sqlx::query_as("SELECT status,attempts FROM cloud_verification_jobs WHERE upload_id=$1")
            .bind(upload)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(result, ("antivirus_passed".into(), 1));
    // Reset this fixture as if an operator scheduled a rescan, then report a detection.
    sqlx::query("UPDATE cloud_plugin_releases SET status='awaiting_verification' WHERE id=$1")
        .bind(release)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE cloud_verification_jobs SET status='queued',attempts=0,result_class=NULL WHERE upload_id=$1").bind(upload).execute(&pool).await.unwrap();
    let unavailable_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_scanner =
        crate::scanner::ClamAv::new(unavailable_listener.local_addr().unwrap());
    drop(unavailable_listener);
    assert!(worker::once(&pool, &storage, &unavailable_scanner)
        .await
        .unwrap());
    let result: (String, String) = sqlx::query_as(
        "SELECT status,result_class FROM cloud_verification_jobs WHERE upload_id=$1",
    )
    .bind(upload)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(result, ("queued".into(), "temporary_failure".into()));
    infected.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(worker::once(&pool, &storage, &scanner).await.unwrap());
    let result: (String, String) = sqlx::query_as(
        "SELECT status,result_class FROM cloud_verification_jobs WHERE upload_id=$1",
    )
    .bind(upload)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(result, ("rejected".into(), "antivirus_alert".into()));
    assert!(
        !recovery::retry(&pool, recovery::Kind::Verification, upload, "test")
            .await
            .unwrap()
    );
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(release)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");
    infected.store(false, std::sync::atomic::Ordering::SeqCst);
    // A mismatched signed manifest is a permanent rejection even with a matching digest.
    let (upload, release) = queued(
        &pool, publisher, key_row, &plugin_id, &digest, size, "2.0.0",
    )
    .await;
    assert!(worker::once(&pool, &storage, &scanner).await.unwrap());
    let result: (String, String) = sqlx::query_as(
        "SELECT status,result_class FROM cloud_verification_jobs WHERE upload_id=$1",
    )
    .bind(upload)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(result, ("rejected".into(), "invalid_package".into()));
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(release)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "rejected");
    // Revoke the signing key while the worker is downloading; its result must be rejected.
    type DelayedState = (
        Arc<Vec<u8>>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    );
    async fn delayed_s3(
        State((bytes, entered, proceed)): State<DelayedState>,
    ) -> axum::response::Response {
        entered.notify_one();
        proceed.notified().await;
        (
            [(
                header::HeaderName::from_static("x-amz-version-id"),
                "fixture-version",
            )],
            bytes.as_ref().clone(),
        )
            .into_response()
    }
    let entered = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let delayed = tokio::spawn(
        axum::serve(
            listener,
            Router::new().fallback(delayed_s3).with_state((
                bytes,
                entered.clone(),
                proceed.clone(),
            )),
        )
        .into_future(),
    );
    let delayed_store = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let (race_upload, _) = queued(
        &pool, publisher, key_row, &plugin_id, &digest, size, "4.0.0",
    )
    .await;
    let worker_pool = pool.clone();
    let race_scanner = scanner.clone();
    let stale_store = delayed_store.clone();
    let running = tokio::spawn(async move {
        worker::once(&worker_pool, &delayed_store, &race_scanner)
            .await
            .map_err(|e| e.to_string())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_row)
        .execute(&pool)
        .await
        .unwrap();
    proceed.notify_one();
    assert!(running.await.unwrap().unwrap());
    let result: (String, String) = sqlx::query_as(
        "SELECT status,result_class FROM cloud_verification_jobs WHERE upload_id=$1",
    )
    .bind(race_upload)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(result, ("rejected".into(), "key_not_authorized".into()));
    sqlx::query("UPDATE cloud_publisher_keys SET status='approved' WHERE id=$1")
        .bind(key_row)
        .execute(&pool)
        .await
        .unwrap();
    // A replaced lease fences out a worker which was still downloading.
    let (stale_upload, stale_release) = queued(
        &pool, publisher, key_row, &plugin_id, &digest, size, "5.0.0",
    )
    .await;
    let worker_pool = pool.clone();
    let stale_scanner = scanner.clone();
    let running = tokio::spawn(async move {
        worker::once(&worker_pool, &stale_store, &stale_scanner)
            .await
            .map_err(|e| e.to_string())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let replacement_lease = uuid::Uuid::new_v4();
    sqlx::query("UPDATE cloud_verification_jobs SET lease_id=$2,lease_expires_at=now()+interval '10 minutes' WHERE upload_id=$1").bind(stale_upload).bind(replacement_lease).execute(&pool).await.unwrap();
    proceed.notify_one();
    assert!(running.await.unwrap().unwrap());
    let row: (String, uuid::Uuid) =
        sqlx::query_as("SELECT status,lease_id FROM cloud_verification_jobs WHERE upload_id=$1")
            .bind(stale_upload)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, ("running".into(), replacement_lease));
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(stale_release)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "awaiting_verification");
    sqlx::query("UPDATE cloud_verification_jobs SET status='failed',lease_id=NULL,lease_expires_at=NULL,result_class='temporary_failure' WHERE upload_id=$1").bind(stale_upload).execute(&pool).await.unwrap();
    delayed.abort();
    // A failed worker loses its lease; retry with a new lease, then stop after three attempts.
    server.abort();
    let (upload, _) = queued(
        &pool, publisher, key_row, &plugin_id, &digest, size, "3.0.0",
    )
    .await;
    sqlx::query("UPDATE cloud_verification_jobs SET status='running',attempts=1,lease_id=$2,lease_expires_at=now()-interval '1 second' WHERE upload_id=$1").bind(upload).bind(uuid::Uuid::new_v4()).execute(&pool).await.unwrap();
    assert!(worker::once(&pool, &storage, &scanner).await.unwrap());
    let result: (String, i32) =
        sqlx::query_as("SELECT status,attempts FROM cloud_verification_jobs WHERE upload_id=$1")
            .bind(upload)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(result, ("queued".into(), 2));
    assert!(worker::once(&pool, &storage, &scanner).await.unwrap());
    let result: (String, i32) =
        sqlx::query_as("SELECT status,attempts FROM cloud_verification_jobs WHERE upload_id=$1")
            .bind(upload)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(result, ("failed".into(), 3));
    scan_server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn moderation_requires_independent_reviewer_and_current_verification() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use tiktools_plugin_package::{KeyId, SigningKey};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let mut users = Vec::new();
    for _ in 0..4 {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: "test password with enough characters".into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push((
            result.user.id,
            format!("{}={}", result.cookie.name, result.cookie.value),
        ));
    }
    for idx in [0, 1, 2] {
        admin::change_role(&pool, true, &users[idx].0, "moderator", "test")
            .await
            .unwrap();
    }
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("pub{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&users[0].0).execute(&pool).await.unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap()
    .public_key();
    let key_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved',$6)").bind(key_id).bind(publisher).bind(key.key_id.as_str()).bind(&key.public_key).bind(key.fingerprint().unwrap().to_string()).bind(&users[0].0).execute(&pool).await.unwrap();
    async fn candidate(
        pool: &PgPool,
        publisher: uuid::Uuid,
        key: uuid::Uuid,
        namespace: &str,
        requester: &str,
        version: &str,
        statuses: (&str, &str),
    ) -> uuid::Uuid {
        let (release_status, job_status) = statuses;
        let upload = uuid::Uuid::new_v4();
        let release = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,$6,'quarantined',now(),'version')").bind(upload).bind(publisher).bind(requester).bind(format!("key{}",upload.simple())).bind("a".repeat(64)).bind(format!("quarantine/{publisher}/{upload}")).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,$6,'any',$7,$8)").bind(release).bind(publisher).bind(upload).bind(key).bind(format!("{namespace}.plugin")).bind(version).bind(release_status).bind(requester).execute(pool).await.unwrap();
        sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,$3,1,$4)").bind(upload).bind(release).bind(job_status).bind(if job_status=="antivirus_passed" {Some("antivirus_passed")}else{None}).execute(pool).await.unwrap();
        release
    }
    let release = candidate(
        &pool,
        publisher,
        key_id,
        &namespace,
        &users[0].0,
        "1.0.0",
        ("antivirus_passed", "antivirus_passed"),
    )
    .await;
    let pending = candidate(
        &pool,
        publisher,
        key_id,
        &namespace,
        &users[0].0,
        "2.0.0",
        ("awaiting_verification", "queued"),
    )
    .await;
    let self_requested = candidate(
        &pool,
        publisher,
        key_id,
        &namespace,
        &users[1].0,
        "3.0.0",
        ("antivirus_passed", "antivirus_passed"),
    )
    .await;
    type VersioningState = (
        Arc<std::sync::atomic::AtomicBool>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    );
    async fn versioning(
        axum::extract::State((hold, entered, proceed)): axum::extract::State<VersioningState>,
    ) -> impl axum::response::IntoResponse {
        if hold.load(std::sync::atomic::Ordering::SeqCst) {
            entered.notify_one();
            proceed.notified().await;
        }
        ([(header::CONTENT_TYPE,"application/xml")],"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>")
    }
    let hold = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let proceed = Arc::new(tokio::sync::Notify::new());
    let server_state = (hold.clone(), entered.clone(), proceed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let storage_server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(versioning).with_state(server_state),
        )
        .await
        .unwrap()
    });
    let storage = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app_with_storage(ctx, pool.clone(), auth, Some(storage));
    let queue = "/api/v1/moderation/releases";
    assert_eq!(
        request(&app, "GET", queue, None, None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "GET", queue, Some(&users[3].1), None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = request(&app, "GET", queue, Some(&users[1].1), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let list: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    let ids: Vec<_> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect();
    assert!(ids.contains(&release.to_string().as_str()));
    assert!(!ids.contains(&pending.to_string().as_str()));
    assert!(!ids.contains(&self_requested.to_string().as_str()));
    let inspection_path = format!("/api/v1/moderation/releases/{release}/inspection");
    assert_eq!(
        request(&app, "POST", &inspection_path, None, Some(ORIGIN))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &inspection_path,
            Some(&users[3].1),
            Some(ORIGIN)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &inspection_path,
            Some(&users[0].1),
            Some(ORIGIN)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &inspection_path,
            Some(&users[1].1),
            Some("https://evil.test")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let response = request(
        &app,
        "POST",
        &inspection_path,
        Some(&users[1].1),
        Some(ORIGIN),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let inspection: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap(),
    )
    .unwrap();
    let url = Url::parse(inspection["url"].as_str().unwrap()).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(params.get("versionId").map(String::as_str), Some("version"));
    assert_eq!(
        params
            .get("response-content-disposition")
            .map(String::as_str),
        Some("attachment")
    );
    assert_eq!(inspection["expiresIn"], 60);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.inspection_granted'").bind(release).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    // Revoke the moderator while the S3 versioning request is in flight.
    hold.store(true, std::sync::atomic::Ordering::SeqCst);
    let race_app = app.clone();
    let race_path = inspection_path.clone();
    let race_cookie = users[2].1.clone();
    let running = tokio::spawn(async move {
        request(
            &race_app,
            "POST",
            &race_path,
            Some(&race_cookie),
            Some(ORIGIN),
        )
        .await
        .status()
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    admin::change_role(&pool, false, &users[2].0, "moderator", "test")
        .await
        .unwrap();
    hold.store(false, std::sync::atomic::Ordering::SeqCst);
    proceed.notify_one();
    assert_eq!(running.await.unwrap(), StatusCode::FORBIDDEN);
    admin::change_role(&pool, true, &users[2].0, "moderator", "test")
        .await
        .unwrap();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.inspection_granted'").bind(release).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    async fn decide(
        app: &Router,
        cookie: Option<&str>,
        origin: &str,
        id: uuid::Uuid,
        decision: &str,
        reason: &str,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/moderation/releases/{id}/decision"))
            .header(header::ORIGIN, origin)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie)
        }
        app.clone()
            .oneshot(
                req.body(Body::from(
                    json!({"decision":decision,"reasonCode":reason}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    assert_eq!(
        decide(&app, None, ORIGIN, release, "approve", "policy_reviewed").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[1].1),
            "https://evil.test",
            release,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[3].1),
            ORIGIN,
            release,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[0].1),
            ORIGIN,
            release,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[1].1),
            ORIGIN,
            self_requested,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[1].1),
            ORIGIN,
            pending,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::CONFLICT
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[1].1),
            ORIGIN,
            release,
            "approve",
            "malware"
        )
        .await,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        decide(
            &app,
            Some(&users[1].1),
            ORIGIN,
            release,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE cloud_publisher_keys SET status='approved' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        decide(
            &app,
            Some(&users[1].1),
            ORIGIN,
            release,
            "approve",
            "policy_reviewed"
        ),
        decide(&app, Some(&users[2].1), ORIGIN, release, "reject", "policy")
    );
    assert!(
        (a == StatusCode::NO_CONTENT && b == StatusCode::CONFLICT)
            || (b == StatusCode::NO_CONTENT && a == StatusCode::CONFLICT)
    );
    let (winner, decision, reason, status) = if a == StatusCode::NO_CONTENT {
        (1, "approve", "policy_reviewed", "review_approved")
    } else {
        (2, "reject", "policy", "review_rejected")
    };
    assert_eq!(
        decide(
            &app,
            Some(&users[winner].1),
            ORIGIN,
            release,
            decision,
            reason
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let actual: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(release)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actual, status);
    assert_eq!(
        request(
            &app,
            "POST",
            &inspection_path,
            Some(&users[1].1),
            Some(ORIGIN)
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let review_path = format!("/api/v1/plugins/releases/{release}/review");
    assert_eq!(
        request(&app, "GET", &review_path, None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "GET", &review_path, Some(&users[3].1), None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    let response = request(&app, "GET", &review_path, Some(&users[0].1), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let review: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(review["decision"], decision);
    assert_eq!(review["reasonCode"], reason);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_moderation_events WHERE release_id=$1")
            .bind(release)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action IN ('release.review_approved','release.review_rejected')").bind(release).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    // Only an independently reviewed and still-authorized release may enter the publication queue.
    let publish_path = format!("/api/v1/plugins/releases/{self_requested}/publish");
    assert_eq!(
        request(&app, "POST", &publish_path, None, Some(ORIGIN))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[3].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[0].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[1].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            "POST",
            &publish_path,
            Some(&users[2].1),
            Some("https://evil.test")
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[2].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        decide(
            &app,
            Some(&users[2].1),
            ORIGIN,
            self_requested,
            "approve",
            "policy_reviewed"
        )
        .await,
        StatusCode::NO_CONTENT
    );
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(&app, "POST", &publish_path, Some(&users[2].1), Some(ORIGIN))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE cloud_publisher_keys SET status='approved' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        request(&app, "POST", &publish_path, Some(&users[2].1), Some(ORIGIN)),
        request(&app, "POST", &publish_path, Some(&users[2].1), Some(ORIGIN))
    );
    assert_eq!(a.status(), StatusCode::ACCEPTED);
    assert_eq!(b.status(), StatusCode::ACCEPTED);
    assert_eq!(a.headers()[header::CACHE_CONTROL], "no-store");
    let a: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(a.into_body(), 4096).await.unwrap()).unwrap();
    let b: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(b.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(a["jobId"], b["jobId"]);
    assert_eq!(a["status"], "queued");
    assert_eq!(a["processingAvailable"], false);
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
        .bind(self_requested)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "review_approved");
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.publication_requested'").bind(self_requested).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    admin::change_role(&pool, false, &users[1].0, "moderator", "test")
        .await
        .unwrap();
    assert_eq!(
        request(&app, "GET", queue, Some(&users[1].1), None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    storage_server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn publication_preparer_rechecks_trust_and_fences_stale_workers() {
    use axum::{
        extract::State,
        http::{Method, Uri},
        response::IntoResponse,
    };
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use std::{
        collections::HashMap,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tiktools_plugin_package::{
        pack, sign_archive, KeyId, KeyRole, PackRequest, Sha256Digest, SigningKey, TrustedKey,
    };
    use tiktools_plugin_registry::IndexWriter;
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::query("UPDATE cloud_publication_jobs SET status='failed',lease_id=NULL,lease_expires_at=NULL,prepared_key=NULL,prepared_version_id=NULL,result_class='temporary_failure' WHERE status IN ('queued','running','prepared')").execute(&pool).await.unwrap();
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let signed_up = service
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let replacement_user = service
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Replacement Moderator".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let replacement_id = replacement_user.user.id;
    let replacement_cookie = format!(
        "{}={}",
        replacement_user.cookie.name, replacement_user.cookie.value
    );
    admin::change_role(&pool, true, &replacement_id, "moderator", "test")
        .await
        .unwrap();
    let requester = signed_up.user.id;
    let requester_cookie = format!("{}={}", signed_up.cookie.name, signed_up.cookie.value);
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    admin::change_role(&pool, true, &requester, "moderator", "test")
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("pub{}", publisher.simple());
    let plugin_id = format!("{namespace}.plugin");
    let manifest = dir.path().join("plugin.json");
    std::fs::write(&manifest,serde_json::to_vec(&json!({"schemaVersion":2,"id":plugin_id,"name":"Test","version":"1.0.0","runtime":"process","entry":"index.js","protocolVersion":1,"publisher":namespace,"description":"A test plugin","license":"MIT","engines":{"tiktools":">=0.4.0"},"categories":["audio"]})).unwrap()).unwrap();
    let entry = dir.path().join("entry");
    std::fs::write(&entry, b"valid plugin bytes").unwrap();
    let package = dir.path().join("artifact.plugin");
    pack(&PackRequest {
        manifest,
        entry: Some(entry.clone()),
        output: package.clone(),
        target: None,
    })
    .unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        Some(namespace.clone()),
    )
    .unwrap();
    sign_archive(&package, &key).unwrap();
    let public = key.public_key();
    let second_plugin = format!("{namespace}.other");
    let second_manifest = dir.path().join("second.json");
    std::fs::write(&second_manifest,serde_json::to_vec(&json!({"schemaVersion":2,"id":second_plugin,"name":"Other","version":"2.0.0","runtime":"process","entry":"index.js","protocolVersion":1,"publisher":namespace,"description":"Another test plugin","license":"MIT","engines":{"tiktools":">=0.4.0"},"categories":["audio"]})).unwrap()).unwrap();
    let second_package = dir.path().join("second.plugin");
    pack(&PackRequest {
        manifest: second_manifest,
        entry: Some(entry.clone()),
        output: second_package.clone(),
        target: None,
    })
    .unwrap();
    sign_archive(&second_package, &key).unwrap();
    let second_digest = Sha256Digest::of_file(&second_package).unwrap().to_string();
    let second_bytes = std::fs::read(&second_package).unwrap();
    let digest = Sha256Digest::of_file(&package).unwrap().to_string();
    let bytes = Arc::new(std::fs::read(&package).unwrap());
    let size = bytes.len() as i64;
    #[derive(Clone)]
    struct S3State {
        source: Arc<Vec<u8>>,
        publisher: uuid::Uuid,
        objects: Arc<tokio::sync::Mutex<HashMap<String, Vec<u8>>>>,
        hold: Arc<AtomicBool>,
        hold_candidate: Arc<AtomicBool>,
        hold_export: Arc<AtomicBool>,
        tamper_read_candidate: Arc<AtomicBool>,
        tamper_candidate: Arc<AtomicBool>,
        tamper: Arc<AtomicBool>,
        entered: Arc<tokio::sync::Notify>,
        proceed: Arc<tokio::sync::Notify>,
    }
    async fn s3(
        State(state): State<S3State>,
        method: Method,
        uri: Uri,
        headers: axum::http::HeaderMap,
        body: Body,
    ) -> axum::response::Response {
        if method == Method::GET && uri.query().is_some_and(|q| q.contains("versioning")) {
            return ([(header::CONTENT_TYPE,"application/xml")],"<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>").into_response();
        }
        if method == Method::PUT && uri.path().contains("/prepared/") {
            assert_eq!(headers.get("if-none-match").unwrap(), "*");
            assert!(headers.contains_key("x-amz-checksum-sha256"));
            let mut bytes = axum::body::to_bytes(body, 128 * 1024 * 1024 + 1)
                .await
                .unwrap()
                .to_vec();
            let release_object = uri
                .path()
                .contains(&format!("/prepared/{}/", state.publisher));
            if release_object {
                assert_eq!(&bytes, state.source.as_ref());
            }
            if (release_object && state.tamper.load(Ordering::SeqCst))
                || (!release_object && state.tamper_candidate.load(Ordering::SeqCst))
            {
                bytes[0] ^= 1;
            }
            state
                .objects
                .lock()
                .await
                .insert(uri.path().to_owned(), bytes);
            if (release_object && state.hold.load(Ordering::SeqCst))
                || (!release_object && state.hold_candidate.load(Ordering::SeqCst))
            {
                state.entered.notify_one();
                state.proceed.notified().await;
            }
            return (
                [(
                    header::HeaderName::from_static("x-amz-version-id"),
                    "staged-version",
                )],
                "",
            )
                .into_response();
        }
        if method == Method::GET && uri.path().contains("/prepared/") {
            if uri
                .path()
                .contains(&format!("/prepared/{}/", state.publisher))
                && state.hold.load(Ordering::SeqCst)
            {
                state.entered.notify_one();
                state.proceed.notified().await;
            }
            assert!(uri
                .query()
                .is_some_and(|q| q.contains("versionId=staged-version")));
            let mut bytes = state.objects.lock().await.get(uri.path()).cloned().unwrap();
            let candidate_object = !uri
                .path()
                .contains(&format!("/prepared/{}/", state.publisher));
            if candidate_object && state.hold_export.load(Ordering::SeqCst) {
                state.entered.notify_one();
                state.proceed.notified().await;
            }
            if candidate_object && state.tamper_read_candidate.load(Ordering::SeqCst) {
                bytes[0] ^= 1;
            }
            return (
                [(
                    header::HeaderName::from_static("x-amz-version-id"),
                    "staged-version",
                )],
                bytes,
            )
                .into_response();
        }
        if method == Method::GET && uri.path().contains("/quarantine/") {
            assert!(uri
                .query()
                .is_some_and(|q| q.contains("versionId=fixture-version")));
            return (
                [(
                    header::HeaderName::from_static("x-amz-version-id"),
                    "fixture-version",
                )],
                state.source.as_ref().clone(),
            )
                .into_response();
        }
        StatusCode::NOT_FOUND.into_response()
    }
    let state = S3State {
        source: bytes.clone(),
        publisher,
        objects: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        hold: Arc::new(AtomicBool::new(false)),
        hold_candidate: Arc::new(AtomicBool::new(false)),
        hold_export: Arc::new(AtomicBool::new(false)),
        tamper_read_candidate: Arc::new(AtomicBool::new(false)),
        tamper_candidate: Arc::new(AtomicBool::new(false)),
        tamper: Arc::new(AtomicBool::new(false)),
        entered: Arc::new(tokio::sync::Notify::new()),
        proceed: Arc::new(tokio::sync::Notify::new()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(s3).with_state(server_state),
        )
        .await
        .unwrap()
    });
    let store = cloud_storage::QuarantineStore::new(cloud_storage::Config {
        endpoint,
        region: "us-east-1".into(),
        bucket: "cloud-test".into(),
        access_key: "test".into(),
        secret_key: "test-secret".into(),
    })
    .unwrap();
    let scan_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scanner = crate::scanner::ClamAv::new(scan_listener.local_addr().unwrap());
    let expected = Arc::new(vec![bytes.as_ref().clone(), second_bytes.clone()]);
    let infected = Arc::new(AtomicBool::new(false));
    let scan_infected = infected.clone();
    let scan_server = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let (mut socket, _) = scan_listener.accept().await.unwrap();
            let expected = expected.clone();
            let infected = scan_infected.clone();
            tokio::spawn(async move {
                let mut command = [0u8; 10];
                socket.read_exact(&mut command).await.unwrap();
                assert_eq!(&command, b"zINSTREAM\0");
                let mut data = Vec::new();
                loop {
                    let mut len = [0u8; 4];
                    socket.read_exact(&mut len).await.unwrap();
                    let n = u32::from_be_bytes(len) as usize;
                    if n == 0 {
                        break;
                    }
                    let at = data.len();
                    data.resize(at + n, 0);
                    socket.read_exact(&mut data[at..]).await.unwrap();
                }
                assert!(expected.iter().any(|candidate| candidate == &data));
                let reply = if infected.load(Ordering::SeqCst) {
                    b"stream: Test FOUND\0".as_slice()
                } else {
                    b"stream: OK\0".as_slice()
                };
                socket.write_all(reply).await.unwrap();
            });
        }
    });
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    let key_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved','owner-fixture')").bind(key_id).bind(publisher).bind(public.key_id.as_str()).bind(&public.public_key).bind(public.fingerprint().unwrap().to_string()).execute(&pool).await.unwrap();
    let upload = uuid::Uuid::new_v4();
    let release = uuid::Uuid::new_v4();
    let job = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,'owner-fixture',$3,$4,$5,$6,'quarantined',now(),'fixture-version')").bind(upload).bind(publisher).bind(format!("key{}",upload.simple())).bind(size).bind(&digest).bind(format!("quarantine/{publisher}/{upload}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,'1.0.0','any','review_approved','owner-fixture')").bind(release).bind(publisher).bind(upload).bind(key_id).bind(&plugin_id).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,'antivirus_passed',1,'antivirus_passed')").bind(upload).bind(release).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id,release_id,actor_user_id,decision,reason_code) VALUES ($1,$2,'reviewer-fixture','approve','policy_reviewed')").bind(uuid::Uuid::new_v4()).bind(release).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_publication_jobs (id,release_id,requested_by,status) VALUES ($1,$2,$3,'queued')").bind(job).bind(release).bind(&requester).execute(&pool).await.unwrap();
    assert!(
        !recovery::retry(&pool, recovery::Kind::Publication, job, "test")
            .await
            .unwrap()
    );
    sqlx::query("UPDATE cloud_publication_jobs SET status='failed',attempts=3,result_class='temporary_failure' WHERE id=$1").bind(job).execute(&pool).await.unwrap();
    let (a, b) = tokio::join!(
        recovery::retry(&pool, recovery::Kind::Publication, job, "test"),
        recovery::retry(&pool, recovery::Kind::Publication, job, "test")
    );
    assert_ne!(a.unwrap(), b.unwrap());
    let audit:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='publication.retry_requested'").bind(job).fetch_one(&pool).await.unwrap();
    assert_eq!(audit, 1);
    assert!(publication_worker::once(&pool, &store, &scanner)
        .await
        .unwrap());
    let row:(String,Option<String>,Option<String>,i32)=sqlx::query_as("SELECT status,prepared_key,prepared_version_id,attempts FROM cloud_publication_jobs WHERE id=$1").bind(job).fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, "prepared");
    assert!(
        !recovery::retry(&pool, recovery::Kind::Publication, job, "test")
            .await
            .unwrap()
    );
    assert!(row
        .1
        .unwrap()
        .starts_with(&format!("prepared/{publisher}/")));
    assert_eq!(row.2.as_deref(), Some("staged-version"));
    assert_eq!(row.3, 1);
    let path = format!("/api/v1/plugins/releases/{release}/publish");
    let response = request(&app, "POST", &path, Some(&requester_cookie), Some(ORIGIN)).await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response["status"], "prepared");
    assert_eq!(response["processingAvailable"], false);
    let release_status: String =
        sqlx::query_scalar("SELECT status FROM cloud_plugin_releases WHERE id=$1")
            .bind(release)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(release_status, "review_approved");
    // A second independently prepared release must be included in the same inventory.
    let upload2 = uuid::Uuid::new_v4();
    let release2 = uuid::Uuid::new_v4();
    let job2 = uuid::Uuid::new_v4();
    let prepared2 = format!("prepared/{publisher}/{}", uuid::Uuid::new_v4());
    state
        .objects
        .lock()
        .await
        .insert(format!("/cloud-test/{prepared2}"), second_bytes.clone());
    sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,'owner-fixture',$3,$4,$5,$6,'quarantined',now(),'fixture-version')").bind(upload2).bind(publisher).bind(format!("key{}",upload2.simple())).bind(second_bytes.len() as i64).bind(&second_digest).bind(format!("quarantine/{publisher}/{upload2}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,'2.0.0','any','review_approved','owner-fixture')").bind(release2).bind(publisher).bind(upload2).bind(key_id).bind(&second_plugin).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_verification_jobs (upload_id,release_id,status,attempts,result_class) VALUES ($1,$2,'antivirus_passed',1,'antivirus_passed')").bind(upload2).bind(release2).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_moderation_events (id,release_id,actor_user_id,decision,reason_code) VALUES ($1,$2,'reviewer-fixture','approve','policy_reviewed')").bind(uuid::Uuid::new_v4()).bind(release2).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_publication_jobs (id,release_id,requested_by,status,attempts,result_class,prepared_key,prepared_version_id) VALUES ($1,$2,$3,'prepared',1,'prepared',$4,'staged-version')").bind(job2).bind(release2).bind(&requester).bind(&prepared2).execute(&pool).await.unwrap();
    // The initial candidate consumes every prepared job and records private, versioned files.
    let root_key = SigningKey::generate(KeyId::parse("fixture-root").unwrap(), None).unwrap();
    let index_key = SigningKey::generate(KeyId::parse("fixture-index").unwrap(), None).unwrap();
    let index_json = index_key.to_json();
    let root_pin = TrustedKey::new(root_key.public_key(), KeyRole::Root);
    let seed = dir.path().join("seed");
    IndexWriter::open(&seed, "fixture", Some(index_key))
        .init(
            &root_key,
            vec![
                TrustedKey::new(
                    SigningKey::from_json(&index_json).unwrap().public_key(),
                    KeyRole::Index,
                ),
                TrustedKey::new(public.clone(), KeyRole::Publisher).publisher(&namespace),
            ],
            None,
            None,
        )
        .unwrap();
    let inputs = snapshot_worker::Inputs {
        seed: seed.clone(),
        root: root_pin.clone(),
        index: SigningKey::from_json(&index_json).unwrap(),
    };
    let candidate = snapshot_worker::build(&pool, &store, &scanner, inputs)
        .await
        .unwrap()
        .unwrap();
    let counts:(i32,i32)=sqlx::query_as("SELECT release_count,file_count FROM cloud_snapshot_candidates WHERE id=$1 AND status='candidate'").bind(candidate).fetch_one(&pool).await.unwrap();
    assert_eq!(counts.0, 2);
    assert!(counts.1 >= 8);
    let rows:Vec<(String,String,String,i64)>=sqlx::query_as("SELECT path,object_key,sha256,size FROM cloud_snapshot_candidate_files WHERE candidate_id=$1 ORDER BY path").bind(candidate).fetch_all(&pool).await.unwrap();
    assert_eq!(rows.len(), counts.1 as usize);
    assert!(rows.iter().any(|(path, _, _, _)| path == "keys.json.sig"));
    assert!(rows
        .iter()
        .any(|(path, _, _, _)| path.starts_with("packages/")));
    {
        let objects = state.objects.lock().await;
        for (_, key, hash, size) in &rows {
            let data = objects.get(&format!("/cloud-test/{key}")).unwrap();
            assert_eq!(data.len() as i64, *size);
            assert_eq!(Sha256Digest::of_bytes(data).as_hex(), hash);
        }
    }
    let links:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_candidate_releases WHERE candidate_id=$1 AND publication_job_id=$2").bind(candidate).bind(job).fetch_one(&pool).await.unwrap();
    assert_eq!(links, 1);
    let total_links: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_snapshot_candidate_releases WHERE candidate_id=$1",
    )
    .bind(candidate)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total_links, 2);
    let index_public = SigningKey::from_json(&index_json).unwrap().public_key();
    Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &root_pin,
        &index_public,
    ))
    .await
    .unwrap();
    let seed_config = std::fs::read(seed.join("config.json")).unwrap();
    let seed_signature = std::fs::read(seed.join("config.json.sig")).unwrap();
    IndexWriter::open(
        &seed,
        "fixture",
        Some(SigningKey::from_json(&index_json).unwrap()),
    )
    .revoke_digest(&Sha256Digest::parse(&digest).unwrap())
    .unwrap();
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &root_pin,
        &index_public
    ))
    .await
    .is_err());
    std::fs::write(seed.join("config.json"), &seed_config).unwrap();
    std::fs::write(seed.join("config.json.sig"), &seed_signature).unwrap();
    std::fs::write(seed.join("config.json"), b"{}").unwrap();
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &root_pin,
        &index_public
    ))
    .await
    .is_err());
    std::fs::write(seed.join("config.json"), &seed_config).unwrap();
    infected.store(true, Ordering::SeqCst);
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &root_pin,
        &index_public
    ))
    .await
    .is_err());
    infected.store(false, Ordering::SeqCst);
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = crate::scanner::ClamAv::new(unused.local_addr().unwrap());
    drop(unused);
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &unavailable,
        &seed,
        candidate,
        &root_pin,
        &index_public
    ))
    .await
    .is_err());
    let wrong_root = TrustedKey::new(
        SigningKey::generate(KeyId::parse("wrong-root").unwrap(), None)
            .unwrap()
            .public_key(),
        KeyRole::Root,
    );
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &wrong_root,
        &index_public
    ))
    .await
    .is_err());
    state.tamper_read_candidate.store(true, Ordering::SeqCst);
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &root_pin,
        &index_public
    ))
    .await
    .is_err());
    state.tamper_read_candidate.store(false, Ordering::SeqCst);
    // Reconstruct the exact private candidate and verify it with the real TikTools client.
    let exported = dir.path().join("exported");
    Box::pin(snapshot_export::export(&pool, &store, candidate, &exported))
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&exported).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    let marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(exported.join(".cloud-candidate.json")).unwrap())
            .unwrap();
    assert_eq!(marker["candidateId"], candidate.to_string());
    assert_eq!(marker["status"], "private-candidate");
    assert!(
        Box::pin(snapshot_export::export(&pool, &store, candidate, &exported))
            .await
            .is_err()
    );
    async fn static_files(
        State(root): State<std::path::PathBuf>,
        uri: Uri,
    ) -> axum::response::Response {
        let relative = uri.path().trim_start_matches('/');
        if std::path::Path::new(relative)
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        match tokio::fs::read(root.join(relative)).await {
            Ok(bytes) => bytes.into_response(),
            Err(_) => StatusCode::NOT_FOUND.into_response(),
        }
    }
    let static_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let static_base = format!("http://{}", static_listener.local_addr().unwrap());
    let static_exported = exported.clone();
    let static_server = tokio::spawn(async move {
        axum::serve(
            static_listener,
            Router::new()
                .fallback(static_files)
                .with_state(static_exported),
        )
        .await
        .unwrap()
    });
    let mut source =
        tiktools_plugin_registry::RegistrySource::new("fixture", &static_base).unwrap();
    source.root_keys = vec![root_key.public_key()];
    let client = tiktools_plugin_registry::RegistryClient::new(
        dir.path().join("registry-cache"),
        dir.path().join("registries.json"),
        vec![source],
        Arc::new(std::sync::RwLock::new(
            tiktools_plugin_package::TrustStore::new(),
        )),
    )
    .unwrap();
    assert!(client.refresh("fixture").await.unwrap().verified);
    for (id, expected) in [(&plugin_id, &digest), (&second_plugin, &second_digest)] {
        let (_, document) = client.package(id, None).await.unwrap();
        assert_eq!(document.releases[0].artifacts[0].sha256.as_hex(), expected);
    }
    static_server.abort();
    // Signed content must describe exactly the authorized inventory.
    let inventory = snapshot_worker::current(&pool).await.unwrap();
    let approved = inventory
        .iter()
        .map(snapshot_worker::Item::approved)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let manifest = snapshot_export::current(&pool, candidate).await.unwrap();
    let files: std::collections::BTreeMap<_, _> = manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), file.digest.clone()))
        .collect();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_ok());
    let index_path = tiktools_plugin_registry::shard_path(&plugin_id);
    let mut missing = files.clone();
    missing.remove(&index_path);
    assert!(snapshot_verify::check_contents(&exported, &missing, &inventory, &approved).is_err());
    let mut extra = files.clone();
    extra.insert("packages/unexpected.plugin".into(), "a".repeat(64));
    assert!(snapshot_verify::check_contents(&exported, &extra, &inventory, &approved).is_err());
    let index_bytes = std::fs::read(exported.join(&index_path)).unwrap();
    let mut doc: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    doc["releases"][0]["artifacts"][0]["target"] = serde_json::json!("forged-target");
    std::fs::write(
        exported.join(&index_path),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_err());
    let mut doc: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    doc["releases"][0]["runtime"] = serde_json::json!("forged-runtime");
    std::fs::write(
        exported.join(&index_path),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_err());
    let mut doc: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    doc["name"] = serde_json::json!("forged-name");
    std::fs::write(
        exported.join(&index_path),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_err());
    let mut doc: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    doc["dist-tags"]["stable"] = serde_json::json!("99.0.0");
    std::fs::write(
        exported.join(&index_path),
        serde_json::to_vec(&doc).unwrap(),
    )
    .unwrap();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_err());
    std::fs::write(exported.join(&index_path), index_bytes).unwrap();
    let catalog_path = exported.join("catalog/page-1.json");
    let catalog_bytes = std::fs::read(&catalog_path).unwrap();
    let mut catalog: serde_json::Value = serde_json::from_slice(&catalog_bytes).unwrap();
    catalog["entries"][0]["name"] = serde_json::json!("forged-name");
    std::fs::write(&catalog_path, serde_json::to_vec(&catalog).unwrap()).unwrap();
    assert!(snapshot_verify::check_contents(&exported, &files, &inventory, &approved).is_err());
    std::fs::write(&catalog_path, catalog_bytes).unwrap();
    // Corrupt object bytes and changing DB metadata must leave exports without a completion marker.
    state.tamper_read_candidate.store(true, Ordering::SeqCst);
    let bad_export = dir.path().join("bad-export");
    assert!(Box::pin(snapshot_export::export(
        &pool,
        &store,
        candidate,
        &bad_export
    ))
    .await
    .is_err());
    assert!(!bad_export.join(".cloud-candidate.json").exists());
    state.tamper_read_candidate.store(false, Ordering::SeqCst);
    let old_hash:String=sqlx::query_scalar("SELECT sha256 FROM cloud_snapshot_candidate_files WHERE candidate_id=$1 AND path='root.json'").bind(candidate).fetch_one(&pool).await.unwrap();
    state.hold_export.store(true, Ordering::SeqCst);
    let changed_export = dir.path().join("changed-export");
    let exporting = Box::pin(snapshot_export::export(
        &pool,
        &store,
        candidate,
        &changed_export,
    ));
    let change = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
            .await
            .unwrap();
        sqlx::query("UPDATE cloud_snapshot_candidate_files SET sha256=$2 WHERE candidate_id=$1 AND path='root.json'").bind(candidate).bind("f".repeat(64)).execute(&pool).await.unwrap();
        state.hold_export.store(false, Ordering::SeqCst);
        state.proceed.notify_one();
    };
    let (result, ()) = tokio::join!(exporting, change);
    assert!(result.is_err());
    assert!(!changed_export.join(".cloud-candidate.json").exists());
    sqlx::query("UPDATE cloud_snapshot_candidate_files SET sha256=$2 WHERE candidate_id=$1 AND path='root.json'").bind(candidate).bind(old_hash).execute(&pool).await.unwrap();
    let baseline = state.objects.lock().await.len();
    let candidate_count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    // Revocation while a prepared version is fetched prevents candidate registration.
    state.hold.store(true, Ordering::SeqCst);
    let inputs = snapshot_worker::Inputs {
        seed: seed.clone(),
        root: root_pin,
        index: SigningKey::from_json(&index_json).unwrap(),
    };
    let building = snapshot_worker::build(&pool, &store, &scanner, inputs);
    let change = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
            .await
            .unwrap();
        sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
            .bind(key_id)
            .execute(&pool)
            .await
            .unwrap();
        state.hold.store(false, Ordering::SeqCst);
        state.proceed.notify_one();
    };
    let (result, ()) = tokio::join!(building, change);
    assert!(result.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, candidate_count);
    assert_eq!(state.objects.lock().await.len(), baseline);
    sqlx::query("UPDATE cloud_publisher_keys SET status='approved' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    // Even restored authorization changes the inventory revision and invalidates the old candidate.
    assert!(Box::pin(snapshot_verify::verify(
        &pool,
        &store,
        &scanner,
        &seed,
        candidate,
        &TrustedKey::new(root_key.public_key(), KeyRole::Root),
        &index_public
    ))
    .await
    .is_err());
    // A role change during candidate file staging leaves objects unreferenced and no candidate record.
    state.hold_candidate.store(true, Ordering::SeqCst);
    let inputs = snapshot_worker::Inputs {
        seed: seed.clone(),
        root: TrustedKey::new(root_key.public_key(), KeyRole::Root),
        index: SigningKey::from_json(&index_json).unwrap(),
    };
    let building = snapshot_worker::build(&pool, &store, &scanner, inputs);
    let change = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
            .await
            .unwrap();
        admin::change_role(&pool, false, &requester, "moderator", "test")
            .await
            .unwrap();
        state.hold_candidate.store(false, Ordering::SeqCst);
        state.proceed.notify_one();
    };
    let (result, ()) = tokio::join!(building, change);
    assert!(result.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, candidate_count);
    assert!(state.objects.lock().await.len() > baseline);
    admin::change_role(&pool, true, &requester, "moderator", "test")
        .await
        .unwrap();
    // A corrupted candidate-object read-back cannot create a candidate record.
    state.tamper_candidate.store(true, Ordering::SeqCst);
    let inputs = snapshot_worker::Inputs {
        seed: seed.clone(),
        root: TrustedKey::new(root_key.public_key(), KeyRole::Root),
        index: SigningKey::from_json(&index_json).unwrap(),
    };
    assert!(snapshot_worker::build(&pool, &store, &scanner, inputs)
        .await
        .is_err());
    state.tamper_candidate.store(false, Ordering::SeqCst);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_snapshot_candidates")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, candidate_count);
    // The initial-builder command refuses a seed that already contains registry content.
    std::fs::create_dir(seed.join("index")).unwrap();
    let inputs = snapshot_worker::Inputs {
        seed: seed.clone(),
        root: TrustedKey::new(root_key.public_key(), KeyRole::Root),
        index: SigningKey::from_json(&index_json).unwrap(),
    };
    assert!(snapshot_worker::build(&pool, &store, &scanner, inputs)
        .await
        .is_err());
    std::fs::remove_dir(seed.join("index")).unwrap();
    let baseline = state.objects.lock().await.len();
    // A key revoked during the write leaves an orphan, never a referenced prepared version.
    sqlx::query("UPDATE cloud_publication_jobs SET status='queued',attempts=0,result_class=NULL,prepared_key=NULL,prepared_version_id=NULL WHERE id=$1").bind(job).execute(&pool).await.unwrap();
    state.hold.store(true, Ordering::SeqCst);
    let worker_pool = pool.clone();
    let worker_store = store.clone();
    let worker_scanner = scanner.clone();
    let running = tokio::spawn(async move {
        publication_worker::once(&worker_pool, &worker_store, &worker_scanner)
            .await
            .map_err(|e| e.to_string())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
        .await
        .unwrap();
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    state.hold.store(false, Ordering::SeqCst);
    state.proceed.notify_one();
    assert!(running.await.unwrap().unwrap());
    let row: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status,prepared_key,prepared_version_id FROM cloud_publication_jobs WHERE id=$1",
    )
    .bind(job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("blocked".into(), None, None));
    assert_eq!(state.objects.lock().await.len(), baseline + 1);
    assert_eq!(
        request(&app, "POST", &path, Some(&requester_cookie), Some(ORIGIN))
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // Losing the requester's moderator role blocks preparation before any new upload.
    sqlx::query("UPDATE cloud_publisher_keys SET status='approved' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let rerequest = request(&app, "POST", &path, Some(&requester_cookie), Some(ORIGIN)).await;
    assert_eq!(rerequest.status(), StatusCode::ACCEPTED);
    let rerequest: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(rerequest.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rerequest["status"], "queued");

    admin::change_role(&pool, false, &requester, "moderator", "test")
        .await
        .unwrap();
    assert!(publication_worker::once(&pool, &store, &scanner)
        .await
        .unwrap());
    let status: String =
        sqlx::query_scalar("SELECT status FROM cloud_publication_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "blocked");
    assert_eq!(state.objects.lock().await.len(), baseline + 1);
    assert_eq!(
        request(&app, "POST", &path, Some(&requester_cookie), Some(ORIGIN))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let (a, b) = tokio::join!(
        request(&app, "POST", &path, Some(&replacement_cookie), Some(ORIGIN)),
        request(&app, "POST", &path, Some(&replacement_cookie), Some(ORIGIN))
    );
    assert_eq!(a.status(), StatusCode::ACCEPTED);
    assert_eq!(b.status(), StatusCode::ACCEPTED);
    let current: (String, String) =
        sqlx::query_as("SELECT status,requested_by FROM cloud_publication_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(current, ("queued".into(), replacement_id.clone()));
    let events:i64=sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE subject_id=$1 AND action='release.publication_rerequested'").bind(release).fetch_one(&pool).await.unwrap();
    assert_eq!(events, 2);
    admin::change_role(&pool, false, &replacement_id, "moderator", "test")
        .await
        .unwrap();
    assert!(publication_worker::once(&pool, &store, &scanner)
        .await
        .unwrap());
    let status: String =
        sqlx::query_scalar("SELECT status FROM cloud_publication_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "blocked");
    admin::change_role(&pool, true, &requester, "moderator", "test")
        .await
        .unwrap();
    assert_eq!(
        request(&app, "POST", &path, Some(&requester_cookie), Some(ORIGIN))
            .await
            .status(),
        StatusCode::ACCEPTED
    );
    // The role is also rechecked after storage I/O, not just before work begins.
    state.hold.store(true, Ordering::SeqCst);
    let worker_pool = pool.clone();
    let worker_store = store.clone();
    let worker_scanner = scanner.clone();
    let running = tokio::spawn(async move {
        publication_worker::once(&worker_pool, &worker_store, &worker_scanner)
            .await
            .map_err(|e| e.to_string())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
        .await
        .unwrap();
    admin::change_role(&pool, false, &requester, "moderator", "test")
        .await
        .unwrap();
    state.hold.store(false, Ordering::SeqCst);
    state.proceed.notify_one();
    assert!(running.await.unwrap().unwrap());
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT status,prepared_key FROM cloud_publication_jobs WHERE id=$1")
            .bind(job)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, ("blocked".into(), None));
    assert_eq!(state.objects.lock().await.len(), baseline + 2);
    admin::change_role(&pool, true, &requester, "moderator", "test")
        .await
        .unwrap();
    // A superseded lease cannot record a prepared result either.
    sqlx::query("UPDATE cloud_publication_jobs SET status='queued',attempts=0,result_class=NULL WHERE id=$1").bind(job).execute(&pool).await.unwrap();
    state.hold.store(true, Ordering::SeqCst);
    let worker_pool = pool.clone();
    let worker_store = store.clone();
    let worker_scanner = scanner.clone();
    let running = tokio::spawn(async move {
        publication_worker::once(&worker_pool, &worker_store, &worker_scanner)
            .await
            .map_err(|e| e.to_string())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), state.entered.notified())
        .await
        .unwrap();
    // A concurrent worker cannot claim a live lease for the same job.
    assert!(!Box::pin(publication_worker::once(&pool, &store, &scanner))
        .await
        .unwrap());
    let replacement = uuid::Uuid::new_v4();
    sqlx::query("UPDATE cloud_publication_jobs SET lease_id=$2,lease_expires_at=now()+interval '10 minutes' WHERE id=$1").bind(job).bind(replacement).execute(&pool).await.unwrap();
    state.hold.store(false, Ordering::SeqCst);
    state.proceed.notify_one();
    assert!(running.await.unwrap().unwrap());
    let row: (String, uuid::Uuid, Option<String>) = sqlx::query_as(
        "SELECT status,lease_id,prepared_key FROM cloud_publication_jobs WHERE id=$1",
    )
    .bind(job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("running".into(), replacement, None));
    assert_eq!(state.objects.lock().await.len(), baseline + 3);
    // A store returning changed bytes is retried and never becomes a prepared artifact.
    sqlx::query("UPDATE cloud_publication_jobs SET status='queued',lease_id=NULL,lease_expires_at=NULL,attempts=0,result_class=NULL WHERE id=$1").bind(job).execute(&pool).await.unwrap();
    state.tamper.store(true, Ordering::SeqCst);
    assert!(publication_worker::once(&pool, &store, &scanner)
        .await
        .unwrap());
    let row: (String, String, Option<String>) = sqlx::query_as(
        "SELECT status,result_class,prepared_key FROM cloud_publication_jobs WHERE id=$1",
    )
    .bind(job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("queued".into(), "temporary_failure".into(), None));
    sqlx::query("UPDATE cloud_publication_jobs SET attempts=2 WHERE id=$1")
        .bind(job)
        .execute(&pool)
        .await
        .unwrap();
    assert!(publication_worker::once(&pool, &store, &scanner)
        .await
        .unwrap());
    let row: (String, i32, Option<String>) = sqlx::query_as(
        "SELECT status,attempts,prepared_key FROM cloud_publication_jobs WHERE id=$1",
    )
    .bind(job)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("failed".into(), 3, None));
    server.abort();
    scan_server.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn public_revocation_serves_yank_advisory_and_key_state() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use tiktools_plugin_package::{KeyId, SigningKey};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let result = service
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let user = result.user.id;
    let cookie = format!("{}={}", result.cookie.name, result.cookie.value);
    let publisher = uuid::Uuid::new_v4();
    let namespace = format!("pub{}", publisher.simple());
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&user).execute(&pool).await.unwrap();
    let key = SigningKey::generate(
        KeyId::parse(&format!("key-{}", uuid::Uuid::new_v4().simple())).unwrap(),
        None,
    )
    .unwrap()
    .public_key();
    let key_id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'approved',$6)").bind(key_id).bind(publisher).bind(key.key_id.as_str()).bind(&key.public_key).bind(key.fingerprint().unwrap().to_string()).bind(&user).execute(&pool).await.unwrap();
    let upload = uuid::Uuid::new_v4();
    let release = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_upload_sessions (id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at,version_id) VALUES ($1,$2,$3,$4,5,$5,$6,'quarantined',now()+interval '5 minutes','version')").bind(upload).bind(publisher).bind(&user).bind(format!("key{}",upload.simple())).bind("a".repeat(64)).bind(format!("quarantine/{publisher}/{upload}")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases (id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) VALUES ($1,$2,$3,$4,$5,'1.0.0','any','antivirus_passed',$6)").bind(release).bind(publisher).bind(upload).bind(key_id).bind(format!("{namespace}.plugin")).bind(&user).execute(&pool).await.unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let path = format!("/api/v1/plugins/releases/{release}/revocation");
    async fn get(
        app: &Router,
        path: &str,
        cookie: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let response = request(app, "GET", path, cookie, None).await;
        let status = response.status();
        let data: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap(),
        )
        .unwrap_or(serde_json::Value::Null);
        (status, data)
    }
    // Unknown releases stay hidden from anonymous clients.
    let (status, _) = get(
        &app,
        &format!(
            "/api/v1/plugins/releases/{}/revocation",
            uuid::Uuid::new_v4()
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Anonymous clients see identity and clean trust state, nothing internal.
    let (status, data) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_no_store(&app, &path).await, StatusCode::OK);
    assert_eq!(data["id"], release.to_string());
    assert_eq!(data["pluginId"], format!("{namespace}.plugin"));
    assert_eq!(data["version"], "1.0.0");
    assert_eq!(data["target"], "any");
    assert_eq!(data["yanked"], false);
    assert!(data["advisory"].is_null());
    assert_eq!(data["keyRevoked"], false);
    for hidden in [
        "publisherId",
        "publisher_id",
        "uploadId",
        "upload_id",
        "publisherKeyId",
        "publisher_key_id",
        "requestedBy",
        "requested_by",
        "status",
    ] {
        assert!(data.get(hidden).is_none(), "{hidden} must stay hidden");
    }
    // Authenticated members get the same public view.
    let (status, _) = get(&app, &path, Some(&cookie)).await;
    assert_eq!(status, StatusCode::OK);
    // A yank and advisory become visible to anonymous clients.
    sqlx::query(
        "INSERT INTO cloud_release_yanks (release_id,yanked_by,reason) VALUES ($1,$2,'malware')",
    )
    .bind(release)
    .bind(&user)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cloud_release_advisories (release_id,severity,message,url,created_by) VALUES ($1,'critical','update now','https://example.test/fix',$2)").bind(release).bind(&user).execute(&pool).await.unwrap();
    let (status, data) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["yanked"], true);
    assert_eq!(data["yankReason"], "malware");
    assert_eq!(data["advisory"]["severity"], "critical");
    assert_eq!(data["advisory"]["message"], "update now");
    assert_eq!(data["advisory"]["url"], "https://example.test/fix");
    // Revoking the signing key is reflected without exposing the key.
    sqlx::query("UPDATE cloud_publisher_keys SET status='revoked' WHERE id=$1")
        .bind(key_id)
        .execute(&pool)
        .await
        .unwrap();
    let (status, data) = get(&app, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["keyRevoked"], true);
}

async fn response_no_store(app: &Router, path: &str) -> StatusCode {
    let response = request(app, "GET", path, None, None).await;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    response.status()
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn username_set_sign_in_and_availability() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    async fn sign_up(
        service: &better_auth::email_password::EmailPasswordService,
        password: &str,
    ) -> (String, String) {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
                    password: password.into(),
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
    async fn post(
        app: &Router,
        path: &str,
        cookie: Option<&str>,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        app.clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    fn session_cookie(response: &axum::response::Response) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .next()
            .expect("sign-in must set a session cookie")
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }
    let password = "test password with enough characters";
    let (_user, cookie) = sign_up(&service, password).await;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    // Random per run: the ignored suite shares one disposable database, so a
    // fixed username would collide with earlier runs.
    let mixed = format!("Tester.{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let normalized = mixed.to_ascii_lowercase();
    // Usernames are normalized to lowercase on set.
    let response = post(
        &app,
        "/api/auth/username/set",
        Some(&cookie),
        json!({"username": mixed.clone()}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["username"], normalized);
    // Setting without a session is refused.
    assert_eq!(
        post(
            &app,
            "/api/auth/username/set",
            None,
            json!({"username": "other.name"})
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Availability reflects taken names and rejects invalid ones.
    let response = post(
        &app,
        "/api/auth/is-username-available",
        None,
        json!({"username": normalized}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["available"], false);
    let response = post(
        &app,
        "/api/auth/is-username-available",
        None,
        json!({"username": "free.name"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["available"], true);
    assert_eq!(
        post(
            &app,
            "/api/auth/is-username-available",
            None,
            json!({"username": "x"})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    // A second user cannot claim the same username (any casing).
    let (_other, other_cookie) = sign_up(&service, password).await;
    assert_eq!(
        post(
            &app,
            "/api/auth/username/set",
            Some(&other_cookie),
            json!({"username": mixed.to_ascii_uppercase()})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    // Sign in with the username yields a working session.
    let response = post(
        &app,
        "/api/auth/sign-in/username",
        None,
        json!({"username": mixed, "password": password}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = session_cookie(&response);
    let me = request(&app, "GET", "/api/v1/me", Some(&session), None).await;
    assert_eq!(me.status(), StatusCode::OK);
    // Unknown usernames and wrong passwords are refused without detail.
    assert_eq!(
        post(
            &app,
            "/api/auth/sign-in/username",
            None,
            json!({"username": "nobody.here", "password": password})
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        post(
            &app,
            "/api/auth/sign-in/username",
            None,
            json!({"username": normalized, "password": "wrong password that is long enough"})
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn account_deletion_removes_identity_and_sync_state() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    async fn sign_up(
        service: &better_auth::email_password::EmailPasswordService,
    ) -> (String, String) {
        let result = service
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Test".into(),
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
    async fn delete(
        app: &Router,
        cookie: Option<&str>,
        origin: Option<&str>,
        body: serde_json::Value,
    ) -> axum::response::Response {
        let mut req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/me")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(cookie) = cookie {
            req = req.header(header::COOKIE, cookie);
        }
        if let Some(origin) = origin {
            req = req.header(header::ORIGIN, origin);
        }
        app.clone()
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
    }
    let (user, cookie) = sign_up(&service).await;
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = app(ctx, pool.clone(), auth);
    let good = || json!({"password": "test password with enough characters"});
    // No session is rejected before any password handling.
    assert_eq!(
        delete(&app, None, Some(ORIGIN), good()).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // An absent origin is accepted for non-browser clients, but the password
    // check still applies.
    assert_eq!(
        delete(
            &app,
            Some(&cookie),
            None,
            json!({"password": "wrong password that is long enough"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // An untrusted origin is refused before any password handling.
    assert_eq!(
        delete(&app, Some(&cookie), Some("https://evil.test"), good())
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    // Empty passwords are rejected without touching the database.
    assert_eq!(
        delete(&app, Some(&cookie), Some(ORIGIN), json!({"password": ""}))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    // A wrong password fails closed without deleting anything.
    assert_eq!(
        delete(
            &app,
            Some(&cookie),
            Some(ORIGIN),
            json!({"password": "wrong password that is long enough"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    // Failed attempts leave no audit or sync writes behind.
    let stale_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE actor_user_id=$1 AND action='account.deleted'",
    )
    .bind(&user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_audits, 0);
    // Publisher memberships block deletion until the user leaves.
    let publisher = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(format!("del{}", publisher.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')").bind(publisher).bind(&user).execute(&pool).await.unwrap();
    assert_eq!(
        delete(&app, Some(&cookie), Some(ORIGIN), good())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id=$2")
        .bind(publisher)
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    // Cloud roles block deletion until self-revoked.
    admin::change_role(&pool, true, &user, "moderator", "test")
        .await
        .unwrap();
    assert_eq!(
        delete(&app, Some(&cookie), Some(ORIGIN), good())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let left = request(
        &app,
        "DELETE",
        "/api/v1/me/roles/moderator",
        Some(&cookie),
        Some(ORIGIN),
    )
    .await;
    assert_eq!(left.status(), StatusCode::NO_CONTENT);
    // Accounts without a password credential cannot re-authenticate.
    let (social_user, social_cookie) = sign_up(&service).await;
    sqlx::query("DELETE FROM account WHERE id=$1")
        .bind(format!("{social_user}:credential"))
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        delete(&app, Some(&social_cookie), Some(ORIGIN), good())
            .await
            .status(),
        StatusCode::CONFLICT
    );
    // Sync state is removed with the account.
    sqlx::query("INSERT INTO cloud_sync_cursors (user_id,cursor) VALUES ($1,1)")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_sync_records (user_id,collection,key,revision,value,deleted) VALUES ($1,'plugin-selections','del.plugin',1,'{\"v\":1}',false)").bind(&user).execute(&pool).await.unwrap();
    let response = delete(&app, Some(&cookie), Some(ORIGIN), good()).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .next()
        .is_some());
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM \"user\" WHERE id=$1")
        .bind(&user)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
    let sync_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_sync_records WHERE user_id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sync_left, 0);
    let cursor_left: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_sync_cursors WHERE user_id=$1")
            .bind(&user)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cursor_left, 0);
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_audit_events WHERE actor_user_id=$1 AND action='account.deleted'",
    )
    .bind(&user)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 1);
    assert_eq!(
        request(&app, "GET", "/api/v1/me", Some(&cookie), None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

fn memory_context() -> AuthContext {
    use better_auth_core::adapter::memory::{MemoryDb, MemorySecondaryStorage};
    AuthContext::new(
        AuthOptions {
            password_hash: crate::test_support::password_hash(),
            secret: "test-only-secret-32-bytes-long!!".into(),
            base_url: Some(BaseUrl::Static(ORIGIN.into())),
            trusted_origins: vec![ORIGIN.into()],
            ..Default::default()
        },
        Arc::new(MemoryDb::default()),
        Some(Arc::new(MemorySecondaryStorage::default())),
        vec![],
    )
    .unwrap()
}

fn google_step_up() -> step_up::StepUpOAuth {
    let url = |path: &str| Url::parse(&format!("http://127.0.0.1:9{path}")).unwrap();
    let exchange = better_auth::http_oauth::HttpOAuthProvider::insecure_for_testing(
        "google",
        "google-client",
        "google-secret",
        url("/authorize"),
        url("/token"),
        url("/userinfo"),
        ["openid", "email"],
    );
    let verifier = better_auth::jwks::JwksIdTokenVerifier::insecure_for_testing(
        "https://google.test",
        "google-client",
        url("/jwks.json"),
        better_auth::jwks::JwksRefreshPolicy::default(),
    )
    .unwrap();
    step_up::StepUpOAuth::for_testing(
        "google",
        "google-client",
        url("/authorize"),
        format!("{ORIGIN}/api/v1/step-up/oauth/callback"),
        exchange,
        verifier,
    )
}

fn providers_app(oauth: Option<step_up::StepUpOAuth>) -> Router {
    let ctx = memory_context();
    let auth = super::configured_auth_router(ctx.clone()).unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1:1/unused")
        .unwrap();
    super::app_inner(
        ctx,
        pool,
        auth,
        None,
        super::RouterFlags {
            versioning: versioning::unconfigured(),
            peer: crate::remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: oauth,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: false,
        },
    )
}

async fn providers_body(app: &Router) -> (StatusCode, serde_json::Value) {
    let response = request(app, "GET", "/api/v1/auth/providers", None, None).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn auth_providers_hides_google_when_unconfigured() {
    let app = providers_app(None);
    let (status, body) = providers_body(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "google": false }));
}

#[tokio::test]
async fn auth_providers_advertises_google_when_configured() {
    let app = providers_app(Some(google_step_up()));
    let (status, body) = providers_body(&app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "google": true }));
}

async fn post_json(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, ORIGIN);
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

fn session_cookie(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            value.to_str().ok().and_then(|pair| {
                let cookie = pair.split(';').next().unwrap_or_default().trim();
                let (name, _) = cookie.split_once('=')?;
                name.ends_with("session_token").then(|| cookie.to_owned())
            })
        })
        .expect("sign-in must set a session cookie")
}

/// The linked-providers surface: password sign-in shows its credential link,
/// the only method cannot be unlinked, unknown providers 404, and anonymous
/// callers get 401 without enumerating anything.
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn linked_providers_list_and_unlink_guardrails() {
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    let (base, fixture_handle) = fixture().await;
    let app = router(ctx, pool.clone(), &base);
    let email = format!("link-{}@example.test", uuid::Uuid::new_v4());
    let signup = post_json(
        &app,
        "/api/auth/sign-up/email",
        None,
        json!({"email": email, "name": "Link Test", "password": "test password with enough characters"}),
    )
    .await;
    assert_eq!(signup.status(), StatusCode::OK);
    let cookie = session_cookie(&signup);

    let listed = request(&app, "GET", "/api/v1/me/providers", Some(&cookie), None).await;
    assert_eq!(listed.status(), StatusCode::OK);
    let body = axum::body::to_bytes(listed.into_body(), 4096)
        .await
        .unwrap();
    let providers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["providerId"], "credential");

    let unlink_last = post_json(
        &app,
        "/api/v1/me/providers/unlink",
        Some(&cookie),
        json!({"providerId": "credential"}),
    )
    .await;
    assert_eq!(unlink_last.status(), StatusCode::CONFLICT);

    let unlink_missing = post_json(
        &app,
        "/api/v1/me/providers/unlink",
        Some(&cookie),
        json!({"providerId": "google"}),
    )
    .await;
    assert_eq!(unlink_missing.status(), StatusCode::NOT_FOUND);

    assert_eq!(
        request(&app, "GET", "/api/v1/me/providers", None, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    fixture_handle.abort();
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn local_storage_upload_and_inspection_enforce_capabilities() {
    use better_auth::email_password::{EmailPasswordService, SignUpInput};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let database_url = crate::test_support::migrated_url();
    let (ctx, pool) = context(&database_url, false).await;
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let identity = service
        .sign_up(
            SignUpInput {
                email: format!("{}@example.test", uuid::Uuid::new_v4()),
                name: "Local storage test".into(),
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let cookie = format!("{}={}", identity.cookie.name, identity.cookie.value);
    let publisher = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(publisher)
        .bind(format!("pub{}", publisher.simple()))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')")
        .bind(publisher).bind(&identity.user.id).execute(&pool).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = cloud_storage::QuarantineStore::local(
        root.path(),
        ORIGIN,
        b"local-test-only-secret-32-bytes-long",
    )
    .unwrap();
    let app = app_with_storage(
        ctx.clone(),
        pool.clone(),
        AuthRouter::new(ctx).unwrap(),
        Some(store.clone()),
    );
    let data = b"test package contents";
    let digest = hex::encode(Sha256::digest(data));
    let create_request = Request::builder()
        .method("POST")
        .uri("/api/v1/plugins/uploads")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .header("idempotency-key", "local-test-unique-0001")
        .body(Body::from(
            json!({"publisherId":publisher,"size":data.len(),"sha256":digest}).to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(create_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap(),
    )
    .unwrap();
    let signed = Url::parse(value["url"].as_str().unwrap()).unwrap();
    let uri = format!("{}?{}", signed.path(), signed.query().unwrap());
    let upload_id = value["id"].as_str().unwrap();
    let headers = value["headers"].as_object().unwrap();
    let build_put = |uri: &str, bytes: Vec<u8>| {
        let mut builder = Request::builder().method("PUT").uri(uri);
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str().unwrap());
        }
        builder.body(Body::from(bytes)).unwrap()
    };
    let bad_uri = uri.replace("signature=", "signature=0");
    assert_eq!(
        app.clone()
            .oneshot(build_put(&bad_uri, data.to_vec()))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let mut altered = data.to_vec();
    altered[0] ^= 1;
    assert_eq!(
        app.clone()
            .oneshot(build_put(&uri, altered))
            .await
            .unwrap()
            .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        app.clone()
            .oneshot(build_put(&uri, data.to_vec()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(build_put(&uri, data.to_vec()))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let complete = format!("/api/v1/plugins/uploads/{upload_id}/complete");
    assert_eq!(
        request(&app, "POST", &complete, Some(&cookie), Some(ORIGIN))
            .await
            .status(),
        StatusCode::OK
    );
    let key = format!("quarantine/{publisher}/{upload_id}");
    let version = store.capture(&key, data.len() as i64).await.unwrap();
    let inspect = store
        .presign_inspection(
            &key,
            &version.version_id,
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap();
    let url = Url::parse(&inspect.url).unwrap();
    let uri = format!("{}?{}", url.path(), url.query().unwrap());
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment"
    );
    assert_eq!(
        &axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()[..],
        data
    );
}
