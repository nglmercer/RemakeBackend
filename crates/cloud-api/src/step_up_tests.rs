//! Security tests for session-bound step-up authentication.
//!
//! Run against a disposable database: `CLOUD_TEST_DATABASE_URL` must point at
//! an empty PostgreSQL database (the harness applies migrations). The OAuth
//! fixture below is a local test double, never a live Google verification:
//! it uses `provider_id "fixture"`, localhost HTTP endpoints, and throwaway
//! RSA keys, while the production flow only accepts Google's issuer,
//! audience, and JWKS.
use super::*;
use axum::response::IntoResponse as _;
use axum::{
    body::Body,
    http::{header, Request},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use better_auth::email_password::{EmailPasswordService, SignUpInput};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;
use url::Url;

const ORIGIN: &str = "https://cloud.example.test";
const FIXTURE_ISSUER: &str = "https://step-up-fixture.test";
const FIXTURE_CLIENT_ID: &str = "step-up-fixture-client";
const FIXTURE_CODE: &str = "step-up-fixture-code";

/// Throwaway RSA signing key for the fixture JWKS. Test-only; never used to
/// verify anything outside these tests.
const FIXTURE_KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDB17wACnOI3pHQ\nQmly5wkJUHI70GTw32CD+En6T/kOcwQMGrRZTB495/71J1Nrl1nRhMlAiU7ocHY2\nYGEOtDzNur6rCK9lIjeQdymsdokHwrSc++i79ChG8NJfyK5P2PwXtDRgJc5utdpv\n/nyHa1PX1Cqkbv81Uza+/uY+PovoZEMp2F8QQMJraZ/HlRn1bQrq0x5MZqhlR2F6\nGXQCReJWwFLfQyMAgV1htwh5KfN6tFODTd2TrJ0CWs+L3rgOO7OEHPEyhljNjVhC\no3PF+TnCL/NlM9qQdPE+sUp4AvdJtxFZdDS9x7OT1o2c1CESAD45zOPaAVVehud0\nE1U+HoYFAgMBAAECggEAJ9xp6dU8XGsub3XUst7tJgfvsbqhI0JAGetDJTDwXYcL\n0ERmjU1gk6jjLj0Tw7Z4LyRf8UA7JIPJ31Uy6D/qmAC8qDWtQb4HUJMck/09IQYq\nN3T67zmeVbY8gJtnMv7DGknBknr7yBrnzCt4Jq3MrD+SNEWp/+h4g86tgKPCh/tI\nYF6LmcKXrmYVFKk981nPtUkgkElR20K1/BdrRkTALuYTxMeO14Nr7SZKwmxkn8ua\nvhoYThAfT6OXPc4deHCEnQs+EbQx4Trd+ToMxP0qcJhcnqdkq6kO0vpr+qjk0OAd\nehra/4CGqO+vBA0jNmeuqjIKSvUw97AxvsXNh++j0QKBgQDtnzvEI8ujnS2o4Xqt\nPPiY4t16DZBBU97uEtbBqC9rhJzJSCJ6TLCqB3aLoQB4+AC4mu93HDt4ZEIhTVaX\nA0eMGQdWuQtKse1U0gaDD/8r/PmYDCOnOvlJCpmH48eezkkP4vN7BJokjKYHO/Qq\n7FXqPeA7YtcMEEQchBFd1e+0FQKBgQDQ1bLJtrXW+Ad60u4yJUV5Bj+Q7bHniftW\n90Ec87vbDa9xM95ztm1Ieg0gBc0N3uXDMY/rRGDSyelr8lLl3/2PgjlO8uCGD/KQ\nleMKBZf4kPRJKMQ7C46YlWcq5aF2TNz1IDL71L2ACB5aCb0fiHzTzH9yiDRhFMIG\n6/heK0ZWMQKBgEXTNsLKKfroIxSvPVdOxVZXw/ErryojNS0MSCMcAuM7Ur8q/Uam\n5nrwOnuJUhQ5/CxDCv8bQrZ775rNmRZDFnEqoadwNMs8QZtdJCC7QKZybf2qA4gO\nolY+USNHYc9emsWaUSXjElCPK/KQQY2jaROuHwgUYVDgLsOaY2gJh6iJAoGAcl4F\n+ugf76mH1yD7J+U3hc8BMuqpumbbicYBF8z3fUCiazl/wxkOAlotI/NpWAZRCDP1\nYF/jMq03M1HTSmb/4v7rSaxDf8fuDHa5jvx/PLaNwh8cUEXFAxUXGewGH9Z6T5gh\ns77PRPWtQZwBweoqiod86IllPiFzHP1P2KqUa5ECgYBD8Ux0WAWbJKBqo1tBurzw\nZNsIEbIBpxFAo1TsfPYBrCB6ckn8a5vYPVxbrp7YqPF+H9FlF40jsgdUE60RJocA\n6NYDrUnsroV0UwDtNBuCQoBe45ZNKz8hAGNCi4SqyjFOjfy8tDzwjCSOZdFrC73A\nbDFkmDbNkLKv/mcjkT42kw==\n-----END PRIVATE KEY-----\n";
/// Wrong key: signs tokens the fixture JWKS must not validate.
const FIXTURE_KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDMMC4wQAVPo4m/\nV9sewYxCcIRYD4hS6x6bmphFBA3Geqd7Tw9em5inDPQTzAbIUM229j+vdyKJT/9N\neB8GAOJfFEBaRYXABBiiCoP1u0o94stBQAqS9uhX+faZv1nTNq2n4x2v9lEgAJgf\nwuBu2ulO8Au8IOblL65iL70qFC/cB08T0LA7QuSRog9whu37fwB+qz5mD6zIF95D\nomNZnjtG2XzRZDI+p9aeEVdDiGsRQRca4EHqGvd+A08+mLitZCQxnaHhRxT71Fm6\nK/+euBg4i00x/4wSWM9i7XA9T2aAetrDtOGNZkOx+zdmm/45UwQcsNtV5DvnDAV5\nDaPR1pBXAgMBAAECggEAQKjzP3lOlUEbAlpee9dbxMBf0IkeqO9m0my60oQtnpBB\n0DUhj1qjlSbvdgNylGWuN0W0tip6Z9RK6yviWyLVjLlbhZqld8B0UoAU+LCWGpHi\nvqd6kb6Zph50foyPc+jJRjSQNqRAXWuCwPAT5VbycfpnJOygYaxfQx2OADDDVR/0\naQW0PkpnDom1bHBE0E4B6NIHn7yWhRk69/c16Px7RMRyEr0w2AibQVW/TLyFoFE7\nEY/9DWYmvhrIeVL4e8pajLCSksReitxlT4qgsqCOYyKYV92W6jWignffVvQGnLUO\nA0UyKr40MP26mob0sj4eBEFJ9hYD9r8e2jDlcwglIQKBgQDwZjQndaiObVRLupR1\npzmtX9vrrnNJa9nVIelBWihEgGP04Po4bQ0D16CikWt+fHrdInUOulwJHE8hDXvu\n6JaV2yAUsAnZExgc+J2xxLMfDdH9YdPnK54lNbjBvVm3EuBjqXjEsDjfAMAqBPa0\njgJRyrGHdlY0pkJVJffI04PzIQKBgQDZcGVypg26iHs7ltdlrWbIDf3Qv+KfOizm\nsgZtWG+5sBreZqHF/tt5n2roF0IatfuNn+NISZEz3PH3gh5sydgK/17//6iFugjk\nioqVArqV1bQIVK1A5tiB2fAheQ251H73m3gGovZtnU3U4Gby4DR599wblsbpbFSO\n2VVM17sMdwKBgHh5D4vy18zAl2z4DOxFKI9tKZ4bp6TUyq6XtvhMQT/LA8y1blAW\nvl39kn/F1pPluADYAseltvfN2w3aXxBkOQrSbGpRqi3B9uSV5xkuVQGsAF81xmbk\nIfXNzVAyHyKy8Aah6GbRVT7UdnjYUfY78Ieix4L2V888vqNDSsC21zphAoGAfgls\nhHxEUO9znyLcUA+nGCckDLBtSCaMiFyA5Tjx6gxuRqPu+bm0tlb1vPpeUuVRntIj\nCG+8Pve/Odyujhihph5IjtM+d+VR6kdz9NPUG6334SxUEN6+eOY/DugAUMsfnZ78\nf7xOY1NfHhnFEttrD5fgeg131y34BaVskFIsFhkCgYBV10yBnjlFf05rzksJHpcC\nOix3nPVNHcteLBv9ezMcdpeaZ3a56Bac7OIzunjx/lVjIIHE4kmhzzCcVvd8nQJK\nAKrFdyDvnWMXPnBWcNcTDcFrwu90/LF0OddRs5lAytP0cUkTmTVFwG46kqTpaWtD\nRZaspd8ex8gXrRsD+zJcZQ==\n-----END PRIVATE KEY-----\n";
/// `n` of the fixture JWKS (key A, 2048-bit RSA, base64url, no padding).
const FIXTURE_JWK_N: &str = "wde8AApziN6R0EJpcucJCVByO9Bk8N9gg_hJ-k_5DnMEDBq0WUwePef-9SdTa5dZ0YTJQIlO6HB2NmBhDrQ8zbq-qwivZSI3kHcprHaJB8K0nPvou_QoRvDSX8iuT9j8F7Q0YCXObrXab_58h2tT19QqpG7_NVM2vv7mPj6L6GRDKdhfEEDCa2mfx5UZ9W0K6tMeTGaoZUdhehl0AkXiVsBS30MjAIFdYbcIeSnzerRTg03dk6ydAlrPi964DjuzhBzxMoZYzY1YQqNzxfk5wi_zZTPakHTxPrFKeAL3SbcRWXQ0vcezk9aNnNQhEgA-Oczj2gFVXobndBNVPh6GBQ";
const FIXTURE_KID: &str = "step-up-fixture-1";

#[derive(Clone)]
struct IdTokenControl {
    nonce: String,
    sub: String,
    iss: String,
    aud: String,
    exp_offset_secs: i64,
    auth_time: Option<u64>,
    kid: String,
    bad_key: bool,
    nonce_override: Option<String>,
    omit_id_token: bool,
    reject_exchange: bool,
}

/// One invalid-claims row: label, fixture mutation, expected `stepUpError`.
type ClaimCase = (&'static str, Box<dyn Fn(&mut IdTokenControl)>, &'static str);

impl IdTokenControl {
    fn fresh(nonce: &str, sub: &str) -> Self {
        Self {
            nonce: nonce.into(),
            sub: sub.into(),
            iss: FIXTURE_ISSUER.into(),
            aud: FIXTURE_CLIENT_ID.into(),
            exp_offset_secs: 3600,
            auth_time: Some(now_seconds()),
            kid: FIXTURE_KID.into(),
            bad_key: false,
            nonce_override: None,
            omit_id_token: false,
            reject_exchange: false,
        }
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mint_id_token(control: &IdTokenControl) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(control.kid.clone());
    let now = now_seconds();
    let mut claims = json!({
        "iss": control.iss,
        "sub": control.sub,
        "aud": control.aud,
        "exp": (now as i64 + control.exp_offset_secs) as u64,
        "iat": now,
        "nonce": control.nonce_override.clone().unwrap_or_else(|| control.nonce.clone()),
    });
    if let Some(auth_time) = control.auth_time {
        claims["auth_time"] = json!(auth_time);
    }
    let pem = if control.bad_key {
        FIXTURE_KEY_B_PEM
    } else {
        FIXTURE_KEY_A_PEM
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[derive(Clone)]
struct FixtureState {
    control: Arc<Mutex<IdTokenControl>>,
    allowed_redirects: Vec<String>,
    sub_tag: String,
}

/// Local OIDC test double: token endpoint (PKCE-checked, exact redirect
/// match, fixture-minted ID tokens), JWKS, and userinfo for fixture sign-in.
/// It models Google's exact-redirect enforcement and signed ID tokens; it is
/// never presented as a live Google verification.
async fn fixture_oidc(
    control: Arc<Mutex<IdTokenControl>>,
    sub_tag: &str,
    step_up_redirect: &str,
    auth_callback_redirect: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = FixtureState {
        control,
        allowed_redirects: vec![
            step_up_redirect.to_owned(),
            auth_callback_redirect.to_owned(),
        ],
        sub_tag: sub_tag.to_owned(),
    };
    async fn token(
        axum::extract::State(st): axum::extract::State<FixtureState>,
        axum::Form(form): axum::Form<HashMap<String, String>>,
    ) -> axum::response::Response {
        let ok_code = form.get("code").map(String::as_str) == Some(FIXTURE_CODE);
        let ok_verifier = form.get("code_verifier").is_some_and(|v| v.len() >= 43);
        let ok_redirect = form
            .get("redirect_uri")
            .is_some_and(|uri| st.allowed_redirects.iter().any(|allowed| allowed == uri));
        let control = st.control.lock().unwrap().clone();
        if !ok_code || !ok_verifier || !ok_redirect || control.reject_exchange {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_grant"})),
            )
                .into_response();
        }
        let mut body = json!({
            "access_token": "step-up-fixture-access",
            "token_type": "Bearer",
            "expires_in": 3600,
        });
        if !control.omit_id_token {
            body["id_token"] = json!(mint_id_token(&control));
        }
        (StatusCode::OK, Json(body)).into_response()
    }
    async fn jwks() -> Json<serde_json::Value> {
        Json(json!({"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256",
            "kid": FIXTURE_KID, "n": FIXTURE_JWK_N, "e": "AQAB",
        }]}))
    }
    async fn userinfo(
        axum::extract::State(st): axum::extract::State<FixtureState>,
    ) -> Json<serde_json::Value> {
        let sub = format!("cloud-test-{}", st.sub_tag);
        Json(json!({
            "sub": sub,
            "email": format!("{sub}@example.test"),
            "email_verified": false,
            "name": "Fixture",
        }))
    }
    let router = Router::new()
        .route("/token", post(token))
        .route("/jwks.json", get(jwks))
        .route("/userinfo", get(userinfo))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

/// Serializes migration setup across this module's tests: the upstream
/// migration plans create custom types without `IF NOT EXISTS`, so two
/// concurrent first-time setups on one database collide. Retries below cover
/// races with other test modules sharing the same database.
static SETUP_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn step_up_context(database_url: &str) -> (AuthContext, PgPool) {
    use sqlx::postgres::PgPoolOptions;
    let _setup = SETUP_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let adapter = Arc::new(SqlxDbAdapter::postgres(database_url).await.unwrap());
    let secondary = Arc::new(SqlxSecondaryStorage::postgres(database_url).await.unwrap());
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
        vec![Arc::new(better_auth::UsernamePlugin)],
    )
    .unwrap();
    // A concurrent setup from another test module may be halfway through the
    // same migrations; retry until they converge instead of failing on a
    // unique violation for an object the other setup is creating.
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
            "migrations did not converge: {}",
            secondary_result.unwrap_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let pool = PgPoolOptions::new()
        .max_connections(4)
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

/// Test app with step-up OAuth backed by the fixture. Pass `None` to model a
/// deployment without Google, where only password step-up exists.
fn step_up_app(
    ctx: AuthContext,
    pool: PgPool,
    social_base: Option<&str>,
    oauth: Option<step_up::StepUpOAuth>,
) -> Router {
    let mut auth = AuthRouter::new(ctx.clone()).unwrap();
    if let Some(base) = social_base {
        let url = |path: &str| Url::parse(&format!("{base}{path}")).unwrap();
        auth = auth
            .with_social_providers(vec![HttpOAuthProvider::insecure_for_testing(
                "fixture",
                "fixture-client",
                "fixture-secret",
                url("/authorize"),
                url("/token"),
                url("/userinfo"),
                ["openid", "email"],
            )])
            .unwrap();
    }
    super::app_inner(
        ctx,
        pool,
        auth,
        None,
        super::RouterFlags {
            engine: None,
            peer: crate::remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: oauth,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: false,
        },
    )
}

fn step_up_oauth_for_testing(base: &str) -> step_up::StepUpOAuth {
    let url = |path: &str| Url::parse(&format!("{base}{path}")).unwrap();
    let exchange = HttpOAuthProvider::insecure_for_testing(
        "step-up-fixture",
        FIXTURE_CLIENT_ID,
        "step-up-fixture-secret",
        url("/authorize"),
        url("/token"),
        url("/userinfo"),
        ["openid", "email"],
    );
    let verifier = better_auth::jwks::JwksIdTokenVerifier::insecure_for_testing(
        FIXTURE_ISSUER,
        FIXTURE_CLIENT_ID,
        url("/jwks.json"),
        better_auth::jwks::JwksRefreshPolicy::default(),
    )
    .unwrap();
    step_up::StepUpOAuth::for_testing(
        "fixture",
        FIXTURE_CLIENT_ID,
        url("/authorize"),
        format!("{ORIGIN}/api/v1/step-up/oauth/callback"),
        exchange,
        verifier,
    )
}

async fn post_json(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    origin: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    app.clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn response_cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next())
        .collect::<Vec<_>>()
        .join("; ")
}

async fn signup_password_user(ctx: &AuthContext, email: &str, password: &str) -> (String, String) {
    let service = EmailPasswordService::new(ctx.clone()).unwrap();
    let result = service
        .sign_up(
            SignUpInput {
                email: email.into(),
                name: "Step Up".into(),
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

async fn create_publisher(pool: &PgPool, namespace: &str, owner: &str, role: &str) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publishers (id,namespace,status) VALUES ($1,$2,'approved')")
        .bind(id)
        .bind(namespace)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,$3)",
    )
    .bind(id)
    .bind(owner)
    .bind(role)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Google-only account: created through the fixture OAuth sign-in flow, so no
/// password credential exists for it.
async fn signup_oauth_user(app: &Router, pool: &PgPool, sub_tag: &str) -> (String, String) {
    let begin = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/sign-in/social/fixture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(begin.status(), StatusCode::FOUND);
    let location = Url::parse(begin.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let state = location
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned())
        .unwrap();
    let callback = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/auth/callback/fixture?code={FIXTURE_CODE}&state={state}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::FOUND);
    let cookies = response_cookies(&callback);
    assert!(cookies.contains('='), "sign-in must set a session cookie");
    let sub = format!("cloud-test-{sub_tag}");
    let user_id: String = sqlx::query_scalar(
        "SELECT user_id FROM account WHERE provider_id='fixture' AND account_id=$1",
    )
    .bind(&sub)
    .fetch_one(pool)
    .await
    .unwrap();
    (user_id, cookies)
}

async fn password_grant(
    app: &Router,
    cookie: &str,
    action: &str,
    publisher: &uuid::Uuid,
    key_id: Option<&str>,
    password: &str,
) -> axum::response::Response {
    post_json(
        app,
        "/api/v1/step-up/password",
        Some(cookie),
        ORIGIN,
        json!({"action":action,"publisherId":publisher,"keyId":key_id,"password":password}),
    )
    .await
}

async fn grant_id(
    app: &Router,
    cookie: &str,
    action: &str,
    publisher: &uuid::Uuid,
    key_id: Option<&str>,
    password: &str,
) -> uuid::Uuid {
    let response = password_grant(app, cookie, action, publisher, key_id, password).await;
    assert_eq!(response.status(), StatusCode::OK);
    let data = body_json(response).await;
    assert_eq!(data["expiresIn"], 300);
    uuid::Uuid::parse_str(data["grantId"].as_str().unwrap()).unwrap()
}

fn unique_ns(prefix: &str) -> String {
    format!("{}{}", prefix, uuid::Uuid::new_v4().simple())
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn temporary_log_codes_are_bound_limited_single_use_and_audited() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let email = format!("{}@example.test", uuid::Uuid::new_v4());
    let (user, cookie) =
        signup_password_user(&ctx, &email, "test password with enough characters").await;
    let (other, other_cookie) = signup_password_user(
        &ctx,
        &format!("{}@example.test", uuid::Uuid::new_v4()),
        "test password with enough characters",
    )
    .await;
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'admin'),($2,'admin')")
        .bind(&user)
        .bind(&other)
        .execute(&pool)
        .await
        .unwrap();
    let publisher = create_publisher(&pool, &unique_ns("tmp"), &user, "owner").await;
    sqlx::query("UPDATE cloud_publishers SET status='pending' WHERE id=$1")
        .bind(publisher)
        .execute(&pool)
        .await
        .unwrap();
    let auth = AuthRouter::new(ctx.clone()).unwrap();
    let app = super::app_inner(
        ctx.clone(),
        pool.clone(),
        auth,
        None,
        super::RouterFlags {
            engine: None,
            peer: crate::remote::peers::PeerConfig::default(),
            trusted_proxy_cidrs: Vec::new(),
            step_up_oauth: None,
            social_limit_enabled: false,
            hsts: false,
            temporary_log_approvals: true,
        },
    );
    let path = "/api/v1/admin/temporary-log-approvals";
    let response = post_json(
        &app,
        path,
        Some(&cookie),
        ORIGIN,
        json!({"publisherId":publisher,"keyId":null}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data = body_json(response).await;
    assert!(data.get("code").is_none());
    let id = uuid::Uuid::parse_str(data["challengeId"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE cloud_temporary_log_approvals SET code_digest=$1 WHERE id=$2")
        .bind(crate::temporary_log_approval::digest(
            &ctx.options.secret,
            id,
            "12345678",
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let confirm = format!("{path}/{id}/confirm");
    let second = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_in(
            better_auth::email_password::SignInInput {
                email,
                password: "test password with enough characters".into(),
            },
            true,
        )
        .await
        .unwrap();
    let second_cookie = format!("{}={}", second.cookie.name, second.cookie.value);
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&second_cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&other_cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"87654321"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id=$1 AND actor_user_id=$2 AND action='publisher.temporary_operator_approved'").bind(publisher).bind(&user).fetch_one(&pool).await.unwrap();
    assert_eq!(audit, 1);
    let key = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_publisher_keys(id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES($1,$2,$3,'test',$4,'pending',$5)")
        .bind(key).bind(publisher).bind(format!("key-{}", key.simple())).bind(format!("{}{}",key.simple(),key.simple())).bind(&user).execute(&pool).await.unwrap();
    let response = post_json(
        &app,
        path,
        Some(&cookie),
        ORIGIN,
        json!({"publisherId":publisher,"keyId":key}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data = body_json(response).await;
    assert_eq!(
        data["fingerprint"],
        format!("{}{}", key.simple(), key.simple())
    );
    let id = uuid::Uuid::parse_str(data["challengeId"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE cloud_temporary_log_approvals SET code_digest=$1 WHERE id=$2")
        .bind(crate::temporary_log_approval::digest(
            &ctx.options.secret,
            id,
            "12345678",
        ))
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let confirm = format!("{path}/{id}/confirm");
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let status: String = sqlx::query_scalar("SELECT status FROM cloud_publisher_keys WHERE id=$1")
        .bind(key)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "approved");
    let key_audit: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE publisher_id=$1 AND subject_id=$2 AND actor_user_id=$3 AND action='publisher_key.temporary_operator_approved'")
        .bind(publisher).bind(key).bind(&user).fetch_one(&pool).await.unwrap();
    assert_eq!(key_audit, 1);
    let pending = create_publisher(&pool, &unique_ns("tmp"), &user, "owner").await;
    sqlx::query("UPDATE cloud_publishers SET status='pending' WHERE id=$1")
        .bind(pending)
        .execute(&pool)
        .await
        .unwrap();
    let response = post_json(
        &app,
        path,
        Some(&cookie),
        ORIGIN,
        json!({"publisherId":pending,"keyId":null}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let data = body_json(response).await;
    let id = uuid::Uuid::parse_str(data["challengeId"].as_str().unwrap()).unwrap();
    sqlx::query("UPDATE cloud_temporary_log_approvals SET code_digest=$1,expires_at=now()-interval '1 second' WHERE id=$2")
        .bind(crate::temporary_log_approval::digest(&ctx.options.secret, id, "12345678")).bind(id).execute(&pool).await.unwrap();
    let confirm = format!("{path}/{id}/confirm");
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query(
        "UPDATE cloud_temporary_log_approvals SET expires_at=now()+interval '1 minute' WHERE id=$1",
    )
    .bind(id)
    .execute(&pool)
    .await
    .unwrap();
    for _ in 0..5 {
        assert_eq!(
            post_json(
                &app,
                &confirm,
                Some(&cookie),
                ORIGIN,
                json!({"code":"87654321"})
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM cloud_temporary_log_approvals WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(attempts, 5);
    assert_eq!(
        post_json(
            &app,
            &confirm,
            Some(&cookie),
            ORIGIN,
            json!({"code":"12345678"})
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let disabled = step_up_app(ctx.clone(), pool.clone(), None, None);
    assert_eq!(
        post_json(
            &disabled,
            path,
            Some(&cookie),
            ORIGIN,
            json!({"publisherId":publisher,"keyId":null})
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn password_step_up_mints_grant_and_enables_enrollment() {
    use tiktools_plugin_package::{KeyId, SigningKey};
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let password = "test password with enough characters";
    let (user_id, cookie) = signup_password_user(&ctx, &email, password).await;
    let publisher = create_publisher(&pool, &unique_ns("enroll"), &user_id, "owner").await;
    let grant = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    let granted: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE action='step_up.granted' AND actor_user_id=$1 AND publisher_id=$2")
        .bind(&user_id).bind(publisher).fetch_one(&pool).await.unwrap();
    assert_eq!(granted, 1);
    // The grant spans challenge issuance and registration: the challenge call
    // validates it without spending it.
    let challenge = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys/challenges"),
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let data = body_json(challenge).await;
    let challenge_id = uuid::Uuid::parse_str(data["challengeId"].as_str().unwrap()).unwrap();
    let nonce = data["nonce"].as_str().unwrap();
    let key_id = format!("key-{}", uuid::Uuid::new_v4().simple());
    let signing = SigningKey::generate(KeyId::parse(&key_id).unwrap(), None).unwrap();
    let public = signing.public_key();
    let message = publisher_keys::proof_message(
        publisher,
        challenge_id,
        nonce,
        public.key_id.as_str(),
        &public.public_key,
    );
    let signature =
        base64::engine::general_purpose::STANDARD.encode(signing.sign(message.as_bytes()));
    let registered = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys"),
        Some(&cookie),
        ORIGIN,
        json!({"challengeId":challenge_id,"keyId":public.key_id,"publicKey":public.public_key,"signature":signature,"stepUpGrant":grant}),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let data = body_json(registered).await;
    assert_eq!(data["status"], "pending");
    // Key-signature verification is intact: a tampered proof with a fresh
    // grant still fails as a bad request, not as an authorization error.
    let grant2 = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    let challenge2 = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys/challenges"),
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant2}),
    )
    .await;
    assert_eq!(challenge2.status(), StatusCode::OK);
    let data2 = body_json(challenge2).await;
    let bad = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys"),
        Some(&cookie),
        ORIGIN,
        json!({"challengeId":data2["challengeId"],"keyId":public.key_id,"publicKey":public.public_key,"signature":base64::engine::general_purpose::STANDARD.encode([0u8;64]),"stepUpGrant":grant2}),
    )
    .await;
    assert_eq!(bad.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn password_step_up_rejects_wrong_password() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_id, cookie) =
        signup_password_user(&ctx, &email, "test password with enough characters").await;
    let publisher = create_publisher(&pool, &unique_ns("wrongpw"), &user_id, "owner").await;
    let response = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        "wrong password with enough characters",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body_json(response).await["error"], "invalid_credentials");
    let grants: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_step_up_grants WHERE user_id=$1")
            .bind(&user_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(grants, 0, "failed verification must not mint a grant");
    let failed: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_audit_events WHERE action='step_up.failed' AND actor_user_id=$1")
        .bind(&user_id).fetch_one(&pool).await.unwrap();
    assert_eq!(failed, 1);
    // Empty and oversized passwords are refused before any verification work.
    for bad in ["", &"x".repeat(1025)] {
        let response =
            password_grant(&app, &cookie, "publisher.key.enroll", &publisher, None, bad).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn password_step_up_is_unavailable_without_a_password() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let control = Arc::new(Mutex::new(IdTokenControl {
        nonce: "signup".into(),
        sub: format!("cloud-test-{tag}"),
        ..IdTokenControl::fresh("signup", &format!("cloud-test-{tag}"))
    }));
    let redirect = format!("{ORIGIN}/api/v1/step-up/oauth/callback");
    let (base, fixture) = fixture_oidc(
        control,
        &tag,
        &redirect,
        "https://cloud.example.test/api/auth/callback/fixture",
    )
    .await;
    let oauth = step_up_oauth_for_testing(&base);
    let app = step_up_app(ctx.clone(), pool.clone(), Some(&base), Some(oauth));
    let (user_id, cookie) = signup_oauth_user(&app, &pool, &tag).await;
    fixture.abort();
    let publisher = create_publisher(&pool, &unique_ns("nopw"), &user_id, "owner").await;
    // A Google-only account has no password to re-check; the client learns it
    // must offer the OAuth path without learning anything else.
    let response = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        "any password works here 123",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error"], "password_unavailable");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_grants_reject_forged_expired_and_reused() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let password = "test password with enough characters";
    let (user_id, cookie) = signup_password_user(&ctx, &email, password).await;
    let publisher = create_publisher(&pool, &unique_ns("reuse"), &user_id, "owner").await;
    let challenge_path = format!("/api/v1/publishers/{publisher}/keys/challenges");
    // A forged grant identifier is a plain requirement, not an expiry.
    let forged = post_json(
        &app,
        &challenge_path,
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": uuid::Uuid::new_v4()}),
    )
    .await;
    assert_eq!(forged.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(forged).await["error"], "step_up_required");
    // An expired grant must be re-verified for.
    let grant = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    sqlx::query("UPDATE cloud_step_up_grants SET expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(grant)
        .execute(&pool)
        .await
        .unwrap();
    let expired = post_json(
        &app,
        &challenge_path,
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(expired.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(expired).await["error"], "step_up_expired");
    // A grant spent by one registration cannot register a second key.
    let grant = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    let first = post_json(
        &app,
        &challenge_path,
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_data = body_json(first).await;
    use tiktools_plugin_package::{KeyId, SigningKey};
    let key_id = format!("key-{}", uuid::Uuid::new_v4().simple());
    let signing = SigningKey::generate(KeyId::parse(&key_id).unwrap(), None).unwrap();
    let public = signing.public_key();
    let challenge_id = uuid::Uuid::parse_str(first_data["challengeId"].as_str().unwrap()).unwrap();
    let message = publisher_keys::proof_message(
        publisher,
        challenge_id,
        first_data["nonce"].as_str().unwrap(),
        public.key_id.as_str(),
        &public.public_key,
    );
    let registered = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys"),
        Some(&cookie),
        ORIGIN,
        json!({"challengeId":challenge_id,"keyId":public.key_id,"publicKey":public.public_key,"signature":base64::engine::general_purpose::STANDARD.encode(signing.sign(message.as_bytes())),"stepUpGrant":grant}),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let second = post_json(
        &app,
        &challenge_path,
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(second.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(second).await["error"], "step_up_expired");
    let _ = user_id;
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_grants_reject_cross_user_session_publisher_and_action() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let password = "test password with enough characters";
    let email_a = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let email_b = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_a, cookie_a) = signup_password_user(&ctx, &email_a, password).await;
    let (user_b, cookie_b) = signup_password_user(&ctx, &email_b, password).await;
    let pub_a = create_publisher(&pool, &unique_ns("xa"), &user_a, "owner").await;
    let pub_b = create_publisher(&pool, &unique_ns("xb"), &user_a, "owner").await;
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'admin')")
        .bind(pub_a).bind(&user_b).execute(&pool).await.unwrap();
    let grant_a = grant_id(
        &app,
        &cookie_a,
        "publisher.key.enroll",
        &pub_a,
        None,
        password,
    )
    .await;
    // Cross-user: B's session cannot spend A's grant.
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{pub_a}/keys/challenges"),
        Some(&cookie_b),
        ORIGIN,
        json!({"stepUpGrant": grant_a}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Cross-session: a second session of the same user cannot spend a grant
    // bound to the first session.
    let second = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_in(
            better_auth::email_password::SignInInput {
                email: email_a.clone(),
                password: password.into(),
            },
            true,
        )
        .await
        .unwrap();
    let cookie_a2 = format!("{}={}", second.cookie.name, second.cookie.value);
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{pub_a}/keys/challenges"),
        Some(&cookie_a2),
        ORIGIN,
        json!({"stepUpGrant": grant_a}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // The original session still can: the grant was not burned by misuse.
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{pub_a}/keys/challenges"),
        Some(&cookie_a),
        ORIGIN,
        json!({"stepUpGrant": grant_a}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    // Cross-publisher: a grant for A authorizes nothing on B.
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{pub_b}/keys/challenges"),
        Some(&cookie_a),
        ORIGIN,
        json!({"stepUpGrant": grant_a}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error"], "step_up_required");
    // Cross-action: an enrollment grant cannot approve a key, even when the
    // caller is an independent admin and the key is otherwise approvable.
    let email_c = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_c, cookie_c) = signup_password_user(&ctx, &email_c, password).await;
    admin::change_role(&pool, true, &user_c, "admin", "test")
        .await
        .unwrap();
    let key_row = uuid::Uuid::new_v4();
    let cross_key_id = format!("crossaction-{}", uuid::Uuid::new_v4().simple());
    let cross_fp = format!("{:064x}", uuid::Uuid::new_v4().as_u128());
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'pending',$6)")
        .bind(key_row).bind(pub_a).bind(&cross_key_id).bind("cGtleQ").bind(&cross_fp).bind(&user_a).execute(&pool).await.unwrap();
    let enroll_grant_c = grant_id(
        &app,
        &cookie_c,
        "publisher.key.enroll",
        &pub_a,
        None,
        password,
    )
    .await;
    let response = post_json(
        &app,
        &format!("/api/v1/admin/publishers/{pub_a}/keys/{key_row}/approve"),
        Some(&cookie_c),
        ORIGIN,
        json!({"stepUpGrant": enroll_grant_c}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_json(response).await["error"], "step_up_required");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_rate_limits_password_attempts() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_id, cookie) =
        signup_password_user(&ctx, &email, "test password with enough characters").await;
    let publisher = create_publisher(&pool, &unique_ns("limits"), &user_id, "owner").await;
    for _ in 0..10 {
        let response = password_grant(
            &app,
            &cookie,
            "publisher.key.enroll",
            &publisher,
            None,
            "wrong password with enough characters",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let limited = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        "wrong password with enough characters",
    )
    .await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body_json(limited).await["error"], "rate_limited");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_rejects_forged_origin() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let password = "test password with enough characters";
    let (user_id, cookie) = signup_password_user(&ctx, &email, password).await;
    let publisher = create_publisher(&pool, &unique_ns("origin"), &user_id, "owner").await;
    // The step-up POSTs run through the same trusted-origin CSRF policy as
    // every other browser credentialed endpoint.
    let response = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let evil = post_json(
        &app,
        "/api/v1/step-up/password",
        Some(&cookie),
        "https://evil.test",
        json!({"action":"publisher.key.enroll","publisherId":publisher,"password":password}),
    )
    .await;
    assert_eq!(evil.status(), StatusCode::FORBIDDEN);
}

struct OauthCase {
    ctx: AuthContext,
    app: Router,
    pool: PgPool,
    cookie: String,
    user_id: String,
    publisher: uuid::Uuid,
    tag: String,
    control: Arc<Mutex<IdTokenControl>>,
    fixture: tokio::task::JoinHandle<()>,
    _base: String,
}

/// Fresh OAuth fixture, Google-only user, and approved publisher per case so
/// cases cannot leak grants, states, or rate-limit budget into each other.
async fn oauth_case() -> OauthCase {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let sub = format!("cloud-test-{tag}");
    let control = Arc::new(Mutex::new(IdTokenControl::fresh("signup", &sub)));
    let redirect = format!("{ORIGIN}/api/v1/step-up/oauth/callback");
    let (base, fixture) = fixture_oidc(
        control.clone(),
        &tag,
        &redirect,
        &format!("{ORIGIN}/api/auth/callback/fixture"),
    )
    .await;
    let oauth = step_up_oauth_for_testing(&base);
    let app = step_up_app(ctx.clone(), pool.clone(), Some(&base), Some(oauth));
    let (user_id, cookie) = signup_oauth_user(&app, &pool, &tag).await;
    let publisher = create_publisher(&pool, &unique_ns("oauth"), &user_id, "owner").await;
    OauthCase {
        ctx,
        app,
        pool,
        cookie,
        user_id,
        publisher,
        tag,
        control,
        fixture,
        _base: base,
    }
}

async fn oauth_start(
    case: &OauthCase,
    action: &str,
    key_id: Option<&str>,
    return_to: &str,
) -> axum::response::Response {
    post_json(
        &case.app,
        "/api/v1/step-up/oauth/start",
        Some(&case.cookie),
        ORIGIN,
        json!({"action":action,"publisherId":case.publisher,"keyId":key_id,"returnTo":return_to}),
    )
    .await
}

async fn oauth_callback(
    case: &OauthCase,
    query: &str,
    cookie: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/step-up/oauth/callback?{query}"));
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    case.app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn callback_grant(
    response: &axum::response::Response,
) -> (StatusCode, Option<uuid::Uuid>, Option<String>) {
    let status = response.status();
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let url = Url::parse(&format!("https://callback.invalid{location}"))
        .or_else(|_| Url::parse("https://callback.invalid/app"))
        .unwrap();
    let grant = url
        .query_pairs()
        .find(|(name, _)| name == "stepUpGrant")
        .and_then(|(_, value)| uuid::Uuid::parse_str(&value).ok());
    let error = url
        .query_pairs()
        .find(|(name, _)| name == "stepUpError")
        .map(|(_, value)| value.into_owned());
    (status, grant, error)
}

async fn pending_state(case: &OauthCase, user: &str) -> (String, String) {
    let row: (String, String) = sqlx::query_as(
        "SELECT state, nonce FROM cloud_step_up_oauth_states WHERE user_id=$1 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user)
    .fetch_one(&case.pool)
    .await
    .unwrap();
    row
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_step_up_completes_full_enrollment_for_google_only_account() {
    use tiktools_plugin_package::{KeyId, SigningKey};
    let case = oauth_case().await;
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    assert_eq!(data["expiresIn"], 600);
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
    assert_eq!(params["response_type"], "code");
    assert_eq!(params["client_id"], FIXTURE_CLIENT_ID);
    assert_eq!(params["code_challenge_method"], "S256");
    assert!(params["code_challenge"].len() >= 43);
    assert_eq!(params["max_age"], "300");
    assert_eq!(
        params["redirect_uri"],
        format!("{ORIGIN}/api/v1/step-up/oauth/callback")
    );
    let state = params["state"].clone();
    let (stored_state, nonce) = pending_state(&case, &case.user_id).await;
    assert_eq!(
        stored_state, state,
        "the state must be the server-side record"
    );
    *case.control.lock().unwrap() =
        IdTokenControl::fresh(&nonce, &format!("cloud-test-{}", case.tag));
    let callback = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&callback);
    assert_eq!(status, StatusCode::SEE_OTHER, "error: {error:?}");
    let grant = grant.expect("callback must mint a grant");
    // The grant authorizes the enrollment flow end to end.
    let challenge = post_json(
        &case.app,
        &format!("/api/v1/publishers/{}/keys/challenges", case.publisher),
        Some(&case.cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(challenge.status(), StatusCode::OK);
    let data = body_json(challenge).await;
    let challenge_id = uuid::Uuid::parse_str(data["challengeId"].as_str().unwrap()).unwrap();
    let key_id = format!("key-{}", uuid::Uuid::new_v4().simple());
    let signing = SigningKey::generate(KeyId::parse(&key_id).unwrap(), None).unwrap();
    let public = signing.public_key();
    let message = publisher_keys::proof_message(
        case.publisher,
        challenge_id,
        data["nonce"].as_str().unwrap(),
        public.key_id.as_str(),
        &public.public_key,
    );
    let registered = post_json(
        &case.app,
        &format!("/api/v1/publishers/{}/keys", case.publisher),
        Some(&case.cookie),
        ORIGIN,
        json!({"challengeId":challenge_id,"keyId":public.key_id,"publicKey":public.public_key,"signature":base64::engine::general_purpose::STANDARD.encode(signing.sign(message.as_bytes())),"stepUpGrant":grant}),
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let method: String = sqlx::query_scalar("SELECT method FROM cloud_step_up_grants WHERE id=$1")
        .bind(grant)
        .fetch_one(&case.pool)
        .await
        .unwrap();
    assert_eq!(method, "oauth");
    case.fixture.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_start_validates_target_return_and_availability() {
    let case = oauth_case().await;
    // Unknown action.
    let response = oauth_start(&case, "publisher.key.delete", None, "/app/portal").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Approve without the key record under review, and enroll naming one.
    let response = oauth_start(&case, "publisher.key.approve", None, "/app/portal").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = oauth_start(
        &case,
        "publisher.key.enroll",
        Some(&uuid::Uuid::new_v4().to_string()),
        "/app/portal",
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // External, protocol-relative, and fragment return paths are refused so a
    // grant identifier can never leak off-origin.
    for bad in [
        "https://evil.test/app",
        "//evil.test/app",
        "/app/portal#stepUpGrant=x",
        "/login?next=/app",
        "/app\\portal",
    ] {
        let response = oauth_start(&case, "publisher.key.enroll", None, bad).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "return_to {bad}"
        );
    }
    let response = oauth_start(&case, "publisher.key.enroll", None, "/app/portal?tab=keys").await;
    assert_eq!(response.status(), StatusCode::OK);
    // Unknown publisher.
    let unknown = uuid::Uuid::new_v4();
    let response = post_json(
        &case.app,
        "/api/v1/step-up/oauth/start",
        Some(&case.cookie),
        ORIGIN,
        json!({"action":"publisher.key.enroll","publisherId":unknown,"returnTo":"/app/portal"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // A deployment without Google exposes only password step-up.
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_id, cookie) =
        signup_password_user(&ctx, &email, "test password with enough characters").await;
    let publisher = create_publisher(&pool, &unique_ns("nogoogle"), &user_id, "owner").await;
    let response = post_json(
        &app,
        "/api/v1/step-up/oauth/start",
        Some(&cookie),
        ORIGIN,
        json!({"action":"publisher.key.enroll","publisherId":publisher,"returnTo":"/app/portal"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(response).await["error"], "oauth_unavailable");
    case.fixture.abort();
}

/// One start plus one callback with a mutated fixture token. Returns the
/// redirect outcome: HTTP status, optional grant, optional error code.
async fn oauth_attempt(
    case: &OauthCase,
    mutate: impl FnOnce(&mut IdTokenControl),
) -> (StatusCode, Option<uuid::Uuid>, Option<String>) {
    let start = oauth_start(case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let (_, nonce) = pending_state(case, &case.user_id).await;
    let sub = format!("cloud-test-{}", case.tag);
    let mut control = IdTokenControl::fresh(&nonce, &sub);
    mutate(&mut control);
    *case.control.lock().unwrap() = control;
    let callback = oauth_callback(
        case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    callback_grant(&callback)
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_callback_rejects_invalid_tokens() {
    let case = oauth_case().await;
    // Each row: control mutation, then the expected stepUpError code.
    let matrix: Vec<ClaimCase> = vec![
        (
            "wrong audience",
            Box::new(|c| c.aud = "someone-else".into()),
            "invalid_token",
        ),
        (
            "wrong issuer",
            Box::new(|c| c.iss = "https://evil.test".into()),
            "invalid_token",
        ),
        (
            "bad signature",
            Box::new(|c| c.bad_key = true),
            "invalid_token",
        ),
        (
            "unknown kid",
            Box::new(|c| c.kid = "unknown".into()),
            "invalid_token",
        ),
        (
            "expired token",
            Box::new(|c| c.exp_offset_secs = -10),
            "invalid_token",
        ),
        (
            "wrong nonce",
            Box::new(|c| c.nonce_override = Some("attacker-nonce".into())),
            "invalid_token",
        ),
        (
            "missing id_token",
            Box::new(|c| c.omit_id_token = true),
            "invalid_token",
        ),
    ];
    for (label, mutate, expected) in matrix {
        let (status, grant, error) = oauth_attempt(&case, |c| mutate(c)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{label}");
        assert_eq!(error.as_deref(), Some(expected), "{label}");
        assert!(grant.is_none(), "{label}");
    }
    // A tampered stored redirect URI fails the exchange: the code is only
    // ever redeemed for the exact registered callback.
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let (_, nonce) = pending_state(&case, &case.user_id).await;
    let sub = format!("cloud-test-{}", case.tag);
    *case.control.lock().unwrap() = IdTokenControl::fresh(&nonce, &sub);
    sqlx::query("UPDATE cloud_step_up_oauth_states SET redirect_uri='https://evil.test/callback' WHERE state=$1")
        .bind(&state).execute(&case.pool).await.unwrap();
    let callback = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&callback);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(error.as_deref(), Some("token_exchange_failed"));
    assert!(grant.is_none());
    case.fixture.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_callback_requires_fresh_bound_authentication() {
    let case = oauth_case().await;
    // Without `auth_time`, or with a stale one, there is no recent provider
    // authentication no matter what the session or email claims.
    let matrix: Vec<ClaimCase> = vec![
        (
            "missing auth_time",
            Box::new(|c| c.auth_time = None),
            "stale_authentication",
        ),
        (
            "stale auth_time",
            Box::new(|c| c.auth_time = Some(now_seconds() - 301)),
            "stale_authentication",
        ),
        (
            "future auth_time",
            Box::new(|c| c.auth_time = Some(now_seconds() + 3600)),
            "stale_authentication",
        ),
        (
            "wrong subject",
            Box::new(|c| c.sub = "cloud-test-someone-else".into()),
            "account_mismatch",
        ),
    ];
    for (label, mutate, expected) in matrix {
        let (status, grant, error) = oauth_attempt(&case, |c| mutate(c)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{label}");
        assert_eq!(error.as_deref(), Some(expected), "{label}");
        assert!(grant.is_none(), "{label}");
    }
    case.fixture.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn oauth_state_is_single_use_session_bound_and_expirable() {
    let case = oauth_case().await;
    let sub = format!("cloud-test-{}", case.tag);
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let (_, nonce) = pending_state(&case, &case.user_id).await;
    *case.control.lock().unwrap() = IdTokenControl::fresh(&nonce, &sub);
    let first = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, _) = callback_grant(&first);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(grant.is_some());
    // Replay of the same callback URL finds the state consumed.
    let replay = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&replay);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(grant.is_none());
    assert_eq!(error.as_deref(), Some("step_up_expired"));
    // An unknown state carries no return path and fails closed as JSON.
    let unknown = oauth_callback(
        &case,
        &format!(
            "code={FIXTURE_CODE}&state={}",
            uuid::Uuid::new_v4().simple()
        ),
        Some(&case.cookie),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);
    // A different session cannot complete the victim's flow, even for the
    // same user: the pending record is bound to the starting session.
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let email2 = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (_, other_cookie) =
        signup_password_user(&case.ctx, &email2, "test password with enough characters").await;
    let cross = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&other_cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&cross);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(grant.is_none());
    assert_eq!(error.as_deref(), Some("invalid_callback"));
    // Without any session there is nothing to bind a grant to.
    let anon = oauth_callback(&case, &format!("code={FIXTURE_CODE}&state={state}"), None).await;
    assert_eq!(anon.status(), StatusCode::UNAUTHORIZED);
    // An expired pending flow fails closed.
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    sqlx::query(
        "UPDATE cloud_step_up_oauth_states SET expires_at=now()-interval '1 second' WHERE state=$1",
    )
    .bind(&state)
    .execute(&case.pool)
    .await
    .unwrap();
    let stale = oauth_callback(
        &case,
        &format!("code={FIXTURE_CODE}&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&stale);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(grant.is_none());
    assert_eq!(error.as_deref(), Some("step_up_expired"));
    // A provider denial consumes the flow and reports without a grant.
    let start = oauth_start(&case, "publisher.key.enroll", None, "/app/portal").await;
    assert_eq!(start.status(), StatusCode::OK);
    let data = body_json(start).await;
    let auth_url = Url::parse(data["authorizationUrl"].as_str().unwrap()).unwrap();
    let state: String = auth_url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    let denied = oauth_callback(
        &case,
        &format!("error=access_denied&state={state}"),
        Some(&case.cookie),
    )
    .await;
    let (status, grant, error) = callback_grant(&denied);
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(grant.is_none());
    assert_eq!(error.as_deref(), Some("provider_denied"));
    case.fixture.abort();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_grants_die_with_expired_revoked_and_deleted_sessions() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let password = "test password with enough characters";
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_id, cookie) = signup_password_user(&ctx, &email, password).await;
    let publisher = create_publisher(&pool, &unique_ns("sess"), &user_id, "owner").await;
    let grant = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    // Expiring the session invalidates both verification and grant use: the
    // request layer no longer resolves the session at all.
    sqlx::query("UPDATE session SET expires_at=0 WHERE user_id=$1")
        .bind(&user_id)
        .execute(&pool)
        .await
        .unwrap();
    let response = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys/challenges"),
        Some(&cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // The in-transaction session guard is covered deterministically below, so
    // a session that dies between authentication and the mutation still fails
    // closed even if request resolution had succeeded.
    let target =
        super::step_up::validate_target(super::step_up::ACTION_ENROLL, publisher, None).unwrap();
    let mut tx = pool.begin().await.unwrap();
    let consumed =
        super::step_up::consume_grant(&mut tx, grant, &user_id, "missing-session", &target).await;
    assert!(consumed.is_err());
    let _ = tx.rollback().await;
    // A fresh session verifies again; signing out revokes it, and the grant
    // minted for it stops working.
    let second = EmailPasswordService::new(ctx.clone())
        .unwrap()
        .sign_in(
            better_auth::email_password::SignInInput {
                email: email.clone(),
                password: password.into(),
            },
            true,
        )
        .await
        .unwrap();
    let cookie2 = format!("{}={}", second.cookie.name, second.cookie.value);
    let grant2 = grant_id(
        &app,
        &cookie2,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    let sign_out = Request::builder()
        .method("POST")
        .uri("/api/auth/sign-out")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie2)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let sign_out = app.clone().oneshot(sign_out).await.unwrap();
    assert!(sign_out.status().is_success());
    let response = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys/challenges"),
        Some(&cookie2),
        ORIGIN,
        json!({"stepUpGrant": grant2}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_rechecks_authorization_and_supports_concurrent_approval() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let password = "test password with enough characters";
    let email_owner = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let email_admin = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (owner, owner_cookie) = signup_password_user(&ctx, &email_owner, password).await;
    let (admin, admin_cookie) = signup_password_user(&ctx, &email_admin, password).await;
    let publisher = create_publisher(&pool, &unique_ns("race"), &owner, "owner").await;
    admin::change_role(&pool, true, &admin, "admin", "test")
        .await
        .unwrap();
    let key_row = uuid::Uuid::new_v4();
    let race_key_id = format!("revokerace-{}", uuid::Uuid::new_v4().simple());
    let race_fp = format!("{:064x}", uuid::Uuid::new_v4().as_u128());
    sqlx::query("INSERT INTO cloud_publisher_keys (id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES ($1,$2,$3,$4,$5,'pending',$6)")
        .bind(key_row).bind(publisher).bind(&race_key_id).bind("cGtleQ").bind(&race_fp).bind(&owner).execute(&pool).await.unwrap();
    // A membership revoked after verification authorizes nothing.
    let grant = grant_id(
        &app,
        &owner_cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    sqlx::query("DELETE FROM cloud_publisher_memberships WHERE publisher_id=$1 AND user_id=$2")
        .bind(publisher)
        .bind(&owner)
        .execute(&pool)
        .await
        .unwrap();
    let challenge = post_json(
        &app,
        &format!("/api/v1/publishers/{publisher}/keys/challenges"),
        Some(&owner_cookie),
        ORIGIN,
        json!({"stepUpGrant": grant}),
    )
    .await;
    assert!(
        challenge.status() == StatusCode::NOT_FOUND || challenge.status() == StatusCode::FORBIDDEN,
        "revoked membership must authorize nothing, got {}",
        challenge.status()
    );
    // An admin role revoked after verification authorizes no approval.
    let approve_grant = grant_id(
        &app,
        &admin_cookie,
        "publisher.key.approve",
        &publisher,
        Some(&key_row.to_string()),
        password,
    )
    .await;
    // The last admin cannot be revoked. Another test used to leave a second admin
    // in the shared database; with a private database this test provides its own.
    let (keeper, _) = signup_password_user(
        &ctx,
        &format!("{}@example.test", uuid::Uuid::new_v4().simple()),
        password,
    )
    .await;
    admin::change_role(&pool, true, &keeper, "admin", "test")
        .await
        .unwrap();
    admin::change_role(&pool, false, &admin, "admin", "test")
        .await
        .unwrap();
    let denied = post_json(
        &app,
        &format!("/api/v1/admin/publishers/{publisher}/keys/{key_row}/approve"),
        Some(&admin_cookie),
        ORIGIN,
        json!({"stepUpGrant": approve_grant}),
    )
    .await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    // Concurrent double submission spends the grant exactly once.
    admin::change_role(&pool, true, &admin, "admin", "test")
        .await
        .unwrap();
    let race_grant = grant_id(
        &app,
        &admin_cookie,
        "publisher.key.approve",
        &publisher,
        Some(&key_row.to_string()),
        password,
    )
    .await;
    let approve_path = format!("/api/v1/admin/publishers/{publisher}/keys/{key_row}/approve");
    let attempt = || {
        let app = app.clone();
        let admin_cookie = admin_cookie.clone();
        let body = json!({"stepUpGrant": race_grant});
        let approve_path = approve_path.clone();
        async move { post_json(&app, &approve_path, Some(&admin_cookie), ORIGIN, body).await }
    };
    let (first, second) = tokio::join!(attempt(), attempt());
    let statuses = [first.status(), second.status()];
    assert!(
        statuses.contains(&StatusCode::NO_CONTENT),
        "one approval wins: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::NO_CONTENT)
            .count(),
        1,
        "the grant is single-use: {statuses:?}"
    );
    assert!(
        statuses.contains(&StatusCode::FORBIDDEN) || statuses.contains(&StatusCode::CONFLICT),
        "the loser fails closed: {statuses:?}"
    );
    // A member cannot self-approve even with a fresh grant, and an outsider
    // cannot even list the keys.
    sqlx::query("INSERT INTO cloud_publisher_memberships (publisher_id,user_id,role) VALUES ($1,$2,'owner')")
        .bind(publisher).bind(&owner).execute(&pool).await.unwrap();
    let self_grant = grant_id(
        &app,
        &owner_cookie,
        "publisher.key.approve",
        &publisher,
        Some(&key_row.to_string()),
        password,
    )
    .await;
    let mine = post_json(
        &app,
        &format!("/api/v1/admin/publishers/{publisher}/keys/{key_row}/approve"),
        Some(&owner_cookie),
        ORIGIN,
        json!({"stepUpGrant": self_grant}),
    )
    .await;
    assert_eq!(mine.status(), StatusCode::FORBIDDEN);
    let outsider = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (_, outsider_cookie) = signup_password_user(&ctx, &outsider, password).await;
    let list = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/publishers/{publisher}/keys"))
        .header(header::COOKIE, &outsider_cookie)
        .body(Body::empty())
        .unwrap();
    let list = app.clone().oneshot(list).await.unwrap();
    assert_eq!(list.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn step_up_lifecycle_is_audited() {
    let url = crate::test_support::migrated_url();
    let (ctx, pool) = step_up_context(&url).await;
    let app = step_up_app(ctx.clone(), pool.clone(), None, None);
    let password = "test password with enough characters";
    let email = format!("{}@example.test", uuid::Uuid::new_v4().simple());
    let (user_id, cookie) = signup_password_user(&ctx, &email, password).await;
    let publisher = create_publisher(&pool, &unique_ns("audit"), &user_id, "owner").await;
    let _ = password_grant(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        "wrong password with enough characters",
    )
    .await;
    let grant = grant_id(
        &app,
        &cookie,
        "publisher.key.enroll",
        &publisher,
        None,
        password,
    )
    .await;
    let subject: Option<uuid::Uuid> = sqlx::query_scalar("SELECT subject_id FROM cloud_audit_events WHERE action='step_up.granted' AND actor_user_id=$1 AND publisher_id=$2")
        .bind(&user_id).bind(publisher).fetch_one(&pool).await.unwrap();
    assert_eq!(subject, Some(grant));
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM cloud_audit_events WHERE actor_user_id=$1 AND publisher_id=$2 ORDER BY created_at",
    )
    .bind(&user_id)
    .bind(publisher)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        actions.contains(&"step_up.failed".to_string())
            && actions.contains(&"step_up.granted".to_string()),
        "verification failures and grants are audited: {actions:?}"
    );
}
