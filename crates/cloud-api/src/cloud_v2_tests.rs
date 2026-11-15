//! Real PostgreSQL and HTTP/SDK coverage for the single-instance product API.
use super::*;
use axum::{
    body::Body,
    http::{header, Request},
    response::Response,
};
use better_auth::email_password::{EmailPasswordService, SignUpInput};
use serde_json::{json, Value};
use tower::ServiceExt;
const ORIGIN: &str = "https://cloud.example.test";
const PASSWORD: &str = "test password with enough characters";

struct User {
    id: String,
    cookie: String,
    token: String,
}
struct Fixture {
    router: Router,
    pool: PgPool,
    users: Vec<User>,
    origin: String,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn fixture() -> Fixture {
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
    for _ in 0..3 {
        let user = EmailPasswordService::new(context.clone())
            .unwrap()
            .sign_up(
                SignUpInput {
                    email: format!("{}@example.test", uuid::Uuid::new_v4()),
                    name: "Cloud V2 Test".into(),
                    password: PASSWORD.into(),
                },
                true,
            )
            .await
            .unwrap();
        users.push(User {
            id: user.user.id,
            cookie: format!("{}={}", user.cookie.name, user.cookie.value),
            token: user.session_token,
        });
    }
    let router = app(
        context.clone(),
        pool.clone(),
        AuthRouter::new(context).unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let served = router.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            served.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Fixture {
        router,
        pool,
        users,
        origin,
        server,
    }
}
fn template() -> Value {
    json!({"templateVersion":1,"id":"gift-rule","title":"Gift rule","actions":[{"name":"Notify","typeId":"core.notify","enabled":true,"config":{"message":"Thanks {{ event.user.nickname }}"}}],"event":{"name":"Gift","trigger":"tiktok.gift"}})
}
async fn request(
    f: &Fixture,
    user: Option<usize>,
    method: &str,
    path: &str,
    value: Value,
    condition: Option<(&str, &str)>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(user) = user {
        request = request
            .header(header::COOKIE, &f.users[user].cookie)
            .header(header::ORIGIN, ORIGIN);
    }
    if let Some((key, value)) = condition {
        request = request.header(key, value);
    }
    f.router
        .clone()
        .oneshot(request.body(Body::from(value.to_string())).unwrap())
        .await
        .unwrap()
}
async fn json_body(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

/// Run the actual application SDK from the other checkout against this
/// fixture, without a build-time path dependency on that checkout. The
/// executable is an ignored test binary built by the caller; credentials are
/// passed only through a pipe and never placed in argv or environment.
#[cfg(feature = "app-sdk-acceptance")]
#[tokio::test]
#[ignore = "requires disposable CLOUD_TEST_DATABASE_URL and CLOUD_V2_APP_SDK_TEST_BIN"]
async fn actual_app_sdk_epoch_contract_against_postgres() {
    use std::{path::Path, process::Stdio, time::Duration};
    use tokio::io::AsyncWriteExt;

    let binary = std::env::var_os("CLOUD_V2_APP_SDK_TEST_BIN")
        .expect("provide the separately built application SDK test binary");
    assert!(Path::new(&binary).is_absolute());
    assert!(Path::new(&binary).is_file());
    // This fixture applies migrations. Refuse ordinary local or remote
    // databases even if the caller accidentally supplies one in the env.
    // Check the caller's database before the helper creates and migrates its
    // isolated cloud_test_t_* clone, whose name intentionally differs.
    let database = std::env::var("CLOUD_TEST_DATABASE_URL")
        .expect("provide the dedicated SDK acceptance database");
    let database = url::Url::parse(&database).expect("invalid disposable database URL");
    assert!(matches!(database.scheme(), "postgres" | "postgresql"));
    assert_eq!(database.host_str(), Some("127.0.0.1"));
    assert!(database.port().is_some());
    assert!(database.path().starts_with("/tiktools_sdk_epoch_"));
    assert!(database.query().is_none() && database.fragment().is_none());
    let f = fixture().await;
    let input = serde_json::to_vec(&json!({
        "origin": f.origin,
        "first_token": f.users[0].token,
        "second_token": f.users[1].token
    }))
    .unwrap();
    let execution = tokio::time::timeout(Duration::from_secs(40), async {
        let mut child = tokio::process::Command::new(binary)
            .env_clear()
            .arg("--exact")
            .arg("real_backend_epoch_contract")
            .arg("--ignored")
            .arg("--nocapture")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().expect("child stdin");
        stdin.write_all(&input).await?;
        drop(stdin);
        child.wait_with_output().await
    })
    .await;
    // Always remove exactly these synthetic accounts, including on timeout or
    // child failure. The dedicated disposable database remains caller-owned.
    let ids: Vec<_> = f.users.iter().map(|user| user.id.as_str()).collect();
    let cleanup = sqlx::query("DELETE FROM \"user\" WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&f.pool)
        .await;
    cleanup.expect("remove isolated fixture accounts");
    let output = execution
        .expect("SDK test timed out")
        .expect("SDK test execution failed");
    let sanitized = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .replace(&f.users[0].token, "[redacted]")
            .replace(&f.users[1].token, "[redacted]")
    };
    assert!(
        output.status.success(),
        "application SDK fixture failed (exit: {:?})\n{}\n{}",
        output.status.code(),
        sanitized(&output.stdout),
        sanitized(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_barrier_fences_a_delayed_http_write_and_is_account_scoped() {
    use futures_util::stream;
    use tokio::sync::oneshot;

    let f = fixture().await;
    let endpoint = "/api/v2/sync/collections/preferences/desktop";
    assert_eq!(
        request(
            &f,
            None,
            "POST",
            "/api/v2/sync/write-barrier",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let initial = request(
        &f,
        Some(0),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(json_body(initial).await["writeEpoch"], "0");

    // The body has reached the handler, but the original write cannot even
    // open its mutation transaction until the barrier commits.
    let (started_tx, started_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let body = Body::from_stream(stream::once(async move {
        started_tx.send(()).unwrap();
        resume_rx.await.unwrap();
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
            b"{\"schemaVersion\":1,\"theme\":\"dark\"}",
        ))
    }));
    let delayed = Request::builder()
        .method("PUT")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*")
        .header("x-workspace-write-epoch", "0")
        .body(body)
        .unwrap();
    let router = f.router.clone();
    let pending = tokio::spawn(async move { router.oneshot(delayed).await.unwrap() });
    started_rx.await.unwrap();
    let barrier = request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/write-barrier",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(barrier.status(), StatusCode::OK);
    assert_eq!(json_body(barrier).await["writeEpoch"], "1");
    resume_tx.send(()).unwrap();
    assert_eq!(
        pending.await.unwrap().status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        request(&f, Some(0), "GET", endpoint, Value::Null, None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );

    let fenced = Request::builder()
        .method("PUT")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*")
        .header("x-workspace-write-epoch", "1")
        .body(Body::from("{\"schemaVersion\":1,\"theme\":\"dark\"}"))
        .unwrap();
    assert_eq!(
        f.router.clone().oneshot(fenced).await.unwrap().status(),
        StatusCode::CREATED
    );
    let repeat = request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/write-barrier",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(json_body(repeat).await["writeEpoch"], "2");
    let stale_delete = Request::builder()
        .method("DELETE")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::IF_MATCH, "\"1\"")
        .header("x-workspace-write-epoch", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        f.router
            .clone()
            .oneshot(stale_delete)
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    let stale_other_collection = Request::builder()
        .method("PUT")
        .uri("/api/v2/sync/collections/plugin-selections/hotkeys")
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*")
        .header("x-workspace-write-epoch", "1")
        .body(Body::from(
            "{\"schemaVersion\":1,\"pluginId\":\"hotkeys\",\"version\":\"1.0.0\",\"enabled\":true}",
        ))
        .unwrap();
    assert_eq!(
        f.router
            .clone()
            .oneshot(stale_other_collection)
            .await
            .unwrap()
            .status(),
        StatusCode::PRECONDITION_FAILED
    );
    let other = request(
        &f,
        Some(1),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(json_body(other).await["writeEpoch"], "0");
    // Unfenced legacy clients remain compatible; they are not covered by a barrier.
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            endpoint,
            json!({"schemaVersion":1,"theme":"light"}),
            Some(("if-match", "\"1\""))
        )
        .await
        .status(),
        StatusCode::OK
    );

    sqlx::query(
        "UPDATE cloud_workspace_cursors SET write_epoch=9223372036854775807 WHERE user_id=$1",
    )
    .bind(&f.users[0].id)
    .execute(&f.pool)
    .await
    .unwrap();
    let overflow = request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/write-barrier",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(overflow.status(), StatusCode::SERVICE_UNAVAILABLE);
    let max = request(
        &f,
        Some(0),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(json_body(max).await["writeEpoch"], "9223372036854775807");
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_required_epoch_blocks_delayed_legacy_and_is_irreversible() {
    use futures_util::stream;
    use tokio::sync::oneshot;
    let f = fixture().await;
    let endpoint = "/api/v2/sync/collections/preferences/desktop";
    assert_eq!(
        request(
            &f,
            None,
            "POST",
            "/api/v2/sync/require-write-epoch",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let initial = request(
        &f,
        Some(0),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(
        json_body(initial).await,
        json!({"writeEpoch":"0","epochRequired":false})
    );
    let (started_tx, started_rx) = oneshot::channel();
    let (resume_tx, resume_rx) = oneshot::channel();
    let body = Body::from_stream(stream::once(async move {
        started_tx.send(()).unwrap();
        resume_rx.await.unwrap();
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
            b"{\"schemaVersion\":1,\"theme\":\"dark\"}",
        ))
    }));
    let delayed = Request::builder()
        .method("PUT")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*")
        .body(body)
        .unwrap();
    let router = f.router.clone();
    let pending = tokio::spawn(async move { router.oneshot(delayed).await.unwrap() });
    started_rx.await.unwrap();
    let enabled = request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/require-write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    assert_eq!(
        json_body(enabled).await,
        json!({"writeEpoch":"1","epochRequired":true})
    );
    resume_tx.send(()).unwrap();
    assert_eq!(
        pending.await.unwrap().status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let repeat = request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/require-write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(
        json_body(repeat).await,
        json!({"writeEpoch":"2","epochRequired":true})
    );
    let epoch = request(
        &f,
        Some(0),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(
        json_body(epoch).await,
        json!({"writeEpoch":"2","epochRequired":true})
    );
    let other = request(
        &f,
        Some(1),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(
        json_body(other).await,
        json!({"writeEpoch":"0","epochRequired":false})
    );
    assert_eq!(
        request(
            &f,
            Some(1),
            "PUT",
            endpoint,
            json!({"schemaVersion":1}),
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            endpoint,
            json!({"schemaVersion":1}),
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let valid = Request::builder()
        .method("PUT")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*")
        .header("x-workspace-write-epoch", "2")
        .body(Body::from("{\"schemaVersion\":1}"))
        .unwrap();
    assert_eq!(
        f.router.clone().oneshot(valid).await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "DELETE",
            endpoint,
            Value::Null,
            Some(("if-match", "\"1\""))
        )
        .await
        .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let stale = Request::builder()
        .method("DELETE")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::IF_MATCH, "\"1\"")
        .header("x-workspace-write-epoch", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        f.router.clone().oneshot(stale).await.unwrap().status(),
        StatusCode::PRECONDITION_FAILED
    );
    // The separate v1 API is unaffected by this v2 policy.
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v1/sync/collections/plugin-selections/acme.hotkeys",
            json!({"schemaVersion":1,"pluginId":"acme.hotkeys","version":"1.0.0","enabled":true}),
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    // Exhaustion cannot partially activate the required mode.
    sqlx::query(
        "INSERT INTO cloud_workspace_cursors(user_id,write_epoch) VALUES($1,9223372036854775807)",
    )
    .bind(&f.users[2].id)
    .execute(&f.pool)
    .await
    .unwrap();
    let exhausted = request(
        &f,
        Some(2),
        "POST",
        "/api/v2/sync/require-write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(exhausted.status(), StatusCode::SERVICE_UNAVAILABLE);
    let state = request(
        &f,
        Some(2),
        "GET",
        "/api/v2/sync/write-epoch",
        Value::Null,
        None,
    )
    .await;
    assert_eq!(
        json_body(state).await,
        json!({"writeEpoch":"9223372036854775807","epochRequired":false})
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_barrier_waits_for_write_already_in_transaction() {
    workspace_fence_waits_for_earlier_write(false).await;
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_required_epoch_waits_for_legacy_write_already_in_transaction() {
    workspace_fence_waits_for_earlier_write(true).await;
}

async fn workspace_fence_waits_for_earlier_write(require: bool) {
    let f = fixture().await;
    // A trigger pauses a real HTTP write after it has obtained the workspace
    // cursor lock but before it can commit. This test uses a dedicated DB.
    sqlx::query("CREATE FUNCTION barrier_test_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(5200601); RETURN NEW; END $$")
        .execute(&f.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER barrier_test_pause BEFORE INSERT ON cloud_workspace_records FOR EACH ROW EXECUTE FUNCTION barrier_test_pause()")
        .execute(&f.pool).await.unwrap();
    let mut blocker = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(5200601)")
        .execute(&mut *blocker)
        .await
        .unwrap();

    let endpoint = "/api/v2/sync/collections/preferences/desktop";
    let mut write = Request::builder()
        .method("PUT")
        .uri(endpoint)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_NONE_MATCH, "*");
    if !require {
        write = write.header("x-workspace-write-epoch", "0");
    }
    let write = write
        .body(Body::from("{\"schemaVersion\":1,\"theme\":\"dark\"}"))
        .unwrap();
    let router = f.router.clone();
    let writer = tokio::spawn(async move { router.oneshot(write).await.unwrap() });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE 'INSERT INTO cloud_workspace_records%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("writer reached trigger while holding cursor lock");

    let barrier_request = Request::builder()
        .method("POST")
        .uri(if require {
            "/api/v2/sync/require-write-epoch"
        } else {
            "/api/v2/sync/write-barrier"
        })
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::empty())
        .unwrap();
    let router = f.router.clone();
    let barrier = tokio::spawn(async move { router.oneshot(barrier_request).await.unwrap() });
    // Verify that the barrier actually reached PostgreSQL and is waiting on
    // the writer's uncommitted cursor insert; elapsed wall time alone could
    // also mean the barrier task had not been scheduled.
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'INSERT INTO cloud_workspace_cursors%')")
                .fetch_one(&f.pool).await.unwrap();
            if waiting { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("barrier reached PostgreSQL and waits for the writer");
    assert!(!barrier.is_finished());
    blocker.commit().await.unwrap();
    assert_eq!(writer.await.unwrap().status(), StatusCode::CREATED);
    let response = barrier.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = json_body(response).await;
    assert_eq!(response["writeEpoch"], "1");
    if require {
        assert_eq!(response["epochRequired"], true);
    }
    let record = request(&f, Some(0), "GET", endpoint, Value::Null, None).await;
    assert_eq!(json_body(record).await["value"]["theme"], "dark");
    sqlx::query("DROP TRIGGER barrier_test_pause ON cloud_workspace_records")
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION barrier_test_pause()")
        .execute(&f.pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn sync_feeds_refuse_missing_retained_changes_without_advancing_cursor() {
    let f = fixture().await;
    let user = &f.users[0].id;
    for (cursors, changes, endpoint) in [
        (
            "cloud_sync_cursors",
            "cloud_sync_changes",
            "/api/v1/sync/changes",
        ),
        (
            "cloud_workspace_cursors",
            "cloud_workspace_changes",
            "/api/v2/sync/changes",
        ),
    ] {
        sqlx::query(&format!(
            "INSERT INTO {cursors}(user_id,cursor) VALUES($1,3)"
        ))
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
        sqlx::query(&format!("INSERT INTO {changes}(user_id,cursor,collection,key,value,deleted) SELECT $1,n,'plugin-selections','acme.p'||n,NULL,true FROM generate_series(1,3) n"))
            .bind(user).execute(&f.pool).await.unwrap();
        let path = format!("{endpoint}?cursor=0");
        let original = request(&f, Some(0), "GET", &path, Value::Null, None).await;
        assert_eq!(original.status(), StatusCode::OK);
        assert_eq!(json_body(original).await["cursor"], 3);
        sqlx::query(&format!(
            "DELETE FROM {changes} WHERE user_id=$1 AND cursor=2"
        ))
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            request(&f, Some(0), "GET", &path, Value::Null, None)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let later = format!("{endpoint}?cursor=2");
        assert_eq!(
            request(&f, Some(0), "GET", &later, Value::Null, None)
                .await
                .status(),
            StatusCode::OK
        );
        sqlx::query(&format!(
            "DELETE FROM {changes} WHERE user_id=$1 AND cursor=3"
        ))
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            request(&f, Some(0), "GET", &later, Value::Null, None)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let saved: i64 =
            sqlx::query_scalar(&format!("SELECT cursor FROM {cursors} WHERE user_id=$1"))
                .bind(user)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(saved, 3);
    }
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn sync_reads_refuse_corrupt_records_without_disclosing_their_contents() {
    let f = fixture().await;
    let user = &f.users[0].id;
    let invalid = json!({"schemaVersion":1,"pluginId":"acme.bad","version":"1.0.0","enabled":true,"token":"private-sentinel"});
    for (cursors, records, changes, prefix) in [
        (
            "cloud_sync_cursors",
            "cloud_sync_records",
            "cloud_sync_changes",
            "/api/v1/sync",
        ),
        (
            "cloud_workspace_cursors",
            "cloud_workspace_records",
            "cloud_workspace_changes",
            "/api/v2/sync",
        ),
    ] {
        sqlx::query(&format!(
            "INSERT INTO {cursors}(user_id,cursor) VALUES($1,1)"
        ))
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
        sqlx::query(&format!("INSERT INTO {records}(user_id,collection,key,revision,value,deleted) VALUES($1,'plugin-selections','acme.bad',1,$2,false)"))
            .bind(user).bind(&invalid).execute(&f.pool).await.unwrap();
        sqlx::query(&format!("INSERT INTO {changes}(user_id,cursor,collection,key,value,deleted) VALUES($1,1,'plugin-selections','acme.bad',$2,false)"))
            .bind(user).bind(&invalid).execute(&f.pool).await.unwrap();
        for path in [
            format!("{prefix}/changes?cursor=0"),
            format!("{prefix}/collections/plugin-selections"),
        ] {
            let response = request(&f, Some(0), "GET", &path, Value::Null, None).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("private-sentinel"));
        }
        if prefix == "/api/v2/sync" {
            let path = format!("{prefix}/collections/plugin-selections/acme.bad");
            let response = request(&f, Some(0), "GET", &path, Value::Null, None).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("private-sentinel"));
        }
        let record_path = format!("{prefix}/collections/plugin-selections/acme.bad");
        let replacement =
            json!({"schemaVersion":1,"pluginId":"acme.bad","version":"1.0.0","enabled":false});
        let refused = request(
            &f,
            Some(0),
            "PUT",
            &record_path,
            replacement.clone(),
            Some(("if-match", "\"1\"")),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let retained: Value = sqlx::query_scalar(&format!(
            "SELECT value FROM {records} WHERE user_id=$1 AND key='acme.bad'"
        ))
        .bind(user)
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(retained, invalid);
        // Even a structurally valid record cannot claim a revision ahead of
        // the account head observed in the same database statement.
        let valid =
            json!({"schemaVersion":1,"pluginId":"acme.bad","version":"1.0.0","enabled":true});
        sqlx::query(&format!(
            "UPDATE {records} SET value=$2, revision=2 WHERE user_id=$1 AND key='acme.bad'"
        ))
        .bind(user)
        .bind(&valid)
        .execute(&f.pool)
        .await
        .unwrap();
        let listing = format!("{prefix}/collections/plugin-selections");
        assert_eq!(
            request(&f, Some(0), "GET", &listing, Value::Null, None)
                .await
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        if prefix == "/api/v2/sync" {
            assert_eq!(
                request(
                    &f,
                    Some(0),
                    "GET",
                    &format!("{listing}/acme.bad"),
                    Value::Null,
                    None
                )
                .await
                .status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }
        let refused = request(
            &f,
            Some(0),
            "PUT",
            &record_path,
            replacement,
            Some(("if-match", "\"2\"")),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let cursor: i64 =
            sqlx::query_scalar(&format!("SELECT cursor FROM {cursors} WHERE user_id=$1"))
                .bind(user)
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(cursor, 1);

        // The extra row used to decide whether another page exists is also
        // validated; a corrupt sentinel must not be returned or concealed.
        let sentinel_user = &f.users[2].id;
        let page_size: i32 = if prefix == "/api/v1/sync" { 100 } else { 50 };
        sqlx::query(&format!(
            "INSERT INTO {cursors}(user_id,cursor) VALUES($1,$2)"
        ))
        .bind(sentinel_user)
        .bind(i64::from(page_size + 1))
        .execute(&f.pool)
        .await
        .unwrap();
        sqlx::query(&format!("INSERT INTO {records}(user_id,collection,key,revision,value,deleted) SELECT $1,'plugin-selections','acme.a'||lpad(n::text,4,'0'),n,NULL,true FROM generate_series(1,$2::integer) n"))
            .bind(sentinel_user).bind(page_size).execute(&f.pool).await.unwrap();
        sqlx::query(&format!("INSERT INTO {records}(user_id,collection,key,revision,value,deleted) VALUES($1,'plugin-selections','acme.z',$2,$3,false)"))
            .bind(sentinel_user).bind(i64::from(page_size + 1)).bind(&invalid).execute(&f.pool).await.unwrap();
        let response = request(&f, Some(2), "GET", &listing, Value::Null, None).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("private-sentinel"));
        let other = request(
            &f,
            Some(1),
            "GET",
            &format!("{prefix}/changes?cursor=0"),
            Value::Null,
            None,
        )
        .await;
        assert_eq!(other.status(), StatusCode::OK);
        assert_eq!(json_body(other).await["cursor"], 0);
    }
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn v1_snapshot_pagination_uses_byte_order_for_punctuation_and_rebuild() {
    let f = fixture().await;
    let namespace = format!("ordering{}", uuid::Uuid::new_v4().simple());
    // The punctuation group straddles the first 100-record page, so this
    // checks both ordering and the exclusive continuation comparison.
    let mut ids: Vec<String> = (0..98)
        .map(|index| format!("{namespace}.a{index:03}"))
        .collect();
    ids.extend(
        ["m-0", "m.0", "m0", "m_0", "z0", "z1", "z2", "z3"]
            .into_iter()
            .map(|suffix| format!("{namespace}.{suffix}")),
    );
    ids.sort();
    assert_eq!(ids.len(), 106);
    assert_eq!(ids[99], format!("{namespace}.m.0"));
    assert_eq!(ids[100], format!("{namespace}.m0"));

    sqlx::query("INSERT INTO cloud_sync_cursors(user_id,cursor) VALUES($1,$2)")
        .bind(&f.users[0].id)
        .bind(ids.len() as i64)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_sync_records(user_id,collection,key,revision,value,deleted) SELECT $1,'plugin-selections',key,revision,jsonb_build_object('schemaVersion',1,'pluginId',key,'version','1.0.0','enabled',true),false FROM unnest($2::text[]) WITH ORDINALITY AS fixture(key,revision)")
        .bind(&f.users[0].id).bind(&ids).execute(&f.pool).await.unwrap();

    let path = "/api/v1/sync/collections/plugin-selections";
    let first = request(&f, Some(0), "GET", path, Value::Null, None).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = json_body(first).await;
    let first_records = first["records"].as_array().unwrap();
    assert_eq!(first_records.len(), 100);
    let after = first["nextAfter"].as_str().unwrap();
    assert_eq!(after, ids[99]);
    let second_path = format!("{path}?after={after}");
    let second = request(&f, Some(0), "GET", &second_path, Value::Null, None).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second = json_body(second).await;
    assert!(second["nextAfter"].is_null());
    let mut actual: Vec<String> = first_records
        .iter()
        .map(|row| row["key"].as_str().unwrap().to_owned())
        .collect();
    actual.extend(
        second["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["key"].as_str().unwrap().to_owned()),
    );
    assert_eq!(actual, ids);
    let isolated = request(&f, Some(1), "GET", path, Value::Null, None).await;
    assert!(json_body(isolated).await["records"]
        .as_array()
        .unwrap()
        .is_empty());

    // A real native SDK rebuild uses the native route and requires strictly
    // byte-ordered pages. Existing pending edits must survive the snapshot.
    let session = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let mut state = session.new_state();
    state
        .stage("local.pending".into(), cloud_client::Edit::Delete)
        .unwrap();
    assert_eq!(session.rebuild_with_count(&mut state).await.unwrap(), 106);
    assert!(state.entries["local.pending"].pending.is_some());
    assert!(ids.iter().all(|key| state.entries[key].remote.is_some()));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_two_sessions_conflicts_pagination_and_v1_isolation() {
    let f = fixture().await;
    let a = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let b = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let other = cloud_client::Session::connect(&f.origin, f.users[1].token.clone())
        .await
        .unwrap();
    let catalog = cloud_client::CloudCatalog::new(&f.origin).unwrap();
    let capabilities = catalog.capabilities().await.unwrap();
    assert_eq!(capabilities["instanceMode"], "single");
    assert_eq!(capabilities["userConfigurableRegistries"], false);
    let first = a
        .workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"dark"}),
            None,
        )
        .await
        .unwrap();
    assert_eq!(first.revision, 1);
    assert_eq!(b.workspace_snapshot().await.unwrap().records.len(), 1);
    let updated = b
        .workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"light"}),
            Some(1),
        )
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert!(matches!(
        a.workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"dark"}),
            Some(1)
        )
        .await,
        Err(cloud_client::SyncError::Conflict)
    ));
    assert_eq!(
        b.workspace_put(
            "preferences",
            "desktop",
            updated.value.clone().unwrap(),
            Some(2)
        )
        .await
        .unwrap()
        .revision,
        2
    );
    assert!(other.workspace_snapshot().await.unwrap().records.is_empty());
    assert!(matches!(
        other.workspace_record("preferences", "desktop").await,
        Err(cloud_client::SyncError::Http(404))
    ));
    a.workspace_put("rule-templates", "gift-rule", template(), None)
        .await
        .unwrap();
    a.workspace_put("profiles","gift-pack",json!({"profileVersion":1,"id":"gift-pack","name":"Gift pack","templates":[{"template":template()}]}),None).await.unwrap();
    a.workspace_put(
        "plugin-selections",
        "acme.plugin",
        json!({"schemaVersion":1,"pluginId":"acme.plugin","version":"1.2.3","enabled":true}),
        None,
    )
    .await
    .unwrap();
    for i in 0..51 {
        let id = format!("acme.plugin{i}");
        a.workspace_put(
            "plugin-settings",
            &id,
            json!({"schemaVersion":1,"pluginId":id,"settings":{"volume":50}}),
            None,
        )
        .await
        .unwrap();
    }
    let page = a.workspace_changes(0).await.unwrap();
    assert_eq!(page.changes.len(), 50);
    assert!(page.has_more);
    let page2 = b.workspace_changes(page.cursor).await.unwrap();
    assert!(!page2.has_more);
    assert_eq!(page2.changes.len(), 6);
    let snapshot = a.workspace_snapshot().await.unwrap();
    assert_eq!(snapshot.records.len(), 55);
    // Legacy callers receive exactly their old plugin-only dataset and DTO.
    assert!(a.export_sync().await.unwrap().records.is_empty());
    assert!(a.export_account().await.unwrap().sync.records.is_empty());
    let export = a.export_account_v2().await.unwrap();
    assert_eq!(
        export["workspaceSync"]["records"].as_array().unwrap().len(),
        55
    );
    let tombstone = a
        .workspace_delete("preferences", "desktop", 2)
        .await
        .unwrap();
    assert!(tombstone.deleted);
    assert!(
        b.workspace_record("preferences", "desktop")
            .await
            .unwrap()
            .deleted
    );
    let path = "/api/v2/sync/collections/preferences/desktop";
    assert_eq!(
        request(&f, Some(0), "PUT", path, json!({"schemaVersion":1}), None)
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            path,
            json!({"schemaVersion":1,"registryUrl":"https://other.test"}),
            Some(("if-match", "\"2\""))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let request = Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::COOKIE, &f.users[0].cookie)
        .header(header::ORIGIN, "https://evil.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_MATCH, "\"2\"")
        .body(Body::from("{\"schemaVersion\":1}"))
        .unwrap();
    assert!(f
        .router
        .clone()
        .oneshot(request)
        .await
        .unwrap()
        .status()
        .is_client_error());
    // Force a retained-feed gap while preserving a valid snapshot.
    sqlx::query("DELETE FROM cloud_workspace_changes WHERE user_id=$1 AND cursor<=50")
        .bind(&f.users[0].id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        b.workspace_changes(0).await,
        Err(cloud_client::SyncError::CursorExpired)
    ));
    assert!(b.workspace_snapshot().await.unwrap().valid());
    assert!(b
        .workspace_changes(tombstone.revision)
        .await
        .unwrap()
        .changes
        .is_empty());
    // Two devices racing from the same base can never both win.
    let (left, right) = tokio::join!(
        a.workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"dark"}),
            Some(tombstone.revision)
        ),
        b.workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"light"}),
            Some(tombstone.revision)
        )
    );
    assert_ne!(left.is_ok(), right.is_ok());
    assert!(
        matches!(left, Err(cloud_client::SyncError::Conflict))
            || matches!(right, Err(cloud_client::SyncError::Conflict))
    );
    assert_eq!(
        a.workspace_record("preferences", "desktop")
            .await
            .unwrap()
            .revision,
        tombstone.revision + 1
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn library_independent_publication_immutable_versions_withdrawal_and_cleanup() {
    let f = fixture().await;
    let a = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let other = cloud_client::Session::connect(&f.origin, f.users[2].token.clone())
        .await
        .unwrap();
    let public = cloud_client::CloudCatalog::new(&f.origin).unwrap();
    let created = a.library_create("template", template()).await.unwrap();
    let id = uuid::Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    assert!(matches!(
        public.document(id, None).await,
        Err(cloud_client::SyncError::Http(404))
    ));
    assert!(matches!(
        other.library_document(id).await,
        Err(cloud_client::SyncError::Http(404))
    ));
    assert!(matches!(
        a.library_create("template", template()).await,
        Err(cloud_client::SyncError::Conflict)
    ));
    a.library_submit(id, 1).await.unwrap();
    for user in [0, 1] {
        sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'moderator')")
            .bind(&f.users[user].id)
            .execute(&f.pool)
            .await
            .unwrap();
    }
    let decision = format!("/api/v2/moderation/documents/{id}/versions/1/decision");
    let approval = json!({"decision":"approve","reason":"Reviewed portable actions"});
    assert_eq!(
        request(&f, Some(0), "POST", &decision, approval.clone(), None)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let queue = json_body(
        request(
            &f,
            Some(1),
            "GET",
            "/api/v2/moderation/documents",
            Value::Null,
            None,
        )
        .await,
    )
    .await;
    assert!(queue["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["id"] == id.to_string()));
    assert_eq!(
        request(&f, Some(1), "POST", &decision, approval, None)
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        public.document(id, None).await.unwrap()["document"],
        template()
    );
    let mut changed = template();
    changed["title"] = json!("Updated gift rule");
    a.library_update(id, "template", changed.clone(), 1)
        .await
        .unwrap();
    assert_eq!(public.document(id, None).await.unwrap()["revision"], 1);
    assert_eq!(a.library_document(id).await.unwrap()["revision"], 2);
    assert!(matches!(
        a.library_update(id, "template", changed, 1).await,
        Err(cloud_client::SyncError::Conflict)
    ));
    a.library_withdraw(id, 1, "Replace outdated guidance")
        .await
        .unwrap();
    assert!(matches!(
        public.document(id, None).await,
        Err(cloud_client::SyncError::Http(404))
    ));
    assert!(matches!(
        public.document(id, Some(1)).await,
        Err(cloud_client::SyncError::Http(404))
    ));
    let export = a.export_account_v2().await.unwrap();
    assert_eq!(export["library"]["items"].as_array().unwrap().len(), 2);
    // Deleting a library document cascades its revisions even with a public pointer.
    let path = format!("/api/v2/library/documents/{id}");
    assert_eq!(
        request(
            &f,
            Some(2),
            "DELETE",
            &path,
            Value::Null,
            Some(("if-match", "\"2\""))
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "DELETE",
            &path,
            Value::Null,
            Some(("if-match", "\"1\""))
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "DELETE",
            &path,
            Value::Null,
            Some(("if-match", "\"2\""))
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_library_versions WHERE document_id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    // The existing account deletion operation removes both new private stores.
    let owner = cloud_client::Session::connect(&f.origin, f.users[2].token.clone())
        .await
        .unwrap();
    owner
        .workspace_put(
            "preferences",
            "desktop",
            json!({"schemaVersion":1,"theme":"dark"}),
            None,
        )
        .await
        .unwrap();
    let own = owner.library_create("template", template()).await.unwrap();
    let deleted = request(
        &f,
        Some(2),
        "DELETE",
        "/api/v1/me",
        json!({"password":PASSWORD}),
        None,
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_library_documents WHERE id=$1")
        .bind(uuid::Uuid::parse_str(own["id"].as_str().unwrap()).unwrap())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_workspace_records WHERE user_id=$1")
            .bind(&f.users[2].id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_quotas_and_untrusted_inputs_are_enforced_by_the_api() {
    let f = fixture().await;
    let path = "/api/v2/sync/collections/plugin-settings/acme.plugin";
    for settings in [
        json!({"password":"do-not-store"}),
        json!({"headers":{"Authorization":"Bearer secret"}}),
        json!({"registryUrl":"https://other.test"}),
    ] {
        let body = json!({"schemaVersion":1,"pluginId":"acme.plugin","settings":settings});
        assert_eq!(
            request(&f, Some(0), "PUT", path, body, Some(("if-none-match", "*")))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    sqlx::query("INSERT INTO cloud_workspace_cursors(user_id,cursor) VALUES($1,1)")
        .bind(&f.users[0].id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_workspace_records(user_id,collection,key,revision,value,deleted) SELECT $1,'plugin-settings','acme.plugin'||n,1,jsonb_build_object('schemaVersion',1,'pluginId','acme.plugin'||n,'settings','{}'::jsonb),false FROM generate_series(1,1000) n").bind(&f.users[0].id).execute(&f.pool).await.unwrap();
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v2/sync/collections/preferences/desktop",
            json!({"schemaVersion":1}),
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    // Modifications and tombstones remain possible at the record-count limit.
    assert_eq!(
        request(
            &f,
            Some(0),
            "DELETE",
            "/api/v2/sync/collections/plugin-settings/acme.plugin1",
            Value::Null,
            Some(("if-match", "\"1\""))
        )
        .await
        .status(),
        StatusCode::OK
    );
    let response = request(&f, None, "GET", "/api/v2/capabilities", Value::Null, None).await;
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        request(
            &f,
            None,
            "GET",
            "/api/v2/catalog/plugins?registry=https://other.test",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &f,
            None,
            "GET",
            "/api/v2/library/documents",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

fn wire_digest(document: &Value) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(serde_json::to_vec(document).unwrap()))
}

fn numeric_template() -> Value {
    let mut document = template();
    document["actions"][0]["config"]["numbers"] = serde_json::from_str(
        r#"{"large":1e18,"negativeZero":-0.0,"fraction":1e-6,"whole":1.0,"exact":18446744073709551615}"#,
    )
    .unwrap();
    document
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn jsonb_numeric_normalization_preserves_library_identity_and_workspace_noops() {
    let f = fixture().await;
    let owner = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let input = numeric_template();
    let created = owner
        .library_create("template", input.clone())
        .await
        .unwrap();
    let id = uuid::Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    let stored = owner.library_document(id).await.unwrap();
    assert_ne!(wire_digest(&input), wire_digest(&stored["document"]));
    assert_eq!(stored["sha256"], wire_digest(&stored["document"]));
    assert_eq!(
        stored["document"]["actions"][0]["config"]["numbers"]["large"],
        json!(1_000_000_000_000_000_000_u64)
    );
    assert_eq!(
        stored["document"]["actions"][0]["config"]["numbers"]["exact"],
        json!(u64::MAX)
    );
    let mut edited = input.clone();
    edited["title"] = json!("Numeric update");
    owner
        .library_update(id, "template", edited.clone(), 1)
        .await
        .unwrap();
    let updated = owner.library_document(id).await.unwrap();
    assert_ne!(wire_digest(&edited), wire_digest(&updated["document"]));
    assert_eq!(updated["sha256"], wire_digest(&updated["document"]));
    let immutable_response = request(
        &f,
        Some(0),
        "GET",
        &format!("/api/v2/library/documents/{id}/versions/1"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(immutable_response.status(), StatusCode::OK);
    let immutable = json_body(immutable_response).await;
    assert_eq!(immutable["sha256"], stored["sha256"]);
    assert_eq!(immutable["document"], stored["document"]);

    let value = json!({"schemaVersion":1,"pluginId":"acme.numeric","settings":input["actions"][0]["config"]["numbers"]});
    let ack = owner
        .workspace_put("plugin-settings", "acme.numeric", value.clone(), None)
        .await
        .unwrap();
    let get = owner
        .workspace_record("plugin-settings", "acme.numeric")
        .await
        .unwrap();
    let feed = owner.workspace_changes(0).await.unwrap();
    let snapshot = owner.workspace_snapshot().await.unwrap();
    assert_eq!(ack, get);
    assert_eq!(feed.changes, vec![ack.clone()]);
    assert_eq!(snapshot.records, vec![ack.clone()]);
    // A repeated original exponent-form request is a true no-op, and its ACK
    // still contains the stored representation used by the unchanged feed.
    let repeat = owner
        .workspace_put("plugin-settings", "acme.numeric", value, Some(ack.revision))
        .await
        .unwrap();
    assert_eq!(repeat, ack);
    assert!(owner
        .workspace_changes(ack.revision)
        .await
        .unwrap()
        .changes
        .is_empty());
    // Equal integer/decimal representations also preserve the original body.
    let mut equivalent = ack.value.clone().unwrap();
    equivalent["settings"]["whole"] = json!(1);
    let repeat = owner
        .workspace_put(
            "plugin-settings",
            "acme.numeric",
            equivalent,
            Some(ack.revision),
        )
        .await
        .unwrap();
    assert_eq!(repeat, ack);
    assert_eq!(
        owner.workspace_snapshot().await.unwrap().cursor,
        ack.revision
    );

    // JSONB can expand exponent notation past the portable document limit.
    // Both APIs revalidate before committing any source, revision or cursor.
    let expanded_settings =
        json!({"numbers":vec![vec![json!(1e18);256];8],"padding":vec!["a".repeat(8000);30]});
    let expanded_workspace =
        json!({"schemaVersion":1,"pluginId":"acme.expanded","settings":expanded_settings});
    assert!(portable::validate(
        "plugin-settings",
        "acme.expanded",
        &expanded_workspace
    ));
    let normalized: Value = sqlx::query_scalar("SELECT $1::jsonb")
        .bind(&expanded_workspace)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(!portable::validate(
        "plugin-settings",
        "acme.expanded",
        &normalized
    ));
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v2/sync/collections/plugin-settings/acme.expanded",
            expanded_workspace,
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        owner.workspace_snapshot().await.unwrap().cursor,
        ack.revision
    );
    let mut expanded_document = template();
    expanded_document["id"] = json!("expanded-rule");
    expanded_document["actions"][0]["config"] = expanded_settings;
    assert!(portable::document("template", &expanded_document));
    assert_eq!(
        request(
            &f,
            Some(0),
            "POST",
            "/api/v2/library/documents",
            json!({"kind":"template","document":expanded_document}),
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM cloud_library_documents WHERE owner_user_id=$1")
            .bind(&f.users[0].id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    expanded_document["id"] = json!("gift-rule");
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            &format!("/api/v2/library/documents/{id}"),
            json!({"document":expanded_document}),
            Some(("if-match", "\"2\""))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(owner.library_document(id).await.unwrap()["revision"], 2);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn legacy_library_digest_mismatch_fails_closed_and_repairs_only_reviewed_metadata() {
    use crate::library_digest_repair::{self as repair, AuditCursor, RepairError};
    let f = fixture().await;
    let owner = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let input = numeric_template();
    let created = owner
        .library_create("template", input.clone())
        .await
        .unwrap();
    let id = uuid::Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    owner.library_submit(id, 1).await.unwrap();
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'moderator')")
        .bind(&f.users[1].id)
        .execute(&f.pool)
        .await
        .unwrap();
    let decision = format!("/api/v2/moderation/documents/{id}/versions/1/decision");
    assert_eq!(
        request(
            &f,
            Some(1),
            "POST",
            &decision,
            json!({"decision":"approve","reason":"Reviewed stored numeric content"}),
            None
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let current = owner.library_document(id).await.unwrap();
    let old_hash = wire_digest(&input);
    let normalized_hash = current["sha256"].as_str().unwrap();
    assert_ne!(old_hash, normalized_hash);
    // Simulate exactly the pre-fix write, without changing approved content.
    sqlx::query("UPDATE cloud_library_versions SET sha256=$2 WHERE document_id=$1 AND revision=1")
        .bind(id)
        .bind(&old_hash)
        .execute(&f.pool)
        .await
        .unwrap();
    let before: Value = sqlx::query_scalar(
        "SELECT to_jsonb(v) FROM cloud_library_versions v WHERE document_id=$1 AND revision=1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let document_before: Value =
        sqlx::query_scalar("SELECT to_jsonb(d) FROM cloud_library_documents d WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    for (user, path) in [
        (Some(0), format!("/api/v2/library/documents/{id}")),
        (
            Some(0),
            format!("/api/v2/library/documents/{id}/versions/1"),
        ),
        (Some(0), format!("/api/v2/library/documents/{id}/versions")),
        (Some(0), "/api/v2/library/documents".into()),
        (Some(0), "/api/v2/me/export".into()),
        (None, format!("/api/v2/catalog/documents/{id}")),
        (None, format!("/api/v2/catalog/documents/{id}/versions/1")),
        (None, "/api/v2/catalog/documents?q=Gift%20rule".into()),
    ] {
        assert_eq!(
            request(&f, user, "GET", &path, Value::Null, None)
                .await
                .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    let audit = repair::audit(&f.pool, None, 100).await.unwrap();
    // Other tests can leave rows in this dedicated database; scan all pages.
    let mut items = audit.items;
    let mut cursor = audit.next_after;
    while let Some(after) = cursor {
        let page = repair::audit(&f.pool, Some(after), 100).await.unwrap();
        items.extend(page.items);
        cursor = page.next_after;
    }
    let issue = items
        .iter()
        .find(|item| item.document_id == id && item.revision == 1)
        .unwrap();
    assert_eq!(issue.status, "published");
    assert_eq!(issue.stored_sha256, old_hash);
    assert_eq!(issue.normalized_sha256, normalized_hash);
    assert!(issue.portable);
    let still_bad: String = sqlx::query_scalar(
        "SELECT sha256 FROM cloud_library_versions WHERE document_id=$1 AND revision=1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(still_bad, old_hash);
    assert!(matches!(
        repair::repair(
            &f.pool,
            id,
            1,
            &"f".repeat(64),
            normalized_hash,
            "fixture-operator"
        )
        .await,
        Err(RepairError::Conflict)
    ));
    assert!(matches!(
        repair::repair(
            &f.pool,
            id,
            1,
            &old_hash,
            &"e".repeat(64),
            "fixture-operator"
        )
        .await,
        Err(RepairError::Conflict)
    ));
    let receipt = repair::repair(
        &f.pool,
        id,
        1,
        &old_hash,
        normalized_hash,
        "fixture-operator",
    )
    .await
    .unwrap();
    assert_eq!(receipt.normalized_sha256, normalized_hash);
    let after: Value = sqlx::query_scalar(
        "SELECT to_jsonb(v) FROM cloud_library_versions v WHERE document_id=$1 AND revision=1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let mut expected = before;
    expected["sha256"] = json!(normalized_hash);
    assert_eq!(after, expected);
    let document_after: Value =
        sqlx::query_scalar("SELECT to_jsonb(d) FROM cloud_library_documents d WHERE id=$1")
            .bind(id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(document_after, document_before);
    assert_eq!(
        cloud_client::CloudCatalog::new(&f.origin)
            .unwrap()
            .document(id, None)
            .await
            .unwrap(),
        current
    );
    assert!(matches!(
        repair::repair(
            &f.pool,
            id,
            1,
            &old_hash,
            normalized_hash,
            "fixture-operator"
        )
        .await,
        Err(RepairError::Conflict)
    ));
    let evidence: Value = sqlx::query_scalar("SELECT jsonb_build_object('old',old_sha256,'new',normalized_sha256,'operator',operator) FROM cloud_library_digest_repairs WHERE document_id=$1 AND revision=1").bind(id).fetch_one(&f.pool).await.unwrap();
    assert_eq!(
        evidence,
        json!({"old":old_hash,"new":normalized_hash,"operator":"fixture-operator"})
    );

    // An empty audit page still advances past valid rows to a later mismatch.
    owner
        .library_update(id, "template", input.clone(), 1)
        .await
        .unwrap();
    owner
        .library_update(id, "template", input.clone(), 2)
        .await
        .unwrap();
    sqlx::query("UPDATE cloud_library_versions SET sha256=$2 WHERE document_id=$1 AND revision=3")
        .bind(id)
        .bind(&old_hash)
        .execute(&f.pool)
        .await
        .unwrap();
    let empty = repair::audit(
        &f.pool,
        Some(AuditCursor {
            document_id: id,
            revision: 1,
        }),
        1,
    )
    .await
    .unwrap();
    assert!(empty.items.is_empty());
    let next = empty.next_after.unwrap();
    assert_eq!(next.document_id, id);
    assert_eq!(next.revision, 2);
    let page = repair::audit(&f.pool, Some(next), 1).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].revision, 3);
    assert_eq!(
        request(
            &f,
            Some(0),
            "POST",
            &format!("/api/v2/library/documents/{id}/versions/3/submit"),
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    sqlx::query(
        "UPDATE cloud_library_versions SET status='pending' WHERE document_id=$1 AND revision=3",
    )
    .bind(id)
    .execute(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        request(
            &f,
            Some(1),
            "GET",
            "/api/v2/moderation/documents?q=Gift%20rule",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(
            &f,
            Some(1),
            "POST",
            &format!("/api/v2/moderation/documents/{id}/versions/3/decision"),
            json!({"decision":"approve","reason":"Must not approve a false identity"}),
            None
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM cloud_library_versions WHERE document_id=$1 AND revision=3",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(status, "pending");
    // Corrective withdrawal remains available even for a broken digest.
    owner
        .library_withdraw(id, 3, "Withdraw invalid identity")
        .await
        .unwrap();
    sqlx::query("UPDATE cloud_library_versions SET document=jsonb_set(document,'{title}','\"\"'::jsonb) WHERE document_id=$1 AND revision=3").bind(id).execute(&f.pool).await.unwrap();
    let invalid: Value = sqlx::query_scalar(
        "SELECT document FROM cloud_library_versions WHERE document_id=$1 AND revision=3",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(matches!(
        repair::repair(
            &f.pool,
            id,
            3,
            &old_hash,
            &wire_digest(&invalid),
            "fixture-operator"
        )
        .await,
        Err(RepairError::InvalidPortable)
    ));
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_library_digest_repairs WHERE document_id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        request(
            &f,
            Some(0),
            "DELETE",
            &format!("/api/v2/library/documents/{id}"),
            Value::Null,
            Some(("if-match", "\"3\""))
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cloud_library_digest_repairs WHERE document_id=$1",
    )
    .bind(id)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn ascii_punctuation_key_and_plugin_pages_use_locale_independent_exclusive_cursors() {
    let f = fixture().await;
    let namespace = format!("ordering{}", uuid::Uuid::new_v4().simple());
    let mut ids: Vec<String> = ["a-b", "a.b", "a_b", "aa"]
        .into_iter()
        .map(|suffix| format!("{namespace}.{suffix}"))
        .collect();
    ids.extend((0..52).map(|index| format!("{namespace}.p{index:02}")));
    ids.sort();
    assert_eq!(ids.len(), 56);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));

    // Where libc locales exist, prove these IDs distinguish byte order from
    // locale order. The HTTP assertions below always run; they neither change
    // the database locale nor depend on a non-C locale being installed in CI.
    for locale in ["en_US.utf8", "es_PE.utf8"] {
        let available:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_collation c JOIN pg_namespace n ON n.oid=c.collnamespace WHERE n.nspname='pg_catalog' AND c.collname=$1 AND c.collprovider='c' AND c.collencoding IN (-1,pg_char_to_encoding('UTF8')))").bind(locale).fetch_one(&f.pool).await.unwrap();
        if available {
            let query = format!(
                r#"SELECT id FROM unnest($1::text[]) AS id ORDER BY id COLLATE pg_catalog."{locale}""#
            );
            let localized: Vec<String> = sqlx::query_scalar(&query)
                .bind(&ids)
                .fetch_all(&f.pool)
                .await
                .unwrap();
            assert_ne!(
                localized, ids,
                "punctuation fixture must distinguish installed libc locale {locale}"
            );
            break;
        }
    }

    // Seed only metadata/data for pagination: this test does not claim signed
    // publication, package verification, or plugin execution authorization.
    sqlx::query("INSERT INTO cloud_workspace_cursors(user_id,cursor) VALUES($1,$2)")
        .bind(&f.users[0].id)
        .bind(ids.len() as i64)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_workspace_records(user_id,collection,key,revision,value,deleted) SELECT $1,'plugin-settings',key,revision,jsonb_build_object('schemaVersion',1,'pluginId',key,'settings','{}'::jsonb),false FROM unnest($2::text[]) WITH ORDINALITY AS fixture(key,revision)")
        .bind(&f.users[0].id).bind(&ids).execute(&f.pool).await.unwrap();
    let owner = cloud_client::Session::connect(&f.origin, f.users[0].token.clone())
        .await
        .unwrap();
    let mut received = Vec::new();
    let mut after: Option<String> = None;
    for page_number in 0..2 {
        let page = owner
            .workspace_collection("plugin-settings", after.as_deref())
            .await
            .unwrap();
        let rows = page["records"].as_array().unwrap();
        assert_eq!(rows.len(), if page_number == 0 { 50 } else { 6 });
        received.extend(
            rows.iter()
                .map(|row| row["key"].as_str().unwrap().to_owned()),
        );
        after = page["nextAfter"].as_str().map(str::to_owned);
        assert_eq!(after.is_some(), page_number == 0);
    }
    assert_eq!(received, ids);
    let checkpoint = &ids[1];
    let remainder = owner
        .workspace_collection("plugin-settings", Some(checkpoint))
        .await
        .unwrap();
    let first = remainder["records"][0]["key"].as_str().unwrap();
    assert_eq!(first, ids[2]);

    let publisher = uuid::Uuid::new_v4();
    let key = uuid::Uuid::new_v4();
    let candidate = uuid::Uuid::new_v4();
    let generation = (uuid::Uuid::new_v4().as_u128() & 0x3fff_ffff_ffff_ffff) as i64 + 1;
    let hash = "a".repeat(64);
    sqlx::query("INSERT INTO cloud_publishers(id,namespace,status) VALUES($1,$2,'approved')")
        .bind(publisher)
        .bind(&namespace)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_publisher_keys(id,publisher_id,key_id,public_key,fingerprint,status,requested_by) VALUES($1,$2,$3,$4,$5,'approved',$6)")
        .bind(key).bind(publisher).bind(format!("{namespace}-key")).bind("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").bind(uuid::Uuid::new_v4().simple().to_string().repeat(2)).bind(&f.users[0].id).execute(&f.pool).await.unwrap();
    // Catalog IDs follow manifest grammar; workspace sync deliberately keeps
    // its separate stricter key grammar. These rows are synthetic metadata.
    let single = format!("{namespace}foo");
    let repeated_dots = format!("b..{namespace}");
    let parent_shard = format!("ab..{namespace}");
    let mut catalog_ids = ids.clone();
    catalog_ids.extend([single.clone(), repeated_dots.clone(), parent_shard.clone()]);
    let uploads: Vec<_> = (0..catalog_ids.len())
        .map(|_| uuid::Uuid::new_v4())
        .collect();
    let releases: Vec<_> = (0..catalog_ids.len())
        .map(|_| uuid::Uuid::new_v4())
        .collect();
    sqlx::query("INSERT INTO cloud_upload_sessions(id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at) SELECT id,$2,$3,id::text,100,$4,'ordering/uploads/'||id::text,'pending',now()+interval '1 hour' FROM unnest($1::uuid[]) AS fixture(id)")
        .bind(&uploads).bind(publisher).bind(&f.users[0].id).bind(&hash).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases(id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) SELECT id,$4,upload_id,$5,plugin_id,'1.0.0','any','awaiting_verification',$6 FROM unnest($1::uuid[],$2::uuid[],$3::text[]) AS fixture(id,upload_id,plugin_id)")
        .bind(&releases).bind(&uploads).bind(&catalog_ids).bind(publisher).bind(key).bind(&f.users[0].id).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_snapshot_candidates(id,status,root_fingerprint,inventory_sha256,release_count,file_count) VALUES($1,'candidate',$2,$2,$3,1)")
        .bind(candidate).bind(&hash).bind(catalog_ids.len() as i32).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_registry_generations(id,generation,candidate_id,inventory_sha256,manifest_sha256,root_fingerprint,index_key_id,release_count,file_count,status) VALUES($1,$2,$3,$4,$4,$4,'ordering-test-index',$5,1,'superseded')")
        .bind(uuid::Uuid::new_v4()).bind(generation).bind(candidate).bind(&hash).bind(catalog_ids.len() as i32).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_registry_generation_releases(generation,plugin_id,version,target,release_id,sha256,size,object_key,version_id) SELECT $1,plugin_id,'1.0.0','any',release_id,$4,100,'ordering/releases/'||release_id::text,'v1' FROM unnest($2::text[],$3::uuid[]) AS fixture(plugin_id,release_id)")
        .bind(generation).bind(&catalog_ids).bind(&releases).bind(&hash).execute(&f.pool).await.unwrap();
    let catalog = cloud_client::CloudCatalog::new(&f.origin).unwrap();
    let mut received = Vec::new();
    let mut after: Option<String> = None;
    for page_number in 0..2 {
        let page = catalog
            .plugins_filtered(
                &format!("{namespace}."),
                after.as_deref(),
                Some(generation),
                Some("x86_64-unknown-linux-gnu"),
            )
            .await
            .unwrap();
        assert_eq!(page["generation"], generation);
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), if page_number == 0 { 50 } else { 6 });
        received.extend(
            items
                .iter()
                .map(|item| item["id"].as_str().unwrap().to_owned()),
        );
        after = page["nextCursor"].as_str().map(str::to_owned);
        assert_eq!(after.is_some(), page_number == 0);
    }
    assert_eq!(received, ids);
    let remainder = catalog
        .plugins_filtered(
            &format!("{namespace}."),
            Some(checkpoint),
            Some(generation),
            None,
        )
        .await
        .unwrap();
    assert_eq!(remainder["items"][0]["id"], ids[2]);
    for id in [&single, &repeated_dots, &parent_shard] {
        assert_eq!(
            catalog.plugin(id, Some(generation)).await.unwrap()["plugin"]["id"],
            *id
        );
        assert!(catalog
            .plugins_filtered("", Some(id), Some(generation), None)
            .await
            .is_ok());
        assert!(!crate::sync::valid_plugin_id(id));
    }
    let canonical_path =
        format!("/api/v1/registry/generations/{generation}/files/index/{parent_shard}.json");
    let parent_summary = catalog
        .plugin_summaries(Some(&parent_shard), None, Some(generation), None)
        .await
        .unwrap();
    assert_eq!(parent_summary.items.len(), 1);
    assert_eq!(parent_summary.items[0].id, parent_shard);
    assert_eq!(parent_summary.items[0].metadata_path, canonical_path);
    let parent_versions = catalog
        .plugin_version_page(&parent_shard, None, Some(generation), None)
        .await
        .unwrap();
    assert_eq!(parent_versions.metadata_path, canonical_path);
    assert_eq!(parent_versions.items.len(), 1);
    for id in ["hotkeys", "textintel"] {
        // The synthetic generation does not contain these legacy IDs; 404,
        // rather than 400, proves that the route accepts their grammar.
        let path = format!("/api/v2/catalog/plugins/{id}?generation={generation}");
        assert_eq!(
            request(&f, None, "GET", &path, json!({}), None)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    for path in [
        "/api/v2/catalog/plugins/1bad",
        "/api/v2/catalog/plugins?after=1bad",
    ] {
        assert_eq!(
            request(&f, None, "GET", path, json!({}), None)
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    // The additive bounded summary endpoint pins the complete query in its cursor.
    let q = format!("{namespace}.");
    let prefix = format!("/api/v2/catalog/plugin-summaries?generation={generation}&q={q}&target=x86_64-unknown-linux-gnu");
    let first = request(&f, None, "GET", &prefix, json!({}), None).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first = json_body(first).await;
    assert_eq!(first["generation"], generation.to_string());
    assert_eq!(first["items"].as_array().unwrap().len(), 50);
    let cursor = first["nextCursor"].as_str().unwrap();
    let changed = format!("/api/v2/catalog/plugin-summaries?generation={generation}&q=other&target=x86_64-unknown-linux-gnu&cursor={cursor}");
    assert_eq!(
        request(&f, None, "GET", &changed, json!({}), None)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let second = request(
        &f,
        None,
        "GET",
        &format!("{prefix}&cursor={cursor}"),
        json!({}),
        None,
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    let second = json_body(second).await;
    assert_eq!(second["items"].as_array().unwrap().len(), 6);
    assert!(second["nextCursor"].is_null());
    let got: Vec<_> = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["items"].as_array().unwrap())
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(got, ids);

    // Add many releases of one ID. A second page must observe current yank
    // state without dropping or repeating immutable generation members.
    let plugin = &ids[0];
    let additional: Vec<String> = (1..=70)
        .map(|i| {
            let prefix = format!("1.0.{i}+");
            format!("{prefix}{}", "a".repeat(128 - prefix.len()))
        })
        .collect();
    let long_target = "x".repeat(128);
    let more_uploads: Vec<_> = additional.iter().map(|_| uuid::Uuid::new_v4()).collect();
    let more_releases: Vec<_> = additional.iter().map(|_| uuid::Uuid::new_v4()).collect();
    sqlx::query("INSERT INTO cloud_upload_sessions(id,publisher_id,requested_by,idempotency_key,expected_size,expected_sha256,object_key,status,expires_at) SELECT id,$2,$3,id::text,100,$4,'ordering/uploads/'||id::text,'pending',now()+interval '1 hour' FROM unnest($1::uuid[]) AS fixture(id)")
        .bind(&more_uploads).bind(publisher).bind(&f.users[0].id).bind(&hash).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_plugin_releases(id,publisher_id,upload_id,publisher_key_id,plugin_id,version,target,status,requested_by) SELECT id,$4,upload_id,$5,$6,version,$8,'awaiting_verification',$7 FROM unnest($1::uuid[],$2::uuid[],$3::text[]) AS fixture(id,upload_id,version)")
        .bind(&more_releases).bind(&more_uploads).bind(&additional).bind(publisher).bind(key).bind(plugin).bind(&f.users[0].id).bind(&long_target).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_registry_generation_releases(generation,plugin_id,version,target,release_id,sha256,size,object_key,version_id) SELECT $1,$2,version,$6,release_id,$5,100,'ordering/releases/'||release_id::text,'v1' FROM unnest($3::text[],$4::uuid[]) AS fixture(version,release_id)")
        .bind(generation).bind(plugin).bind(&additional).bind(&more_releases).bind(&hash).bind(&long_target).execute(&f.pool).await.unwrap();
    // Advisory fields satisfy the actual moderation validator, including its
    // 1024-byte message limit; JSON escaping and the multibyte URL make a
    // valid row large enough to exercise the page byte boundary.
    let mut advisory_releases = more_releases.clone();
    advisory_releases.push(releases[0]);
    let advisory_message = "\"".repeat(1024);
    let advisory_url = format!("https://example.test/{}", "𐀀".repeat(2027));
    assert!(
        crate::moderation::valid_advisory("low", &advisory_message, Some(&advisory_url)).is_ok()
    );
    sqlx::query("INSERT INTO cloud_release_advisories(release_id,severity,message,url,created_by) SELECT id,'low',$2,$3,'fixture' FROM unnest($1::uuid[]) AS fixture(id)")
        .bind(&advisory_releases).bind(&advisory_message).bind(&advisory_url).execute(&f.pool).await.unwrap();
    let version_prefix = format!("/api/v2/catalog/plugins/{plugin}/version-pages?generation={generation}&target={long_target}");
    let first_versions = request(&f, None, "GET", &version_prefix, json!({}), None).await;
    assert_eq!(first_versions.status(), StatusCode::OK);
    let first_versions = json_body(first_versions).await;
    let first_len = first_versions["items"].as_array().unwrap().len();
    assert!(
        (1..50).contains(&first_len),
        "the byte limit must end this page before the item limit"
    );
    assert!(serde_json::to_vec(&first_versions).unwrap().len() <= 512 * 1024);
    let cursor = first_versions["nextCursor"].as_str().unwrap();
    let changed = format!("/api/v2/catalog/plugins/{plugin}/version-pages?generation={generation}&target=other&cursor={cursor}");
    assert_eq!(
        request(&f, None, "GET", &changed, json!({}), None)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    sqlx::query(
        "INSERT INTO cloud_release_yanks(release_id,yanked_by,reason) VALUES($1,'fixture','test')",
    )
    .bind(more_releases[8])
    .execute(&f.pool)
    .await
    .unwrap();
    let second_versions = request(
        &f,
        None,
        "GET",
        &format!("{version_prefix}&cursor={cursor}"),
        json!({}),
        None,
    )
    .await;
    assert_eq!(second_versions.status(), StatusCode::OK);
    let second_versions = json_body(second_versions).await;
    assert_eq!(
        second_versions["items"].as_array().unwrap().len(),
        71 - first_len
    );
    assert!(serde_json::to_vec(&second_versions).unwrap().len() <= 512 * 1024);
    assert!(second_versions["nextCursor"].is_null());
    let rows: Vec<_> = first_versions["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second_versions["items"].as_array().unwrap())
        .collect();
    assert_eq!(rows.len(), 71);
    assert!(rows
        .windows(2)
        .all(|v| v[0]["version"].as_str().unwrap() < v[1]["version"].as_str().unwrap()));
    assert_eq!(
        rows.iter()
            .find(|v| v["version"].as_str().unwrap().starts_with("1.0.9+"))
            .unwrap()["yanked"],
        true
    );
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn workspace_selection_accepts_legacy_ids_and_release_version_boundaries() {
    let f = fixture().await;
    let version = format!("1.0.0+{}", "a".repeat(122));
    assert_eq!(version.len(), 128);
    let valid = json!({"schemaVersion":1,"pluginId":"hotkeys","version":version,"enabled":false});
    let response = request(
        &f,
        Some(0),
        "PUT",
        "/api/v2/sync/collections/plugin-selections/hotkeys",
        valid.clone(),
        Some(("if-none-match", "*")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(json_body(response).await["value"], valid);
    let returned = request(
        &f,
        Some(0),
        "GET",
        "/api/v2/sync/collections/plugin-selections/hotkeys",
        json!({}),
        None,
    )
    .await;
    assert_eq!(returned.status(), StatusCode::OK);
    assert_eq!(json_body(returned).await["value"], valid);
    let previous_v2_key =
        json!({"schemaVersion":1,"pluginId":"1.old","version":"1.0.0","enabled":false});
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v2/sync/collections/plugin-selections/1.old",
            previous_v2_key,
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    let invalid_id = json!({"schemaVersion":1,"pluginId":"1bad","version":"1.0.0","enabled":false});
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v2/sync/collections/plugin-selections/1bad",
            invalid_id,
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let too_long = format!("1.0.0+{}", "a".repeat(123));
    let invalid_version =
        json!({"schemaVersion":1,"pluginId":"textintel","version":too_long,"enabled":false});
    assert_eq!(
        request(
            &f,
            Some(0),
            "PUT",
            "/api/v2/sync/collections/plugin-selections/textintel",
            invalid_version,
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
}

fn variable(name: &str, kind: &str, value: Value) -> Value {
    json!({"schemaVersion":1,"name":name,"type":kind,"value":value})
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn variables_collection_validates_and_uses_the_regular_sync_write_path() {
    let f = fixture().await;
    let base = "/api/v2/sync/collections/variables";
    let put = |user: usize, name: String, body: Value, condition: (&'static str, &'static str)| {
        let f = &f;
        async move {
            request(
                f,
                Some(user),
                "PUT",
                &format!("{base}/{name}"),
                body,
                Some(condition),
            )
            .await
        }
    };

    // Announced for gating, while the legacy list a deployed client checks stays as it was.
    let caps =
        json_body(request(&f, None, "GET", "/api/v2/capabilities", Value::Null, None).await).await;
    assert_eq!(caps["sync"]["collections"], json!(portable::COLLECTIONS));
    assert_eq!(caps["sync"]["optionalCollections"], json!(["variables"]));
    assert_eq!(caps["variables"]["maxTextBytes"], 4096);
    let discovered = cloud_client::CloudCatalog::new(&f.origin)
        .unwrap()
        .workspace_sync_capabilities()
        .await
        .unwrap();
    assert!(discovered.variables);

    // Every type is accepted, and creation needs If-None-Match: *.
    for (name, kind, value) in [
        ("greeting", "text", json!("hola")),
        ("commandPort", "number", json!(46665)),
        ("enabled", "boolean", json!(true)),
        ("vips", "list", json!(["ana", "luis"])),
    ] {
        let response = put(
            0,
            name.into(),
            variable(name, kind, value.clone()),
            ("if-none-match", "*"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED, "{name}");
        assert_eq!(
            response.headers()[header::ETAG],
            "\"".to_owned()
                + &(1 + ["greeting", "commandPort", "enabled", "vips"]
                    .iter()
                    .position(|n| *n == name)
                    .unwrap())
                .to_string()
                + "\""
        );
        let record = json_body(response).await;
        assert_eq!(
            (
                record["collection"].as_str(),
                record["value"]["value"].clone()
            ),
            (Some("variables"), value)
        );
    }
    assert_eq!(
        put(
            0,
            "greeting".into(),
            variable("greeting", "text", json!("x")),
            ("if-none-match", "*")
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );

    // The validation matrix. Nothing below is stored.
    let oversized_text = variable("big", "text", json!("a".repeat(4097)));
    let too_many = variable("many", "list", json!(vec!["a"; 101]));
    let long_item = variable("long", "list", json!(["a".repeat(257)]));
    let mut extra = variable("extra", "text", json!("x"));
    extra["secret"] = json!(true);
    let mut wrong_version = variable("version", "text", json!("x"));
    wrong_version["schemaVersion"] = json!(2);
    for (name, body) in [
        ("apiKey", variable("apiKey", "secret", json!("hunter2"))),
        ("pwd", variable("pwd", "password", json!("hunter2"))),
        ("typed", variable("typed", "number", json!("1"))),
        ("flag", variable("flag", "boolean", json!("true"))),
        ("text", variable("text", "text", json!(7))),
        ("nulls", variable("nulls", "text", Value::Null)),
        ("listy", variable("listy", "list", json!("a,b"))),
        ("mixed", variable("mixed", "list", json!(["a", 1]))),
        ("mismatch", variable("other", "text", json!("x"))),
        ("big", oversized_text),
        ("many", too_many),
        ("long", long_item),
        ("extra", extra),
        ("version", wrong_version),
        (
            "missing",
            json!({"schemaVersion":1,"name":"missing","type":"text"}),
        ),
        ("bearer", variable("bearer", "text", json!("Bearer abcdef"))),
    ] {
        let response = put(0, name.into(), body, ("if-none-match", "*")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{name}");
    }
    for name in [
        "9lives",
        "has%20space",
        "semi;colon",
        "dot..ok%2Fslash",
        "%C3%A9",
    ] {
        let response = put(
            0,
            name.into(),
            variable("x", "text", json!("x")),
            ("if-none-match", "*"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "key {name}");
    }
    let too_long_name = "k".repeat(65);
    assert_eq!(
        put(
            0,
            too_long_name.clone(),
            variable(&too_long_name, "text", json!("x")),
            ("if-none-match", "*")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let boundary = "k".repeat(64);
    assert_eq!(
        put(
            0,
            boundary.clone(),
            variable(&boundary, "text", json!("x")),
            ("if-none-match", "*")
        )
        .await
        .status(),
        StatusCode::CREATED
    );
    assert_eq!(
        put(
            0,
            "ok".into(),
            variable("ok", "text", json!("a".repeat(4096))),
            ("if-none-match", "*")
        )
        .await
        .status(),
        StatusCode::CREATED,
        "4 KiB of text is allowed"
    );
    assert_eq!(
        request(
            &f,
            None,
            "PUT",
            &format!("{base}/anon"),
            variable("anon", "text", json!("x")),
            Some(("if-none-match", "*"))
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );

    // Replace and delete use If-Match; a stale base conflicts; a tombstone is kept.
    let updated = put(
        0,
        "greeting".into(),
        variable("greeting", "text", json!("adios")),
        ("if-match", "\"1\""),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(json_body(updated).await["revision"], 7);
    assert_eq!(
        put(
            0,
            "greeting".into(),
            variable("greeting", "text", json!("again")),
            ("if-match", "\"1\"")
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let noop = put(
        0,
        "greeting".into(),
        variable("greeting", "text", json!("adios")),
        ("if-match", "\"7\""),
    )
    .await;
    assert_eq!(
        (noop.status(), json_body(noop).await["revision"].clone()),
        (StatusCode::OK, json!(7)),
        "an identical write keeps its revision"
    );
    let delete = request(
        &f,
        Some(0),
        "DELETE",
        &format!("{base}/enabled"),
        Value::Null,
        Some(("if-match", "\"3\"")),
    )
    .await;
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(json_body(delete).await["deleted"], true);

    // Reads: collection page, single record, change feed, export; isolated per account.
    let page = json_body(request(&f, Some(0), "GET", base, Value::Null, None).await).await;
    let keys: Vec<&str> = page["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["key"].as_str().unwrap())
        .collect();
    assert!(keys.contains(&"commandPort") && keys.contains(&"vips") && keys.contains(&"enabled"));
    assert!(
        keys.windows(2).all(|w| w[0] < w[1]),
        "ordered by byte value of the key"
    );
    let single = request(
        &f,
        Some(0),
        "GET",
        &format!("{base}/commandPort"),
        Value::Null,
        None,
    )
    .await;
    assert_eq!(single.status(), StatusCode::OK);
    let changes = json_body(
        request(
            &f,
            Some(0),
            "GET",
            "/api/v2/sync/changes?cursor=0",
            Value::Null,
            None,
        )
        .await,
    )
    .await;
    assert!(changes["changes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["collection"] == "variables"));
    let export =
        json_body(request(&f, Some(0), "GET", "/api/v2/sync/export", Value::Null, None).await)
            .await;
    assert_eq!(
        export["records"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["collection"] == "variables")
            .count(),
        6
    );
    let theirs = json_body(request(&f, Some(1), "GET", base, Value::Null, None).await).await;
    assert_eq!(theirs["records"], json!([]));
    assert_eq!(
        request(
            &f,
            Some(1),
            "GET",
            &format!("{base}/commandPort"),
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &f,
            Some(0),
            "GET",
            "/api/v2/sync/collections/secrets",
            Value::Null,
            None
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // The client SDK stages a variable end to end through the same routes.
    let session = cloud_client::Session::connect(&f.origin, f.users[1].token.clone())
        .await
        .unwrap();
    let sent = variable("sdk_value", "number", json!(1.5));
    let record = session
        .workspace_put("variables", "sdk_value", sent.clone(), None)
        .await
        .unwrap();
    assert_eq!(
        (record.collection.as_str(), record.value),
        ("variables", Some(sent))
    );
    assert!(session
        .workspace_snapshot()
        .await
        .unwrap()
        .records
        .iter()
        .any(|r| r.collection == "variables"));

    // Write-epoch fence: a stale epoch is refused with 412 and writes nothing.
    let epoch = json_body(
        request(
            &f,
            Some(0),
            "GET",
            "/api/v2/sync/write-epoch",
            Value::Null,
            None,
        )
        .await,
    )
    .await;
    let current = epoch["writeEpoch"].as_str().unwrap().to_owned();
    request(
        &f,
        Some(0),
        "POST",
        "/api/v2/sync/write-barrier",
        Value::Null,
        None,
    )
    .await;
    let fenced = f
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{base}/fenced"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &f.users[0].cookie)
                .header(header::ORIGIN, ORIGIN)
                .header("if-none-match", "*")
                .header("x-workspace-write-epoch", current.as_str())
                .body(Body::from(
                    variable("fenced", "text", json!("x")).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fenced.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn variables_share_the_record_quota_and_the_write_rate_limit() {
    let f = fixture().await;
    sqlx::query("INSERT INTO cloud_workspace_cursors(user_id,cursor) VALUES($1,1)")
        .bind(&f.users[0].id)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_workspace_records(user_id,collection,key,revision,value,deleted) SELECT $1,'variables','v'||n,1,jsonb_build_object('schemaVersion',1,'name','v'||n,'type','number','value',n),false FROM generate_series(1,1000) n").bind(&f.users[0].id).execute(&f.pool).await.unwrap();
    let blocked = request(
        &f,
        Some(0),
        "PUT",
        "/api/v2/sync/collections/variables/extra",
        variable("extra", "text", json!("x")),
        Some(("if-none-match", "*")),
    )
    .await;
    assert_eq!(
        blocked.status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "variables count toward the 1,000 records"
    );
    let other_collection = request(
        &f,
        Some(0),
        "PUT",
        "/api/v2/sync/collections/preferences/desktop",
        json!({"schemaVersion":1}),
        Some(("if-none-match", "*")),
    )
    .await;
    assert_eq!(other_collection.status(), StatusCode::INSUFFICIENT_STORAGE);
    // The write limit (120 a minute) covers variables like every other collection.
    let path = "/api/v2/sync/collections/variables/limited";
    let mut last = StatusCode::OK;
    for _ in 0..121 {
        last = request(
            &f,
            Some(1),
            "PUT",
            path,
            variable("limited", "text", json!("x")),
            Some(("if-none-match", "*")),
        )
        .await
        .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

fn profile_of(template: Value) -> Value {
    json!({"profileVersion":1,"id":"gift-pack","name":"Gift pack","templates":[{"template":template}]})
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn forking_a_public_document_copies_it_privately_with_metadata_provenance() {
    let f = fixture().await;
    let (author, moderator, forker) = (0, 1, 2);
    sqlx::query("INSERT INTO cloud_account_roles(user_id,role) VALUES($1,'moderator')")
        .bind(&f.users[moderator].id)
        .execute(&f.pool)
        .await
        .unwrap();
    let author_session = cloud_client::Session::connect(&f.origin, f.users[author].token.clone())
        .await
        .unwrap();
    let forker_session = cloud_client::Session::connect(&f.origin, f.users[forker].token.clone())
        .await
        .unwrap();
    let fork = |user: Option<usize>, id: String, body: Value| {
        let f = &f;
        async move {
            request(
                f,
                user,
                "POST",
                &format!("/api/v2/catalog/documents/{id}/fork"),
                body,
                None,
            )
            .await
        }
    };
    let publish = |id: uuid::Uuid, revision: i64| {
        let f = &f;
        async move {
            let response = request(
                f,
                Some(moderator),
                "POST",
                &format!("/api/v2/moderation/documents/{id}/versions/{revision}/decision"),
                json!({"decision":"approve","reason":"Reviewed portable actions"}),
                None,
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
    };

    // Not publicly visible: draft, pending, unknown, and unauthenticated callers.
    let created = author_session
        .library_create("template", template())
        .await
        .unwrap();
    let id = uuid::Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    assert_eq!(
        fork(Some(forker), id.to_string(), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "draft"
    );
    author_session.library_submit(id, 1).await.unwrap();
    assert_eq!(
        fork(Some(forker), id.to_string(), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "pending"
    );
    assert_eq!(
        fork(Some(forker), uuid::Uuid::new_v4().to_string(), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fork(None, id.to_string(), Value::Null).await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fork(Some(forker), "not-a-uuid".into(), Value::Null)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    publish(id, 1).await;

    // Body validation: the only accepted field is a positive revision.
    for body in [
        json!({"revision":0}),
        json!({"revision":-1}),
        json!({"parent":"x"}),
        json!({"revision":"1"}),
    ] {
        assert_eq!(
            fork(Some(forker), id.to_string(), body.clone())
                .await
                .status(),
            StatusCode::BAD_REQUEST,
            "{body}"
        );
    }
    assert_eq!(
        fork(Some(forker), id.to_string(), json!({"revision":2}))
            .await
            .status(),
        StatusCode::NOT_FOUND,
        "revision 2 is not published"
    );

    // The fork: a new private draft in the caller's library, same ack shape plus forkOf.
    let response = fork(Some(forker), id.to_string(), json!({})).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::ETAG], "\"1\"");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let ack = json_body(response).await;
    assert_eq!(
        (ack["revision"].clone(), ack["status"].clone()),
        (json!(1), json!("draft"))
    );
    assert_eq!(ack["forkOf"], json!({"documentId": id, "revision": 1}));
    let copy = uuid::Uuid::parse_str(ack["id"].as_str().unwrap()).unwrap();
    assert_ne!(copy, id);
    let mut keys: Vec<_> = ack.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["forkOf", "id", "revision", "status"]);

    // Own reads and lists expose forkOf; the portable value is byte-identical to the source.
    let own = forker_session.library_document(copy).await.unwrap();
    assert_eq!(own["forkOf"], json!({"documentId": id, "revision": 1}));
    assert_eq!(
        own["document"],
        template(),
        "provenance is not inside the portable value"
    );
    assert!(portable::document("template", &own["document"]));
    assert_eq!(
        (own["status"].as_str(), own["slug"].as_str()),
        (Some("draft"), Some("gift-rule"))
    );
    let listed = forker_session.library_documents(None).await.unwrap();
    assert_eq!(listed["items"][0]["forkOf"]["documentId"], id.to_string());
    let versions = forker_session.library_versions(copy, None).await.unwrap();
    assert_eq!(versions["items"][0]["forkOf"]["revision"], 1);
    assert_eq!(
        forker_session.library_version(copy, 1).await.unwrap()["forkOf"]["documentId"],
        id.to_string()
    );
    let export = forker_session.export_account_v2().await.unwrap();
    assert_eq!(
        export["library"]["items"][0]["forkOf"]["documentId"],
        id.to_string()
    );
    // Documents without provenance are unchanged; the public catalog never shows it.
    assert!(author_session
        .library_document(id)
        .await
        .unwrap()
        .get("forkOf")
        .is_none());
    let public = cloud_client::CloudCatalog::new(&f.origin)
        .unwrap()
        .document(id, None)
        .await
        .unwrap();
    assert!(public.get("forkOf").is_none());
    // The author's other private documents stay out of reach; the forker cannot read the source privately.
    assert!(matches!(
        forker_session.library_document(id).await,
        Err(cloud_client::SyncError::Http(404))
    ));
    // The copy is an ordinary draft: editable, and independent of the source.
    let mut edited = template();
    edited["title"] = json!("My gift rule");
    forker_session
        .library_update(copy, "template", edited, 1)
        .await
        .unwrap();
    assert_eq!(
        forker_session.library_document(copy).await.unwrap()["forkOf"]["revision"],
        1
    );
    assert_eq!(
        cloud_client::CloudCatalog::new(&f.origin)
            .unwrap()
            .document(id, None)
            .await
            .unwrap()["document"],
        template()
    );

    // Forking twice (or onto an existing id) conflicts instead of overwriting.
    assert_eq!(
        fork(Some(forker), id.to_string(), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        fork(Some(author), id.to_string(), Value::Null)
            .await
            .status(),
        StatusCode::CONFLICT,
        "the author already owns that id"
    );

    // A newer public revision: the default follows it, an older published one can be named.
    let mut second = template();
    second["title"] = json!("Gift rule v2");
    author_session
        .library_update(id, "template", second.clone(), 1)
        .await
        .unwrap();
    author_session.library_submit(id, 2).await.unwrap();
    publish(id, 2).await;
    sqlx::query("DELETE FROM cloud_library_documents WHERE id=$1")
        .bind(copy)
        .execute(&f.pool)
        .await
        .unwrap();
    let latest = json_body(fork(Some(forker), id.to_string(), Value::Null).await).await;
    assert_eq!(latest["forkOf"]["revision"], 2);
    let latest_id = uuid::Uuid::parse_str(latest["id"].as_str().unwrap()).unwrap();
    assert_eq!(
        forker_session.library_document(latest_id).await.unwrap()["document"],
        second
    );
    sqlx::query("DELETE FROM cloud_library_documents WHERE id=$1")
        .bind(latest_id)
        .execute(&f.pool)
        .await
        .unwrap();
    let pinned = json_body(fork(Some(forker), id.to_string(), json!({"revision":1})).await).await;
    assert_eq!(pinned["forkOf"]["revision"], 1);
    let pinned_id = uuid::Uuid::parse_str(pinned["id"].as_str().unwrap()).unwrap();
    assert_eq!(
        forker_session.library_document(pinned_id).await.unwrap()["document"],
        template()
    );

    // Withdrawn revisions are no longer public and cannot be forked.
    author_session
        .library_withdraw(id, 2, "Replace outdated guidance")
        .await
        .unwrap();
    assert_eq!(
        fork(Some(forker), id.to_string(), json!({"revision":2}))
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    // Deleting the source clears provenance on the fork instead of dangling or blocking.
    author_session
        .library_withdraw(id, 1, "Retired")
        .await
        .unwrap();
    assert_eq!(
        fork(Some(forker), id.to_string(), Value::Null)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    author_session.library_delete(id, 2).await.unwrap();
    let orphan = forker_session.library_document(pinned_id).await.unwrap();
    assert!(orphan.get("forkOf").is_none(), "{orphan}");
    assert_eq!(orphan["document"], template());

    // Profiles fork the same way.
    let profile = profile_of(template());
    let created = author_session
        .library_create("profile", profile.clone())
        .await
        .unwrap();
    let profile_id = uuid::Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    author_session.library_submit(profile_id, 1).await.unwrap();
    publish(profile_id, 1).await;
    let forked = json_body(fork(Some(forker), profile_id.to_string(), Value::Null).await).await;
    let forked_id = uuid::Uuid::parse_str(forked["id"].as_str().unwrap()).unwrap();
    let forked_profile = forker_session.library_document(forked_id).await.unwrap();
    assert_eq!(
        (
            forked_profile["kind"].as_str(),
            forked_profile["document"].clone()
        ),
        (Some("profile"), profile)
    );
    assert_eq!(
        forked_profile["forkOf"]["documentId"],
        profile_id.to_string()
    );
    // Profiles stay portable-only: no branch or parent field exists to set.
    assert!(!portable::document("profile", &{
        let mut p = profile_of(template());
        p["parentId"] = json!(profile_id);
        p
    }));
}

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL database in CLOUD_TEST_DATABASE_URL"]
async fn fork_respects_library_quotas_and_the_write_rate_limit() {
    let f = fixture().await;
    let (author, forker, limited) = (0, 1, 2);
    let id = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO cloud_library_documents(id,owner_user_id,kind,slug) VALUES($1,$2,'template','gift-rule')").bind(id).bind(&f.users[author].id).execute(&f.pool).await.unwrap();
    // The stored digest must be the one the API computes for the stored value.
    let stored: Value = sqlx::query_scalar("SELECT $1::jsonb")
        .bind(template())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO cloud_library_versions(document_id,revision,title,document,sha256,status) VALUES($1,1,'Gift rule',$2,$3,'published')").bind(id).bind(&stored).bind(crate::library::digest(&stored)).execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE cloud_library_documents SET published_revision=1 WHERE id=$1")
        .bind(id)
        .execute(&f.pool)
        .await
        .unwrap();
    let path = format!("/api/v2/catalog/documents/{id}/fork");

    // 100 documents per account: the 101st (fork) is refused with 507.
    sqlx::query("INSERT INTO cloud_library_documents(id,owner_user_id,kind,slug) SELECT gen_random_uuid(),$1,'template','fill-'||n FROM generate_series(1,100) n").bind(&f.users[forker].id).execute(&f.pool).await.unwrap();
    assert_eq!(
        request(&f, Some(forker), "POST", &path, Value::Null, None)
            .await
            .status(),
        StatusCode::INSUFFICIENT_STORAGE
    );
    sqlx::query("DELETE FROM cloud_library_documents WHERE owner_user_id=$1 AND slug='fill-1'")
        .bind(&f.users[forker].id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        request(&f, Some(forker), "POST", &path, Value::Null, None)
            .await
            .status(),
        StatusCode::CREATED
    );
    // Overlays and packages never count toward the template/profile quota.
    sqlx::query(
        "DELETE FROM cloud_library_documents WHERE owner_user_id=$1 AND slug LIKE 'fill-%'",
    )
    .bind(&f.users[forker].id)
    .execute(&f.pool)
    .await
    .unwrap();

    // 8 MiB of stored template/profile bytes per account.
    sqlx::query("INSERT INTO cloud_library_documents(id,owner_user_id,kind,slug) VALUES($1,$2,'template','heavy')").bind(uuid::Uuid::from_u128(9)).bind(&f.users[author].id).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO cloud_library_versions(document_id,revision,title,document,sha256,status) VALUES($1,1,'Heavy',jsonb_build_object('pad',repeat('x',8388500)),$2,'draft')").bind(uuid::Uuid::from_u128(9)).bind("0".repeat(64)).execute(&f.pool).await.unwrap();
    assert_eq!(
        request(&f, Some(author), "POST", &path, Value::Null, None)
            .await
            .status(),
        StatusCode::INSUFFICIENT_STORAGE,
        "bytes quota, checked before the slug conflict"
    );

    // The 60 a minute write limit (shared with the other library writes).
    let missing = format!("/api/v2/catalog/documents/{}/fork", uuid::Uuid::new_v4());
    let mut last = StatusCode::OK;
    for _ in 0..61 {
        last = request(&f, Some(limited), "POST", &missing, Value::Null, None)
            .await
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}
