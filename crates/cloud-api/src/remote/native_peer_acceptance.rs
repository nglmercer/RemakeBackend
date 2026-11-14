//! Launch the real native SDK against this disposable PostgreSQL-backed server.
//! Enabled only for the explicit cross-repository acceptance runner.
use super::*;
use tokio::io::AsyncBufReadExt;

#[tokio::test]
#[ignore = "requires scripts/collaboration-cloud-lab.py from the native app checkout"]
async fn native_app_cloud_onboarding_reaches_real_host() {
    run(false).await;
}

#[tokio::test]
#[ignore = "requires scripts/collaboration-cloud-lab.py from the native app checkout"]
async fn native_app_cloud_falls_back_to_native_relay() {
    run(true).await;
}

#[cfg(feature = "native-cli-acceptance")]
#[tokio::test]
#[ignore = "requires the headless Teams runner, compiled CLI and disposable database"]
async fn native_cli_teams_end_to_end() {
    run_mode(false, true).await;
}

async fn run(relay_only: bool) {
    run_mode(relay_only, false).await;
}

async fn run_mode(relay_only: bool, cli: bool) {
    if cli {
        // The CLI scenario creates real identities and grants. Only the
        // disposable loopback cluster provisioned by the lab is admissible.
        let database = std::env::var("CLOUD_TEST_DATABASE_URL").expect("isolated database URL");
        let database = url::Url::parse(&database).expect("valid isolated database URL");
        let data = std::path::PathBuf::from(
            std::env::var_os("REMAKE_DEV_DATA_DIR").expect("isolated cluster directory"),
        );
        assert!(
            matches!(database.scheme(), "postgres" | "postgresql")
                && database.host_str() == Some("127.0.0.1")
                && database.port().is_some()
                && database.path() == "/postgres"
                && data.is_absolute()
                && data
                    .parent()
                    .and_then(|p| p.file_name())
                    .and_then(|p| p.to_str())
                    .is_some_and(|name| name.starts_with("tiktools-cloud-native-")),
            "CLI acceptance requires the private loopback lab"
        );
    }
    let executable = std::env::var_os(if cli {
        "TIKTOOLS_CLI_ACCEPTANCE_BINARY"
    } else {
        "TIKTOOLS_PEER_ACCEPTANCE_TEST_BINARY"
    })
    .expect("native test executable must be supplied by the isolated runner");
    assert!(std::path::Path::new(&executable).is_absolute());
    let f = fixture_with_peer(
        if cli { 3 } else { 2 },
        crate::remote::peers::PeerConfig {
            relay_only,
            ..Default::default()
        },
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("native-fixture.json");
    let control = directory.path().join("cloud-control");
    std::fs::write(&control, "online").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let upstream = f
        .ws_url
        .strip_suffix("/api/v3/remote/socket")
        .unwrap()
        .replacen("ws://", "http://", 1);
    let required =
        |name| std::env::var_os(name).expect("runner must provide isolated TLS material");
    let mut proxy = tokio::process::Command::new("python3")
        .arg(required("TIKTOOLS_PEER_ACCEPTANCE_TLS_PROXY"))
        .arg("--upstream")
        .arg(upstream)
        .arg("--cert")
        .arg(required("TIKTOOLS_PEER_ACCEPTANCE_TLS_CERT"))
        .arg("--key")
        .arg(required("TIKTOOLS_PEER_ACCEPTANCE_TLS_KEY"))
        .arg("--port")
        .arg(std::env::var("TIKTOOLS_PEER_ACCEPTANCE_PROXY_PORT").unwrap_or_else(|_| "0".into()))
        .arg("--control")
        .arg(&control)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut reader = tokio::io::BufReader::new(proxy.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let port: u16 = line
        .trim()
        .parse()
        .expect("TLS fixture must publish its loopback port");
    let origin = format!("https://127.0.0.1:{port}");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(&path).unwrap();
    let mut input = json!({
        "origin":origin,"browserOrigin":ORIGIN,"cloudControlPath":control,
        "ownerCookie":f.users[0].cookie,"moderatorCookie":f.users[1].cookie
    });
    if cli {
        input["runId"] =
            json!(std::env::var("TIKTOOLS_CLI_ACCEPTANCE_RUN_ID").expect("isolated run identity"));
        input["outsiderCookie"] = json!(f.users[2].cookie);
        let email: String = sqlx::query_scalar(r#"SELECT email FROM "user" WHERE id=$1"#)
            .bind(&f.users[1].id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
        input["moderatorNickname"] = json!(email.split('@').next().unwrap());
        input["moderatorId"] = json!(f.users[1].id);
    }
    serde_json::to_writer(file, &input).unwrap();
    let mut command = if cli {
        let mut command = tokio::process::Command::new(required("TIKTOOLS_CLI_ACCEPTANCE_BUN"));
        command
            .arg(required("TIKTOOLS_CLI_ACCEPTANCE_SCRIPT"))
            .arg("--binary")
            .arg(&executable)
            .arg("--fixture")
            .arg(&path)
            .arg("--report")
            .arg(required("TIKTOOLS_CLI_ACCEPTANCE_REPORT"));
        command
    } else {
        let mut command = tokio::process::Command::new(&executable);
        command.args([
            "--ignored",
            "--exact",
            if relay_only {
                "cloud_onboarding_uses_relay_when_webrtc_unavailable"
            } else {
                "cloud_onboarding_reaches_the_real_native_host"
            },
            "--nocapture",
        ]);
        command
    };
    let child = command
        .env("TIKTOOLS_PEER_ACCEPTANCE_CONFIG", &path)
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(if cli { 240 } else { 120 }), child)
        .await
        .expect("native fixture must finish before its deadline")
        .unwrap();
    assert!(
        output.status.success(),
        "native SDK acceptance failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if relay_only {
        let tunnels: i64 =
            sqlx::query_scalar("SELECT count(*) FROM cloud_remote_relay_tunnels WHERE answered")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(
            tunnels > 0,
            "the normal native SDK must establish an authenticated relay tunnel"
        );
        let commands: i64 = sqlx::query_scalar("SELECT count(*) FROM cloud_remote_commands")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(
            commands, 0,
            "native relay RPC must never execute as a backend command"
        );
    }
    // CLI mode owns the entire disposable cluster. The lab stops it and
    // removes its data directory, rather than deleting users through SQL
    // with an incomplete understanding of every remote-control foreign key.
    proxy.kill().await.unwrap();
    proxy.wait().await.unwrap();
}
