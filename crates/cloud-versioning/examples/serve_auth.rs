//! Runs the embedded engine with authenticated native endpoints, plus a loopback helper that
//! publishes the key set and mints tokens, for evaluating isolation with the Lore CLI.
//!
//! The mint endpoint hands a token to anyone who can reach it. It exists only to drive this
//! evaluation: in the backend, minting sits behind Better Auth and the repository policy.
//!
//! `cargo run -p cloud-versioning --example serve_auth -- <data-dir> <127.0.0.1:port>`
//! JWKS and `GET /mint?sub=<s>&repo=<hex|*>&actions=read,write` are served on `port + 1`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::Router;
use cloud_versioning::bridge::{CredentialBridge, NativeAuth, RepositoryGrant};
use cloud_versioning::{VersioningConfig, VersioningHost};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("data directory");
    let address: std::net::SocketAddr = args.next().expect("loopback address").parse()?;
    anyhow::ensure!(address.ip().is_loopback(), "loopback only");
    let helper = std::net::SocketAddr::new(address.ip(), address.port() + 1);

    let bridge = Arc::new(CredentialBridge::generate(
        &format!("http://{helper}"),
        "remake-versioning",
    )?);
    let app = Router::new()
        .route(
            "/jwks.json",
            get(|State(bridge): State<Arc<CredentialBridge>>| async move { bridge.jwks_json() }),
        )
        .route(
            "/mint",
            get(
                |State(bridge): State<Arc<CredentialBridge>>,
                 Query(query): Query<HashMap<String, String>>| async move {
                    let repository_id = match query.get("repo").map(String::as_str) {
                        Some("*") | None => None,
                        Some(id) => Some(id.to_string()),
                    };
                    let actions = query
                        .get("actions")
                        .map_or("read", String::as_str)
                        .split(',')
                        .map(str::to_string)
                        .collect();
                    bridge
                        .mint(
                            query.get("sub").map_or("anonymous", String::as_str),
                            &[RepositoryGrant {
                                repository_id,
                                actions,
                            }],
                            300,
                        )
                        .unwrap_or_else(|error| format!("error: {error:#}"))
                },
            ),
        )
        .with_state(bridge.clone());
    let listener = tokio::net::TcpListener::bind(helper).await?;
    tokio::spawn(async move { axum::serve(listener, app).await });

    let host = VersioningHost::start(VersioningConfig {
        data_dir: data_dir.into(),
        native_listen: Some(address),
        native_auth: Some(NativeAuth {
            issuer: bridge.issuer().to_string(),
            audience: bridge.audience().to_string(),
            jwks_url: format!("http://{helper}/jwks.json"),
        }),
    })
    .await?;
    println!("serving on {address}, helper on {helper}; Ctrl-C to stop");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    host.stop().await
}
