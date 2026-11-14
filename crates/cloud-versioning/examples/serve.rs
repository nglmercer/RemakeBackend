//! Runs the embedded versioning engine with Lore's native endpoints on a loopback address,
//! for evaluating the Lore CLI against it. The endpoint is unauthenticated: local use only.
//!
//! `cargo run -p cloud-versioning --example serve -- <data-dir> <127.0.0.1:port>`

use cloud_versioning::{VersioningConfig, VersioningHost};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let data_dir = args.next().expect("data directory");
    let address: std::net::SocketAddr = args.next().expect("loopback address").parse()?;
    anyhow::ensure!(
        address.ip().is_loopback(),
        "the unauthenticated endpoint must bind a loopback address"
    );
    let host = VersioningHost::start(VersioningConfig {
        data_dir: data_dir.into(),
        native_listen: Some(address),
        native_auth: None,
    })
    .await?;
    println!("serving on {address}; Ctrl-C to stop");
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    host.stop().await
}
