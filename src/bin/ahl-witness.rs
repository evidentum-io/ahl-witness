//! `ahl-witness` server binary: load a deployment configuration, open the store, and serve
//! the witness's HTTP API.

#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
// See ahl-core's Cargo.toml and this crate's lib.rs for the rationale: transitive deps pull
// both syn 2.x/3.x and thiserror 1.x/2.x. Not actionable from this binary.
#![allow(clippy::multiple_crate_versions)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ahl_witness::config::{Deployment, DeploymentSpec};
use ahl_witness::http::{router, AppState};
use ahl_witness::store::Store;
use clap::Parser;

/// Command-line arguments for the `ahl-witness` server.
#[derive(Parser, Debug)]
#[command(about = "Independent AHL witness for the ahl-adaptor-atl-v1 profile")]
struct Args {
    /// Path to a JSON deployment configuration file (see README.md for the shape).
    #[arg(long)]
    config: PathBuf,

    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8081")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let raw = std::fs::read_to_string(&args.config)?;
    let spec: DeploymentSpec = serde_json::from_str(&raw)?;
    let deployment = Deployment::resolve(&spec)?;
    let store = Store::open(Path::new(&deployment.store_path))?;

    let state = AppState {
        store: Arc::new(store),
        signer: Arc::new(deployment.signer),
        anchors: Arc::new(deployment.anchors),
    };
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(listen = %args.listen, "ahl-witness listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

/// Resolve once either Ctrl-C or, on Unix, SIGTERM is received, so the server can drain and
/// exit cleanly rather than dropping in-flight connections.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if let Ok(mut signal) = signal {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
