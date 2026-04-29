//! envsd — long-running daemon for envs.

mod audit;
mod binary;
mod cache;
mod config;
mod discovery;
mod error;
mod handlers;
mod helper;
mod llm;
mod peer;
mod persistence;
mod rbw;
mod registry;
mod rule;
mod server;

use crate::cache::{RuleCache, ValueCache};
use crate::handlers::Handlers;
use crate::helper::HelperHandle;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "envsd starting");
    let _ = audit::event("daemon_start")
        .field("version", env!("CARGO_PKG_VERSION"))
        .write();

    // Load persisted rules (filtering expired).
    let initial_rules = persistence::load().unwrap_or_else(|e| {
        tracing::warn!(?e, "could not load rules.toml, starting empty");
        Vec::new()
    });
    tracing::info!(count = initial_rules.len(), "loaded persisted rules");

    // Lazy registry sync (skip if fresh < 7 days; ignore network errors).
    if std::env::var_os("ENVS_SKIP_REGISTRY_SYNC").is_none() {
        tokio::spawn(async {
            match registry::sync(false).await {
                Ok(result) => tracing::info!(?result, "registry sync"),
                Err(e) => tracing::debug!(?e, "registry sync failed (non-fatal)"),
            }
        });
    }

    let rule_cache = Arc::new(RuleCache::new(initial_rules));
    let value_cache = Arc::new(ValueCache::new(Duration::from_secs(30)));

    // Spawn helper (stub mode unless explicitly real).
    let helper = if std::env::var("ENVS_HELPER_STUB").is_ok() {
        tracing::info!("helper: stub mode (ENVS_HELPER_STUB set)");
        Arc::new(HelperHandle::stub())
    } else {
        match HelperHandle::spawn_real().await {
            Ok(h) => Arc::new(h),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "envs-prompt subprocess unavailable, falling back to stub"
                );
                Arc::new(HelperHandle::stub())
            }
        }
    };

    let handlers = Arc::new(Handlers {
        rule_cache: rule_cache.clone(),
        value_cache: value_cache.clone(),
        helper: helper.clone(),
        started_at: Instant::now(),
        rbw_mutex: Arc::new(tokio::sync::Mutex::new(())),
    });

    // Sweep task: every 30s, purge expired rules and value cache entries.
    {
        let rc = rule_cache.clone();
        let vc = value_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.tick().await; // skip the immediate tick
            loop {
                interval.tick().await;
                let purged = rc.sweep_expired().await;
                for id in purged {
                    let _ = audit::event("expired_sweep").field("rule_id", &id).write();
                }
                let v_purged = vc.sweep_expired().await;
                if v_purged > 0 {
                    tracing::debug!(count = v_purged, "swept expired value cache entries");
                }
            }
        });
    }

    // UDS server.
    let socket = server::socket_path()?;
    let server_task = tokio::spawn(server::run(handlers.clone(), socket.clone()));

    // Signal handling for graceful shutdown.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("SIGTERM received");
        }
        _ = sigint.recv() => {
            tracing::info!("SIGINT received");
        }
        res = server_task => {
            tracing::warn!(?res, "server task exited unexpectedly");
        }
    }

    // Graceful shutdown.
    tracing::info!("shutting down");
    let _ = audit::event("daemon_stop").write();
    let snapshot = rule_cache.snapshot().await;
    if let Err(e) = persistence::save(&snapshot) {
        tracing::warn!(?e, "failed to save rules on shutdown");
    }
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }

    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("envsd=info,envs_daemon=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
