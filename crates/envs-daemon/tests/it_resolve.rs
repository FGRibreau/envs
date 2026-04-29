//! Black-box integration tests against a real Vaultwarden + real rbw.
//!
//! No mocks. Each test spins up its own vaultwarden via testcontainers,
//! registers a fresh account, and drives `envsd` end-to-end.

mod common;

use common::{resolve_request_for, send, start_daemon, VaultFixture};
use envs_proto::{ArgvMatch, Request, Response};

#[serial_test::serial]
#[tokio::test]
async fn ping_pong() {
    let fx = VaultFixture::start().await;
    let h = start_daemon(fx);
    let resp = send(&h.socket, &Request::Ping).await;
    assert!(matches!(resp, Response::Pong), "got {resp:?}");
}

#[serial_test::serial]
#[tokio::test]
async fn status_reports_version() {
    let fx = VaultFixture::start().await;
    let h = start_daemon(fx);
    let resp = send(&h.socket, &Request::Status).await;
    match resp {
        Response::Status {
            version, protocol, ..
        } => {
            assert!(!version.is_empty());
            assert_eq!(protocol, envs_proto::PROTOCOL_VERSION);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn resolve_returns_value_from_real_vault() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("TEST_KEY", "vault-resolved-value");
    fx.write_profile("envsd", &[("TEST_KEY", "rbw://TEST_KEY")]);

    let h = start_daemon(fx);
    let canon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let resp = send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await;

    match resp {
        Response::Resolved { entries, .. } => {
            assert_eq!(entries.len(), 1, "got {entries:?}");
            assert_eq!(entries[0].key, "TEST_KEY");
            assert_eq!(entries[0].value, "vault-resolved-value");
        }
        Response::Error { code, message } => {
            panic!("expected Resolved, got Error {code:?}: {message}");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn auto_lock_locks_rbw_after_resolve() {
    // Vault unlocked at start, has an item; after a successful Resolve the
    // daemon must auto-lock rbw (the v0.5 feature, end-to-end against a real
    // vault not a shim).
    let fx = VaultFixture::start().await;
    fx.rbw_add("LOCK_TEST", "lock-test-secret");
    fx.write_profile("envsd", &[("LOCK_TEST", "rbw://LOCK_TEST")]);

    let h = start_daemon(fx);
    let canon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let resp = send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await;
    assert!(
        matches!(resp, Response::Resolved { .. }),
        "expected Resolved, got {resp:?}"
    );

    assert!(
        !h.rbw_unlocked(),
        "vault should be locked after resolve (auto_lock)"
    );
}

#[serial_test::serial]
#[tokio::test]
async fn auto_unlock_retries_on_locked_vault() {
    // Vault locked at start; daemon must auto-unlock and produce the value.
    // Proving auto_unlock fired without log files: the only way Resolved came
    // back with the right value is unlock → get → lock all happened.
    let fx = VaultFixture::start().await;
    fx.rbw_add("AUTO_UNLOCK", "auto-unlock-secret");
    fx.write_profile("envsd", &[("AUTO_UNLOCK", "rbw://AUTO_UNLOCK")]);
    fx.rbw_lock(); // pre-condition: vault locked before envsd starts

    let h = start_daemon(fx);
    let canon = std::path::PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let resp = send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await;

    match resp {
        Response::Resolved { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].key, "AUTO_UNLOCK");
            assert_eq!(entries[0].value, "auto-unlock-secret");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
    // Post-condition: re-locked.
    assert!(
        !h.rbw_unlocked(),
        "vault should end locked after auto_unlock+resolve"
    );
}

#[serial_test::serial]
#[tokio::test]
async fn argv_match_proto_roundtrip() {
    let fx = VaultFixture::start().await;
    let h = start_daemon(fx);
    let resp = send(&h.socket, &Request::ListRules).await;
    match resp {
        Response::Rules { rules } => assert!(rules.is_empty()),
        other => panic!("expected Rules, got {other:?}"),
    }
    let _ = ArgvMatch::Any;
}
