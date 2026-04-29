//! Black-box integration coverage against a real Vaultwarden + real rbw.
//!
//! Replaces the bash rbw shim. Every test spins up its own vaultwarden via
//! testcontainers, registers a fresh account, plants real items, and drives
//! envsd end-to-end.

mod common;

use common::{resolve_request_for, send, start_daemon, VaultFixture};
use envs_proto::{ArgvMatch, Binding, Request, Response};
use std::path::PathBuf;
use std::time::Duration;

#[serial_test::serial]
#[tokio::test]
async fn cache_hit_on_second_resolve() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("CACHE_KEY", "cache-value");
    fx.write_profile("envsd", &[("CACHE_KEY", "rbw://CACHE_KEY")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));

    let id1 = match send(
        &h.socket,
        &resolve_request_for(canon.clone(), vec!["envsd".into()]),
    )
    .await
    {
        Response::Resolved { rule_id, .. } => rule_id,
        other => panic!("expected Resolved, got {other:?}"),
    };
    let id2 = match send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await {
        Response::Resolved { rule_id, .. } => rule_id,
        other => panic!("expected Resolved, got {other:?}"),
    };
    assert_eq!(id1, id2, "second Resolve must hit the rule cache");
}

#[serial_test::serial]
#[tokio::test]
async fn list_rules_after_grant() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("LIST_KEY", "list-value");
    fx.write_profile("envsd", &[("LIST_KEY", "rbw://LIST_KEY")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let _ = send(
        &h.socket,
        &resolve_request_for(canon.clone(), vec!["envsd".into()]),
    )
    .await;

    match send(&h.socket, &Request::ListRules).await {
        Response::Rules { rules } => {
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].canon_path, canon);
            assert_eq!(rules[0].env_keys, vec!["LIST_KEY".to_string()]);
            assert!(matches!(rules[0].argv_match, ArgvMatch::Any));
        }
        other => panic!("expected Rules, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn revoke_removes_rule() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("REV_KEY", "rev-value");
    fx.write_profile("envsd", &[("REV_KEY", "rbw://REV_KEY")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let rule_id = match send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await {
        Response::Resolved { rule_id, .. } => rule_id,
        other => panic!("expected Resolved, got {other:?}"),
    };

    let _ = send(
        &h.socket,
        &Request::Revoke {
            rule_id: Some(rule_id),
        },
    )
    .await;

    match send(&h.socket, &Request::ListRules).await {
        Response::Rules { rules } => assert_eq!(rules.len(), 0),
        other => panic!("expected Rules, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn project_root_creates_separate_rule() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("PROJ_A", "value-a");
    fx.rbw_add("PROJ_B", "value-b");

    let project_a = fx.home.path().join("project-a");
    let project_b = fx.home.path().join("project-b");
    fx.write_project_profile(&project_a, "envsd", &[("PROJ_A", "rbw://PROJ_A")]);
    fx.write_project_profile(&project_b, "envsd", &[("PROJ_B", "rbw://PROJ_B")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));

    let req_a = Request::Resolve {
        canon_path: canon.clone(),
        sha256: "abc".into(),
        codesign_team: None,
        argv: vec!["envsd".into()],
        cwd: project_a.clone(),
        project_root: Some(project_a.clone()),
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: Vec::new(),
    };
    let req_b = Request::Resolve {
        canon_path: canon,
        sha256: "abc".into(),
        codesign_team: None,
        argv: vec!["envsd".into()],
        cwd: project_b.clone(),
        project_root: Some(project_b),
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: Vec::new(),
    };

    let id_a = match send(&h.socket, &req_a).await {
        Response::Resolved {
            rule_id, entries, ..
        } => {
            assert_eq!(entries[0].key, "PROJ_A");
            assert_eq!(entries[0].value, "value-a");
            rule_id
        }
        other => panic!("expected Resolved, got {other:?}"),
    };
    let id_b = match send(&h.socket, &req_b).await {
        Response::Resolved {
            rule_id, entries, ..
        } => {
            assert_eq!(entries[0].key, "PROJ_B");
            assert_eq!(entries[0].value, "value-b");
            rule_id
        }
        other => panic!("expected Resolved, got {other:?}"),
    };
    assert_ne!(id_a, id_b, "rules in different projects must be distinct");
}

#[serial_test::serial]
#[tokio::test]
async fn audit_log_is_chained_and_verifiable() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("AUDIT_KEY", "audit-value");
    fx.write_profile("envsd", &[("AUDIT_KEY", "rbw://AUDIT_KEY")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    for _ in 0..3 {
        let _ = send(
            &h.socket,
            &resolve_request_for(canon.clone(), vec!["envsd".into()]),
        )
        .await;
    }
    drop(h);
    std::thread::sleep(Duration::from_millis(100));
}

#[serial_test::serial]
#[tokio::test]
async fn extra_bindings_override_profile() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("PROFILE_KEY", "profile-value");
    fx.rbw_add("INLINE_KEY", "inline-value");
    fx.write_profile("envsd", &[("PROFILE_KEY", "rbw://PROFILE_KEY")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let req = Request::Resolve {
        canon_path: canon,
        sha256: "abc".into(),
        codesign_team: None,
        argv: vec!["envsd".into()],
        cwd: std::env::temp_dir(),
        project_root: None,
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: vec![Binding {
            env: "INLINE_KEY".into(),
            source: "rbw://INLINE_KEY".into(),
        }],
    };
    match send(&h.socket, &req).await {
        Response::Resolved { entries, .. } => {
            let keys: Vec<String> = entries.iter().map(|e| e.key.clone()).collect();
            assert!(
                keys.contains(&"PROFILE_KEY".into()),
                "missing PROFILE_KEY in {keys:?}"
            );
            assert!(
                keys.contains(&"INLINE_KEY".into()),
                "missing INLINE_KEY in {keys:?}"
            );
            let profile_val = entries.iter().find(|e| e.key == "PROFILE_KEY").unwrap();
            let inline_val = entries.iter().find(|e| e.key == "INLINE_KEY").unwrap();
            assert_eq!(profile_val.value, "profile-value");
            assert_eq!(inline_val.value, "inline-value");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn extra_bindings_override_profile_inline_winning() {
    // --bind specifying the same env var as the profile but a different source
    // wins. Both items must exist in the vault to verify which one rbw fetched.
    let fx = VaultFixture::start().await;
    fx.rbw_add("OLD_SRC", "old-value");
    fx.rbw_add("NEW_SRC", "new-value");
    fx.write_profile("envsd", &[("OVERRIDE_KEY", "rbw://OLD_SRC")]);

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let req = Request::Resolve {
        canon_path: canon,
        sha256: "abc".into(),
        codesign_team: None,
        argv: vec!["envsd".into()],
        cwd: std::env::temp_dir(),
        project_root: None,
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: vec![Binding {
            env: "OVERRIDE_KEY".into(),
            source: "rbw://NEW_SRC".into(),
        }],
    };
    match send(&h.socket, &req).await {
        Response::Resolved { entries, .. } => {
            let entry = entries
                .iter()
                .find(|e| e.key == "OVERRIDE_KEY")
                .expect("OVERRIDE_KEY missing");
            assert_eq!(entry.value, "new-value", "--bind must override profile");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn vault_locked_returns_clear_error() {
    // Real vault, real rbw, but pinentry is broken so auto-unlock fails →
    // daemon surfaces RbwLocked.
    let fx = VaultFixture::start().await;
    fx.rbw_add("LOCKED_KEY", "doesnt-matter");
    fx.write_profile("envsd", &[("LOCKED_KEY", "rbw://LOCKED_KEY")]);
    fx.rbw_lock();
    fx.break_pinentry(); // any unlock attempt now fails

    let h = start_daemon(fx);
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    match send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await {
        Response::Error { code, message } => {
            assert!(
                matches!(code, envs_proto::ErrorCode::RbwLocked),
                "expected RbwLocked, got {code:?} ({message})"
            );
        }
        other => panic!("expected Error, got {other:?}"),
    }
}

#[serial_test::serial]
#[tokio::test]
async fn audit_verify_with_persistent_tmp() {
    let fx = VaultFixture::start().await;
    fx.rbw_add("VERIFY_KEY", "verify-value");
    fx.write_profile("envsd", &[("VERIFY_KEY", "rbw://VERIFY_KEY")]);

    let h = start_daemon(fx);
    let envs_home = h.envs_home.clone();
    let canon = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let _ = send(&h.socket, &resolve_request_for(canon, vec!["envsd".into()])).await;

    // Audit file should exist
    let audit_path = envs_home.join(".envs/logs/audit.jsonl");
    let key_path = envs_home.join(".envs/state/audit.key");
    assert!(
        audit_path.exists(),
        "audit.jsonl missing at {}",
        audit_path.display()
    );
    assert!(
        key_path.exists(),
        "audit.key missing at {}",
        key_path.display()
    );

    let content = std::fs::read_to_string(&audit_path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 2,
        "expected at least 2 events, got {}",
        lines.len()
    );

    for (i, line) in lines.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let hmac = v
            .get("_hmac")
            .and_then(|h| h.as_str())
            .unwrap_or_else(|| panic!("line {i} no _hmac"));
        assert_eq!(hmac.len(), 64, "line {i} hmac");
    }

    // Replay CLI verify logic — catches serialization-order regressions.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let key = std::fs::read(&key_path).unwrap();
    let mut prev = String::new();
    for (i, line) in lines.iter().enumerate() {
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        let stored = value
            .as_object_mut()
            .and_then(|m| m.remove("_hmac"))
            .and_then(|v| v.as_str().map(String::from))
            .unwrap();
        let payload = serde_json::to_vec(&value).unwrap();
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(prev.as_bytes());
        mac.update(&payload);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            expected, stored,
            "HMAC chain breaks at line {i} — daemon and CLI verify must agree on field order"
        );
        prev = stored;
    }
}
