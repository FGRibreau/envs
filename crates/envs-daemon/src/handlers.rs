//! Request → Response dispatch logic.

use crate::audit;
use crate::cache::{RuleCache, ValueCache};
use crate::error::{DaemonError, Result};
use crate::helper::HelperHandle;
use crate::rbw;
use crate::rule::Rule;
use envs_proto::{
    EnvEntry, ErrorCode, GrantScope, HelperReply, ProfileSnapshot, PromptRequest, Request,
    Response, RuleDetail, RuleSummary,
};
use secrecy::{ExposeSecret, SecretString};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

pub struct Handlers {
    pub rule_cache: Arc<RuleCache>,
    pub value_cache: Arc<ValueCache>,
    pub helper: Arc<HelperHandle>,
    pub started_at: Instant,
    /// Serializes the `unlock → rbw get* → lock` sequence so a concurrent
    /// resolve cannot lock the vault while another resolve is reading.
    pub rbw_mutex: Arc<Mutex<()>>,
}

impl Handlers {
    pub async fn dispatch(&self, req: Request) -> Response {
        match self.handle(req).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(?e, "request handler error");
                let code = match e {
                    DaemonError::RbwLocked => ErrorCode::RbwLocked,
                    DaemonError::RbwNotInstalled => ErrorCode::RbwNotInstalled,
                    DaemonError::RbwLookupFailed(_) => ErrorCode::RbwLookupFailed,
                    DaemonError::SystemBinaryRefused(_) => ErrorCode::SystemBinaryRefused,
                    DaemonError::NoProfile(_) => ErrorCode::BinaryNotInProfile,
                    DaemonError::BadInput(_) => ErrorCode::Internal,
                    DaemonError::BadRbwUri(_) => ErrorCode::Internal,
                    DaemonError::RuleNotFound(_) => ErrorCode::Internal,
                    DaemonError::Helper(_) => ErrorCode::Internal,
                    _ => ErrorCode::Internal,
                };
                Response::Error {
                    code,
                    message: e.to_string(),
                }
            }
        }
    }

    async fn handle(&self, req: Request) -> Result<Response> {
        match req {
            Request::Ping => Ok(Response::Pong),

            Request::Status => {
                let rules_count = self.rule_cache.count().await;
                let cache_entries = self.value_cache.count().await;
                let rbw_unlocked = rbw::check_status().await.unwrap_or(false);
                Ok(Response::Status {
                    version: env!("CARGO_PKG_VERSION").into(),
                    protocol: envs_proto::PROTOCOL_VERSION,
                    cache_entries,
                    rules_count,
                    rbw_unlocked,
                    uptime_secs: self.started_at.elapsed().as_secs(),
                })
            }

            Request::ListRules => {
                let rules: Vec<RuleSummary> = self
                    .rule_cache
                    .list()
                    .await
                    .iter()
                    .map(|r| r.to_summary())
                    .collect();
                Ok(Response::Rules { rules })
            }

            Request::GetRule { rule_id } => {
                let rule: Option<RuleDetail> =
                    self.rule_cache.get(&rule_id).await.map(|r| r.to_detail());
                Ok(Response::Rule { rule })
            }

            Request::Revoke { rule_id } => match rule_id {
                Some(id) => {
                    let removed = self.rule_cache.revoke(&id).await;
                    if removed {
                        let _ = audit::event("revoke").field("rule_id", &id).write();
                    }
                    crate::persistence::save(&self.rule_cache.snapshot().await).ok();
                    Ok(Response::Ok)
                }
                None => {
                    let n = self.rule_cache.revoke_all().await;
                    let _ = audit::event("revoke").field("count", n).write();
                    crate::persistence::save(&[]).ok();
                    Ok(Response::Ok)
                }
            },

            Request::Flush => {
                self.value_cache.flush().await;
                Ok(Response::Ok)
            }

            Request::Resolve {
                canon_path,
                sha256,
                codesign_team,
                argv,
                cwd: _cwd,
                project_root,
                client_pid,
                profiles,
                extra_bindings,
            } => {
                self.resolve(
                    canon_path.as_path(),
                    sha256,
                    codesign_team,
                    argv,
                    project_root.as_deref(),
                    client_pid,
                    profiles,
                    extra_bindings,
                )
                .await
            }
        }
    }

    async fn resolve(
        &self,
        canon_path: &Path,
        sha256: String,
        codesign_team: Option<String>,
        argv: Vec<String>,
        project_root: Option<&Path>,
        _client_pid: i32,
        profiles: Vec<String>,
        extra_bindings: Vec<envs_proto::Binding>,
    ) -> Result<Response> {
        // Pre-flight integrity checks.
        crate::binary::ensure_not_world_writable(canon_path)?;

        // Look for an existing rule that matches.
        let existing = self
            .rule_cache
            .find_match(canon_path, &argv, project_root)
            .await;

        let rule = match existing {
            Some(r) => {
                if r.sha256 != sha256 {
                    // Hash drifted. If codesign Team ID matches → auto-update silently.
                    // Otherwise → treat as cache miss (re-prompt the user).
                    let same_team = match (&r.codesign_team, &codesign_team) {
                        (Some(old), Some(new)) => old == new,
                        _ => false,
                    };
                    let _ = audit::event("hash_mismatch")
                        .field("rule_id", &r.id)
                        .field("path", canon_path.to_string_lossy())
                        .field("expected_sha", &r.sha256)
                        .field("actual_sha", &sha256)
                        .field("codesign_match", same_team)
                        .write();
                    if same_team {
                        let _ = audit::event("hash_codesign_auto_update")
                            .field("rule_id", &r.id)
                            .field("path", canon_path.to_string_lossy())
                            .field("team", r.codesign_team.clone().unwrap_or_default())
                            .write();
                        // Update sha256 in place (rebuild the rule).
                        let mut updated = r.clone();
                        updated.sha256 = sha256.clone();
                        // Replace in cache.
                        self.rule_cache.revoke(&updated.id).await;
                        self.rule_cache.insert(updated.clone()).await;
                        crate::persistence::save(&self.rule_cache.snapshot().await).ok();
                        updated
                    } else {
                        self.create_via_helper(
                            canon_path,
                            sha256,
                            codesign_team,
                            argv.clone(),
                            project_root,
                            &profiles,
                            &extra_bindings,
                        )
                        .await?
                    }
                } else {
                    r
                }
            }
            None => {
                self.create_via_helper(
                    canon_path,
                    sha256,
                    codesign_team,
                    argv.clone(),
                    project_root,
                    &profiles,
                    &extra_bindings,
                )
                .await?
            }
        };

        // Hold the rbw mutex for the entire unlock → get* → lock sequence so a
        // concurrent resolve cannot race the lock state. We only need to touch
        // rbw if at least one binding is uncached; figure that out first to
        // skip the unlock/lock round-trip on a fully-warm cache.
        let any_uncached = {
            let mut any = false;
            for (k, src) in rule.env_keys.iter().zip(rule.sources.iter()) {
                if self.value_cache.get(k, src).await.is_none() {
                    any = true;
                    break;
                }
            }
            any
        };

        let _rbw_guard = if any_uncached {
            let guard = self.rbw_mutex.lock().await;
            // If the vault is locked, unlock it. With pinentry-touchid configured
            // this is silent against the Keychain (or shows TouchID); without it,
            // the user will see a pinentry prompt.
            let unlocked = rbw::check_status().await.unwrap_or(false);
            if !unlocked {
                let t0 = Instant::now();
                if let Err(e) = rbw::unlock().await {
                    let _ = audit::event("auto_unlock_failed")
                        .field("rule_id", &rule.id)
                        .field("error", e.to_string())
                        .write();
                    return Err(DaemonError::RbwLocked);
                }
                let _ = audit::event("auto_unlock")
                    .field("rule_id", &rule.id)
                    .field("duration_ms", t0.elapsed().as_millis() as u64)
                    .write();
            }
            Some(guard)
        } else {
            None
        };

        // Resolve each binding to a value (cache or rbw).
        let mut entries: Vec<EnvEntry> = Vec::with_capacity(rule.env_keys.len());
        for (k, src) in rule.env_keys.iter().zip(rule.sources.iter()) {
            let value: SecretString = match self.value_cache.get(k, src).await {
                Some(v) => v,
                None => {
                    let v = rbw::get(src).await?;
                    self.value_cache
                        .insert(k.clone(), src.clone(), v.clone())
                        .await;
                    let _ = audit::event("resolve")
                        .field("rule_id", &rule.id)
                        .field("env_key", k)
                        .field("cached", false)
                        .write();
                    v
                }
            };
            entries.push(EnvEntry {
                key: k.clone(),
                value: value.expose_secret().to_string(),
            });
        }

        // Best-effort lock: we already have the values cached (RAM, 30s TTL).
        // A failed lock here is a security warning but not a fatal error — the
        // resolve already succeeded and the caller should not retry.
        if _rbw_guard.is_some() {
            match rbw::lock().await {
                Ok(()) => {
                    let _ = audit::event("auto_lock")
                        .field("rule_id", &rule.id)
                        .write();
                }
                Err(e) => {
                    tracing::warn!(?e, "auto_lock failed");
                    let _ = audit::event("auto_lock_failed")
                        .field("rule_id", &rule.id)
                        .field("error", e.to_string())
                        .write();
                }
            }
        }

        Ok(Response::Resolved {
            rule_id: rule.id.clone(),
            entries,
            cached: false,
            expires_at: rule.expires_at,
        })
    }

    /// Ask the helper to authorize a new rule, then persist it.
    async fn create_via_helper(
        &self,
        canon_path: &Path,
        sha256: String,
        codesign_team: Option<String>,
        argv: Vec<String>,
        project_root: Option<&Path>,
        named_profiles: &[String],
        extra_bindings: &[envs_proto::Binding],
    ) -> Result<Rule> {
        let binary_name = canon_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        let request_id = ulid::Ulid::new().to_string();
        let suggested = crate::discovery::discover(canon_path, &binary_name).await;

        // Build `current_profile` by composing:
        //   1. The default profile for this binary (project-local then global)
        //   2. Each named profile from `--profile X --profile Y` (with includes recursion)
        //   3. Inline `--bind` overrides on top
        // Conflict detection: same env_var twice with different sources → fail-fast.
        let current_profile =
            compose_profile(&binary_name, project_root, named_profiles, extra_bindings)?;

        // Short-circuit when the helper has nothing to offer — no discovered suggestions,
        // no profile, no inline --bind. Without this, the popup auto-cancels (stub mode)
        // or shows an empty list (native mode) and the user sees a misleading
        // "user cancelled" message. NoProfile maps to `BinaryNotInProfile`, which the
        // CLI renders as "no profile or registry entry for <bin>" with a hint to
        // run `envs project init`.
        if suggested.is_empty() && current_profile.is_none() && extra_bindings.is_empty() {
            return Err(DaemonError::NoProfile(binary_name));
        }

        let req = PromptRequest {
            request_id: request_id.clone(),
            canon_path: canon_path.to_path_buf(),
            binary_name: binary_name.clone(),
            argv: argv.clone(),
            cwd: project_root
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::env::current_dir().unwrap_or_default()),
            project_root: project_root.map(|p| p.to_path_buf()),
            suggested_bindings: suggested,
            available_vault_items: Vec::new(),
            current_profile,
        };

        let reply = self.helper.request(req, Duration::from_secs(120)).await?;

        let (bindings, scope, ttl_secs, _save) = match reply {
            HelperReply::Authorized {
                bindings,
                scope,
                ttl_secs,
                save_as_profile,
                ..
            } => (bindings, scope, ttl_secs, save_as_profile),
            HelperReply::Cancelled { .. } => {
                let _ = audit::event("popup_cancel")
                    .field("request_id", &request_id)
                    .field("path", canon_path.to_string_lossy())
                    .write();
                return Err(DaemonError::BadInput("user cancelled".into()));
            }
            HelperReply::Error { message, .. } => {
                return Err(DaemonError::Helper(message));
            }
        };

        if bindings.is_empty() {
            return Err(DaemonError::NoProfile(binary_name.clone()));
        }

        // Refuse scope=Any for system binaries (shared, drift on every macOS update).
        // System binaries can still be granted with scope=ExactArgv.
        if matches!(scope, GrantScope::Any) && crate::binary::is_system_binary(canon_path) {
            return Err(DaemonError::SystemBinaryRefused(format!(
                "scope=Any refused for system binary {}",
                canon_path.display()
            )));
        }

        let argv_match = match scope {
            GrantScope::Any => envs_proto::ArgvMatch::Any,
            GrantScope::ExactArgv { argv } => envs_proto::ArgvMatch::Exact { argv },
        };

        let env_keys: Vec<String> = bindings.iter().map(|b| b.env.clone()).collect();
        let sources: Vec<String> = bindings.iter().map(|b| b.source.clone()).collect();
        let profile_id = format!(
            "{}{}",
            project_root
                .map(|p| format!("{}:", p.display()))
                .unwrap_or_default(),
            binary_name
        );

        let rule = Rule::new(
            canon_path.to_path_buf(),
            sha256,
            codesign_team,
            argv_match,
            project_root.map(|p| p.to_path_buf()),
            env_keys.clone(),
            sources.clone(),
            profile_id,
            Duration::from_secs(ttl_secs),
        );

        let _ = audit::event("grant")
            .field("rule_id", &rule.id)
            .field("path", canon_path.to_string_lossy())
            .field("argv", &argv)
            .field("env_keys", &env_keys)
            .field(
                "project_root",
                project_root.map(|p| p.to_string_lossy().to_string()),
            )
            .field("expires_at", rule.expires_at.to_rfc3339())
            .write();

        self.rule_cache.insert(rule.clone()).await;
        crate::persistence::save(&self.rule_cache.snapshot().await).ok();

        Ok(rule)
    }
}

/// Compose the final profile from default + named profiles + inline binds.
/// Recursion: each profile may declare `includes = [...]` for further composition.
/// Conflict detection: a single env_var defined by two different sources → error.
fn compose_profile(
    binary_name: &str,
    project_root: Option<&Path>,
    named_profiles: &[String],
    extra_bindings: &[envs_proto::Binding],
) -> Result<Option<ProfileSnapshot>> {
    use envs_proto::{Binding, ProfileTarget};
    use std::collections::HashMap;

    let mut merged: HashMap<String, (String, String)> = HashMap::new(); // env → (source, origin)
    let mut merged_path: Option<std::path::PathBuf> = None;
    let mut merged_target: Option<ProfileTarget> = None;
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    // 1. Default profile for this binary (project-local then global).
    let default = load_profile_by_name(binary_name, project_root);
    if let Some((path, target, file)) = default {
        merge_profile_into(
            &mut merged,
            &file,
            project_root,
            &mut visited,
            &format!("default:{}", binary_name),
        )?;
        merged_path = Some(path);
        merged_target = Some(target);
    }

    // 2. Each named profile (--profile X) plus its includes
    for name in named_profiles {
        if let Some((_, _, file)) = load_profile_by_name(name, project_root) {
            merge_profile_into(
                &mut merged,
                &file,
                project_root,
                &mut visited,
                &format!("--profile {name}"),
            )?;
        } else {
            return Err(DaemonError::BadInput(format!(
                "profile '{name}' not found in project or global"
            )));
        }
    }

    // 3. Inline --bind overrides (always win on conflict)
    for b in extra_bindings {
        merged.insert(b.env.clone(), (b.source.clone(), "--bind".to_string()));
    }

    if merged.is_empty() {
        return Ok(None);
    }

    let bindings: Vec<Binding> = merged
        .into_iter()
        .map(|(env, (source, _origin))| Binding { env, source })
        .collect();

    Ok(Some(ProfileSnapshot {
        source: merged_target.unwrap_or(ProfileTarget::Global),
        path: merged_path.unwrap_or_default(),
        bindings,
    }))
}

/// Load a profile file by its name (project-local first, then global).
/// Returns (path, target, parsed file).
fn load_profile_by_name(
    name: &str,
    project_root: Option<&Path>,
) -> Option<(std::path::PathBuf, envs_proto::ProfileTarget, ProfileFile)> {
    use envs_proto::ProfileTarget;

    if let Some(root) = project_root {
        let path = root.join(".envs").join(format!("{name}.toml"));
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(parsed) = toml::from_str::<ProfileFile>(&content) {
                    return Some((path, ProfileTarget::Project, parsed));
                }
            }
        }
    }
    if let Some(home) = dirs::home_dir() {
        let path = home
            .join(".envs")
            .join("profiles")
            .join(format!("{name}.toml"));
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(parsed) = toml::from_str::<ProfileFile>(&content) {
                    return Some((path, ProfileTarget::Global, parsed));
                }
            }
        }
    }
    None
}

/// Recursively merge a profile (and its `includes`) into the accumulator.
/// Cycle detection via `visited` set. Conflict detection via env_var presence.
fn merge_profile_into(
    merged: &mut std::collections::HashMap<String, (String, String)>,
    file: &ProfileFile,
    project_root: Option<&Path>,
    visited: &mut std::collections::HashSet<String>,
    origin: &str,
) -> Result<()> {
    if !visited.insert(origin.to_string()) {
        return Err(DaemonError::BadInput(format!(
            "include cycle detected at {origin}"
        )));
    }

    // First, recurse into includes
    for include_name in &file.includes {
        if let Some((_, _, included)) = load_profile_by_name(include_name, project_root) {
            merge_profile_into(
                merged,
                &included,
                project_root,
                visited,
                &format!("include:{include_name}"),
            )?;
        } else {
            return Err(DaemonError::BadInput(format!(
                "profile '{include_name}' (included by {origin}) not found"
            )));
        }
    }

    // Then, this profile's bindings (later layers override earlier ones)
    for b in &file.bindings {
        if let Some((existing_src, existing_origin)) = merged.get(&b.env) {
            if existing_src != &b.source {
                return Err(DaemonError::BadInput(format!(
                    "conflicting binding for {}: {existing_origin} → {existing_src} vs {origin} → {}",
                    b.env, b.source
                )));
            }
        }
        merged.insert(b.env.clone(), (b.source.clone(), origin.to_string()));
    }
    Ok(())
}

#[derive(serde::Deserialize, Default)]
struct ProfileFile {
    #[serde(default)]
    #[allow(dead_code)]
    schema: u32,
    #[serde(default, rename = "binding")]
    bindings: Vec<ProfileBinding>,
    #[serde(default)]
    includes: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ProfileBinding {
    env: String,
    #[serde(alias = "src")]
    source: String,
}
