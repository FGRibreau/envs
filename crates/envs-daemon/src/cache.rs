//! In-memory caches: `RuleCache` (active rules) and `ValueCache` (resolved secrets, 30s TTL).

use crate::rule::Rule;
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Default)]
pub struct RuleCache {
    pub rules: RwLock<Vec<Rule>>,
}

impl RuleCache {
    pub fn new(initial: Vec<Rule>) -> Self {
        Self {
            rules: RwLock::new(initial),
        }
    }

    /// Find a non-expired rule that matches the invocation.
    pub async fn find_match(
        &self,
        canon_path: &Path,
        argv: &[String],
        project_root: Option<&Path>,
    ) -> Option<Rule> {
        let now = Utc::now();
        let guard = self.rules.read().await;
        guard
            .iter()
            .find(|r| !r.is_expired(now) && r.matches(canon_path, argv, project_root))
            .cloned()
    }

    pub async fn insert(&self, rule: Rule) {
        let mut guard = self.rules.write().await;
        guard.push(rule);
    }

    pub async fn list(&self) -> Vec<Rule> {
        let now = Utc::now();
        self.rules
            .read()
            .await
            .iter()
            .filter(|r| !r.is_expired(now))
            .cloned()
            .collect()
    }

    pub async fn get(&self, rule_id: &str) -> Option<Rule> {
        self.rules
            .read()
            .await
            .iter()
            .find(|r| r.id == rule_id)
            .cloned()
    }

    /// Revoke a rule by id. Returns true if a rule was removed.
    pub async fn revoke(&self, rule_id: &str) -> bool {
        let mut guard = self.rules.write().await;
        let before = guard.len();
        guard.retain(|r| r.id != rule_id);
        guard.len() < before
    }

    pub async fn revoke_all(&self) -> usize {
        let mut guard = self.rules.write().await;
        let n = guard.len();
        guard.clear();
        n
    }

    /// Remove all expired rules. Returns the IDs of purged rules.
    pub async fn sweep_expired(&self) -> Vec<String> {
        let now = Utc::now();
        let mut guard = self.rules.write().await;
        let expired: Vec<String> = guard
            .iter()
            .filter(|r| r.is_expired(now))
            .map(|r| r.id.clone())
            .collect();
        if !expired.is_empty() {
            guard.retain(|r| !r.is_expired(now));
        }
        expired
    }

    pub async fn count(&self) -> usize {
        self.rules.read().await.len()
    }

    /// Return a snapshot of all rules (for persistence).
    pub async fn snapshot(&self) -> Vec<Rule> {
        self.rules.read().await.clone()
    }
}

/// Cache of resolved secret values, keyed by (env_key, source URI).
#[derive(Default)]
pub struct ValueCache {
    map: RwLock<HashMap<(String, String), CachedValue>>,
    ttl: Duration,
}

struct CachedValue {
    value: String, // held as String for serde simplicity; wrapped in SecretString on serve
    fetched_at: Instant,
}

impl ValueCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    pub async fn get(&self, env_key: &str, source: &str) -> Option<SecretString> {
        let guard = self.map.read().await;
        let entry = guard.get(&(env_key.to_string(), source.to_string()))?;
        if entry.fetched_at.elapsed() > self.ttl {
            return None;
        }
        Some(SecretString::new(entry.value.clone().into()))
    }

    pub async fn insert(&self, env_key: String, source: String, value: SecretString) {
        let mut guard = self.map.write().await;
        guard.insert(
            (env_key, source),
            CachedValue {
                value: value.expose_secret().to_string(),
                fetched_at: Instant::now(),
            },
        );
    }

    pub async fn sweep_expired(&self) -> usize {
        let mut guard = self.map.write().await;
        let before = guard.len();
        guard.retain(|_, v| v.fetched_at.elapsed() <= self.ttl);
        before - guard.len()
    }

    pub async fn count(&self) -> usize {
        self.map.read().await.len()
    }

    pub async fn flush(&self) {
        self.map.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envs_proto::ArgvMatch;
    use std::path::PathBuf;

    fn mk_rule(canon: &str, ttl_secs: i64) -> Rule {
        let now = Utc::now();
        Rule {
            id: ulid::Ulid::new().to_string(),
            canon_path: PathBuf::from(canon),
            sha256: "abc".into(),
            codesign_team: None,
            argv_match: ArgvMatch::Any,
            project_root: None,
            env_keys: vec!["X".into()],
            sources: vec!["rbw://X".into()],
            profile_id: "p".into(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            last_used_at: None,
        }
    }

    #[tokio::test]
    async fn rule_cache_find_match() {
        let cache = RuleCache::new(vec![mk_rule("/bin/foo", 60)]);
        let m = cache
            .find_match(Path::new("/bin/foo"), &["foo".into()], None)
            .await;
        assert!(m.is_some());
    }

    #[tokio::test]
    async fn rule_cache_no_match_diff_path() {
        let cache = RuleCache::new(vec![mk_rule("/bin/foo", 60)]);
        let m = cache
            .find_match(Path::new("/bin/bar"), &["bar".into()], None)
            .await;
        assert!(m.is_none());
    }

    #[tokio::test]
    async fn rule_cache_sweep_expired() {
        let cache = RuleCache::new(vec![mk_rule("/bin/foo", -10)]);
        let purged = cache.sweep_expired().await;
        assert_eq!(purged.len(), 1);
        assert_eq!(cache.count().await, 0);
    }

    #[tokio::test]
    async fn value_cache_ttl() {
        let cache = ValueCache::new(Duration::from_millis(50));
        cache
            .insert("X".into(), "rbw://X".into(), SecretString::new("v".into()))
            .await;
        assert!(cache.get("X", "rbw://X").await.is_some());
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(cache.get("X", "rbw://X").await.is_none());
    }
}
