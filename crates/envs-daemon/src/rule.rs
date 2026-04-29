//! In-memory `Rule` representation and conversion to/from proto types.

use chrono::{DateTime, Utc};
use envs_proto::{ArgvMatch, RuleDetail, RuleSummary};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,                          // ulid
    pub canon_path: PathBuf,
    pub sha256: String,
    pub codesign_team: Option<String>,
    pub argv_match: ArgvMatch,
    #[serde(default)]
    pub project_root: Option<PathBuf>,
    pub env_keys: Vec<String>,
    pub sources: Vec<String>,
    pub profile_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
}

impl Rule {
    pub fn new(
        canon_path: PathBuf,
        sha256: String,
        codesign_team: Option<String>,
        argv_match: ArgvMatch,
        project_root: Option<PathBuf>,
        env_keys: Vec<String>,
        sources: Vec<String>,
        profile_id: String,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        let expires = now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(300));
        Self {
            id: ulid::Ulid::new().to_string(),
            canon_path,
            sha256,
            codesign_team,
            argv_match,
            project_root,
            env_keys,
            sources,
            profile_id,
            created_at: now,
            expires_at: expires,
            last_used_at: None,
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at <= now
    }

    /// Does this rule match the given invocation?
    pub fn matches(
        &self,
        canon_path: &std::path::Path,
        argv: &[String],
        project_root: Option<&std::path::Path>,
    ) -> bool {
        if self.canon_path != canon_path {
            return false;
        }
        if self.project_root.as_deref() != project_root {
            return false;
        }
        self.argv_match.matches(argv)
    }

    pub fn to_summary(&self) -> RuleSummary {
        RuleSummary {
            id: self.id.clone(),
            canon_path: self.canon_path.clone(),
            argv_match: self.argv_match.clone(),
            project_root: self.project_root.clone(),
            env_keys: self.env_keys.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }

    pub fn to_detail(&self) -> RuleDetail {
        RuleDetail {
            summary: self.to_summary(),
            sha256: self.sha256.clone(),
            codesign_team: self.codesign_team.clone(),
            sources: self.sources.clone(),
            profile_id: self.profile_id.clone(),
            last_used_at: self.last_used_at,
        }
    }
}
