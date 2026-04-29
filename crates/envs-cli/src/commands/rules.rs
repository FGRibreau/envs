//! `envs rules` — manage active rule cache.

use crate::client;
use crate::error::{CliError, Result};
use envs_proto::{Request, Response};

pub async fn execute(action: super::super::RulesAction) -> Result<()> {
    use super::super::RulesAction;
    match action {
        RulesAction::List => list().await,
        RulesAction::Show { rule_id } => show(rule_id).await,
        RulesAction::Revoke { rule_id_or_all } => revoke(rule_id_or_all).await,
    }
}

async fn list() -> Result<()> {
    let resp = client::send_request(&Request::ListRules).await?;
    match resp {
        Response::Rules { rules } => {
            if rules.is_empty() {
                println!("(no active rules)");
                return Ok(());
            }
            println!("{:24} {:40} {:8} {}", "ID", "BINARY", "SCOPE", "EXPIRES");
            for r in rules {
                let scope = match &r.argv_match {
                    envs_proto::ArgvMatch::Any => "Any".to_string(),
                    envs_proto::ArgvMatch::Exact { argv } => format!("Exact({})", argv.len()),
                };
                println!(
                    "{:24} {:40} {:8} {}",
                    r.id,
                    r.canon_path.display(),
                    scope,
                    r.expires_at.format("%Y-%m-%d %H:%M:%S")
                );
            }
            Ok(())
        }
        other => Err(CliError::Internal(format!("unexpected: {other:?}"))),
    }
}

async fn show(rule_id: String) -> Result<()> {
    let resp = client::send_request(&Request::GetRule { rule_id }).await?;
    match resp {
        Response::Rule { rule: Some(r) } => {
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
        Response::Rule { rule: None } => {
            println!("(not found)");
            Ok(())
        }
        other => Err(CliError::Internal(format!("unexpected: {other:?}"))),
    }
}

async fn revoke(arg: String) -> Result<()> {
    let req = if arg == "all" {
        Request::Revoke { rule_id: None }
    } else {
        Request::Revoke { rule_id: Some(arg) }
    };
    let _ = client::send_request(&req).await?;
    println!("✓ revoked");
    Ok(())
}
