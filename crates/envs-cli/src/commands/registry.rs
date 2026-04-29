//! `envs registry` — manage community registry (stub for v0.1).

use crate::error::Result;

pub async fn execute(action: super::super::RegistryAction) -> Result<()> {
    use super::super::RegistryAction;
    match action {
        RegistryAction::Sync => {
            eprintln!("envs: `registry sync` is not implemented in this version.");
            eprintln!(
                "       (will git pull github.com/fgribreau/envs-registry into ~/.envs/registry/)"
            );
            std::process::exit(64); // EX_USAGE — feature unavailable
        }
        RegistryAction::Show { binary } => {
            eprintln!("envs: `registry show` is not implemented in this version.");
            eprintln!("       (would lookup {binary} in ~/.envs/registry/binaries/)");
            std::process::exit(64);
        }
    }
}
