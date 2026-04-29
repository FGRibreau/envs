//! `envs completions` — emit shell completion scripts.

use crate::error::Result;
use clap::CommandFactory;

pub fn execute(shell: super::super::clap_complete_shell::Shell) -> Result<()> {
    let cmd = &mut crate::Cli::command();
    let bin_name = "envs";
    let mut stdout = std::io::stdout();
    match shell {
        super::super::clap_complete_shell::Shell::Bash => {
            clap_complete::generate(clap_complete::shells::Bash, cmd, bin_name, &mut stdout);
        }
        super::super::clap_complete_shell::Shell::Zsh => {
            clap_complete::generate(clap_complete::shells::Zsh, cmd, bin_name, &mut stdout);
        }
        super::super::clap_complete_shell::Shell::Fish => {
            clap_complete::generate(clap_complete::shells::Fish, cmd, bin_name, &mut stdout);
        }
    }
    Ok(())
}
