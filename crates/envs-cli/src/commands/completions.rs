//! `envs completions` — emit shell completion scripts.

use crate::error::Result;
use clap::CommandFactory;
use clap_complete::Shell;

pub fn execute(shell: Shell) -> Result<()> {
    let cmd = &mut crate::Cli::command();
    let bin_name = "envs";
    let mut stdout = std::io::stdout();
    clap_complete::generate(shell, cmd, bin_name, &mut stdout);
    Ok(())
}
