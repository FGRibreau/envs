//! execvpe wrapper that replaces the current process with the target command,
//! merged env (inherited + injected secrets).

use crate::error::{CliError, Result};
use secrecy::ExposeSecret;
use std::ffi::CString;

pub struct ExecArgs {
    pub argv0: CString,     // typically the canonical path
    pub args: Vec<CString>, // including argv[0] = the command name
    pub env: Vec<CString>,  // KEY=VALUE strings
}

/// Build the merged env: inherit current env, then overlay injected secrets.
/// Injected secrets WIN over any existing values (the user explicitly asked for them).
pub fn build_env(injected: &[(String, secrecy::SecretString)]) -> Vec<CString> {
    use std::collections::BTreeMap;
    let mut map: BTreeMap<String, String> = std::env::vars().collect();
    for (k, v) in injected {
        map.insert(k.clone(), v.expose_secret().to_string());
    }
    map.into_iter()
        .filter_map(|(k, v)| CString::new(format!("{k}={v}")).ok())
        .collect()
}

/// Replace the current process with the target. Never returns on success.
pub fn run(args: ExecArgs) -> Result<std::convert::Infallible> {
    // nix's execvp uses libc::execvp which doesn't accept envp; we need execvpe-style.
    // On macOS, libc has execvP; for env injection, simplest path is execve via the
    // canonical path + manually-built env.

    let env_refs: Vec<&std::ffi::CStr> = args.env.iter().map(|c| c.as_c_str()).collect();
    let arg_refs: Vec<&std::ffi::CStr> = args.args.iter().map(|c| c.as_c_str()).collect();

    // nix exposes execve which takes (path, argv, envp) and is the right primitive.
    let err = nix::unistd::execve(args.argv0.as_c_str(), &arg_refs, &env_refs)
        .err()
        .unwrap_or_else(|| nix::Error::EINVAL);

    Err(CliError::Internal(format!("execve failed: {err}")))
}

/// Convert a `String` to `CString`, returning a friendly error on embedded NUL.
pub fn cstring(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| CliError::Internal(format!("string contains NUL: {s:?}")))
}

/// Same for argv: convert each.
pub fn cstrings<'a, I: IntoIterator<Item = &'a str>>(iter: I) -> Result<Vec<CString>> {
    iter.into_iter().map(cstring).collect()
}
