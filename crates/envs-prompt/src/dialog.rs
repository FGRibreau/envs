//! Lightweight macOS dialog primitives via `osascript`.
//!
//! When the helper has nothing pre-filled (no profile, no registry hit, no
//! `--help` extraction, no `--bind` overrides), we still want the user to
//! be able to authorise something instead of getting "no profile" as a
//! dead-end. AppKit modal sheets are a v0.4 milestone; in the meantime
//! macOS' built-in `display dialog` and `choose from list` give us real
//! native modals — including search-as-you-type for list pickers — without
//! any AppKit layout code.
//!
//! Each helper either returns the user's selection or `None` when they
//! cancel. They never block the calling thread for more than the dialog's
//! lifetime; callers running on the AppKit main thread should spawn a
//! worker thread so the run loop keeps draining events.

use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum DialogError {
    #[error("osascript failed: {0}")]
    Osascript(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DialogError>;

/// `display dialog` text input. Returns `None` when the user clicks Cancel.
pub fn text_input(prompt: &str, default: &str, title: &str) -> Result<Option<String>> {
    let script = format!(
        r#"try
            set the_result to text returned of (display dialog {prompt} default answer {default} with title {title} buttons {{"Cancel", "OK"}} default button "OK" cancel button "Cancel")
            return the_result
        on error number -128
            return "__ENVS_CANCEL__"
        end try"#,
        prompt = applescript_quote(prompt),
        default = applescript_quote(default),
        title = applescript_quote(title),
    );
    let out = run_osascript(&script)?;
    if out == "__ENVS_CANCEL__" {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// `choose from list` with search-as-you-type. Returns `None` on Cancel.
pub fn pick_from_list(prompt: &str, items: &[String], title: &str) -> Result<Option<String>> {
    if items.is_empty() {
        return Ok(None);
    }
    let list_literal = items
        .iter()
        .map(|s| applescript_quote(s))
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"set chosen to choose from list {{{list}}} with prompt {prompt} with title {title} OK button name "Use" cancel button name "Cancel"
        if chosen is false then
            return "__ENVS_CANCEL__"
        else
            return item 1 of chosen as text
        end if"#,
        list = list_literal,
        prompt = applescript_quote(prompt),
        title = applescript_quote(title),
    );
    let out = run_osascript(&script)?;
    if out == "__ENVS_CANCEL__" {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// Yes/No confirmation. `default_yes = true` puts focus on Yes.
pub fn confirm(prompt: &str, default_yes: bool, title: &str) -> Result<bool> {
    let buttons = r#"{"No", "Yes"}"#;
    let default_button = if default_yes { "Yes" } else { "No" };
    let script = format!(
        r#"try
            set rc to button returned of (display dialog {prompt} with title {title} buttons {buttons} default button {default} cancel button "No")
            if rc is "Yes" then return "y"
            return "n"
        on error number -128
            return "n"
        end try"#,
        prompt = applescript_quote(prompt),
        title = applescript_quote(title),
        default = applescript_quote(default_button),
    );
    let out = run_osascript(&script)?;
    Ok(out == "y")
}

/// Centralised osascript invoker — captures stdout, surfaces stderr on failure.
fn run_osascript(script: &str) -> Result<String> {
    let out = Command::new("osascript").arg("-e").arg(script).output()?;
    if !out.status.success() {
        return Err(DialogError::Osascript(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .to_string())
}

/// Wrap a string as an AppleScript literal: surround with double quotes,
/// backslash-escape backslashes and quotes. AppleScript strings don't honour
/// other C escapes (newlines etc.) so we keep the string single-line.
fn applescript_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_basic() {
        assert_eq!(applescript_quote("hello"), "\"hello\"");
    }

    #[test]
    fn quote_escapes_quotes_and_backslashes() {
        assert_eq!(applescript_quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn quote_replaces_newlines_with_spaces() {
        assert_eq!(applescript_quote("a\nb\rc"), "\"a b c\"");
    }
}
