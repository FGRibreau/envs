//! envs-prompt — native macOS popup helper (v0.6 NSWindow + interactive widgets).
//!
//! v0.6 architecture:
//!
//! ```text
//!   ┌──────────────────────┐                ┌───────────────────────┐
//!   │  Main thread         │                │ Background thread     │
//!   │  NSApplication.run() │                │  (std::thread::spawn) │
//!   │                      │   shared       │                       │
//!   │  EnvsAppDelegate     │ ←────────────→ │  stdin reader         │
//!   │  - NSWindow          │   queues       │  - read_line(stdin)   │
//!   │  - NSStatusItem      │   (Mutex)      │  - parse HelperEvent  │
//!   │  - NSTimer 50ms drain│                │  - push to incoming   │
//!   │  - action methods    │                │                       │
//!   │    (declare_class!)  │                │  stdout writer        │
//!   │                      │                │  - poll outgoing      │
//!   │                      │                │  - serialize +write   │
//!   └──────────────────────┘                └───────────────────────┘
//! ```
//!
//! Stub mode (set `ENVS_PROMPT_AUTO_GRANT=1`) bypasses AppKit entirely and
//! runs a synchronous auto-approve loop. Used by daemon e2e tests + CI.

use envs_proto::{Binding, GrantScope, HelperEvent, HelperReply, ProfileTarget, PromptRequest};
use std::io::{BufRead, Write};

#[cfg(target_os = "macos")]
mod app;
mod auth;
#[cfg(target_os = "macos")]
mod client;
#[cfg(target_os = "macos")]
mod dialog;
#[cfg(target_os = "macos")]
mod rbw;

fn main() -> anyhow::Result<()> {
    init_tracing();
    let auto_grant = std::env::var_os("ENVS_PROMPT_AUTO_GRANT").is_some();
    tracing::info!(auto_grant, "envs-prompt v0.6 started");

    if auto_grant {
        return run_stub_mode();
    }

    #[cfg(target_os = "macos")]
    {
        run_native_mode()
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Non-macOS: fall back to stub (no AppKit available).
        run_stub_mode()
    }
}

/// Stub mode: synchronous stdin loop, auto-approves with sensible defaults.
fn run_stub_mode() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = handle.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        let line = buf.trim();
        if line.is_empty() {
            continue;
        }
        let event: HelperEvent = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!(?err, line = %line, "failed to parse HelperEvent");
                continue;
            }
        };
        match event {
            HelperEvent::NewRequest(req) => {
                let reply = handle_request_stub(req);
                send_reply(&reply)?;
            }
            HelperEvent::Shutdown => break,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_native_mode() -> anyhow::Result<()> {
    use objc2::msg_send;
    use objc2_app_kit::NSApplication;
    use objc2_foundation::MainThreadMarker;
    use std::sync::Arc;

    // SAFETY: main() runs on the main thread by Rust convention.
    let mtm = unsafe { MainThreadMarker::new_unchecked() };

    let nsapp = NSApplication::sharedApplication(mtm);

    // Activation policy = Accessory (1) — hides the dock icon. envs-prompt is
    // a menubar utility, not a regular application. objc2-app-kit 0.2.2 doesn't
    // expose `setActivationPolicy` directly so we send the selector via raw
    // `msg_send!`. The integer values come from `NSApplicationActivationPolicy`:
    //   0 = Regular, 1 = Accessory, 2 = Prohibited.
    unsafe {
        let _: bool = msg_send![&*nsapp, setActivationPolicy: 1isize];
    }

    let queues = Arc::new(app::SharedQueues::new());

    // Background thread polling envsd every 5s for active-rules count.
    // Rate is generous: status is informational only, not user-driven.
    app::spawn_status_poller(queues.clone(), std::time::Duration::from_secs(5));

    // Create the AppDelegate (owns NSWindow + NSStatusItem + tab state).
    let delegate = app::EnvsAppDelegate::new(mtm, queues.clone());
    delegate.install_status_item(mtm);
    delegate.install_window(mtm);
    delegate.schedule_drain_timer(mtm);
    delegate.schedule_status_menu_timer(mtm);

    // Background thread: read stdin → push to queues.incoming
    let incoming_queue = queues.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut handle = stdin.lock();
        let mut buf = String::new();
        loop {
            buf.clear();
            let n = match handle.read_line(&mut buf) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                // EOF: signal Shutdown so main thread exits NSApp.
                if let Ok(mut q) = incoming_queue.incoming.lock() {
                    q.push_back(HelperEvent::Shutdown);
                }
                break;
            }
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }
            let event: HelperEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(err) => {
                    tracing::warn!(?err, line = %line, "failed to parse HelperEvent");
                    continue;
                }
            };
            if let Ok(mut q) = incoming_queue.incoming.lock() {
                q.push_back(event);
            }
        }
    });

    // Background thread: poll outgoing queue → write to stdout
    let outgoing_queue = queues.clone();
    std::thread::spawn(move || loop {
        let replies: Vec<HelperReply> = {
            let mut q = match outgoing_queue.outgoing.lock() {
                Ok(q) => q,
                Err(_) => return,
            };
            q.drain(..).collect()
        };
        for r in replies {
            if let Err(e) = send_reply(&r) {
                tracing::warn!(?e, "failed to send reply");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    });

    // Hand off main thread to NSApplication's run loop. Returns when
    // [NSApp terminate:] is called (e.g., from Shutdown event handler).
    unsafe { nsapp.run() };

    Ok(())
}

/// Stub-mode handler: auto-approve with default scope (system-binary-aware).
/// The user's saved profile is authoritative; discovery suggestions only
/// matter when no profile exists yet (real popup shows both).
///
/// When all sources are empty AND we're on macOS in non-test mode, drive
/// the user through a sequence of native osascript dialogs to add bindings
/// (env-var name → fuzzy-pick item → choose field). Tests bypass this via
/// `ENVS_PROMPT_AUTO_GRANT=1` which short-circuits to Cancel on empty.
fn handle_request_stub(req: PromptRequest) -> HelperReply {
    let bindings: Vec<Binding> = if let Some(profile) = &req.current_profile {
        profile.bindings.clone()
    } else if !req.suggested_bindings.is_empty() {
        req.suggested_bindings
            .iter()
            .map(|s| Binding {
                env: s.env.clone(),
                source: s.source.clone(),
            })
            .collect()
    } else {
        // No profile, no suggestions — try the interactive osascript flow.
        // Tests force Cancel via ENVS_PROMPT_AUTO_GRANT=1 to keep CI deterministic.
        if std::env::var_os("ENVS_PROMPT_AUTO_GRANT").is_some() {
            Vec::new()
        } else {
            collect_bindings_interactively(&req.binary_name)
        }
    };

    if bindings.is_empty() {
        return HelperReply::Cancelled {
            request_id: req.request_id,
        };
    }

    let scope = if is_system_binary(&req.canon_path) {
        GrantScope::ExactArgv {
            argv: req.argv.clone(),
        }
    } else {
        GrantScope::Any
    };

    HelperReply::Authorized {
        request_id: req.request_id.clone(),
        bindings,
        scope,
        ttl_secs: 300,
        save_as_profile: req
            .project_root
            .as_ref()
            .map(|_| ProfileTarget::Project)
            .or(Some(ProfileTarget::Global)),
    }
}

/// Drive the user through a sequence of native macOS dialogs to add
/// bindings: env-var name (text input) → Bitwarden item (search-as-you-type
/// list picker) → field (list picker) → "add another?" confirm. Loops until
/// the user declines or cancels. Empty result means the user cancelled
/// before authorising anything.
#[cfg(target_os = "macos")]
fn collect_bindings_interactively(binary_name: &str) -> Vec<Binding> {
    let title = format!("envs — authorise `{binary_name}`");
    let items = match rbw::list_items() {
        Ok(items) => items,
        Err(e) => {
            tracing::warn!(?e, "rbw list failed, cannot prompt interactively");
            return Vec::new();
        }
    };

    let mut bindings: Vec<Binding> = Vec::new();
    #[allow(clippy::while_let_loop)] // explicit `break` inside makes the loop body cleaner
    loop {
        let env = match dialog::text_input(
            &format!("Env var to expose for `{binary_name}` (UPPER_SNAKE_CASE):"),
            "",
            &title,
        ) {
            Ok(Some(s)) => s.trim().to_string(),
            Ok(None) | Err(_) => break,
        };
        if env.is_empty() {
            break;
        }
        if !is_valid_env_name(&env) {
            let _ = dialog::text_input(
                &format!("'{env}' is not a valid env var name. Use [A-Z_][A-Z0-9_]*."),
                "",
                &title,
            );
            continue;
        }

        let item_name = match dialog::pick_from_list(
            &format!("Bitwarden item for {env} (search):"),
            &items,
            &title,
        ) {
            Ok(Some(s)) => s,
            Ok(None) | Err(_) => break,
        };

        let fields = match rbw::get_fields(&item_name) {
            Ok(f) if !f.is_empty() => f,
            _ => {
                tracing::warn!(item = %item_name, "no readable fields on item");
                continue;
            }
        };

        let field = match dialog::pick_from_list(
            &format!("Field of '{item_name}' for {env}:"),
            &fields,
            &title,
        ) {
            Ok(Some(s)) => s,
            Ok(None) | Err(_) => break,
        };

        bindings.push(Binding {
            env,
            source: format!("rbw://{item_name}/{field}"),
        });

        let again = dialog::confirm(
            &format!("Add another env var for `{binary_name}`?"),
            false,
            &title,
        )
        .unwrap_or(false);
        if !again {
            break;
        }
    }
    bindings
}

#[cfg(not(target_os = "macos"))]
fn collect_bindings_interactively(_binary_name: &str) -> Vec<Binding> {
    Vec::new()
}

fn is_valid_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    let first = match chars.next() {
        Some(c) => c,
        None => return false,
    };
    if !(first.is_ascii_uppercase() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_system_binary(path: &std::path::Path) -> bool {
    let s = path.to_string_lossy();
    ["/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/System/"]
        .iter()
        .any(|p| s.starts_with(p))
}

fn send_reply(reply: &HelperReply) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(reply).map_err(std::io::Error::other)?;
    buf.push(b'\n');
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(&buf)?;
    handle.flush()?;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("envs_prompt=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
