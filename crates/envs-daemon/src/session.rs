//! GUI (Aqua) session detection.
//!
//! `envs` relaxed its hard TTY requirement: a non-interactive caller — an MCP
//! server or AI agent launched by launchd with no controlling terminal — still
//! gets the native consent popup + TouchID, because the popup is driven by the
//! daemon's helper subprocess living in the user's GUI session, not by the
//! caller. But that only works when a GUI session actually exists. Over SSH
//! with no display, or in headless CI, no window can be drawn; there we must
//! fail fast rather than block on a popup that will never appear.
//!
//! `CGSessionCopyCurrentDictionary` returns NULL when the calling process has
//! no connection to the window server (no Aqua session) and a non-NULL
//! dictionary otherwise — exactly the discriminator we need.

/// True when a window can be drawn for the user (an Aqua session exists), or
/// when explicitly forced via `ENVS_ASSUME_GUI` (an escape hatch for tests and
/// exotic setups). On non-macOS the popup is a stub, so we report true.
pub fn gui_session_available() -> bool {
    if std::env::var_os("ENVS_ASSUME_GUI").is_some() {
        return true;
    }
    detect()
}

#[cfg(target_os = "macos")]
fn detect() -> bool {
    use std::ffi::c_void;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> *const c_void;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    // SAFETY: both are pure C calls with no arguments. The returned dictionary
    // (if any) is owned by us under the Core Foundation "Copy" rule, so we
    // release it immediately — we only care about its presence, not contents.
    unsafe {
        let dict = CGSessionCopyCurrentDictionary();
        if dict.is_null() {
            false
        } else {
            CFRelease(dict);
            true
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn detect() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assume_gui_env_forces_true() {
        std::env::set_var("ENVS_ASSUME_GUI", "1");
        assert!(gui_session_available());
        std::env::remove_var("ENVS_ASSUME_GUI");
    }
}
