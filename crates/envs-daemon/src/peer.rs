//! Peer (caller) identity verification on macOS.
//!
//! When a CLI invocation connects to the daemon via UDS, we verify:
//! - The connecting peer's effective UID matches our own (cross-user denied)
//! - (v0.2) The peer's executable path matches what they claim
//!
//! v0.1 implements only the UID check. PID-based path verification requires
//! `proc_pidpath()` and is racy (PID reuse between connect and lookup), so it's
//! deferred to v0.2 with a libproc dependency. The threat model already
//! excludes same-UID attackers (see docs/THREAT-MODEL.md).

use crate::error::{DaemonError, Result};
use std::os::fd::AsRawFd;
use tokio::net::UnixStream;

/// Verify the connecting peer is the same UID as the daemon.
///
/// Returns Ok if peer UID matches getuid(), Err otherwise.
#[cfg(target_os = "macos")]
pub fn verify_same_uid(stream: &UnixStream) -> Result<()> {
    let fd = stream.as_raw_fd();
    let our_uid = unsafe { libc::getuid() };

    // macOS uses LOCAL_PEERPID and LOCAL_PEEREUID via getsockopt with level SOL_LOCAL.
    // SOL_LOCAL = 0, LOCAL_PEEREUID = 0x6 on Darwin.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEEREUID: libc::c_int = 0x6;

    let mut peer_uid: libc::uid_t = 0;
    let mut len = std::mem::size_of::<libc::uid_t>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEEREUID,
            &mut peer_uid as *mut _ as *mut libc::c_void,
            &mut len as *mut _,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        return Err(DaemonError::Internal(format!(
            "getsockopt LOCAL_PEEREUID failed: {err}"
        )));
    }

    if peer_uid != our_uid {
        return Err(DaemonError::Internal(format!(
            "peer UID mismatch: peer={peer_uid} ours={our_uid}"
        )));
    }

    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn verify_same_uid(_stream: &UnixStream) -> Result<()> {
    // Non-macOS builds (CI/dev): no-op.
    Ok(())
}
