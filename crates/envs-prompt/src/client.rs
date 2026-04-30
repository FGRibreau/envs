//! UDS client to envsd for Status polling.
//!
//! The helper has a stdin/stdout pipe to envsd for HelperEvent traffic, but
//! that channel is one-way (daemon → helper). Status polling needs a
//! request/response, so we open the same UDS socket the CLI uses
//! (`~/.envs/envsd.sock`) and send `Request::Status`.
//!
//! Failures are non-fatal: the menubar just won't update its rules-count
//! line until the next successful poll.

use envs_proto::{Request, Response};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Proto(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

fn socket_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".envs").join("envsd.sock"))
}

/// Send a single Status request and parse the reply. Times out at 2s on each
/// of connect / write / read so a wedged daemon never freezes the polling
/// thread.
pub fn query_status() -> Result<StatusSnapshot> {
    let path = socket_path().ok_or_else(|| ClientError::Proto("no home dir".into()))?;
    let mut stream = UnixStream::connect(&path)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = serde_json::to_vec(&Request::Status)
        .map_err(|e| ClientError::Proto(format!("serialize: {e}")))?;
    buf.push(b'\n');
    stream.write_all(&buf)?;
    stream.flush()?;

    // Newline-delimited JSON response — read until '\n'.
    let mut out = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        out.push(byte[0]);
        if out.len() > 65_536 {
            return Err(ClientError::Proto("status reply too large".into()));
        }
    }
    let resp: Response = serde_json::from_slice(&out)
        .map_err(|e| ClientError::Proto(format!("deserialize: {e}")))?;
    match resp {
        Response::Status {
            rules_count,
            cache_entries,
            rbw_unlocked,
            uptime_secs,
            ..
        } => Ok(StatusSnapshot {
            rules_count,
            cache_entries,
            rbw_unlocked,
            uptime_secs,
        }),
        other => Err(ClientError::Proto(format!(
            "unexpected response variant: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // cache_entries / rbw_unlocked / uptime_secs reserved for menu expansion
pub struct StatusSnapshot {
    pub rules_count: usize,
    pub cache_entries: usize,
    pub rbw_unlocked: bool,
    pub uptime_secs: u64,
}
