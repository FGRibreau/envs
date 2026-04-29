//! Client for the envsd Unix domain socket.

use crate::error::{CliError, Result};
use envs_proto::{Request, Response};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Returns `~/.envs/envsd.sock` (override via `ENVS_SOCKET` env var for tests).
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("ENVS_SOCKET") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("envsd.sock"))
}

pub async fn send_request(req: &Request) -> Result<Response> {
    let path = socket_path()?;
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound
            || e.kind() == std::io::ErrorKind::ConnectionRefused
        {
            CliError::DaemonNotRunning
        } else {
            CliError::Io(e)
        }
    })?;

    let (read_half, mut write_half) = stream.into_split();
    let mut buf = serde_json::to_vec(req)?;
    buf.push(b'\n');
    write_half.write_all(&buf).await?;
    write_half.flush().await?;
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(CliError::Internal("daemon closed connection".into()));
    }
    let resp: Response = serde_json::from_str(line.trim())?;
    if let Response::Error { code, message } = &resp {
        return Err(CliError::Daemon {
            code: *code,
            message: message.clone(),
        });
    }
    Ok(resp)
}
