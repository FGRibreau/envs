//! UDS server: accept connections, parse JSON request, dispatch, write JSON response.

use crate::error::Result;
use crate::handlers::Handlers;
use envs_proto::{ErrorCode, Request, Response};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

pub fn socket_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("ENVS_SOCKET") {
        return Ok(PathBuf::from(p));
    }
    let home = dirs::home_dir()
        .ok_or_else(|| crate::error::DaemonError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("envsd.sock"))
}

pub async fn run(handlers: Arc<Handlers>, socket: PathBuf) -> Result<()> {
    let parent = socket
        .parent()
        .ok_or_else(|| crate::error::DaemonError::Internal("socket has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    set_dir_perms(parent, 0o700)?;

    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    let listener = UnixListener::bind(&socket)?;
    set_file_perms(&socket, 0o600)?;
    tracing::info!(path = %socket.display(), "UDS server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let h = handlers.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, h).await {
                        tracing::warn!(?e, "connection handler error");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(?e, "accept failed");
            }
        }
    }
}

async fn handle_conn(stream: UnixStream, handlers: Arc<Handlers>) -> Result<()> {
    // Verify caller identity (cross-UID denied; same-UID allowed per threat model).
    if let Err(e) = crate::peer::verify_same_uid(&stream) {
        tracing::warn!(?e, "rejecting connection: peer verification failed");
        let _ = crate::audit::event("unknown_caller")
            .field("error", e.to_string())
            .write();
        return Err(e);
    }

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    if let Some(line) = reader.next_line().await? {
        let req_result: std::result::Result<Request, _> = serde_json::from_str(&line);
        let resp = match req_result {
            Ok(req) => handlers.dispatch(req).await,
            Err(e) => Response::Error {
                code: ErrorCode::ProtocolMismatch,
                message: format!("bad request: {e}"),
            },
        };
        let mut buf = serde_json::to_vec(&resp)?;
        buf.push(b'\n');
        write_half.write_all(&buf).await?;
        write_half.flush().await?;
    }

    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}
