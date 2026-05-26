use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use qssh_core::proto::channel::*;
use qssh_core::proto::codec::{read_message, write_message};
use qssh_core::proto::message::ControlMessage;
use qssh_core::transport::framing::FramedBiStream;
use quinn::{Connection, Endpoint};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, mpsc};

use crate::config::{ClientConfig, ForwardSpec};

const MASTER_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const MASTER_STARTUP_POLL: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasterSessionRequest {
    pub command: Option<String>,
    pub no_shell: bool,
    pub local_forwards: Vec<ForwardSpec>,
    pub remote_forwards: Vec<ForwardSpec>,
    pub pty: Option<PtyReqParams>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    Open(MasterSessionRequest),
    Stdin(Vec<u8>),
    Eof,
    WindowChange(WindowChangeParams),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MasterMessage {
    Ready,
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    ExitStatus(u32),
    Eof,
    Error(String),
}

pub struct MasterConnection {
    pub conn: Connection,
    pub endpoint: Endpoint,
    pub control: FramedBiStream,
}

pub async fn run_master(config: ClientConfig, master: MasterConnection) -> Result<()> {
    prepare_socket_path(&config.control_path)?;

    match UnixListener::bind(&config.control_path) {
        Ok(listener) => serve_master(config, master, listener).await,
        Err(e) => Err(e).with_context(|| {
            format!(
                "binding ControlMaster socket {}",
                config.control_path.display()
            )
        }),
    }
}

pub async fn run_via_master_or_spawn(config: ClientConfig) -> Result<bool> {
    if send_request_to_master(&config).await? {
        return Ok(true);
    }

    if !config.control_persist.is_enabled() {
        return Ok(false);
    }

    spawn_master(&config).await?;
    wait_for_master(&config.control_path).await?;

    if send_request_to_master(&config).await? {
        Ok(true)
    } else {
        bail!(
            "ControlMaster at {} did not accept a session after startup",
            config.control_path.display()
        )
    }
}

async fn serve_master(
    config: ClientConfig,
    master: MasterConnection,
    listener: UnixListener,
) -> Result<()> {
    let conn = master.conn;
    let control = Arc::new(Mutex::new(master.control));
    let _migration_handle = crate::migration::spawn_monitor(master.endpoint.clone());
    let remote_forwards = Arc::new(tokio::sync::RwLock::new(Vec::new()));
    tokio::spawn(
        crate::channel::forward::accept_remote_forward_streams_shared(
            conn.clone(),
            remote_forwards.clone(),
        ),
    );
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
    let mut active_clients = 0usize;

    loop {
        if active_clients == 0
            && let Some(timeout) = config.control_persist.idle_timeout()
        {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("accepting ControlMaster client")?;
                    active_clients += 1;
                    spawn_client_handler(stream, conn.clone(), control.clone(), remote_forwards.clone(), done_tx.clone());
                }
                _ = tokio::time::sleep(timeout) => break,
            }
            continue;
        }

        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accepting ControlMaster client")?;
                active_clients += 1;
                spawn_client_handler(stream, conn.clone(), control.clone(), remote_forwards.clone(), done_tx.clone());
            }
            Some(()) = done_rx.recv(), if active_clients > 0 => {
                active_clients -= 1;
            }
        }
    }

    conn.close(0u32.into(), b"control persist timeout");
    let _ = std::fs::remove_file(&config.control_path);
    Ok(())
}

fn spawn_client_handler(
    stream: UnixStream,
    conn: Connection,
    control: Arc<Mutex<FramedBiStream>>,
    remote_forwards: crate::channel::forward::SharedForwardSpecs,
    done_tx: mpsc::UnboundedSender<()>,
) {
    tokio::spawn(async move {
        if let Err(e) = handle_master_client(stream, conn, control, remote_forwards).await {
            tracing::warn!("ControlMaster client error: {e}");
        }
        let _ = done_tx.send(());
    });
}

async fn handle_master_client(
    mut stream: UnixStream,
    conn: Connection,
    control: Arc<Mutex<FramedBiStream>>,
    remote_forwards: crate::channel::forward::SharedForwardSpecs,
) -> Result<()> {
    let request: ClientMessage = read_message(&mut stream).await?;
    let request = match request {
        ClientMessage::Open(request) => request,
        other => bail!("expected ControlMaster open request, got {other:?}"),
    };

    for spec in request.local_forwards.iter().cloned() {
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::channel::forward::run_local_listener(conn, spec).await {
                tracing::warn!("local forward ended: {e}");
            }
        });
    }

    for spec in &request.remote_forwards {
        {
            let mut specs = remote_forwards.write().await;
            if !specs
                .iter()
                .any(|s| s.bind_addr == spec.bind_addr && s.bind_port == spec.bind_port)
            {
                specs.push(spec.clone());
            }
        }

        let mut control = control.lock().await;
        control
            .sender
            .send(&ControlMessage::TcpForwardRequest {
                bind_addr: spec.bind_addr.clone(),
                bind_port: spec.bind_port,
            })
            .await?;
        let reply: ControlMessage = control.receiver.recv().await?;
        match reply {
            ControlMessage::TcpForwardConfirm { .. } => {}
            ControlMessage::TcpForwardFailure { description } => {
                remote_forwards
                    .write()
                    .await
                    .retain(|s| s.bind_addr != spec.bind_addr || s.bind_port != spec.bind_port);
                write_message(&mut stream, &MasterMessage::Error(description)).await?;
                return Ok(());
            }
            other => bail!("expected TcpForwardConfirm, got {other:?}"),
        }
    }

    if request.no_shell {
        write_message(&mut stream, &MasterMessage::Ready).await?;
        drain_client_until_eof(stream).await;
        return Ok(());
    }

    run_session_for_client(stream, conn, request).await
}

async fn run_session_for_client(
    mut stream: UnixStream,
    conn: Connection,
    request: MasterSessionRequest,
) -> Result<()> {
    let (send, recv) = conn.open_bi().await.context("opening session stream")?;
    let mut channel = FramedBiStream::new(send, recv);

    channel
        .sender
        .send(&ChannelMessage::Open {
            channel_type: ChannelType::Session,
            params: ChannelParams::Session,
        })
        .await?;

    let confirm: ChannelMessage = channel.receiver.recv().await?;
    match confirm {
        ChannelMessage::OpenConfirmation { .. } => {}
        ChannelMessage::OpenFailure {
            reason,
            description,
        } => {
            write_message(
                &mut stream,
                &MasterMessage::Error(format!("channel open failed: {reason:?} — {description}")),
            )
            .await?;
            return Ok(());
        }
        other => bail!("expected OpenConfirmation, got {other:?}"),
    }

    if let Some(pty) = request.pty {
        channel
            .sender
            .send(&ChannelMessage::Request {
                request_type: RequestType::PtyReq(pty),
                want_reply: true,
            })
            .await?;
        let _reply: ChannelMessage = channel.receiver.recv().await?;
    }

    let request_type = match request.command {
        Some(command) => RequestType::Exec { command },
        None => RequestType::Shell,
    };

    channel
        .sender
        .send(&ChannelMessage::Request {
            request_type,
            want_reply: true,
        })
        .await?;
    let _reply: ChannelMessage = channel.receiver.recv().await?;

    write_message(&mut stream, &MasterMessage::Ready).await?;

    let (mut local_read, mut local_write) = stream.into_split();
    let (mut sender, mut receiver) = (channel.sender, channel.receiver);
    let mut exit_status = None;

    loop {
        tokio::select! {
            msg = receiver.recv::<ChannelMessage>() => {
                match msg {
                    Ok(ChannelMessage::Data { data }) => {
                        write_message(&mut local_write, &MasterMessage::Stdout(data)).await?;
                    }
                    Ok(ChannelMessage::ExtendedData { data, .. }) => {
                        write_message(&mut local_write, &MasterMessage::Stderr(data)).await?;
                    }
                    Ok(ChannelMessage::ExitStatus { status }) => {
                        exit_status = Some(status);
                        write_message(&mut local_write, &MasterMessage::ExitStatus(status)).await?;
                    }
                    Ok(ChannelMessage::Eof) | Ok(ChannelMessage::Close) => {
                        write_message(&mut local_write, &MasterMessage::Eof).await.ok();
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            msg = read_message::<_, ClientMessage>(&mut local_read) => {
                match msg {
                    Ok(ClientMessage::Stdin(data)) => {
                        sender.send(&ChannelMessage::Data { data }).await?;
                    }
                    Ok(ClientMessage::Eof) => {
                        sender.send(&ChannelMessage::Eof).await.ok();
                    }
                    Ok(ClientMessage::WindowChange(params)) => {
                        sender
                            .send(&ChannelMessage::Request {
                                request_type: RequestType::WindowChange(params),
                                want_reply: false,
                            })
                            .await
                            .ok();
                    }
                    Ok(ClientMessage::Open(_)) => {}
                    Err(_) => break,
                }
            }
        }
    }

    sender.send(&ChannelMessage::Close).await.ok();

    if let Some(status) = exit_status {
        tracing::debug!(status, "ControlMaster session exited");
    }

    Ok(())
}

async fn drain_client_until_eof(mut stream: UnixStream) {
    while let Ok(message) = read_message::<_, ClientMessage>(&mut stream).await {
        if matches!(message, ClientMessage::Eof) {
            break;
        }
    }
}

async fn send_request_to_master(config: &ClientConfig) -> Result<bool> {
    let stream = match UnixStream::connect(&config.control_path).await {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            remove_stale_socket(&config.control_path)?;
            return Ok(false);
        }
        Err(e) => return Err(e).with_context(|| "connecting to ControlMaster"),
    };

    run_slave_session(stream, config).await?;
    Ok(true)
}

async fn run_slave_session(mut stream: UnixStream, config: &ClientConfig) -> Result<()> {
    let interactive = config.command.is_none() && !config.no_shell;
    let pty = if interactive {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        Some(PtyReqParams {
            term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
            width_cols: cols as u32,
            height_rows: rows as u32,
            width_px: 0,
            height_px: 0,
        })
    } else {
        None
    };

    write_message(
        &mut stream,
        &ClientMessage::Open(MasterSessionRequest {
            command: config.command.clone(),
            no_shell: config.no_shell,
            local_forwards: config.local_forwards.clone(),
            remote_forwards: config.remote_forwards.clone(),
            pty,
        }),
    )
    .await?;

    match read_message::<_, MasterMessage>(&mut stream).await? {
        MasterMessage::Ready => {}
        MasterMessage::Error(message) => bail!(message),
        other => bail!("expected ControlMaster ready, got {other:?}"),
    }

    if config.no_shell {
        tokio::signal::ctrl_c().await?;
        write_message(&mut stream, &ClientMessage::Eof).await.ok();
        return Ok(());
    }

    run_slave_io(stream, interactive).await
}

async fn run_slave_io(stream: UnixStream, interactive: bool) -> Result<()> {
    let _raw_guard = if interactive {
        Some(RawModeGuard::enable()?)
    } else {
        None
    };

    let (mut local_read, mut local_write) = stream.into_split();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut stdin = tokio::io::stdin();
    let mut buf = [0u8; 4096];

    #[cfg(unix)]
    let mut sigwinch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            .context("registering SIGWINCH handler")?;

    let mut exit_status = None;
    let mut stdin_open = true;

    loop {
        tokio::select! {
            n = stdin.read(&mut buf), if stdin_open => {
                match n {
                    Ok(0) => {
                        write_message(&mut local_write, &ClientMessage::Eof).await.ok();
                        stdin_open = false;
                    }
                    Ok(n) => {
                        write_message(&mut local_write, &ClientMessage::Stdin(buf[..n].to_vec())).await?;
                    }
                    Err(_) => break,
                }
            }
            msg = read_message::<_, MasterMessage>(&mut local_read) => {
                match msg {
                    Ok(MasterMessage::Stdout(data)) => {
                        stdout.write_all(&data).await?;
                        stdout.flush().await?;
                    }
                    Ok(MasterMessage::Stderr(data)) => {
                        stderr.write_all(&data).await?;
                        stderr.flush().await?;
                    }
                    Ok(MasterMessage::ExitStatus(status)) => {
                        exit_status = Some(status);
                    }
                    Ok(MasterMessage::Eof) | Err(_) => break,
                    Ok(MasterMessage::Error(message)) => bail!(message),
                    Ok(MasterMessage::Ready) => {}
                }
            }
            _ = sigwinch.recv(), if interactive => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    write_message(
                        &mut local_write,
                        &ClientMessage::WindowChange(WindowChangeParams {
                            width_cols: cols as u32,
                            height_rows: rows as u32,
                            width_px: 0,
                            height_px: 0,
                        }),
                    )
                    .await
                    .ok();
                }
            }
        }
    }

    drop(_raw_guard);

    if let Some(code) = exit_status
        && code != 0
    {
        bail!("remote process exited with status {code}");
    }

    Ok(())
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating ControlMaster directory {}", parent.display()))?;
        set_owner_only_permissions(parent)?;
    }

    remove_socket_file(path)
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    remove_socket_file(path)
}

fn remove_socket_file(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };

    if !is_unix_socket(&metadata) {
        bail!(
            "refusing to remove non-socket ControlMaster path {}",
            path.display()
        );
    }

    std::fs::remove_file(path).with_context(|| format!("removing stale socket {}", path.display()))
}

#[cfg(unix)]
fn is_unix_socket(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;

    metadata.file_type().is_socket()
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 700 {}", path.display()))
}

async fn spawn_master(config: &ClientConfig) -> Result<()> {
    let exe = std::env::current_exe().context("resolving current executable")?;
    let mut command = tokio::process::Command::new(exe);
    command
        .arg("--control-master")
        .arg("--control-path")
        .arg(&config.control_path)
        .arg("--control-persist")
        .arg(
            config
                .control_persist
                .as_arg()
                .unwrap_or_else(|| "yes".to_string()),
        )
        .arg("-p")
        .arg(config.port.to_string())
        .arg("-l")
        .arg(&config.username)
        .arg("-i")
        .arg(&config.identity_path)
        .arg(&config.host)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    command.spawn().context("spawning ControlMaster")?;
    Ok(())
}

async fn wait_for_master(path: &Path) -> Result<()> {
    let deadline = tokio::time::Instant::now() + MASTER_STARTUP_TIMEOUT;
    loop {
        match UnixStream::connect(path).await {
            Ok(_) => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                if tokio::time::Instant::now() >= deadline {
                    bail!("timed out waiting for ControlMaster at {}", path.display());
                }
                tokio::time::sleep(MASTER_STARTUP_POLL).await;
            }
            Err(e) => return Err(e).with_context(|| "waiting for ControlMaster"),
        }
    }
}

struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssh_core::proto::codec::{read_message, write_message};

    #[tokio::test]
    async fn control_protocol_roundtrips_session_request() {
        let request = ClientMessage::Open(MasterSessionRequest {
            command: Some("true".to_string()),
            no_shell: false,
            local_forwards: vec![ForwardSpec {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 8022,
                target_host: "localhost".to_string(),
                target_port: 22,
            }],
            remote_forwards: Vec::new(),
            pty: Some(PtyReqParams {
                term: "xterm".to_string(),
                width_cols: 80,
                height_rows: 24,
                width_px: 0,
                height_px: 0,
            }),
        });

        let mut buf = Vec::new();
        write_message(&mut buf, &request).await.unwrap();
        let decoded: ClientMessage = read_message(&mut &buf[..]).await.unwrap();

        match decoded {
            ClientMessage::Open(decoded) => {
                assert_eq!(decoded.command.as_deref(), Some("true"));
                assert_eq!(decoded.local_forwards[0].bind_port, 8022);
                assert_eq!(decoded.pty.unwrap().width_cols, 80);
            }
            other => panic!("expected open request, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_protocol_roundtrips_exit_status() {
        let mut buf = Vec::new();
        write_message(&mut buf, &MasterMessage::ExitStatus(7))
            .await
            .unwrap();
        let decoded: MasterMessage = read_message(&mut &buf[..]).await.unwrap();
        assert!(matches!(decoded, MasterMessage::ExitStatus(7)));
    }
}
