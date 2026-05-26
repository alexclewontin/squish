use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use qssh_core::proto::channel::*;
use qssh_core::transport::framing::FramedBiStream;
use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::config::ForwardSpec;
pub type SharedForwardSpecs = Arc<RwLock<Vec<ForwardSpec>>>;

// ---------------------------------------------------------------------------
// Local forward (-L): listen locally, open DirectTcpip streams to the server.
// ---------------------------------------------------------------------------

/// Bind a local TCP listener and open a DirectTcpip QUIC channel for each
/// accepted connection.  Runs until the QUIC connection closes or the
/// listener encounters an error.
pub async fn run_local_listener(conn: Connection, spec: ForwardSpec) -> Result<()> {
    let bind = format!("{}:{}", spec.bind_addr, spec.bind_port);
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding local forward listener on {bind}"))?;
    tracing::info!(
        listen = %bind,
        target = %format!("{}:{}", spec.target_host, spec.target_port),
        "local forward active",
    );

    loop {
        let (tcp, originator) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("local forward accept error: {e}");
                break;
            }
        };
        let conn = conn.clone();
        let spec = spec.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local_connection(conn, tcp, originator, spec).await {
                tracing::warn!("local forward connection error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_local_connection(
    conn: Connection,
    tcp: TcpStream,
    originator: SocketAddr,
    spec: ForwardSpec,
) -> Result<()> {
    let (send, recv) = conn.open_bi().await.context("opening DirectTcpip stream")?;
    let mut framed = FramedBiStream::new(send, recv);

    framed
        .sender
        .send(&ChannelMessage::Open {
            channel_type: ChannelType::DirectTcpip,
            params: ChannelParams::DirectTcpip(TcpipParams {
                host: spec.target_host.clone(),
                port: spec.target_port,
                originator_addr: originator.ip().to_string(),
                originator_port: originator.port(),
            }),
        })
        .await?;

    let reply: ChannelMessage = framed.receiver.recv().await?;
    match reply {
        ChannelMessage::OpenConfirmation { .. } => {}
        ChannelMessage::OpenFailure {
            reason,
            description,
        } => bail!("direct-tcpip refused: {reason:?} — {description}"),
        other => bail!("expected OpenConfirmation, got {other:?}"),
    }

    pump(tcp, &mut framed).await
}

// ---------------------------------------------------------------------------
// Remote forward (-R): accept ForwardedTcpip streams opened by the server.
// ---------------------------------------------------------------------------

/// Accept inbound QUIC streams (opened by the server for each remote-forward
/// connection) and proxy them to the local target.
pub async fn accept_remote_forward_streams(conn: Connection, specs: Vec<ForwardSpec>) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let specs = specs.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_remote_forward_stream(send, recv, specs).await {
                tracing::warn!("remote forward stream error: {e}");
            }
        });
    }
}

pub async fn accept_remote_forward_streams_shared(conn: Connection, specs: SharedForwardSpecs) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let specs = specs.clone();
        tokio::spawn(async move {
            let specs = specs.read().await.clone();
            if let Err(e) = handle_remote_forward_stream(send, recv, specs).await {
                tracing::warn!("remote forward stream error: {e}");
            }
        });
    }
}

async fn handle_remote_forward_stream(
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    specs: Vec<ForwardSpec>,
) -> Result<()> {
    let mut framed = FramedBiStream::new(send, recv);

    let open: ChannelMessage = framed.receiver.recv().await?;
    let params = match open {
        ChannelMessage::Open {
            channel_type: ChannelType::ForwardedTcpip,
            params: ChannelParams::ForwardedTcpip(p),
        } => p,
        other => bail!("expected ForwardedTcpip Open, got {other:?}"),
    };

    // Match by the bound port (params.port is the server's listening port).
    let spec = match specs.iter().find(|s| s.bind_port == params.port) {
        Some(s) => s.clone(),
        None => {
            framed
                .sender
                .send(&ChannelMessage::OpenFailure {
                    reason: ChannelFailureReason::AdministrativelyProhibited,
                    description: format!("no handler for forwarded port {}", params.port),
                })
                .await
                .ok();
            bail!("no handler for forwarded port {}", params.port);
        }
    };

    let tcp = TcpStream::connect(format!("{}:{}", spec.target_host, spec.target_port))
        .await
        .with_context(|| {
            format!(
                "connecting to local target {}:{}",
                spec.target_host, spec.target_port
            )
        })?;

    framed
        .sender
        .send(&ChannelMessage::OpenConfirmation {
            max_packet_size: 32 * 1024,
        })
        .await?;

    pump(tcp, &mut framed).await
}

// ---------------------------------------------------------------------------
// Shared pump: bidirectional relay between TCP and a framed QUIC channel.
// ---------------------------------------------------------------------------

async fn pump(tcp: TcpStream, framed: &mut FramedBiStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            n = tcp_read.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => {
                        framed.sender.send(&ChannelMessage::Eof).await.ok();
                        break;
                    }
                    Ok(n) => {
                        framed.sender.send(&ChannelMessage::Data {
                            data: buf[..n].to_vec(),
                        }).await?;
                    }
                }
            }
            msg = framed.receiver.recv::<ChannelMessage>() => {
                match msg {
                    Ok(ChannelMessage::Data { data }) => {
                        if tcp_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Ok(ChannelMessage::Eof) | Ok(ChannelMessage::Close) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
    Ok(())
}
