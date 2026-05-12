use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use qssh_core::proto::channel::*;
use qssh_core::transport::framing::FramedBiStream;
use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// DirectTcpip: server connects to the requested target and pumps data.
// ---------------------------------------------------------------------------

/// Handle a DirectTcpip channel.  Called after the dispatcher has already
/// sent `OpenConfirmation`.  Connects to `params.host:params.port` and relays
/// data until either side closes.
pub async fn handle_direct_tcpip(mut stream: FramedBiStream, params: TcpipParams) -> Result<()> {
    let target = format!("{}:{}", params.host, params.port);
    let tcp = TcpStream::connect(&target)
        .await
        .with_context(|| format!("connecting to direct-tcpip target {target}"))?;
    pump(tcp, &mut stream).await
}

// ---------------------------------------------------------------------------
// Remote forward: server listens and opens ForwardedTcpip streams to client.
// ---------------------------------------------------------------------------

/// Bind a TCP listener on the server and open a ForwardedTcpip QUIC stream
/// to the client for every accepted connection.
pub async fn run_remote_forward(conn: Connection, bind_addr: String, bind_port: u16) -> Result<()> {
    let bind = format!("{bind_addr}:{bind_port}");
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding remote forward listener on {bind}"))?;
    tracing::info!("remote forward listening on {bind}");

    loop {
        let (tcp, originator) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("remote forward accept error: {e}");
                break;
            }
        };
        let conn = conn.clone();
        let bind_addr = bind_addr.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_remote_connection(conn, tcp, originator, bind_addr, bind_port).await
            {
                tracing::warn!("remote forward connection error: {e}");
            }
        });
    }
    Ok(())
}

async fn handle_remote_connection(
    conn: Connection,
    tcp: TcpStream,
    originator: SocketAddr,
    bind_addr: String,
    bind_port: u16,
) -> Result<()> {
    let (send, recv) = conn
        .open_bi()
        .await
        .context("opening ForwardedTcpip stream to client")?;
    let mut framed = FramedBiStream::new(send, recv);

    framed
        .sender
        .send(&ChannelMessage::Open {
            channel_type: ChannelType::ForwardedTcpip,
            params: ChannelParams::ForwardedTcpip(TcpipParams {
                host: bind_addr,
                port: bind_port,
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
        } => bail!("client rejected ForwardedTcpip: {reason:?} — {description}"),
        other => bail!("expected OpenConfirmation, got {other:?}"),
    }

    pump(tcp, &mut framed).await
}

// ---------------------------------------------------------------------------
// Shared pump
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
