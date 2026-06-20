//! SFTP file transfer over a sqsh `sftp` subsystem channel.
//!
//! The server execs the OS `sftp-server` (SFTP protocol v3) behind a subsystem
//! channel. We bridge that channel's `ChannelMessage::Data` frames to an
//! in-memory byte duplex and hand the duplex halves to `openssh-sftp-client`,
//! which speaks the SFTP wire protocol over any `AsyncRead`/`AsyncWrite`.

use anyhow::{Context, Result, bail};
use openssh_sftp_client::{Sftp, SftpOptions};
use quinn::{Connection, Endpoint};
use sqsh_core::proto::channel::*;
use sqsh_core::transport::framing::FramedBiStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ClientConfig;
use crate::control::MasterConnection;

const SFTP_SUBSYSTEM: &str = "sftp";
// ponytail: ChannelMessage frames are capped at 64 KiB; 32 KiB chunks leave
// ample headroom for the postcard envelope. Bump if throughput needs it.
const CHUNK: usize = 32 * 1024;
const BRIDGE_BUF: usize = 256 * 1024;

/// An authenticated SFTP session. Holds the QUIC connection, endpoint, control
/// stream, and bridge tasks alive for as long as `sftp` is used.
pub struct SftpClient {
    pub sftp: Sftp,
    conn: Connection,
    endpoint: Endpoint,
    // Kept open so the server's control loop doesn't see EOF and tear down the
    // connection; never written to after auth.
    _control: FramedBiStream,
    writer_task: tokio::task::JoinHandle<()>,
    reader_task: tokio::task::JoinHandle<()>,
}

impl SftpClient {
    /// Tear down the SFTP session and close the underlying QUIC connection.
    pub async fn close(self) {
        drop(self.sftp); // closes the subsystem write side -> server sees EOF
        self.writer_task.abort();
        self.reader_task.abort();
        self.conn.close(0u32.into(), b"bye");
        self.endpoint.wait_idle().await;
    }
}

/// Connect, authenticate, open the `sftp` subsystem, and initialize an SFTP session.
pub async fn connect(config: &ClientConfig) -> Result<SftpClient> {
    let MasterConnection {
        conn,
        endpoint,
        control,
    } = crate::connection::open_authenticated(config).await?;

    let channel = open_subsystem_channel(
        &conn,
        SFTP_SUBSYSTEM,
        &crate::channel::session::forwarded_env(),
    )
    .await?;

    // Bridge: ChannelMessage::Data frames <-> raw byte stream for the SFTP client.
    let (app, bridge) = tokio::io::duplex(BRIDGE_BUF);
    let (app_rd, app_wr) = tokio::io::split(app);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge);

    let FramedBiStream {
        mut sender,
        mut receiver,
    } = channel;

    // Bytes the SFTP client writes -> Data frames to the server.
    let writer_task = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match bridge_rd.read(&mut buf).await {
                Ok(0) => {
                    let _ = sender.send(&ChannelMessage::Eof).await;
                    break;
                }
                Ok(n) => {
                    let data = buf[..n].to_vec();
                    if sender.send(&ChannelMessage::Data { data }).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Data frames from the server -> bytes for the SFTP client.
    let reader_task = tokio::spawn(async move {
        loop {
            match receiver.recv::<ChannelMessage>().await {
                Ok(ChannelMessage::Data { data }) => {
                    if bridge_wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Ok(ChannelMessage::ExtendedData { data, .. }) => {
                    // sftp-server diagnostics on stderr — surface to the user.
                    let mut err = tokio::io::stderr();
                    let _ = err.write_all(&data).await;
                }
                Ok(ChannelMessage::Eof) | Ok(ChannelMessage::Close) | Err(_) => break,
                Ok(_) => {}
            }
        }
        // Dropping bridge_wr here signals EOF to the SFTP client's reader.
    });

    let sftp = Sftp::new(app_wr, app_rd, SftpOptions::default())
        .await
        .context("initializing SFTP session (is sftp-server installed on the server?)")?;

    Ok(SftpClient {
        sftp,
        conn,
        endpoint,
        _control: control,
        writer_task,
        reader_task,
    })
}

async fn open_subsystem_channel(
    conn: &Connection,
    name: &str,
    env: &[(String, String)],
) -> Result<FramedBiStream> {
    let (send, recv) = conn.open_bi().await.context("opening sftp channel")?;
    let mut ch = FramedBiStream::new(send, recv);

    ch.sender
        .send(&ChannelMessage::Open {
            channel_type: ChannelType::Session,
            params: ChannelParams::Session,
        })
        .await?;

    match ch.receiver.recv::<ChannelMessage>().await? {
        ChannelMessage::OpenConfirmation { .. } => {}
        ChannelMessage::OpenFailure {
            reason,
            description,
        } => bail!("channel open failed: {reason:?} — {description}"),
        other => bail!("expected OpenConfirmation, got {other:?}"),
    }

    for (k, v) in env {
        ch.sender
            .send(&ChannelMessage::Request {
                request_type: RequestType::Env {
                    name: k.clone(),
                    value: v.clone(),
                },
                want_reply: false,
            })
            .await?;
    }

    ch.sender
        .send(&ChannelMessage::Request {
            request_type: RequestType::Subsystem {
                name: name.to_string(),
            },
            want_reply: true,
        })
        .await?;

    match ch.receiver.recv::<ChannelMessage>().await? {
        ChannelMessage::RequestSuccess => {}
        ChannelMessage::RequestFailure => {
            bail!("server has no '{name}' subsystem configured")
        }
        other => bail!("expected subsystem reply, got {other:?}"),
    }

    Ok(ch)
}
