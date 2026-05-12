use anyhow::{bail, Context, Result};
use crossterm::terminal;
use qssh_core::proto::channel::*;
use qssh_core::transport::framing::FramedBiStream;
use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ClientConfig;

/// RAII guard that restores the terminal to its original (cooked) mode when
/// dropped, even if the caller returns early or panics.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        terminal::enable_raw_mode().context("enable raw mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub async fn run(conn: &Connection, config: &ClientConfig) -> Result<()> {
    let (send, recv) = conn.open_bi().await.context("opening session stream")?;
    let mut stream = FramedBiStream::new(send, recv);

    // 1. Open session channel
    stream
        .sender
        .send(&ChannelMessage::Open {
            channel_type: ChannelType::Session,
            params: ChannelParams::Session,
        })
        .await?;

    let confirm: ChannelMessage = stream.receiver.recv().await?;
    match confirm {
        ChannelMessage::OpenConfirmation { .. } => {}
        ChannelMessage::OpenFailure {
            reason,
            description,
        } => bail!("channel open failed: {reason:?} — {description}"),
        other => bail!("expected OpenConfirmation, got {other:?}"),
    }

    // 2. Request PTY (if interactive)
    if config.command.is_none() {
        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));

        stream
            .sender
            .send(&ChannelMessage::Request {
                request_type: RequestType::PtyReq(PtyReqParams {
                    term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
                    width_cols: cols as u32,
                    height_rows: rows as u32,
                    width_px: 0,
                    height_px: 0,
                }),
                want_reply: true,
            })
            .await?;

        let _reply: ChannelMessage = stream.receiver.recv().await?;
    }

    // 3. Request shell or exec
    let request_type = match &config.command {
        Some(cmd) => RequestType::Exec {
            command: cmd.clone(),
        },
        None => RequestType::Shell,
    };

    stream
        .sender
        .send(&ChannelMessage::Request {
            request_type,
            want_reply: true,
        })
        .await?;

    let _reply: ChannelMessage = stream.receiver.recv().await?;

    // 4. I/O pump: stdin → Data messages, Data messages → stdout
    //
    // Enter raw mode so every keystroke is forwarded immediately.  The
    // `RawModeGuard` restores cooked mode on drop (including early returns
    // and panics).
    let is_interactive = config.command.is_none();
    let _raw_guard = if is_interactive {
        Some(RawModeGuard::enable()?)
    } else {
        None
    };

    // Split the framed stream so we can move each half into its own task.
    let (mut sender, mut receiver) = (stream.sender, stream.receiver);

    // --- stdout pump: QUIC → local stdout -----------------------------------
    // We use a oneshot to relay the exit status (or close) back to the main
    // thread so it can perform orderly cleanup.
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<Option<u32>>();

    let mut stdout_handle = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let exit_status: Option<u32> = loop {
            let msg: Result<ChannelMessage, _> = receiver.recv().await;
            match msg {
                Ok(ChannelMessage::Data { data }) => {
                    if let Err(e) = stdout.write_all(&data).await {
                        tracing::debug!("stdout write error: {e}");
                        break None;
                    }
                    let _ = stdout.flush().await;
                }
                Ok(ChannelMessage::ExtendedData { data, .. }) => {
                    // Extended data (e.g. stderr) — write to stderr.
                    let mut stderr = tokio::io::stderr();
                    let _ = stderr.write_all(&data).await;
                    let _ = stderr.flush().await;
                }
                Ok(ChannelMessage::ExitStatus { status }) => {
                    tracing::debug!("remote exited with status {status}");
                    break Some(status);
                }
                Ok(ChannelMessage::Eof) | Ok(ChannelMessage::Close) => break None,
                Ok(other) => {
                    tracing::trace!("ignoring channel message: {other:?}");
                }
                Err(e) => {
                    tracing::debug!("receiver error: {e}");
                    break None;
                }
            }
        };

        let _ = exit_tx.send(exit_status);
    });

    // --- stdin pump + SIGWINCH: local stdin → QUIC --------------------------
    // We multiplex stdin reads and SIGWINCH into a single task that owns the
    // `FramedSender`.
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];

        let mut sigwinch = signal(SignalKind::window_change())
            .context("registering SIGWINCH handler")?;

        loop {
            tokio::select! {
                // Stdin data ready.
                n = stdin.read(&mut buf) => {
                    match n {
                        Ok(0) => {
                            // EOF on stdin — tell server we're done sending.
                            let _ = sender.send(&ChannelMessage::Eof).await;
                            break;
                        }
                        Ok(n) => {
                            sender
                                .send(&ChannelMessage::Data {
                                    data: buf[..n].to_vec(),
                                })
                                .await
                                .context("sending stdin data")?;
                        }
                        Err(e) => {
                            tracing::debug!("stdin read error: {e}");
                            break;
                        }
                    }
                }

                // Terminal was resized.
                _ = sigwinch.recv() => {
                    if let Ok((cols, rows)) = terminal::size() {
                        let _ = sender
                            .send(&ChannelMessage::Request {
                                request_type: RequestType::WindowChange(
                                    WindowChangeParams {
                                        width_cols: cols as u32,
                                        height_rows: rows as u32,
                                        width_px: 0,
                                        height_px: 0,
                                    },
                                ),
                                want_reply: false,
                            })
                            .await;
                    }
                }

                // The stdout task has finished (server closed the channel),
                // so stop reading stdin.
                _ = &mut stdout_handle => {
                    break;
                }
            }
        }
    }

    // Wait for the stdout pump to finish (may already be done).
    let exit_status = exit_rx.await.ok().flatten();

    sender.send(&ChannelMessage::Close).await?;

    // Drop the raw-mode guard (if held) before printing the final status.
    drop(_raw_guard);

    if let Some(code) = exit_status {
        if code != 0 {
            bail!("remote process exited with status {code}");
        }
    }

    Ok(())
}
