use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result};
use nix::fcntl::{FcntlArg, OFlag};
use nix::pty::{Winsize, openpty};
use nix::sys::signal::{self, Signal};
use nix::unistd::{Pid, User};
use qssh_core::proto::channel::*;
use qssh_core::transport::framing::FramedBiStream;
use tokio::io::unix::AsyncFd;
use tokio::process::Command;

use crate::config::ServerConfig;

// ---------------------------------------------------------------------------
// TIOCSWINSZ ioctl — resize a PTY. Works on both macOS and Linux.
// ---------------------------------------------------------------------------
nix::ioctl_write_ptr_bad!(tiocswinsz, libc::TIOCSWINSZ, Winsize);

/// Handle a session channel.  Called after the dispatcher has already read
/// the `Open` message and sent `OpenConfirmation`.
pub async fn handle(
    stream: &mut FramedBiStream,
    username: &str,
    _config: &Arc<ServerConfig>,
) -> Result<()> {
    // Handle requests: accumulate pty-req, then launch on shell/exec.
    let mut pty_params: Option<PtyReqParams> = None;

    loop {
        let msg: ChannelMessage = stream
            .receiver
            .recv()
            .await
            .context("reading channel request")?;

        match msg {
            ChannelMessage::Request {
                request_type: RequestType::PtyReq(params),
                want_reply,
            } => {
                tracing::info!(%username, term = %params.term, "pty-req");
                pty_params = Some(params);
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
            }
            ChannelMessage::Request {
                request_type: RequestType::Shell,
                want_reply,
            } => {
                let shell = lookup_shell(username);
                tracing::info!(%username, %shell, "shell request");
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
                return run_child(stream, username, &shell, &[], pty_params.take()).await;
            }
            ChannelMessage::Request {
                request_type: RequestType::Exec { command },
                want_reply,
            } => {
                tracing::info!(%username, %command, "exec request");
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
                let shell = lookup_shell(username);
                return run_child(
                    stream,
                    username,
                    &shell,
                    &["-c", &command],
                    pty_params.take(),
                )
                .await;
            }
            ChannelMessage::Request {
                request_type: RequestType::WindowChange(_),
                want_reply,
            } => {
                // No PTY yet — ignore.
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
            }
            ChannelMessage::Request {
                request_type,
                want_reply,
            } => {
                tracing::debug!(?request_type, "unsupported channel request");
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestFailure).await?;
                }
            }
            ChannelMessage::Close | ChannelMessage::Eof => {
                stream.sender.send(&ChannelMessage::Close).await?;
                return Ok(());
            }
            other => {
                tracing::debug!(?other, "unexpected message before shell/exec");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Child process lifecycle
// ---------------------------------------------------------------------------

async fn run_child(
    stream: &mut FramedBiStream,
    username: &str,
    shell: &str,
    args: &[&str],
    pty_params: Option<PtyReqParams>,
) -> Result<()> {
    // Allocate PTY if requested.
    let winsize = pty_params.as_ref().map(|p| Winsize {
        ws_row: p.height_rows as u16,
        ws_col: p.width_cols as u16,
        ws_xpixel: p.width_px as u16,
        ws_ypixel: p.height_px as u16,
    });

    let pty_result =
        openpty(winsize.as_ref(), None::<&nix::sys::termios::Termios>).context("openpty failed")?;

    let master_fd = pty_result.master;
    let slave_fd = pty_result.slave;

    // Set the master fd to non-blocking for async I/O.
    set_nonblocking(&master_fd)?;

    let term = pty_params
        .as_ref()
        .map(|p| p.term.clone())
        .unwrap_or_else(|| "xterm".to_string());

    // Build the child command.
    let slave_raw_fd = slave_fd.as_raw_fd();
    let mut cmd = std::process::Command::new(shell);
    cmd.args(args);
    cmd.env("TERM", &term);
    cmd.env("USER", username);
    cmd.env("LOGNAME", username);

    // Use the slave fd as stdin/stdout/stderr.
    cmd.stdin(fd_to_stdio(&slave_fd)?);
    cmd.stdout(fd_to_stdio(&slave_fd)?);
    cmd.stderr(fd_to_stdio(&slave_fd)?);

    // Pre-exec: create a new session and set the controlling terminal.
    // SAFETY: pre_exec runs in the child after fork() but before exec().
    // At that point we are single-threaded and only async-signal-safe calls
    // are permitted. setsid(2) and ioctl(2) both qualify. The slave_raw_fd
    // captured here is valid: slave_fd is still open in the parent and the
    // child inherits it across fork. There is no safe Rust wrapper for the
    // post-fork window, so this block is inherently required.
    unsafe {
        cmd.pre_exec(move || {
            // Create a new session (detach from parent's controlling terminal).
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Set the slave as the controlling terminal.
            // TIOCSCTTY with arg 0: don't steal if already owned.
            if libc::ioctl(slave_raw_fd, libc::TIOCSCTTY as libc::c_ulong, 0i32) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    // Spawn the child.
    let mut child = Command::from(cmd)
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn child process")?;

    // Close the slave fd in the parent — the child has its own copy.
    drop(slave_fd);

    // Wrap master fd for async I/O.
    let async_master = AsyncFd::new(master_fd).context("AsyncFd::new on master pty")?;

    // I/O pump: two concurrent tasks.
    //  (a) PTY master → QUIC stream
    //  (b) QUIC stream → PTY master
    //
    // We also watch for:
    //  - child exit
    //  - WindowChange requests from the client
    //  - Close/Eof from the client

    let exit_status = io_pump(stream, &async_master, &mut child).await?;

    // Send exit status and close.
    stream.sender.send(&ChannelMessage::Eof).await.ok(); // best-effort
    stream
        .sender
        .send(&ChannelMessage::ExitStatus {
            status: exit_status,
        })
        .await
        .ok();
    stream.sender.send(&ChannelMessage::Close).await.ok();

    tracing::info!(%username, exit_status, "session ended");
    Ok(())
}

// ---------------------------------------------------------------------------
// I/O pump
// ---------------------------------------------------------------------------

async fn io_pump(
    stream: &mut FramedBiStream,
    async_master: &AsyncFd<OwnedFd>,
    child: &mut tokio::process::Child,
) -> Result<u32> {
    let mut pty_read_buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            // (a) Read from PTY master → send to QUIC stream.
            readable = async_master.readable() => {
                let mut guard = readable.context("waiting for pty readable")?;
                match guard.try_io(|inner| {
                    nix::unistd::read(inner.get_ref(), &mut pty_read_buf)
                        .map_err(std::io::Error::from)
                }) {
                    Ok(Ok(0)) => {
                        // EOF on pty — child closed its side.
                        break;
                    }
                    Ok(Ok(n)) => {
                        let data = pty_read_buf[..n].to_vec();
                        if stream.sender.send(&ChannelMessage::Data { data }).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        // EIO is expected when the child exits on Linux/macOS.
                        if e.raw_os_error() == Some(libc::EIO) {
                            break;
                        }
                        return Err(e).context("reading from pty master");
                    }
                    Err(_would_block) => {
                        // Spurious wake; try_io cleared readiness, loop back.
                        continue;
                    }
                }
            }

            // (b) Read from QUIC stream → write to PTY master or handle requests.
            msg = stream.receiver.recv() => {
                match msg {
                    Ok(ChannelMessage::Data { data }) => {
                        write_all_to_fd(async_master, &data).await?;
                    }
                    Ok(ChannelMessage::Request {
                        request_type: RequestType::WindowChange(wc),
                        want_reply,
                    }) => {
                        let ws = Winsize {
                            ws_row: wc.height_rows as u16,
                            ws_col: wc.width_cols as u16,
                            ws_xpixel: wc.width_px as u16,
                            ws_ypixel: wc.height_px as u16,
                        };
                        // SAFETY: tiocswinsz is generated by nix::ioctl_write_ptr_bad!
                        // and takes a raw fd plus a pointer to a Winsize struct. Both
                        // are valid here: async_master holds a live PTY master fd, and
                        // &ws is a stack-allocated Winsize with the correct layout for
                        // TIOCSWINSZ. No safe wrapper exists for arbitrary ioctls.
                        let ret = unsafe { tiocswinsz(async_master.as_raw_fd(), &ws) };
                        if want_reply {
                            let reply = if ret.is_ok() {
                                ChannelMessage::RequestSuccess
                            } else {
                                ChannelMessage::RequestFailure
                            };
                            stream.sender.send(&reply).await.ok();
                        }
                    }
                    Ok(ChannelMessage::Request {
                        request_type: RequestType::Signal { signal },
                        want_reply,
                    }) => {
                        if let Some(pid) = child.id() {
                            let sig = parse_signal(&signal);
                            if let Some(sig) = sig {
                                signal::kill(Pid::from_raw(pid as i32), sig).ok();
                            }
                        }
                        if want_reply {
                            stream.sender.send(&ChannelMessage::RequestSuccess).await.ok();
                        }
                    }
                    Ok(ChannelMessage::Eof) => {
                        // Client finished sending — close the write side of the PTY
                        // so the shell receives EOF on stdin. We can't half-close
                        // the master fd, but we can break and let the child finish.
                    }
                    Ok(ChannelMessage::Close) => {
                        // Client wants to tear down — kill the child.
                        child.kill().await.ok();
                        break;
                    }
                    Ok(ChannelMessage::Request { want_reply, .. }) => {
                        if want_reply {
                            stream.sender.send(&ChannelMessage::RequestFailure).await.ok();
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // Stream broken.
                        child.kill().await.ok();
                        break;
                    }
                }
            }

            // (c) Child exited.
            status = child.wait() => {
                let status = status.context("waiting for child")?;
                return Ok(exit_code_from_status(status));
            }
        }
    }

    // If we broke out of the loop (PTY EOF or client close), wait for the child.
    match tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => Ok(exit_code_from_status(status)),
        Ok(Err(e)) => Err(e).context("waiting for child after loop exit"),
        Err(_timeout) => {
            child.kill().await.ok();
            child.wait().await.ok();
            Ok(255)
        }
    }
}

// ---------------------------------------------------------------------------
// Async write helper for the PTY master fd
// ---------------------------------------------------------------------------

async fn write_all_to_fd(fd: &AsyncFd<OwnedFd>, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let mut guard = fd.writable().await.context("waiting for pty writable")?;
        match guard
            .try_io(|inner| nix::unistd::write(inner.get_ref(), buf).map_err(std::io::Error::from))
        {
            Ok(Ok(n)) => {
                buf = &buf[n..];
            }
            Ok(Err(e)) => return Err(e).context("writing to pty master"),
            Err(_would_block) => continue,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Look up the user's login shell. Check $SHELL first (useful in dev),
/// then fall back to /etc/passwd, then /bin/sh.
fn lookup_shell(username: &str) -> String {
    // 1. $SHELL env var (common on macOS and development setups)
    if let Ok(shell) = std::env::var("SHELL")
        && !shell.is_empty()
    {
        return shell;
    }

    // 2. /etc/passwd lookup
    let shell = lookup_shell_passwd(username);
    if let Some(s) = shell {
        return s;
    }

    // 3. Fallback
    "/bin/sh".to_string()
}

fn lookup_shell_passwd(username: &str) -> Option<String> {
    let user = User::from_name(username).ok()??;
    let s = user.shell.to_str()?.to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn set_nonblocking(fd: &OwnedFd) -> Result<()> {
    let flags = nix::fcntl::fcntl(fd, FcntlArg::F_GETFL).context("fcntl F_GETFL")?;
    let mut oflags = OFlag::from_bits_truncate(flags);
    oflags.insert(OFlag::O_NONBLOCK);
    nix::fcntl::fcntl(fd, FcntlArg::F_SETFL(oflags)).context("fcntl F_SETFL O_NONBLOCK")?;
    Ok(())
}

fn fd_to_stdio(fd: &OwnedFd) -> Result<Stdio> {
    Ok(Stdio::from(nix::unistd::dup(fd)?))
}

fn exit_code_from_status(status: std::process::ExitStatus) -> u32 {
    // On Unix, if the process was signalled, code() returns None.
    // Use the raw signal number + 128 convention.
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(code) = status.code() {
            return code as u32;
        }
        if let Some(sig) = status.signal() {
            return 128 + sig as u32;
        }
    }
    status.code().unwrap_or(255) as u32
}

fn parse_signal(name: &str) -> Option<Signal> {
    match name.to_uppercase().as_str() {
        "HUP" | "SIGHUP" => Some(Signal::SIGHUP),
        "INT" | "SIGINT" => Some(Signal::SIGINT),
        "QUIT" | "SIGQUIT" => Some(Signal::SIGQUIT),
        "KILL" | "SIGKILL" => Some(Signal::SIGKILL),
        "TERM" | "SIGTERM" => Some(Signal::SIGTERM),
        "USR1" | "SIGUSR1" => Some(Signal::SIGUSR1),
        "USR2" | "SIGUSR2" => Some(Signal::SIGUSR2),
        _ => None,
    }
}
