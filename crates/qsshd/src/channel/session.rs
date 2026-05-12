use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
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
    // Re-validate the user exists. authenticate() already checked this; we
    // re-check here to bind to the user's identity for the privilege drop
    // and to fail cleanly if the user was removed in between.
    let user = User::from_name(username)
        .with_context(|| format!("looking up user '{username}'"))?
        .with_context(|| format!("user '{username}' no longer exists"))?;

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
                tracing::info!(%username, shell = %user.shell.display(), "shell request");
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
                return run_child(stream, &user, None, pty_params.take()).await;
            }
            ChannelMessage::Request {
                request_type: RequestType::Exec { command },
                want_reply,
            } => {
                tracing::info!(%username, %command, "exec request");
                if want_reply {
                    stream.sender.send(&ChannelMessage::RequestSuccess).await?;
                }
                return run_child(stream, &user, Some(&command), pty_params.take()).await;
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
    user: &User,
    exec: Option<&str>,
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

    // Decide whether we need to switch users. If qsshd's euid already matches
    // the target user, no privilege drop is needed (common in dev). If they
    // differ, we must be root to switch — refuse cleanly otherwise.
    let effective_uid = nix::unistd::geteuid();
    let needs_drop = effective_uid != user.uid;
    if needs_drop && !effective_uid.is_root() {
        bail!(
            "cannot run shell as '{}': qsshd must be root to switch users (current euid: {})",
            user.name,
            effective_uid
        );
    }

    // Build the child command.
    let slave_raw_fd = slave_fd.as_raw_fd();
    let shell_path = user.shell.clone();
    let shell_basename = shell_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("sh")
        .to_string();

    let mut cmd = std::process::Command::new(&shell_path);
    match exec {
        Some(command) => {
            cmd.args(["-c", command]);
        }
        None => {
            // Interactive login shell: argv[0] = "-<basename>" by convention so
            // the shell sources the appropriate login profile.
            cmd.arg0(format!("-{shell_basename}"));
        }
    }
    cmd.env("TERM", &term);
    cmd.env("USER", &user.name);
    cmd.env("LOGNAME", &user.name);
    cmd.env("HOME", &user.dir);
    cmd.env("SHELL", &shell_path);
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    cmd.current_dir(&user.dir);

    // Use the slave fd as stdin/stdout/stderr.
    cmd.stdin(fd_to_stdio(&slave_fd)?);
    cmd.stdout(fd_to_stdio(&slave_fd)?);
    cmd.stderr(fd_to_stdio(&slave_fd)?);

    // Capture state needed inside pre_exec. Allocation in pre_exec is unsafe
    // (post-fork in a multi-threaded program), so prepare the CString here.
    let username_c =
        std::ffi::CString::new(user.name.as_str()).context("username contains null byte")?;
    let target_uid = user.uid;
    let target_gid = user.gid;

    // SAFETY: pre_exec runs in the child after fork() but before exec(). Only
    // async-signal-safe calls are strictly permitted; we accept the standard
    // risk of `initgroups` (which may allocate) because it mirrors OpenSSH's
    // approach and avoids the more complex pre-fork getgrouplist path.
    //
    // Order matters: initgroups + setgid require root, so they run BEFORE
    // setuid drops to the unprivileged user. setsid + TIOCSCTTY happen last,
    // after the privilege drop, since they don't require root.
    //
    // We deliberately do NOT use Command::uid/gid — Rust does not document
    // their order relative to pre_exec, and we need initgroups to land in a
    // specific spot in the sequence.
    unsafe {
        cmd.pre_exec(move || {
            if needs_drop {
                // initgroups(3) — nix doesn't expose this on Apple targets,
                // so call libc directly. The arg type for the second arg
                // differs across platforms (gid_t on Linux, int on macOS);
                // `as _` lets the compiler choose.
                let ret = libc::initgroups(username_c.as_ptr(), target_gid.as_raw() as _);
                if ret < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                nix::unistd::setgid(target_gid).map_err(std::io::Error::from)?;
                nix::unistd::setuid(target_uid).map_err(std::io::Error::from)?;
            }
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

    tracing::info!(username = %user.name, exit_status, "session ended");
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
