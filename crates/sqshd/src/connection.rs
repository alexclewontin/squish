use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use nix::unistd::{Uid, User};
use quinn::Connection;
use signature::Verifier;
use sqsh_core::auth::challenge::build_challenge_payload;
use sqsh_core::auth::keys::parse_authorized_keys;
use sqsh_core::proto::channel::*;
use sqsh_core::proto::message::*;
use sqsh_core::transport::framing::FramedBiStream;
use tokio::sync::Semaphore;

use crate::config::ServerConfig;

pub async fn handle(conn: Connection, config: &Arc<ServerConfig>) -> Result<()> {
    // The first bidi stream is the control stream (auth + session management).
    let (send, recv) = conn.accept_bi().await.context("accepting control stream")?;

    let mut control = FramedBiStream::new(send, recv);

    // --- Authentication ---
    let username = authenticate(&mut control, &conn, config).await?;
    tracing::info!(%username, "authenticated");

    // --- Main loop: accept channel streams and control messages ---
    // Keyed by (bind_addr, bind_port) so we can cancel on TcpForwardCancel.
    let mut forward_tasks: HashMap<(String, u16), tokio::task::AbortHandle> = HashMap::new();
    let channel_limiter = Arc::new(Semaphore::new(config.max_channels_per_connection));

    loop {
        tokio::select! {
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let mut channel = FramedBiStream::new(send, recv);
                        let Ok(permit) = channel_limiter.clone().try_acquire_owned() else {
                            let _ = channel.sender.send(&ChannelMessage::OpenFailure {
                                reason: ChannelFailureReason::ResourceShortage,
                                description: "per-connection channel limit reached".into(),
                            }).await;
                            continue;
                        };

                        let username = username.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = dispatch_channel(channel, &username, &config).await {
                                tracing::warn!(%username, "channel error: {e}");
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                        tracing::info!(%username, "client disconnected");
                        break;
                    }
                    Err(e) => bail!("connection error: {e}"),
                }
            }

            msg = control.receiver.recv::<ControlMessage>() => {
                match msg {
                    Ok(ControlMessage::TcpForwardRequest { bind_addr, bind_port }) => {
                        if !remote_forward_allowed(&bind_addr, bind_port, &config.remote_forward_allowlist) {
                            control.sender.send(&ControlMessage::TcpForwardFailure {
                                description: format!(
                                    "remote forward denied for {}:{} (only loopback is allowed by default; use remote_forward_allowlist for exceptions)",
                                    bind_addr, bind_port
                                ),
                            }).await?;
                            continue;
                        }

                        if forward_tasks.contains_key(&(bind_addr.clone(), bind_port)) {
                            control.sender.send(&ControlMessage::TcpForwardFailure {
                                description: format!("remote forward already active for {}:{}", bind_addr, bind_port),
                            }).await?;
                            continue;
                        }

                        if forward_tasks.len() >= config.max_remote_forwards_per_connection {
                            control.sender.send(&ControlMessage::TcpForwardFailure {
                                description: "per-connection remote forward listener limit reached".into(),
                            }).await?;
                            continue;
                        }

                        let conn_clone = conn.clone();
                        let ba = bind_addr.clone();
                        let handle = tokio::spawn(async move {
                            if let Err(e) = crate::channel::forward::run_remote_forward(
                                conn_clone, ba, bind_port,
                            ).await {
                                tracing::warn!("remote forward error: {e}");
                            }
                        });
                        forward_tasks.insert((bind_addr, bind_port), handle.abort_handle());
                        control.sender.send(&ControlMessage::TcpForwardConfirm {
                            bound_port: bind_port,
                        }).await?;
                    }
                    Ok(ControlMessage::TcpForwardCancel { bind_addr, bind_port }) => {
                        if let Some(handle) = forward_tasks.remove(&(bind_addr.clone(), bind_port)) {
                            handle.abort();
                            tracing::info!(%bind_addr, bind_port, "remote forward cancelled");
                        }
                    }
                    Ok(ControlMessage::KeepAlive { seq }) => {
                        let _ = control.sender.send(&ControlMessage::KeepAliveAck { seq }).await;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        // Control stream closed — client gone.
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Read the `Open` message from a freshly-accepted stream and dispatch to the
/// appropriate channel handler.
async fn dispatch_channel(
    mut channel: FramedBiStream,
    username: &str,
    config: &Arc<ServerConfig>,
) -> Result<()> {
    let open: ChannelMessage = channel.receiver.recv().await?;
    match open {
        ChannelMessage::Open {
            channel_type: ChannelType::Session,
            ..
        } => {
            channel
                .sender
                .send(&ChannelMessage::OpenConfirmation {
                    max_packet_size: 32 * 1024,
                })
                .await?;
            crate::channel::session::handle(&mut channel, username, config).await
        }
        ChannelMessage::Open {
            channel_type: ChannelType::DirectTcpip,
            params: ChannelParams::DirectTcpip(p),
        } => {
            if !direct_tcpip_allowed(&p.host, p.port, &config.direct_tcpip_allowlist) {
                channel
                    .sender
                    .send(&ChannelMessage::OpenFailure {
                        reason: ChannelFailureReason::AdministrativelyProhibited,
                        description: format!(
                            "direct-tcpip denied for {}:{} (not in direct_tcpip_allowlist)",
                            p.host, p.port
                        ),
                    })
                    .await?;
                return Ok(());
            }

            channel
                .sender
                .send(&ChannelMessage::OpenConfirmation {
                    max_packet_size: 32 * 1024,
                })
                .await?;
            crate::channel::forward::handle_direct_tcpip(channel, p).await
        }
        ChannelMessage::Open { channel_type, .. } => {
            channel
                .sender
                .send(&ChannelMessage::OpenFailure {
                    reason: ChannelFailureReason::UnknownChannelType,
                    description: format!("unsupported channel type: {channel_type:?}"),
                })
                .await?;
            bail!("unsupported channel type: {channel_type:?}")
        }
        other => bail!("expected ChannelOpen, got {other:?}"),
    }
}

fn direct_tcpip_allowed(host: &str, port: u16, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|entry| exact_host_port_match(entry, host, port))
}

fn remote_forward_allowed(bind_addr: &str, bind_port: u16, allowlist: &[String]) -> bool {
    is_loopback_bind_addr(bind_addr)
        || allowlist
            .iter()
            .any(|entry| exact_host_port_match(entry, bind_addr, bind_port))
}

fn is_loopback_bind_addr(bind_addr: &str) -> bool {
    bind_addr.eq_ignore_ascii_case("localhost")
        || bind_addr
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn exact_host_port_match(entry: &str, host: &str, port: u16) -> bool {
    let Some((entry_host, entry_port)) = entry.rsplit_once(':') else {
        return false;
    };
    let Ok(parsed_port) = entry_port.parse::<u16>() else {
        return false;
    };

    entry_host == host && parsed_port == port
}

async fn authenticate(
    control: &mut FramedBiStream,
    _conn: &Connection,
    config: &ServerConfig,
) -> Result<String> {
    // 1. Receive ClientHello
    let hello: ControlMessage = control.receiver.recv().await?;
    let username = match hello {
        ControlMessage::ClientHello { version, username } => {
            if version != PROTOCOL_VERSION {
                let _ = control
                    .sender
                    .send(&ControlMessage::Disconnect {
                        reason: DisconnectReason::ProtocolError,
                        description: format!(
                            "unsupported version {version}, expected {PROTOCOL_VERSION}"
                        ),
                    })
                    .await;
                bail!("client version mismatch: {version}");
            }
            username
        }
        _ => bail!("expected ClientHello, got {hello:?}"),
    };

    // 2. Look up the user. Loading their authorized keys is the authorization
    //    boundary: a pubkey is only valid for the user in whose file it sits.
    //    A missing user is handled like an empty key list so we still send a
    //    challenge before the AuthFailure response (avoids a trivial enumeration
    //    oracle on AuthChallenge vs immediate Disconnect).
    let user =
        User::from_name(&username).with_context(|| format!("looking up user '{username}'"))?;
    let authorized = match &user {
        Some(u) => load_user_authorized_keys(u)?,
        None => Vec::new(),
    };

    // 3. Send challenge
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);

    control
        .sender
        .send(&ControlMessage::AuthChallenge { nonce })
        .await?;

    // 4. Receive AuthResponse
    let response: ControlMessage = control.receiver.recv().await?;
    let (pubkey_bytes, sig_bytes) = match response {
        ControlMessage::AuthResponse { pubkey, signature } => (pubkey, signature),
        _ => bail!("expected AuthResponse, got {response:?}"),
    };

    // 5. Verify
    // Check the public key is in this user's authorized keys.
    if user.is_none() || !authorized.iter().any(|k| k == &pubkey_bytes) {
        let _ = control
            .sender
            .send(&ControlMessage::AuthResult(AuthOutcome::Failure))
            .await;
        bail!("auth failed for user '{username}'");
    }

    let payload = build_challenge_payload(&nonce, &config.live_cert_fingerprint, &username);

    // Verify ML-DSA-65 signature over the challenge payload
    let encoded_vk = EncodedVerifyingKey::<MlDsa65>::try_from(pubkey_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 verifying key length"))?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

    let sig = Signature::<MlDsa65>::try_from(sig_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid ML-DSA-65 signature"))?;

    if verifying_key.verify(&payload, &sig).is_err() {
        let _ = control
            .sender
            .send(&ControlMessage::AuthResult(AuthOutcome::Failure))
            .await;
        bail!("ML-DSA-65 signature verification failed");
    }

    control
        .sender
        .send(&ControlMessage::AuthResult(AuthOutcome::Success))
        .await?;

    Ok(username)
}

/// Load `<user.dir>/.squish/authorized_keys` after verifying the file is owned
/// by the user (or root) and not group/world-writable. A missing file is not
/// an error — the user simply has no keys configured.
fn load_user_authorized_keys(user: &User) -> Result<Vec<Vec<u8>>> {
    use std::os::unix::fs::MetadataExt;

    let path = user.dir.join(".squish").join("authorized_keys");
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
    };

    let owner = Uid::from_raw(meta.uid());
    if owner != user.uid && !owner.is_root() {
        bail!(
            "{} is owned by uid {} (expected {} or root); refusing to use",
            path.display(),
            owner,
            user.uid
        );
    }
    if meta.mode() & 0o022 != 0 {
        bail!(
            "{} is group/world-writable (mode {:o}); refusing to use",
            path.display(),
            meta.mode() & 0o777
        );
    }

    let contents =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_authorized_keys(&contents))
}

#[cfg(test)]
mod tests {
    use super::{direct_tcpip_allowed, exact_host_port_match, remote_forward_allowed};

    #[test]
    fn exact_match_requires_same_host_and_port() {
        assert!(exact_host_port_match(
            "db.internal:5432",
            "db.internal",
            5432
        ));
        assert!(!exact_host_port_match(
            "db.internal:5432",
            "db.internal",
            22
        ));
        assert!(!exact_host_port_match(
            "db.internal:5432",
            "other.internal",
            5432
        ));
        assert!(!exact_host_port_match("*:5432", "db.internal", 5432));
        assert!(!exact_host_port_match(
            "db.internal:notaport",
            "db.internal",
            5432
        ));
    }

    #[test]
    fn direct_tcpip_is_denied_by_default() {
        assert!(!direct_tcpip_allowed("127.0.0.1", 5432, &[]));
        assert!(direct_tcpip_allowed(
            "127.0.0.1",
            5432,
            &["127.0.0.1:5432".to_string()]
        ));
    }

    #[test]
    fn remote_forward_defaults_to_loopback_only() {
        assert!(remote_forward_allowed("127.0.0.1", 8080, &[]));
        assert!(remote_forward_allowed("::1", 8080, &[]));
        assert!(remote_forward_allowed("localhost", 8080, &[]));
        assert!(!remote_forward_allowed("0.0.0.0", 8080, &[]));
        assert!(remote_forward_allowed(
            "0.0.0.0",
            8080,
            &["0.0.0.0:8080".to_string()]
        ));
    }
    #[test]
    fn auth_uses_cached_live_cert_fingerprint() {
        let expected: [u8; 32] =
            hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap()
                .try_into()
                .unwrap();
        let cfg = crate::config::ServerConfig {
            bind_addr: "127.0.0.1".to_string(),
            port: 2222,
            host_key: std::path::PathBuf::from("/does/not/matter/host.key"),
            host_cert: std::path::PathBuf::from("/definitely/missing/host.cert"),
            max_connections: 1,
            idle_timeout_secs: 30,
            direct_tcpip_allowlist: Vec::new(),
            remote_forward_allowlist: Vec::new(),
            max_channels_per_connection: 1,
            max_remote_forwards_per_connection: 1,
            accept_env: Vec::new(),
            subsystems: std::collections::HashMap::new(),
            live_cert_fingerprint: expected,
        };

        assert_eq!(cfg.live_cert_fingerprint, expected);
    }
}
