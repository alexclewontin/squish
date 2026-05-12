use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use qssh_core::auth::challenge::build_challenge_payload;
use qssh_core::auth::keys::parse_authorized_keys;
use qssh_core::proto::channel::*;
use qssh_core::proto::message::*;
use qssh_core::transport::framing::FramedBiStream;
use quinn::Connection;
use signature::Verifier;

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

    loop {
        tokio::select! {
            stream = conn.accept_bi() => {
                match stream {
                    Ok((send, recv)) => {
                        let username = username.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            let channel = FramedBiStream::new(send, recv);
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

    // 2. Load authorized keys for this user
    let ak_contents = std::fs::read_to_string(&config.authorized_keys)
        .with_context(|| "reading authorized_keys")?;
    let authorized = parse_authorized_keys(&ak_contents);

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
    // Check the public key is in authorized_keys
    if !authorized.iter().any(|k| k == &pubkey_bytes) {
        let _ = control
            .sender
            .send(&ControlMessage::AuthResult(AuthOutcome::Failure))
            .await;
        bail!("public key not in authorized_keys");
    }

    let cert_fingerprint = {
        let cert_pem = std::fs::read_to_string(&config.host_cert)
            .with_context(|| "reading server certificate for fingerprint")?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| anyhow::anyhow!("no certificate in host_cert file"))?
            .with_context(|| "parsing server certificate")?;
        qssh_core::auth::fingerprint::cert_fingerprint(cert_der.as_ref())
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = build_challenge_payload(&nonce, &cert_fingerprint, &username, now);

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
