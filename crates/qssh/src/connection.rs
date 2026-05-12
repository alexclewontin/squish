use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// Returned by `authenticate` when the server rejects the public key so the
/// caller can distinguish auth failure from protocol/network errors.
#[derive(Debug)]
struct AuthFailed;

impl std::fmt::Display for AuthFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("public key not accepted by server")
    }
}

impl std::error::Error for AuthFailed {}
use ml_dsa::{KeyGen, MlDsa65};
use qssh_core::auth::challenge::build_challenge_payload;
use qssh_core::proto::message::*;
use qssh_core::transport::framing::FramedBiStream;
use quinn::Endpoint;
use signature::Signer;

use crate::config::ClientConfig;
use crate::known_hosts::KnownHosts;

pub async fn connect(config: ClientConfig) -> Result<()> {
    match connect_once(&config).await {
        Ok(()) => Ok(()),
        Err(e) if e.is::<AuthFailed>() => {
            eprintln!("squish: public key not accepted — installing key via SSH and retrying…");
            install_key_via_ssh(&config)
                .await
                .context("installing public key via SSH")?;
            connect_once(&config).await
        }
        Err(e) => Err(e),
    }
}

async fn connect_once(config: &ClientConfig) -> Result<()> {
    // --- TLS setup ---
    // Use aws-lc-rs provider (includes PQ key exchange via ML-KEM)
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 config")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerification))
        .with_no_client_auth();

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(300)
            .try_into()
            .expect("valid timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));

    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    client_config.transport_config(Arc::new(transport));

    // --- Connect ---
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .or_else(|_| {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            format!("{}:{}", config.host, config.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "DNS resolution failed")
                })
        })
        .context("resolving server address")?;

    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    let conn = endpoint.connect(addr, &config.host)?.await?;
    tracing::info!("connected to {addr}");

    // --- Host key verification (TOFU) ---
    let server_cert_fingerprint = compute_cert_fingerprint(&conn);
    let mut known_hosts = KnownHosts::load(&config.known_hosts_path)?;
    let host_port = format!("{}:{}", config.host, config.port);
    known_hosts.verify(&host_port, &hex::encode(server_cert_fingerprint))?;

    // --- Authentication on stream 0 ---
    let (send, recv) = conn.open_bi().await.context("opening control stream")?;
    let mut control = FramedBiStream::new(send, recv);

    authenticate(&mut control, &config, &server_cert_fingerprint).await?;
    tracing::info!("authenticated as {}", config.username);

    // --- Start migration monitor ---
    let _migration_handle = crate::migration::spawn_monitor(endpoint.clone());

    // --- Request remote port forwards (-R) via control stream ---
    for rf in &config.remote_forwards {
        control
            .sender
            .send(&ControlMessage::TcpForwardRequest {
                bind_addr: rf.bind_addr.clone(),
                bind_port: rf.bind_port,
            })
            .await?;
        let reply: ControlMessage = control.receiver.recv().await?;
        match reply {
            ControlMessage::TcpForwardConfirm { bound_port } => {
                tracing::info!(
                    port = bound_port,
                    target = %format!("{}:{}", rf.target_host, rf.target_port),
                    "remote forward confirmed",
                );
            }
            ControlMessage::TcpForwardFailure { description } => {
                anyhow::bail!("remote forward on port {} failed: {description}", rf.bind_port);
            }
            other => anyhow::bail!("expected TcpForwardConfirm, got {other:?}"),
        }
    }

    // --- Accept ForwardedTcpip streams from the server (-R) ---
    if !config.remote_forwards.is_empty() {
        let conn_clone = conn.clone();
        let specs = config.remote_forwards.clone();
        tokio::spawn(async move {
            crate::channel::forward::accept_remote_forward_streams(conn_clone, specs).await;
        });
    }

    // --- Spawn local forward listeners (-L) ---
    for spec in config.local_forwards.clone() {
        let conn_clone = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::channel::forward::run_local_listener(conn_clone, spec).await {
                tracing::warn!("local forward ended: {e}");
            }
        });
    }

    // --- Session or forward-only (-N) ---
    if config.no_shell {
        tokio::signal::ctrl_c().await?;
    } else {
        crate::channel::session::run(&conn, &config).await?;
    }

    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    Ok(())
}

/// Use the system `ssh` to append our ML-DSA-65 public key to the server's
/// squishd authorized_keys file.  Called when pubkey auth fails so that the
/// next connection attempt succeeds.
async fn install_key_via_ssh(config: &ClientConfig) -> Result<()> {
    let key_bytes = crate::auth::load_signing_key(&config.identity_path)
        .context("loading signing key")?;
    let seed = ml_dsa::B32::try_from(key_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("identity file must be a 32-byte ML-DSA-65 seed"))?;
    let key_pair = MlDsa65::key_gen_internal(&seed);
    let pubkey_bytes: Vec<u8> = key_pair.verifying_key().encode().to_vec();
    let ak_line = crate::bootstrap::keys::format_authorized_key(&pubkey_bytes, "");

    let userhost = format!("{}@{}", config.username, config.host);
    // Append the key only if it isn't already present; then lock down perms.
    let remote_cmd = format!(
        "sudo sh -c 'mkdir -p /etc/qssh && chmod 755 /etc/qssh && \
         grep -qF \"{ak_line}\" /etc/qssh/authorized_keys 2>/dev/null || \
         {{ echo \"{ak_line}\" >> /etc/qssh/authorized_keys && \
            chmod 600 /etc/qssh/authorized_keys; }}'"
    );

    let status = tokio::process::Command::new("ssh")
        .args(["-t", "-p", "22", &userhost, &remote_cmd])
        .status()
        .await
        .context("spawning ssh for key installation")?;

    if !status.success() {
        bail!("SSH key installation failed");
    }
    Ok(())
}

async fn authenticate(
    control: &mut FramedBiStream,
    config: &ClientConfig,
    server_cert_fingerprint: &[u8; 32],
) -> Result<()> {
    // 1. Send ClientHello
    control
        .sender
        .send(&ControlMessage::ClientHello {
            version: PROTOCOL_VERSION,
            username: config.username.clone(),
        })
        .await?;

    // 2. Receive AuthChallenge
    let challenge: ControlMessage = control.receiver.recv().await?;
    let nonce = match challenge {
        ControlMessage::AuthChallenge { nonce } => nonce,
        ControlMessage::Disconnect {
            reason,
            description,
        } => bail!("server disconnected: {reason:?} — {description}"),
        other => bail!("expected AuthChallenge, got {other:?}"),
    };

    // 3. Sign the challenge
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload =
        build_challenge_payload(&nonce, server_cert_fingerprint, &config.username, now);

    // Load signing key seed and reconstruct the full ML-DSA-65 key pair
    let key_bytes = crate::auth::load_signing_key(&config.identity_path)?;
    let seed = ml_dsa::B32::try_from(key_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("identity file must be a 32-byte ML-DSA-65 seed"))?;
    let key_pair = MlDsa65::key_gen_internal(&seed);

    // Sign the challenge payload
    let sig = key_pair.signing_key().sign(&payload);
    let pubkey_bytes: Vec<u8> = key_pair.verifying_key().encode().to_vec();
    let sig_bytes: Vec<u8> = sig.encode().to_vec();

    // 4. Send AuthResponse
    control
        .sender
        .send(&ControlMessage::AuthResponse {
            pubkey: pubkey_bytes,
            signature: sig_bytes,
        })
        .await?;

    // 5. Receive result
    let result: ControlMessage = control.receiver.recv().await?;
    match result {
        ControlMessage::AuthResult(AuthOutcome::Success) => Ok(()),
        ControlMessage::AuthResult(AuthOutcome::Failure) => {
            bail!(AuthFailed)
        }
        other => bail!("expected AuthResult, got {other:?}"),
    }
}

fn compute_cert_fingerprint(conn: &quinn::Connection) -> [u8; 32] {
    let certs = conn
        .peer_identity()
        .and_then(|id| {
            id.downcast::<Vec<rustls::pki_types::CertificateDer>>()
                .ok()
        })
        .expect("server must present a TLS certificate");

    let server_cert = certs
        .first()
        .expect("server certificate chain must not be empty");

    qssh_core::auth::fingerprint::cert_fingerprint(server_cert.as_ref())
}

/// Certificate verifier that accepts any cert (we do our own TOFU pinning).
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
