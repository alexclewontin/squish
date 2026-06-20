use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

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
use quinn::Endpoint;
use signature::Signer;
use sqsh_core::auth::challenge::build_challenge_payload;
use sqsh_core::proto::message::*;
use sqsh_core::transport::framing::FramedBiStream;

use crate::bootstrap::ssh::SshRunner;
use crate::config::ClientConfig;
use crate::control::MasterConnection;
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

/// Establish an authenticated connection (with the same install-key-on-auth-failure
/// retry as [`connect`]) and hand back the live connection so callers can drive
/// their own channels — used by the `sqftp`/`sqcp` file-transfer tools.
pub async fn open_authenticated(config: &ClientConfig) -> Result<MasterConnection> {
    match establish_connection(config).await {
        Ok(m) => Ok(m),
        Err(e) if e.is::<AuthFailed>() => {
            eprintln!("squish: public key not accepted — installing key via SSH and retrying…");
            install_key_via_ssh(config)
                .await
                .context("installing public key via SSH")?;
            establish_connection(config).await
        }
        Err(e) => Err(e),
    }
}

async fn connect_once(config: &ClientConfig) -> Result<()> {
    // ponytail: a subsystem (e.g. sftp) needs its own dedicated channel with no PTY;
    // skip ControlMaster multiplexing entirely and use the direct path.
    if config.subsystem.is_some() {
        return connect_direct(config).await;
    }

    if config.control_master {
        let master = establish_connection(config).await?;
        return crate::control::run_master(config.clone(), master).await;
    }

    if (config.control_path_explicit
        || config.control_master_auto
        || config.control_persist.is_enabled())
        && crate::control::run_via_master_or_spawn(config.clone()).await?
    {
        return Ok(());
    }

    connect_direct(config).await
}

async fn connect_direct(config: &ClientConfig) -> Result<()> {
    let MasterConnection {
        conn,
        endpoint,
        mut control,
    } = establish_connection(config).await?;
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
                anyhow::bail!(
                    "remote forward on port {} failed: {description}",
                    rf.bind_port
                );
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
        crate::channel::session::run(&conn, config).await?;
    }

    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    Ok(())
}

async fn establish_connection(config: &ClientConfig) -> Result<MasterConnection> {
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
        Duration::from_secs(300).try_into().expect("valid timeout"),
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
    let server_cert_fingerprint = compute_cert_fingerprint(&conn)?;
    let mut known_hosts = KnownHosts::load(&config.known_hosts_path)?;
    let host_port = format!("{}:{}", config.host, config.port);
    known_hosts.verify(&host_port, &hex::encode(server_cert_fingerprint))?;

    // --- Authentication on stream 0 ---
    let (send, recv) = conn.open_bi().await.context("opening control stream")?;
    let mut control = FramedBiStream::new(send, recv);

    authenticate(&mut control, config, &server_cert_fingerprint).await?;
    tracing::info!("authenticated as {}", config.username);

    Ok(MasterConnection {
        conn,
        endpoint,
        control,
    })
}

/// Use the system `ssh` to append our ML-DSA-65 public key to the server's
/// squishd authorized_keys file. Called when pubkey auth fails so that the
/// next connection attempt succeeds.
async fn install_key_via_ssh(config: &ClientConfig) -> Result<()> {
    let key_bytes =
        crate::auth::load_signing_key(&config.identity_path).context("loading signing key")?;
    let seed = ml_dsa::B32::try_from(key_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("identity file must be a 32-byte ML-DSA-65 seed"))?;
    let key_pair = MlDsa65::key_gen_internal(&seed);
    let pubkey_bytes: Vec<u8> = key_pair.verifying_key().encode().to_vec();
    let ak_line = crate::bootstrap::keys::format_authorized_key(&pubkey_bytes, "");

    let runner = SshRunner {
        user: Some(config.username.clone()),
        host: config.host.clone(),
        ssh_port: config.ssh_port,
    };
    tokio::task::spawn_blocking(move || runner.install_authorized_key(&ak_line))
        .await
        .context("joining SSH key installation task")?
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
    let payload = build_challenge_payload(&nonce, server_cert_fingerprint, &config.username);

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

fn compute_cert_fingerprint(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let Some(peer_identity) = conn.peer_identity() else {
        bail!("server did not present a peer identity");
    };

    let certs = peer_identity
        .downcast::<Vec<rustls::pki_types::CertificateDer>>()
        .map_err(|_| anyhow::anyhow!("peer identity is not a certificate chain"))?;

    let Some(server_cert) = certs.first() else {
        bail!("server certificate chain is empty");
    };

    Ok(sqsh_core::auth::fingerprint::cert_fingerprint(
        server_cert.as_ref(),
    ))
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
