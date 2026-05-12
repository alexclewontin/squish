use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use quinn::Endpoint;
use tokio::sync::Semaphore;

use crate::config::ServerConfig;
use crate::connection;
use crate::keys;

pub async fn run(config: ServerConfig) -> Result<()> {
    let (cert_der, key_der) =
        keys::load_or_generate_tls_identity(&config.host_key, &config.host_cert)?;

    // Use aws-lc-rs provider (includes PQ key exchange via ML-KEM)
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 config")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(config.idle_timeout_secs)
            .try_into()
            .expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(15)));

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    server_config.transport_config(Arc::new(transport));

    let bind_addr: SocketAddr = format!("{}:{}", config.bind_addr, config.port).parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;

    tracing::info!("listening on {bind_addr}");

    let semaphore = Arc::new(Semaphore::new(config.max_connections));
    let config = Arc::new(config);

    while let Some(incoming) = endpoint.accept().await {
        let permit = semaphore.clone().acquire_owned().await?;
        let config = config.clone();

        tokio::spawn(async move {
            let remote = incoming.remote_address();
            tracing::info!(%remote, "incoming connection");

            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = connection::handle(conn, &config).await {
                        tracing::warn!(%remote, "connection error: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!(%remote, "failed to accept: {e}");
                }
            }

            drop(permit);
        });
    }

    Ok(())
}
