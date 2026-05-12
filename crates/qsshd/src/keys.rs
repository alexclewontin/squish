use std::path::Path;

use anyhow::{Context, Result};
use rcgen::KeyPair;

/// Load or generate the server's TLS certificate and private key.
///
/// If the key/cert files don't exist, generates a new self-signed
/// Ed25519 certificate and writes them to disk.
pub fn load_or_generate_tls_identity(
    key_path: &Path,
    cert_path: &Path,
) -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
    if key_path.exists() && cert_path.exists() {
        let key_pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading host key from {}", key_path.display()))?;
        let cert_pem = std::fs::read_to_string(cert_path)
            .with_context(|| format!("reading host cert from {}", cert_path.display()))?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .with_context(|| "parsing host private key")?
            .ok_or_else(|| anyhow::anyhow!("no private key found in PEM"))?;

        let cert = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or_else(|| anyhow::anyhow!("no certificate found in PEM"))?
            .with_context(|| "parsing host certificate")?;

        Ok((cert, key))
    } else {
        tracing::info!("generating new host key and certificate");

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let params = rcgen::CertificateParams::new(vec!["qsshd".into()])?;
        let cert = params.self_signed(&key_pair)?;

        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(cert_path, cert.pem())?;
        std::fs::write(key_path, key_pair.serialize_pem())?;

        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        Ok((cert_der, key_der))
    }
}
