#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    if key_path.exists() && cert_path.exists() {
        validate_private_key_permissions(key_path)?;
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
        let params = rcgen::CertificateParams::new(vec!["sqshd".into()])?;
        let cert = params.self_signed(&key_pair)?;

        if let Some(parent) = key_path.parent() {
            create_restrictive_dir_if_missing(parent)?;
        }

        std::fs::write(cert_path, cert.pem())?;
        write_private_key_owner_only(key_path, &key_pair.serialize_pem())?;

        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        Ok((cert_der, key_der))
    }
}
fn create_restrictive_dir_if_missing(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }

    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", path.display()))?;

    Ok(())
}

#[cfg(unix)]
fn write_private_key_owner_only(path: &Path, pem: &str) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating host key at {}", path.display()))?;
    file.write_all(pem.as_bytes())
        .with_context(|| format!("writing host key at {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key_owner_only(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem).with_context(|| format!("writing host key at {}", path.display()))?;
    Ok(())
}
#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<()> {
    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "host key {} is accessible by group/other (mode {:o}); expected 0600",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_key_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        create_restrictive_dir_if_missing, validate_private_key_permissions,
        write_private_key_owner_only,
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sqshd-{name}-{}-{nanos}", std::process::id()))
    }

    #[cfg(unix)]
    #[test]
    fn creates_private_key_with_owner_only_mode() {
        use std::os::unix::fs::MetadataExt;

        let path = unique_temp_path("host-key");
        write_private_key_owner_only(&path, "test-private-key\n")
            .expect("host key write should succeed");

        let mode = std::fs::metadata(&path)
            .expect("metadata should load")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::remove_file(&path).expect("cleanup should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn creates_parent_directory_with_owner_only_mode() {
        use std::os::unix::fs::MetadataExt;

        let path = unique_temp_path("config-dir");
        create_restrictive_dir_if_missing(&path).expect("directory creation should succeed");

        let mode = std::fs::metadata(&path)
            .expect("metadata should load")
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);

        std::fs::remove_dir(&path).expect("cleanup should succeed");
    }
    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_accessible_private_key() {
        let path = unique_temp_path("insecure-host-key");
        std::fs::write(&path, "test-private-key\n").expect("write should succeed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod should succeed");

        let err = validate_private_key_permissions(&path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("accessible by group/other"));

        std::fs::remove_file(&path).expect("cleanup should succeed");
    }
}
