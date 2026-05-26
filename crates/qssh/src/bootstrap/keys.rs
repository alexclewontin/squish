use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use ml_dsa::{KeyGen, MlDsa65};
use zeroize::Zeroizing;
/// Load the existing ML-DSA-65 key pair, or generate one if absent.
///
/// Returns the verifying-key (public key) bytes.
pub fn ensure_client_keypair(identity_path: &Path) -> Result<Vec<u8>> {
    if identity_path.exists() {
        validate_private_key_permissions(identity_path)?;
        let seed_bytes = std::fs::read(identity_path)
            .with_context(|| format!("reading identity from {}", identity_path.display()))?;
        let seed = ml_dsa::B32::try_from(seed_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("identity file must be a 32-byte ML-DSA-65 seed"))?;
        let kp = MlDsa65::key_gen_internal(&seed);
        return Ok(kp.verifying_key().encode().to_vec());
    }

    // Generate a fresh seed.
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed_bytes.as_mut());

    if let Some(parent) = identity_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
        set_dir_owner_only_permissions(parent)?;
    }

    write_seed_owner_only(identity_path, seed_bytes.as_slice())
        .with_context(|| format!("writing identity to {}", identity_path.display()))?;

    let seed = ml_dsa::B32::try_from(seed_bytes.as_ref())
        .map_err(|_| anyhow::anyhow!("seed size mismatch"))?;
    let kp = MlDsa65::key_gen_internal(&seed);
    Ok(kp.verifying_key().encode().to_vec())
}

#[cfg(unix)]
fn write_seed_owner_only(identity_path: &Path, seed: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(identity_path)?;
    file.write_all(seed)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_seed_owner_only(identity_path: &Path, seed: &[u8]) -> Result<()> {
    std::fs::write(identity_path, seed)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_owner_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_owner_only_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "identity key {} is accessible by group/other (mode {:o}); expected 0600",
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

/// Encode a verifying-key as a single authorized_keys line.
///
/// Format: `ml-dsa-65 <base64-pubkey> [comment]`
pub fn format_authorized_key(pubkey: &[u8], comment: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
    if comment.is_empty() {
        format!("ml-dsa-65 {b64}")
    } else {
        format!("ml-dsa-65 {b64} {comment}")
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_client_keypair;

    #[cfg(unix)]
    #[test]
    fn creates_identity_file_and_parent_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let identity_path = dir.path().join("qssh").join("id_ml_dsa_65");

        let pubkey = ensure_client_keypair(&identity_path).unwrap();
        assert!(!pubkey.is_empty());

        let file_mode = std::fs::metadata(&identity_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);

        let dir_mode = std::fs::metadata(identity_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_accessible_existing_identity_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let identity_path = dir.path().join("id_ml_dsa_65");
        std::fs::write(&identity_path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = ensure_client_keypair(&identity_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("accessible by group/other"));
    }
}
