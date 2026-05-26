use std::path::Path;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

/// Load the ML-DSA-65 signing key from disk.
///
/// Returns the raw key bytes wrapped in Zeroizing for secure cleanup.
pub fn load_signing_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    validate_private_key_permissions(path)?;
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading identity key from {}", path.display()))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
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

#[cfg(test)]
mod tests {
    use super::load_signing_key;

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_accessible_identity_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id_ml_dsa_65");
        std::fs::write(&path, [7u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load_signing_key(&path).unwrap_err().to_string();
        assert!(err.contains("accessible by group/other"));
    }
}
