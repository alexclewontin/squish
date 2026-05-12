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
    }

    std::fs::write(identity_path, seed_bytes.as_slice())
        .with_context(|| format!("writing identity to {}", identity_path.display()))?;

    // Restrict permissions to owner-read-only (0600).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(identity_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let seed = ml_dsa::B32::try_from(seed_bytes.as_ref())
        .map_err(|_| anyhow::anyhow!("seed size mismatch"))?;
    let kp = MlDsa65::key_gen_internal(&seed);
    Ok(kp.verifying_key().encode().to_vec())
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
