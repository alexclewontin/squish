use std::path::Path;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

/// Load the ML-DSA-65 signing key from disk.
///
/// Returns the raw key bytes wrapped in Zeroizing for secure cleanup.
pub fn load_signing_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading identity key from {}", path.display()))?;
    Ok(Zeroizing::new(bytes))
}
