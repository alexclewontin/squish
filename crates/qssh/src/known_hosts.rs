use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Result};

/// Trust-On-First-Use host key verification.
///
/// Stores SHA-256 fingerprints of server TLS certificates, keyed by host:port.
pub struct KnownHosts {
    entries: HashMap<String, String>,
    path: std::path::PathBuf,
}

impl KnownHosts {
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = HashMap::new();

        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((host, fingerprint)) = line.split_once(' ') {
                    entries.insert(host.to_string(), fingerprint.to_string());
                }
            }
        }

        Ok(Self {
            entries,
            path: path.to_path_buf(),
        })
    }

    /// Verify a server's certificate fingerprint.
    ///
    /// - If no entry exists for this host, stores it (TOFU) and returns Ok.
    /// - If an entry exists and matches, returns Ok.
    /// - If an entry exists and does NOT match, returns Err.
    pub fn verify(&mut self, host_port: &str, fingerprint: &str) -> Result<()> {
        match self.entries.get(host_port) {
            None => {
                tracing::warn!(
                    "first connection to {host_port} — trusting fingerprint {fingerprint}"
                );
                self.entries
                    .insert(host_port.to_string(), fingerprint.to_string());
                self.save()?;
                Ok(())
            }
            Some(stored) if stored == fingerprint => Ok(()),
            Some(stored) => {
                bail!(
                    "HOST KEY VERIFICATION FAILED for {host_port}!\n\
                     Expected: {stored}\n\
                     Got:      {fingerprint}\n\
                     The server's certificate has changed. This could indicate a \
                     man-in-the-middle attack. Connection refused.\n\
                     To accept the new key, remove the entry from {}",
                    self.path.display()
                );
            }
        }
    }

    /// Unconditionally store (or replace) the fingerprint for a host.
    ///
    /// Used by bootstrap to pre-populate known_hosts so the first
    /// real connection doesn't prompt the user.
    pub fn pin(&mut self, host_port: &str, fingerprint: &str) -> Result<()> {
        self.entries
            .insert(host_port.to_string(), fingerprint.to_string());
        self.save()
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut contents = String::new();
        for (host, fp) in &self.entries {
            contents.push_str(host);
            contents.push(' ');
            contents.push_str(fp);
            contents.push('\n');
        }
        std::fs::write(&self.path, contents)?;
        Ok(())
    }
}
