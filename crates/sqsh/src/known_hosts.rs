use std::collections::HashMap;
use std::path::Path;

use anyhow::{Result, bail};
/// Trust-On-First-Use host key verification.
///
/// Stores SHA-256 fingerprints of server TLS certificates, keyed by host:port.
#[derive(Debug)]
pub struct KnownHosts {
    entries: HashMap<String, String>,
    path: std::path::PathBuf,
}

impl KnownHosts {
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = HashMap::new();

        if path.exists() {
            validate_known_hosts_permissions(path)?;
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
            set_dir_owner_only_permissions(parent)?;
        }

        let mut contents = String::new();
        for (host, fp) in &self.entries {
            contents.push_str(host);
            contents.push(' ');
            contents.push_str(fp);
            contents.push('\n');
        }
        write_owner_only_file(&self.path, contents.as_bytes())?;
        Ok(())
    }
}

#[cfg(unix)]
fn validate_known_hosts_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "known_hosts file {} is accessible by group/other (mode {:o}); refusing to load",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_known_hosts_permissions(_path: &Path) -> Result<()> {
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
fn write_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only_file(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::KnownHosts;

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_other_accessible_known_hosts() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "host.example:2222 fp\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = KnownHosts::load(&path).unwrap_err().to_string();
        assert!(err.contains("accessible by group/other"));
    }

    #[cfg(unix)]
    #[test]
    fn writes_known_hosts_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sqsh").join("known_hosts");

        let mut known_hosts = KnownHosts::load(&path).unwrap();
        known_hosts.pin("host.example:2222", "fp1").unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn rewrites_existing_known_hosts_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sqsh").join("known_hosts");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "old.example:2222 oldfp\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut known_hosts = KnownHosts::load(&path).unwrap();
        known_hosts.pin("new.example:2222", "newfp").unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
    }
}
