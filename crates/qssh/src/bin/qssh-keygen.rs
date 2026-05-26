use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use ml_dsa::{KeyGen, MlDsa65};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "qssh-keygen",
    about = "Generate and manage ML-DSA-65 keypairs for squish"
)]
struct Cli {
    /// Key file path (default: ~/.config/qssh/id_ml_dsa_65)
    #[arg(short = 'f', value_name = "FILE")]
    file: Option<PathBuf>,

    /// Print the public key from an existing key file; do not generate
    #[arg(short = 'y')]
    print_public: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let key_path = cli.file.unwrap_or_else(default_key_path);

    if cli.print_public {
        print_pubkey(&key_path)
    } else {
        generate(&key_path)
    }
}

fn generate(key_path: &PathBuf) -> Result<()> {
    if key_path.exists() {
        bail!(
            "{} already exists. Remove it first or use -f to specify a different path.",
            key_path.display()
        );
    }

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
        set_dir_owner_only_permissions(parent)?;
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());

    write_seed_owner_only(key_path, seed.as_slice())
        .with_context(|| format!("writing key to {}", key_path.display()))?;

    let b32 = ml_dsa::B32::try_from(seed.as_slice())
        .map_err(|_| anyhow::anyhow!("seed size mismatch"))?;
    let kp = MlDsa65::key_gen_internal(&b32);
    let pubkey = kp.verifying_key().encode().to_vec();

    let comment = user_at_host();
    let ak_line = qssh::bootstrap::keys::format_authorized_key(&pubkey, &comment);

    eprintln!("Generated ML-DSA-65 keypair.");
    eprintln!("Private key (seed): {}", key_path.display());
    println!("{ak_line}");

    Ok(())
}

fn print_pubkey(key_path: &PathBuf) -> Result<()> {
    validate_private_key_permissions(key_path)?;
    let seed_bytes = std::fs::read(key_path)
        .with_context(|| format!("reading key from {}", key_path.display()))?;
    let b32 = ml_dsa::B32::try_from(seed_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("identity file must be a 32-byte ML-DSA-65 seed"))?;
    let kp = MlDsa65::key_gen_internal(&b32);
    let pubkey = kp.verifying_key().encode().to_vec();

    let comment = user_at_host();
    let ak_line = qssh::bootstrap::keys::format_authorized_key(&pubkey, &comment);
    println!("{ak_line}");

    Ok(())
}

fn default_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("qssh")
        .join("id_ml_dsa_65")
}

fn user_at_host() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "user".into());
    user_at_host_with(&user, resolve_hostname)
}

#[cfg(unix)]
fn resolve_hostname() -> Option<String> {
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        fn gethostname(name: *mut c_char, len: usize) -> c_int;
    }

    let mut buf = [0u8; 256];
    let rc = unsafe { gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }

    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    let host = String::from_utf8(buf[..end].to_vec()).ok()?;
    let host = host.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(not(unix))]
fn resolve_hostname() -> Option<String> {
    None
}

#[cfg(unix)]
fn write_seed_owner_only(path: &std::path::Path, seed: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening key file {}", path.display()))?;
    file.write_all(seed)
        .with_context(|| format!("writing key file {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_seed_owner_only(path: &std::path::Path, seed: &[u8]) -> Result<()> {
    std::fs::write(path, seed)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_owner_only_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting directory permissions on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_owner_only_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_key_permissions(path: &std::path::Path) -> Result<()> {
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
fn validate_private_key_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

fn user_at_host_with(user: &str, resolve_hostname: impl FnOnce() -> Option<String>) -> String {
    format!(
        "{user}@{}",
        resolve_hostname().unwrap_or_else(|| "localhost".into())
    )
}

#[cfg(test)]
mod tests {
    use super::{generate, resolve_hostname, user_at_host_with};

    #[cfg(unix)]
    #[test]
    fn generate_writes_owner_only_file_and_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("qssh").join("id_ml_dsa_65");

        generate(&key_path).unwrap();

        let file_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        let dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn user_at_host_falls_back_when_hostname_unavailable() {
        let value = user_at_host_with("alice", || None);
        assert_eq!(value, "alice@localhost");
    }

    #[test]
    fn user_at_host_uses_hostname_when_available() {
        let value = user_at_host_with("alice", || Some("workstation".to_string()));
        assert_eq!(value, "alice@workstation");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_hostname_returns_some_or_none() {
        let _ = resolve_hostname();
    }

    #[cfg(unix)]
    #[test]
    fn print_pubkey_rejects_group_or_other_accessible_key_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("id_ml_dsa_65");
        std::fs::write(&key_path, [3u8; 32]).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = super::print_pubkey(&key_path).unwrap_err().to_string();
        assert!(err.contains("accessible by group/other"));
    }
}
