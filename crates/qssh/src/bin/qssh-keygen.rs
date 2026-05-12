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
    }

    let mut seed = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());

    std::fs::write(key_path, seed.as_slice())
        .with_context(|| format!("writing key to {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .context("setting key file permissions")?;
    }

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
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into());
    format!("{user}@{host}")
}
