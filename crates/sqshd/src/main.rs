mod config;
mod connection;
mod keys;
mod listener;

mod channel {
    pub mod forward;
    pub mod session;
}

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "sqshd", about = "SQSH server daemon")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "/etc/sqsh/sqshd.toml")]
    config: String,

    /// Print the server certificate fingerprint (hex SHA-256) and exit
    #[arg(long)]
    emit_fingerprint: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = config::ServerConfig::load(&cli.config)?;

    if cli.emit_fingerprint {
        let (cert_der, _) =
            keys::load_or_generate_tls_identity(&config.host_key, &config.host_cert)?;
        let fp = sqsh_core::auth::fingerprint::cert_fingerprint(cert_der.as_ref());
        println!("{}", hex::encode(fp));
        return Ok(());
    }

    listener::run(config).await
}
