use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    #[serde(default = "default_port")]
    pub port: u16,

    pub host_key: PathBuf,
    pub host_cert: PathBuf,

    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    #[serde(default)]
    pub direct_tcpip_allowlist: Vec<String>,

    #[serde(default)]
    pub remote_forward_allowlist: Vec<String>,

    #[serde(default = "default_max_channels_per_connection")]
    pub max_channels_per_connection: usize,

    #[serde(default = "default_max_remote_forwards_per_connection")]
    pub max_remote_forwards_per_connection: usize,
    #[serde(skip, default)]
    pub live_cert_fingerprint: [u8; 32],
}

fn default_bind_addr() -> String {
    "0.0.0.0".into()
}

fn default_port() -> u16 {
    2222
}

fn default_max_connections() -> usize {
    100
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_max_channels_per_connection() -> usize {
    32
}

fn default_max_remote_forwards_per_connection() -> usize {
    8
}

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(Path::new(path))
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&contents).with_context(|| "parsing server config")
    }
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn defaults_are_conservative_for_forwarding() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            host_key = "/etc/qssh/host.key"
            host_cert = "/etc/qssh/host.cert"
            "#,
        )
        .expect("config should parse");

        assert!(cfg.direct_tcpip_allowlist.is_empty());
        assert!(cfg.remote_forward_allowlist.is_empty());
        assert_eq!(cfg.max_channels_per_connection, 32);
        assert_eq!(cfg.max_remote_forwards_per_connection, 8);
        assert_eq!(cfg.live_cert_fingerprint, [0u8; 32]);
    }
}
