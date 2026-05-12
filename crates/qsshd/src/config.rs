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

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(Path::new(path))
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&contents).with_context(|| "parsing server config")
    }
}
