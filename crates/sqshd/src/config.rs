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

    #[serde(default = "default_accept_env")]
    pub accept_env: Vec<String>,

    #[serde(default)]
    pub subsystems: std::collections::HashMap<String, String>,

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

fn default_accept_env() -> Vec<String> {
    vec!["LANG".into(), "LC_*".into()]
}

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(Path::new(path))
            .with_context(|| format!("reading config from {path}"))?;
        toml::from_str(&contents).with_context(|| "parsing server config")
    }

    /// Whether a client-supplied env var name is allowed to reach the child.
    // ponytail: only exact match and a single trailing `*` prefix are honored;
    // upgrade to a real glob crate if multi-wildcard patterns are ever needed.
    pub fn env_accepted(&self, name: &str) -> bool {
        self.accept_env
            .iter()
            .any(|pat| match pat.strip_suffix('*') {
                Some(prefix) => name.starts_with(prefix),
                None => pat == name,
            })
    }

    /// Resolve a subsystem name to a command line: configured map first, then
    /// a built-in `sftp` autodetect across common sftp-server install paths.
    pub fn resolve_subsystem(&self, name: &str) -> Option<String> {
        if let Some(cmd) = self.subsystems.get(name) {
            return Some(cmd.clone());
        }
        if name == "sftp" {
            for p in [
                "/usr/lib/openssh/sftp-server",
                "/usr/libexec/openssh/sftp-server",
                "/usr/libexec/sftp-server",
                "/usr/lib/ssh/sftp-server",
            ] {
                if Path::new(p).exists() {
                    return Some(p.to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ServerConfig;

    #[test]
    fn defaults_are_conservative_for_forwarding() {
        let cfg: ServerConfig = toml::from_str(
            r#"
            host_key = "/etc/sqsh/host.key"
            host_cert = "/etc/sqsh/host.cert"
            "#,
        )
        .expect("config should parse");

        assert!(cfg.direct_tcpip_allowlist.is_empty());
        assert!(cfg.remote_forward_allowlist.is_empty());
        assert_eq!(cfg.max_channels_per_connection, 32);
        assert_eq!(cfg.max_remote_forwards_per_connection, 8);
        assert_eq!(cfg.live_cert_fingerprint, [0u8; 32]);
    }

    fn parse(extra: &str) -> ServerConfig {
        let toml = format!(
            r#"
            host_key = "/etc/sqsh/host.key"
            host_cert = "/etc/sqsh/host.cert"
            {extra}
            "#
        );
        toml::from_str(&toml).expect("config should parse")
    }

    #[test]
    fn env_accepted_allows_lang_and_lc_rejects_others() {
        let cfg = parse("");
        assert!(cfg.env_accepted("LANG"));
        assert!(cfg.env_accepted("LC_ALL"));
        assert!(!cfg.env_accepted("PATH"));
        assert!(!cfg.env_accepted("LD_PRELOAD"));
    }

    #[test]
    fn resolve_subsystem_uses_configured_map() {
        let cfg = parse(r#"subsystems = { sftp = "/opt/sftp" }"#);
        assert_eq!(cfg.resolve_subsystem("sftp").as_deref(), Some("/opt/sftp"));
        assert_eq!(cfg.resolve_subsystem("nope"), None);
    }
}
