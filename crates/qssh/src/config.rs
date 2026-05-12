use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::target::Target;

/// A TCP port-forwarding specification.
///
/// For `-L`: bind locally on `bind_addr:bind_port`, forward to `target_host:target_port` on the server.
/// For `-R`: bind on the server at `bind_addr:bind_port`, forward to `target_host:target_port` locally.
#[derive(Debug, Clone)]
pub struct ForwardSpec {
    pub bind_addr: String,
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl ForwardSpec {
    /// Parse `[bind_addr:]bind_port:target_host:target_port`.
    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            [bind_port, host, target_port] => Ok(Self {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: bind_port.parse().context("parsing bind port")?,
                target_host: host.to_string(),
                target_port: target_port.parse().context("parsing target port")?,
            }),
            [bind_addr, bind_port, host, target_port] => Ok(Self {
                bind_addr: bind_addr.to_string(),
                bind_port: bind_port.parse().context("parsing bind port")?,
                target_host: host.to_string(),
                target_port: target_port.parse().context("parsing target port")?,
            }),
            _ => {
                bail!("invalid forward spec '{s}'; expected [bind_addr:]bind_port:host:target_port")
            }
        }
    }
}

#[derive(Debug)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub identity_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub command: Option<String>,
    pub local_forwards: Vec<ForwardSpec>,
    pub remote_forwards: Vec<ForwardSpec>,
    pub no_shell: bool,
}

impl ClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        target_str: &str,
        port_override: Option<u16>,
        user_override: Option<&str>,
        identity_override: Option<&str>,
        command_parts: &[String],
        local_forward_strs: &[String],
        remote_forward_strs: &[String],
        no_shell: bool,
    ) -> Result<Self> {
        let target = Target::parse(target_str)?;

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        let config_dir = PathBuf::from(&home).join(".config").join("qssh");

        let username = user_override
            .map(String::from)
            .or(target.user)
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "root".into());

        let port = port_override.or(target.port).unwrap_or(2222);

        let identity_path = identity_override
            .map(PathBuf::from)
            .unwrap_or_else(|| config_dir.join("id_ml_dsa_65"));

        let known_hosts_path = config_dir.join("known_hosts");

        let command = if command_parts.is_empty() {
            None
        } else {
            Some(command_parts.join(" "))
        };

        let local_forwards = local_forward_strs
            .iter()
            .map(|s| ForwardSpec::parse(s))
            .collect::<Result<Vec<_>>>()?;

        let remote_forwards = remote_forward_strs
            .iter()
            .map(|s| ForwardSpec::parse(s))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            host: target.host,
            port,
            username,
            identity_path,
            known_hosts_path,
            command,
            local_forwards,
            remote_forwards,
            no_shell,
        })
    }
}
