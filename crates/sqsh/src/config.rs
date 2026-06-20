use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::target::Target;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPersist {
    Disabled,
    Forever,
    Timeout(Duration),
}

impl ControlPersist {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Self::Disabled),
            Some(value) => match value.trim().to_ascii_lowercase().as_str() {
                "" | "yes" | "true" => Ok(Self::Forever),
                "no" | "false" => Ok(Self::Disabled),
                other => parse_duration(other).map(Self::Timeout),
            },
        }
    }

    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub fn as_arg(self) -> Option<String> {
        match self {
            Self::Disabled => None,
            Self::Forever => Some("yes".to_string()),
            Self::Timeout(duration) => Some(duration.as_secs().to_string()),
        }
    }

    pub fn idle_timeout(self) -> Option<Duration> {
        match self {
            Self::Disabled | Self::Forever => None,
            Self::Timeout(duration) => Some(duration),
        }
    }
}

fn parse_duration(value: &str) -> Result<Duration> {
    let (digits, unit) = value.trim().split_at(
        value
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(value.len()),
    );

    if digits.is_empty() {
        bail!("invalid ControlPersist duration '{value}'");
    }

    let amount: u64 = digits
        .parse()
        .with_context(|| format!("parsing ControlPersist duration '{value}'"))?;

    let multiplier = match unit {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        other => bail!("invalid ControlPersist duration unit '{other}'"),
    };

    Ok(Duration::from_secs(amount.saturating_mul(multiplier)))
}

/// A TCP port-forwarding specification.
///
/// For `-L`: bind locally on `bind_addr:bind_port`, forward to `target_host:target_port` on the server.
/// For `-R`: bind on the server at `bind_addr:bind_port`, forward to `target_host:target_port` locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    fn parse_ssh_config(value: &str) -> Result<Self> {
        let tokens = tokenize_config_line(value);
        match tokens.as_slice() {
            [single] => Self::parse(single),
            [listen, target] => Self::parse(&format!("{listen}:{target}")),
            _ => bail!("invalid forward spec '{value}'"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub ssh_port: u16,
    pub username: String,
    pub identity_path: PathBuf,
    pub known_hosts_path: PathBuf,
    pub command: Option<String>,
    pub subsystem: Option<String>,
    pub local_forwards: Vec<ForwardSpec>,
    pub remote_forwards: Vec<ForwardSpec>,
    pub no_shell: bool,
    pub control_path: PathBuf,
    pub control_path_explicit: bool,
    pub control_master: bool,
    pub control_master_auto: bool,
    pub control_persist: ControlPersist,
}

impl ClientConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        target_str: &str,
        port_override: Option<u16>,
        ssh_port_override: Option<u16>,
        user_override: Option<&str>,
        identity_override: Option<&str>,
        command_parts: &[String],
        subsystem: Option<&str>,
        local_forward_strs: &[String],
        remote_forward_strs: &[String],
        no_shell: bool,
        control_path_override: Option<&str>,
        control_master: bool,
        control_persist: Option<&str>,
    ) -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        Self::resolve_with_home(
            target_str,
            port_override,
            ssh_port_override,
            user_override,
            identity_override,
            command_parts,
            subsystem,
            local_forward_strs,
            remote_forward_strs,
            no_shell,
            control_path_override,
            control_master,
            control_persist,
            Path::new(&home),
            std::env::var("USER").ok().as_deref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_with_home(
        target_str: &str,
        port_override: Option<u16>,
        ssh_port_override: Option<u16>,
        user_override: Option<&str>,
        identity_override: Option<&str>,
        command_parts: &[String],
        subsystem: Option<&str>,
        local_forward_strs: &[String],
        remote_forward_strs: &[String],
        no_shell: bool,
        control_path_override: Option<&str>,
        control_master: bool,
        control_persist: Option<&str>,
        home: &Path,
        user_env: Option<&str>,
    ) -> Result<Self> {
        let target = Target::parse(target_str)?;
        let ssh = SshHostConfig::load(&home.join(".ssh").join("config"), &target.host)?;
        let config_dir = home.join(".config").join("sqsh");

        let host = ssh.host_name.unwrap_or_else(|| target.host.clone());

        let username = user_override
            .map(String::from)
            .or(target.user.clone())
            .or(ssh.user)
            .or_else(|| user_env.map(String::from))
            .unwrap_or_else(|| "root".into());

        let port = port_override.or(target.port).or(ssh.port).unwrap_or(2222);
        let ssh_port = ssh_port_override.unwrap_or(22);

        let identity_path = identity_override
            .map(PathBuf::from)
            .or_else(|| {
                ssh.identity_file
                    .as_deref()
                    .map(|path| expand_ssh_path(path, home, &host, &target.host, port, &username))
            })
            .unwrap_or_else(|| config_dir.join("id_ml_dsa_65"));

        let known_hosts_path = config_dir.join("known_hosts");
        let control_path = control_path_override
            .map(PathBuf::from)
            .or_else(|| {
                ssh.control_path
                    .as_deref()
                    .map(|path| expand_ssh_path(path, home, &host, &target.host, port, &username))
            })
            .unwrap_or_else(|| default_control_path(&config_dir, &username, &host, port));
        let control_path_explicit = control_path_override.is_some() || ssh.control_path.is_some();

        let command = if command_parts.is_empty() {
            None
        } else {
            Some(command_parts.join(" "))
        };
        // ponytail: subsystem takes precedence over a command; a subsystem channel never runs a shell command.
        let command = if subsystem.is_some() { None } else { command };

        let mut local_forwards = ssh.local_forwards;
        local_forwards.extend(
            local_forward_strs
                .iter()
                .map(|s| ForwardSpec::parse(s))
                .collect::<Result<Vec<_>>>()?,
        );

        let mut remote_forwards = ssh.remote_forwards;
        remote_forwards.extend(
            remote_forward_strs
                .iter()
                .map(|s| ForwardSpec::parse(s))
                .collect::<Result<Vec<_>>>()?,
        );

        Ok(Self {
            host,
            port,
            ssh_port,
            username,
            identity_path,
            known_hosts_path,
            command,
            subsystem: subsystem.map(String::from),
            local_forwards,
            remote_forwards,
            no_shell,
            control_path,
            control_path_explicit,
            control_master,
            control_master_auto: ssh.control_master.unwrap_or(false),
            control_persist: ControlPersist::parse(
                control_persist.or(ssh.control_persist.as_deref()),
            )?,
        })
    }
}

#[derive(Debug, Default)]
struct SshHostConfig {
    host_name: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<String>,
    local_forwards: Vec<ForwardSpec>,
    remote_forwards: Vec<ForwardSpec>,
    control_path: Option<String>,
    control_master: Option<bool>,
    control_persist: Option<String>,
}

impl SshHostConfig {
    fn load(path: &Path, target_host: &str) -> Result<Self> {
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };

        Self::parse(&contents, target_host)
    }

    fn parse(contents: &str, target_host: &str) -> Result<Self> {
        let mut config = Self::default();
        let mut active = true;

        for (line_no, line) in contents.lines().enumerate() {
            let tokens = tokenize_config_line(line);
            let Some((keyword, args)) = tokens.split_first() else {
                continue;
            };
            let keyword = keyword.to_ascii_lowercase();

            if keyword == "host" {
                active = host_patterns_match(args, target_host);
                continue;
            }

            if !active || args.is_empty() {
                continue;
            }

            let value = args.join(" ");
            match keyword.as_str() {
                "hostname" => set_once(&mut config.host_name, value),
                "user" => set_once(&mut config.user, value),
                "port" if config.port.is_none() => {
                    config.port = Some(value.parse().with_context(|| {
                        format!("parsing Port on ssh config line {}", line_no + 1)
                    })?);
                }
                "port" => {}
                "identityfile" => set_once(&mut config.identity_file, value),
                "localforward" => {
                    config
                        .local_forwards
                        .push(ForwardSpec::parse_ssh_config(&value).with_context(|| {
                            format!("parsing LocalForward on ssh config line {}", line_no + 1)
                        })?)
                }
                "remoteforward" => config.remote_forwards.push(
                    ForwardSpec::parse_ssh_config(&value).with_context(|| {
                        format!("parsing RemoteForward on ssh config line {}", line_no + 1)
                    })?,
                ),
                "controlpath" => set_once(&mut config.control_path, value),
                "controlmaster" if config.control_master.is_none() => {
                    config.control_master = Some(parse_control_master(&value));
                }
                "controlmaster" => {}
                "controlpersist" => set_once(&mut config.control_persist, value),
                _ => {}
            }
        }

        Ok(config)
    }
}

fn set_once(slot: &mut Option<String>, value: String) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn parse_control_master(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "yes" | "true" | "auto" | "autoask" | "ask"
    )
}

fn host_patterns_match(patterns: &[String], host: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        if let Some(pattern) = pattern.strip_prefix('!') {
            if wildcard_match(pattern, host) {
                return false;
            }
        } else if wildcard_match(pattern, host) {
            matched = true;
        }
    }
    matched
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    fn inner(pattern: &[u8], value: &[u8]) -> bool {
        match pattern.split_first() {
            None => value.is_empty(),
            Some((&b'*', rest)) => {
                inner(rest, value) || (!value.is_empty() && inner(pattern, &value[1..]))
            }
            Some((&b'?', rest)) => !value.is_empty() && inner(rest, &value[1..]),
            Some((&c, rest)) => {
                !value.is_empty() && c.eq_ignore_ascii_case(&value[0]) && inner(rest, &value[1..])
            }
        }
    }

    inner(pattern.as_bytes(), value.as_bytes())
}

fn tokenize_config_line(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;

    for ch in line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => break,
            '=' if quote.is_none() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c if c.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn expand_ssh_path(
    path: &str,
    home: &Path,
    host: &str,
    original_host: &str,
    port: u16,
    username: &str,
) -> PathBuf {
    let mut expanded = String::with_capacity(path.len());
    let mut chars = path.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('h') => expanded.push_str(host),
                Some('n') => expanded.push_str(original_host),
                Some('p') => expanded.push_str(&port.to_string()),
                Some('r') => expanded.push_str(username),
                Some('%') => expanded.push('%'),
                Some(other) => {
                    expanded.push('%');
                    expanded.push(other);
                }
                None => expanded.push('%'),
            }
        } else {
            expanded.push(ch);
        }
    }

    if expanded == "~" {
        home.to_path_buf()
    } else if let Some(rest) = expanded.strip_prefix("~/") {
        home.join(rest)
    } else {
        PathBuf::from(expanded)
    }
}

fn default_control_path(config_dir: &Path, username: &str, host: &str, port: u16) -> PathBuf {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update([0]);
    hasher.update(host.as_bytes());
    hasher.update([0]);
    hasher.update(port.to_le_bytes());
    let digest = hasher.finalize();
    let mut name = String::with_capacity("cm-.sock".len() + 16);
    name.push_str("cm-");
    for byte in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(&mut name, "{byte:02x}");
    }
    name.push_str(".sock");

    config_dir.join("control").join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[String] = &[];

    #[test]
    fn parses_control_persist_values() {
        assert_eq!(
            ControlPersist::parse(None).unwrap(),
            ControlPersist::Disabled
        );
        assert_eq!(
            ControlPersist::parse(Some("no")).unwrap(),
            ControlPersist::Disabled
        );
        assert_eq!(
            ControlPersist::parse(Some("yes")).unwrap(),
            ControlPersist::Forever
        );
        assert_eq!(
            ControlPersist::parse(Some("2m")).unwrap(),
            ControlPersist::Timeout(Duration::from_secs(120)),
        );
    }

    #[test]
    fn default_control_path_is_stable_and_short() {
        let dir = PathBuf::from("/tmp/sqsh");
        let first = default_control_path(&dir, "alice", "example.com", 2222);
        let second = default_control_path(&dir, "alice", "example.com", 2222);
        assert_eq!(first, second);
        assert!(first.to_string_lossy().len() < 80);
    }

    #[test]
    fn ssh_config_host_values_are_applied_and_unknown_keys_ignored() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        std::fs::write(
            home.path().join(".ssh/config"),
            r#"
Host ignored
    HostName ignored.example
    User wrong

Host prod-*
    HostName prod.internal
    User deploy
    Port 2244
    IdentityFile ~/.ssh/sqsh_%r_%h_%p
    ControlPath ~/.ssh/cm-%r@%h:%p
    ControlMaster auto
    ControlPersist 5m
    LocalForward 127.0.0.1:8080 localhost:80
    RemoteForward 9090 localhost:90
    ProxyJump unsupported.example
"#,
        )
        .unwrap();

        let config = ClientConfig::resolve_with_home(
            "prod-app",
            None,
            None,
            None,
            None,
            EMPTY,
            None,
            EMPTY,
            EMPTY,
            false,
            None,
            false,
            None,
            home.path(),
            Some("localuser"),
        )
        .unwrap();

        assert_eq!(config.host, "prod.internal");
        assert_eq!(config.username, "deploy");
        assert_eq!(config.port, 2244);
        assert_eq!(config.ssh_port, 22);
        assert_eq!(
            config.identity_path,
            home.path().join(".ssh/sqsh_deploy_prod.internal_2244")
        );
        assert_eq!(
            config.control_path,
            home.path().join(".ssh/cm-deploy@prod.internal:2244")
        );
        assert!(config.control_path_explicit);
        assert!(config.control_master_auto);
        assert_eq!(
            config.control_persist,
            ControlPersist::Timeout(Duration::from_secs(300))
        );
        assert_eq!(config.local_forwards.len(), 1);
        assert_eq!(config.local_forwards[0].bind_addr, "127.0.0.1");
        assert_eq!(config.local_forwards[0].bind_port, 8080);
        assert_eq!(config.local_forwards[0].target_host, "localhost");
        assert_eq!(config.local_forwards[0].target_port, 80);
        assert_eq!(config.remote_forwards.len(), 1);
        assert_eq!(config.remote_forwards[0].bind_addr, "127.0.0.1");
        assert_eq!(config.remote_forwards[0].bind_port, 9090);
    }

    #[test]
    fn cli_values_override_ssh_config_scalars_and_append_forwards() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        std::fs::write(
            home.path().join(".ssh/config"),
            r#"
Host prod
    HostName config-host
    User config-user
    Port 2022
    IdentityFile ~/.ssh/config-key
    ControlPath ~/.ssh/config-cm
    ControlMaster yes
    ControlPersist yes
    LocalForward 1000 localhost:1001
"#,
        )
        .unwrap();

        let cli_local = vec!["2000:localhost:2001".to_string()];
        let config = ClientConfig::resolve_with_home(
            "target-user@prod:3022",
            Some(4022),
            Some(2200),
            Some("cli-user"),
            Some("/tmp/cli-key"),
            EMPTY,
            None,
            &cli_local,
            EMPTY,
            false,
            Some("/tmp/cli-cm"),
            false,
            Some("no"),
            home.path(),
            Some("localuser"),
        )
        .unwrap();

        assert_eq!(config.host, "config-host");
        assert_eq!(config.username, "cli-user");
        assert_eq!(config.port, 4022);
        assert_eq!(config.ssh_port, 2200);
        assert_eq!(config.identity_path, PathBuf::from("/tmp/cli-key"));
        assert_eq!(config.control_path, PathBuf::from("/tmp/cli-cm"));
        assert!(config.control_master_auto);
        assert_eq!(config.control_persist, ControlPersist::Disabled);
        assert_eq!(config.local_forwards.len(), 2);
        assert_eq!(config.local_forwards[0].bind_port, 1000);
        assert_eq!(config.local_forwards[1].bind_port, 2000);
    }

    #[test]
    fn subsystem_takes_precedence_over_command() {
        let home = tempfile::tempdir().unwrap();
        let command = vec!["ls".to_string(), "-la".to_string()];
        let config = ClientConfig::resolve_with_home(
            "host",
            None,
            None,
            None,
            None,
            &command,
            Some("sftp"),
            EMPTY,
            EMPTY,
            false,
            None,
            false,
            None,
            home.path(),
            Some("localuser"),
        )
        .unwrap();

        assert_eq!(config.subsystem.as_deref(), Some("sftp"));
        assert_eq!(config.command, None);
    }

    #[test]
    fn ssh_config_uses_first_value_from_matching_hosts() {
        let parsed = SshHostConfig::parse(
            r#"
Host *.example
    User first
    Port 1111
Host app.example
    User second
    Port 2222
Host * !blocked.example
    IdentityFile ~/.ssh/fallback
"#,
            "app.example",
        )
        .unwrap();

        assert_eq!(parsed.user.as_deref(), Some("first"));
        assert_eq!(parsed.port, Some(1111));
        assert_eq!(parsed.identity_file.as_deref(), Some("~/.ssh/fallback"));

        let blocked = SshHostConfig::parse(
            r#"
Host * !blocked.example
    User fallback
"#,
            "blocked.example",
        )
        .unwrap();
        assert!(blocked.user.is_none());
    }

    #[test]
    fn tokenizes_whitespace_equals_quotes_and_comments() {
        assert_eq!(
            tokenize_config_line("HostName = \"prod internal\" # comment"),
            vec!["HostName", "prod internal"]
        );
    }
}
