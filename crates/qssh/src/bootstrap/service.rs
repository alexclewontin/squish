use anyhow::Result;

use super::detect::OsKind;
use super::ssh::SshRunner;

pub const QSSHD_INSTALL_PATH: &str = "/usr/local/bin/qsshd";
const QSSHD_CONFIG_PATH: &str = "/etc/qssh/qsshd.toml";
const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/qsshd.service";
const SYSTEMD_TEMP_PATH: &str = "/tmp/qsshd.service";
const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.qssh.qsshd.plist";
const LAUNCHD_TEMP_PATH: &str = "/tmp/com.qssh.qsshd.plist";

/// Generate the qsshd.toml content for a fresh server install.
pub fn default_config() -> String {
    r#"bind_addr = "0.0.0.0"
port = 2222
host_key = "/etc/qssh/host.key"
host_cert = "/etc/qssh/host.cert"
"#
    .to_string()
}

/// Install qsshd as a system service and start it.
pub fn install_and_start(runner: &SshRunner, os: OsKind) -> Result<()> {
    match os {
        OsKind::Linux => install_systemd(runner),
        OsKind::MacOs => install_launchd(runner),
    }
}

/// Retrieve the remote cert fingerprint by running `qsshd --emit-fingerprint`.
pub fn fetch_fingerprint(runner: &SshRunner) -> Result<String> {
    runner.run(&format!(
        "{QSSHD_INSTALL_PATH} --config {QSSHD_CONFIG_PATH} --emit-fingerprint"
    ))
}

fn install_systemd(runner: &SshRunner) -> Result<()> {
    runner.write_file(SYSTEMD_TEMP_PATH, &systemd_unit())?;
    runner.sudo(&format!(
        "install -m 644 {SYSTEMD_TEMP_PATH} {SYSTEMD_UNIT_PATH}"
    ))?;
    runner.sudo("systemctl daemon-reload")?;
    runner.sudo("systemctl enable --now qsshd")?;
    Ok(())
}

fn install_launchd(runner: &SshRunner) -> Result<()> {
    runner.write_file(LAUNCHD_TEMP_PATH, &launchd_plist())?;
    runner.sudo(&format!(
        "install -m 644 {LAUNCHD_TEMP_PATH} {LAUNCHD_PLIST_PATH}"
    ))?;
    runner.sudo("launchctl load -w /Library/LaunchDaemons/com.qssh.qsshd.plist")?;
    Ok(())
}

fn systemd_unit() -> String {
    format!(
        r#"[Unit]
Description=QSSH daemon
After=network.target

[Service]
ExecStart={QSSHD_INSTALL_PATH} --config {QSSHD_CONFIG_PATH}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#
    )
}

fn launchd_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.qssh.qsshd</string>
  <key>ProgramArguments</key>
  <array>
    <string>{QSSHD_INSTALL_PATH}</string>
    <string>--config</string>
    <string>{QSSHD_CONFIG_PATH}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/var/log/qsshd.log</string>
  <key>StandardOutPath</key>
  <string>/var/log/qsshd.log</string>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::{
        QSSHD_CONFIG_PATH, QSSHD_INSTALL_PATH, default_config, launchd_plist, systemd_unit,
    };

    #[test]
    fn default_config_mentions_host_key_and_cert_paths() {
        let config = default_config();
        assert!(config.contains("host_key = \"/etc/qssh/host.key\""));
        assert!(config.contains("host_cert = \"/etc/qssh/host.cert\""));
    }

    #[test]
    fn systemd_unit_execs_expected_binary() {
        let unit = systemd_unit();
        assert!(unit.contains(QSSHD_INSTALL_PATH));
        assert!(unit.contains(QSSHD_CONFIG_PATH));
    }

    #[test]
    fn launchd_plist_execs_expected_binary() {
        let plist = launchd_plist();
        assert!(plist.contains(QSSHD_INSTALL_PATH));
        assert!(plist.contains(QSSHD_CONFIG_PATH));
    }
}
