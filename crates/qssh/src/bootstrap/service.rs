use anyhow::Result;

use super::detect::OsKind;
use super::ssh::SshRunner;

pub const QSSHD_INSTALL_PATH: &str = "/usr/local/bin/qsshd";
const QSSHD_CONFIG_PATH: &str = "/etc/qssh/qsshd.toml";

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
    let unit = format!(
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
    );

    runner.sudo(&format!(
        "bash -c 'cat > /etc/systemd/system/qsshd.service' << 'UNIT'\n{unit}\nUNIT"
    ))?;
    runner.sudo("systemctl daemon-reload")?;
    runner.sudo("systemctl enable --now qsshd")?;
    Ok(())
}

fn install_launchd(runner: &SshRunner) -> Result<()> {
    let plist = format!(
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
    );

    runner.sudo(&format!(
        "bash -c 'cat > /Library/LaunchDaemons/com.qssh.qsshd.plist' << 'PLIST'\n{plist}\nPLIST"
    ))?;
    runner.sudo("launchctl load -w /Library/LaunchDaemons/com.qssh.qsshd.plist")?;
    Ok(())
}
