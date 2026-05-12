use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Runs commands and uploads files on a remote host via the system `ssh`/`scp`.
pub struct SshRunner {
    pub user: Option<String>,
    pub host: String,
    pub ssh_port: u16,
}

impl SshRunner {
    /// Returns the `user@host` (or just `host`) string used in SSH commands.
    fn userhost(&self) -> String {
        match &self.user {
            Some(u) => format!("{}@{}", u, self.host),
            None => self.host.clone(),
        }
    }

    /// Run a remote shell command and return its stdout as a String.
    pub fn run(&self, cmd: &str) -> Result<String> {
        let out = Command::new("ssh")
            .args(["-p", &self.ssh_port.to_string()])
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(self.userhost())
            .arg(cmd)
            .output()
            .context("spawning ssh")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("ssh command failed: {stderr}");
        }

        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Run a remote command with sudo, prompting interactively for the password.
    pub fn sudo(&self, cmd: &str) -> Result<()> {
        let status = Command::new("ssh")
            .args(["-p", &self.ssh_port.to_string()])
            .arg("-t") // allocate a PTY so sudo can prompt
            .arg(self.userhost())
            .arg(format!("sudo {cmd}"))
            .status()
            .context("spawning ssh for sudo")?;

        if !status.success() {
            bail!("sudo command failed on remote");
        }
        Ok(())
    }

    /// Copy a local file to a remote path via scp.
    pub fn upload(&self, local: &Path, remote_path: &str) -> Result<()> {
        let dest = format!("{}:{}", self.userhost(), remote_path);
        let status = Command::new("scp")
            .args(["-P", &self.ssh_port.to_string()])
            .arg(local)
            .arg(&dest)
            .status()
            .context("spawning scp")?;

        if !status.success() {
            bail!("scp upload failed: {} -> {}", local.display(), dest);
        }
        Ok(())
    }

    /// Write a string as a remote file via a here-string piped through ssh.
    pub fn write_file(&self, remote_path: &str, content: &str) -> Result<()> {
        use std::io::Write as _;
        let mut child = Command::new("ssh")
            .args(["-p", &self.ssh_port.to_string()])
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(self.userhost())
            .arg(format!("cat > {remote_path}"))
            .stdin(std::process::Stdio::piped())
            .spawn()
            .context("spawning ssh for write_file")?;

        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(content.as_bytes())
            .context("writing to remote file")?;

        let status = child.wait()?;
        if !status.success() {
            bail!("failed to write remote file {remote_path}");
        }
        Ok(())
    }
}
