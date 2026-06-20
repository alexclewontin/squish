use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;

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
            .arg("-t")
            .arg(self.userhost())
            .arg(format!("sudo sh -c {}", shell_single_quote(cmd)))
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

    /// Write a string to a remote path by uploading a temporary local file.
    pub fn write_file(&self, remote_path: &str, content: &str) -> Result<()> {
        let mut temp = NamedTempFile::new().context("creating temporary upload file")?;
        temp.write_all(content.as_bytes())
            .context("writing temporary upload file")?;
        self.upload(temp.path(), remote_path)
    }

    /// Add an authorized_keys line to `~/.squish/authorized_keys` without
    /// interpolating the key contents into a remote shell command.
    pub fn install_authorized_key(&self, authorized_key_line: &str) -> Result<()> {
        const REMOTE_TEMP_KEY: &str = "/tmp/sqsh-authorized-key";

        let mut key_file = String::with_capacity(authorized_key_line.len() + 1);
        key_file.push_str(authorized_key_line);
        key_file.push('\n');
        self.write_file(REMOTE_TEMP_KEY, &key_file)
            .context("uploading authorized key line")?;

        self.run(&authorized_key_install_command(REMOTE_TEMP_KEY))
            .map(|_| ())
            .context("installing authorized key")
    }
}

fn authorized_key_install_command(remote_temp_key: &str) -> String {
    format!(
        "sh -c 'mkdir -p \"$HOME/.squish\" && chmod 700 \"$HOME/.squish\" && \
         touch \"$HOME/.squish/authorized_keys\" && chmod 600 \"$HOME/.squish/authorized_keys\" && \
         {{ grep -qxF -f {remote_temp_key} \"$HOME/.squish/authorized_keys\" || \
            cat {remote_temp_key} >> \"$HOME/.squish/authorized_keys\"; }} && \
         rm -f {remote_temp_key}'"
    )
}

fn shell_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', r#"'\''"#))
}

#[cfg(test)]
mod tests {
    use super::{authorized_key_install_command, shell_single_quote};

    #[test]
    fn authorized_key_install_command_uses_temp_file_contents() {
        let cmd = authorized_key_install_command("/tmp/test-key");
        assert!(cmd.contains("grep -qxF -f /tmp/test-key"));
        assert!(cmd.contains("cat /tmp/test-key >> \"$HOME/.squish/authorized_keys\""));
        assert!(!cmd.contains("ml-dsa-65"));
    }

    #[test]
    fn shell_single_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_single_quote("echo 'hi'"), "'echo '\\''hi'\\'''");
    }
}
