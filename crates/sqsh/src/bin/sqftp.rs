//! Interactive SFTP client over a sqsh `sftp` subsystem channel (like OpenSSH `sftp`).

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures_util::StreamExt;
use sqsh::config::ClientConfig;
use sqsh::sftp::SftpClient;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing_subscriber::EnvFilter;

// ponytail: mirrors the 32 KiB transfer chunk used by the sftp bridge.
const CHUNK: usize = 32 * 1024;

#[derive(Parser)]
#[command(name = "sqftp", about = "Interactive SFTP client over SQSH")]
struct Cli {
    /// Target as [user@]host
    target: String,

    /// Identity (private key) file
    #[arg(short, long)]
    identity: Option<String>,

    /// Remote port
    #[arg(short = 'P', long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let cfg = ClientConfig::resolve(
        &cli.target,
        cli.port,
        None,
        None,
        cli.identity.as_deref(),
        &[],
        None,
        &[],
        &[],
        false,
        None,
        false,
        None,
    )?;

    let client = sqsh::sftp::connect(&cfg).await?;
    repl(&client).await;
    client.close().await;
    Ok(())
}

/// Resolve a remote path argument against the remote cwd. Absolute paths win.
fn resolve_remote(cwd: &Path, p: &str) -> PathBuf {
    let p = Path::new(p);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        cwd.join(p)
    }
}

/// Split a REPL line into (command, args). `None` for a blank line.
// ponytail: no shell-style quoting; filenames with spaces are unsupported.
fn parse_command(line: &str) -> Option<(String, Vec<String>)> {
    let mut it = line.split_whitespace();
    let cmd = it.next()?;
    Some((cmd.to_string(), it.map(str::to_string).collect()))
}

async fn repl(client: &SftpClient) {
    let mut cwd = client
        .sftp
        .fs()
        .canonicalize(".")
        .await
        .unwrap_or_else(|_| PathBuf::from("/"));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("sqftp> ");
        std::io::stdout().flush().ok();

        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break, // Ctrl-D / EOF
            Err(e) => {
                eprintln!("sqftp: {e}");
                break;
            }
        };

        let (cmd, args) = match parse_command(&line) {
            Some(c) => c,
            None => continue, // blank line -> reprint prompt
        };

        match cmd.as_str() {
            "quit" | "exit" | "bye" => break,
            _ => {
                if let Err(e) = run(client, &mut cwd, &cmd, &args).await {
                    eprintln!("sqftp: {e:#}");
                }
            }
        }
    }
}

async fn run(client: &SftpClient, cwd: &mut PathBuf, cmd: &str, args: &[String]) -> Result<()> {
    match cmd {
        "ls" => {
            let dir = args
                .first()
                .map(|p| resolve_remote(cwd, p))
                .unwrap_or_else(|| cwd.clone());
            let mut fs = client.sftp.fs();
            let rd = fs.open_dir(&dir).await?.read_dir();
            futures_util::pin_mut!(rd);
            while let Some(ent) = rd.next().await {
                let ent = ent?;
                let name = ent.filename().to_string_lossy();
                if name == "." || name == ".." {
                    continue;
                }
                if ent.file_type().is_some_and(|t| t.is_dir()) {
                    println!("{name}/");
                } else {
                    println!("{name}");
                }
            }
        }
        "cd" => {
            let p = args.first().context("cd: missing path")?;
            let mut fs = client.sftp.fs();
            let canon = fs.canonicalize(resolve_remote(cwd, p)).await?;
            let md = fs.metadata(&canon).await?;
            if md.file_type().is_some_and(|t| t.is_dir()) {
                *cwd = canon;
            } else {
                bail!("cd: not a directory: {}", canon.display());
            }
        }
        "pwd" => println!("{}", cwd.display()),
        "get" => {
            let remote = resolve_remote(cwd, args.first().context("get: missing remote path")?);
            let local = match args.get(1) {
                Some(l) => PathBuf::from(l),
                None => PathBuf::from(
                    remote
                        .file_name()
                        .context("get: cannot derive local name")?,
                ),
            };
            download(client, &remote, &local).await?;
        }
        "put" => {
            let local = PathBuf::from(args.first().context("put: missing local path")?);
            let remote = match args.get(1) {
                Some(r) => resolve_remote(cwd, r),
                None => {
                    let base = local
                        .file_name()
                        .context("put: cannot derive remote name")?;
                    resolve_remote(cwd, &base.to_string_lossy())
                }
            };
            upload(client, &local, &remote).await?;
        }
        "mkdir" => {
            let p = resolve_remote(cwd, args.first().context("mkdir: missing path")?);
            client.sftp.fs().create_dir(&p).await?;
        }
        "rmdir" => {
            let p = resolve_remote(cwd, args.first().context("rmdir: missing path")?);
            client.sftp.fs().remove_dir(&p).await?;
        }
        "rm" => {
            let p = resolve_remote(cwd, args.first().context("rm: missing path")?);
            client.sftp.fs().remove_file(&p).await?;
        }
        "rename" => {
            let from = resolve_remote(cwd, args.first().context("rename: missing source")?);
            let to = resolve_remote(cwd, args.get(1).context("rename: missing destination")?);
            client.sftp.fs().rename(&from, &to).await?;
        }
        "lpwd" => println!("{}", std::env::current_dir()?.display()),
        "lcd" => std::env::set_current_dir(args.first().context("lcd: missing path")?)?,
        "lls" => {
            let dir = match args.first() {
                Some(p) => PathBuf::from(p),
                None => std::env::current_dir()?,
            };
            for ent in std::fs::read_dir(&dir)? {
                let ent = ent?;
                let name = ent.file_name();
                let name = name.to_string_lossy();
                if ent.file_type()?.is_dir() {
                    println!("{name}/");
                } else {
                    println!("{name}");
                }
            }
        }
        "help" | "?" => {
            println!(
                "Commands:\n  \
                 ls [path]            list a remote directory\n  \
                 cd <path>            change remote directory\n  \
                 pwd                  print remote directory\n  \
                 get <remote> [local] download a file\n  \
                 put <local> [remote] upload a file\n  \
                 mkdir <path>         create a remote directory\n  \
                 rmdir <path>         remove an empty remote directory\n  \
                 rm <path>            remove a remote file\n  \
                 rename <old> <new>   rename a remote path\n  \
                 lpwd                 print local directory\n  \
                 lcd <path>           change local directory\n  \
                 lls [path]           list a local directory\n  \
                 help, ?              show this help\n  \
                 quit, exit, bye      close the session"
            );
        }
        other => bail!("unknown command: {other}"),
    }
    Ok(())
}

/// Download a remote file to a local path in 32 KiB chunks.
async fn download(client: &SftpClient, remote: &Path, local: &Path) -> Result<()> {
    let mut rf = client
        .sftp
        .open(remote)
        .await
        .with_context(|| format!("opening remote {}", remote.display()))?;
    let mut out = tokio::fs::File::create(local)
        .await
        .with_context(|| format!("creating local {}", local.display()))?;
    loop {
        let buf = bytes::BytesMut::with_capacity(CHUNK);
        match rf.read(CHUNK as u32, buf).await? {
            Some(d) if !d.is_empty() => out.write_all(&d).await?,
            _ => break, // short reads are fine; Ok(None)/empty == EOF
        }
    }
    rf.close().await?;
    out.flush().await?;
    Ok(())
}

/// Upload a local file to a remote path in 32 KiB chunks.
async fn upload(client: &SftpClient, local: &Path, remote: &Path) -> Result<()> {
    let mut inp = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("opening local {}", local.display()))?;
    let mut wf = client
        .sftp
        .create(remote)
        .await
        .with_context(|| format!("creating remote {}", remote.display()))?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = inp.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        wf.write_all(&buf[..n]).await?;
    }
    wf.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_remote_absolute_ignores_cwd() {
        assert_eq!(
            resolve_remote(Path::new("/home/me"), "/etc/x"),
            PathBuf::from("/etc/x")
        );
    }

    #[test]
    fn resolve_remote_relative_joins_cwd() {
        assert_eq!(
            resolve_remote(Path::new("/home/me"), "sub/f"),
            PathBuf::from("/home/me/sub/f")
        );
    }

    #[test]
    fn parse_command_blank_is_none() {
        assert!(parse_command("").is_none());
        assert!(parse_command("   ").is_none());
    }

    #[test]
    fn parse_command_splits_args() {
        let (cmd, args) = parse_command("get a b").unwrap();
        assert_eq!(cmd, "get");
        assert_eq!(args, vec!["a".to_string(), "b".to_string()]);
    }
}
