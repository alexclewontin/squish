//! `sqcp`: scp-like one-shot file copy over the sqsh SFTP subsystem.

use anyhow::{Context, Result, bail};
use clap::Parser;
use futures_util::StreamExt;
use sqsh::config::ClientConfig;
use sqsh::sftp::SftpClient;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;

// ponytail: matches the sftp.rs bridge chunk; 32 KiB stays under the 64 KiB frame cap.
const CHUNK: usize = 32 * 1024;

#[derive(Parser)]
#[command(name = "sqcp", about = "scp-like file copy over SFTP")]
struct Cli {
    /// Recurse into directories
    #[arg(short, long)]
    recursive: bool,

    /// Identity (private key) file
    #[arg(short, long)]
    identity: Option<String>,

    /// Remote port
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// Source ([user@]host:path or local path)
    src: String,

    /// Destination ([user@]host:path or local path)
    dst: String,
}

/// Split a `[user@]host:path` remote spec into its `[user@]host` and `path` parts.
///
/// Returns `None` for a local path. scp colon-before-slash rule: a leading
/// `./a:b` or `/abs` is local; `host:path` is remote.
// ponytail: handle the common `[user@]host:path` and `[ipv6]:path` forms; full
// scp grammar (e.g. local paths embedding `[`) is out of scope.
fn parse_remote(arg: &str) -> Option<(String, String)> {
    let colon = if let Some(lb) = arg.find('[') {
        // Bracketed IPv6 host: separator is the first ':' after the matching ']'.
        let rb = arg[lb..].find(']')? + lb;
        arg[rb + 1..].find(':')? + rb + 1
    } else {
        let c = arg.find(':')?;
        // A '/' before the ':' means it's a local path.
        if matches!(arg.find('/'), Some(slash) if slash < c) {
            return None;
        }
        c
    };
    let host = arg[..colon].to_string();
    let path = &arg[colon + 1..];
    let path = if path.is_empty() { "." } else { path };
    Some((host, path.to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match (parse_remote(&cli.src), parse_remote(&cli.dst)) {
        (Some((host, rpath)), None) => download(&cli, &host, &rpath).await,
        (None, Some((host, rpath))) => upload(&cli, &host, &rpath).await,
        (Some(_), Some(_)) => bail!("both SRC and DST are remote; exactly one must be remote"),
        (None, None) => {
            bail!("neither SRC nor DST is remote; exactly one must be a [user@]host:path spec")
        }
    }
}

async fn connect(cli: &Cli, host: &str) -> Result<SftpClient> {
    let cfg = ClientConfig::resolve(
        host,
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
    sqsh::sftp::connect(&cfg).await
}

// ---- download (remote SRC -> local DST) --------------------------------------

async fn download(cli: &Cli, host: &str, rpath: &str) -> Result<()> {
    let client = connect(cli, host).await?;
    let res = download_inner(cli, &client, rpath).await;
    client.close().await;
    res
}

async fn download_inner(cli: &Cli, client: &SftpClient, rpath: &str) -> Result<()> {
    let md = client
        .sftp
        .fs()
        .metadata(rpath)
        .await
        .with_context(|| format!("stat remote {rpath}"))?;
    let is_dir = md.file_type().map(|t| t.is_dir()).unwrap_or(false);

    let dst = Path::new(&cli.dst);
    let dst_is_dir = dst.is_dir();

    if is_dir {
        if !cli.recursive {
            bail!("{rpath}: omitting directory (use -r)");
        }
        let root = if dst_is_dir {
            dst.join(remote_basename(client, rpath).await?)
        } else {
            dst.to_path_buf()
        };
        download_tree(client, rpath, &root).await
    } else {
        let local = if dst_is_dir {
            dst.join(remote_basename(client, rpath).await?)
        } else {
            dst.to_path_buf()
        };
        download_file(client, rpath, &local).await
    }
}

async fn download_tree(client: &SftpClient, remote_root: &str, local_root: &Path) -> Result<()> {
    let mut fs = client.sftp.fs();
    let mut work: Vec<(PathBuf, PathBuf)> =
        vec![(PathBuf::from(remote_root), local_root.to_path_buf())];

    while let Some((rdir, ldir)) = work.pop() {
        tokio::fs::create_dir_all(&ldir)
            .await
            .with_context(|| format!("create local dir {}", ldir.display()))?;

        let mut files: Vec<(PathBuf, PathBuf)> = Vec::new();
        {
            let rd = fs
                .open_dir(&rdir)
                .await
                .with_context(|| format!("open remote dir {}", rdir.display()))?
                .read_dir();
            tokio::pin!(rd);
            while let Some(ent) = rd.next().await {
                let ent = ent?;
                let name = ent.filename().to_path_buf();
                if matches!(name.to_str(), Some("." | "..")) {
                    continue;
                }
                let rchild = rdir.join(&name);
                let lchild = ldir.join(&name);
                if ent.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    work.push((rchild, lchild));
                } else {
                    files.push((rchild, lchild));
                }
            }
        }
        for (rchild, lchild) in files {
            download_file(client, &rchild.to_string_lossy(), &lchild).await?;
        }
    }
    Ok(())
}

async fn download_file(client: &SftpClient, remote: &str, local: &Path) -> Result<()> {
    let mut rf = client
        .sftp
        .open(remote)
        .await
        .with_context(|| format!("open remote {remote}"))?;
    let mut out = tokio::fs::File::create(local)
        .await
        .with_context(|| format!("create local {}", local.display()))?;
    loop {
        let buf = bytes::BytesMut::with_capacity(CHUNK);
        match rf.read(CHUNK as u32, buf).await? {
            Some(d) if !d.is_empty() => out.write_all(&d).await?,
            _ => break,
        }
    }
    out.flush().await?;
    rf.close().await?;
    eprintln!("sqcp: {remote} -> {}", local.display());
    Ok(())
}

// ---- upload (local SRC -> remote DST) ----------------------------------------

async fn upload(cli: &Cli, host: &str, rpath: &str) -> Result<()> {
    let client = connect(cli, host).await?;
    let res = upload_inner(cli, &client, rpath).await;
    client.close().await;
    res
}

async fn upload_inner(cli: &Cli, client: &SftpClient, rpath: &str) -> Result<()> {
    let src = Path::new(&cli.src);
    let meta = tokio::fs::metadata(src)
        .await
        .with_context(|| format!("stat local {}", src.display()))?;

    let rdst_is_dir = match client.sftp.fs().metadata(rpath).await {
        Ok(m) => m.file_type().map(|t| t.is_dir()).unwrap_or(false),
        Err(_) => false,
    };
    let remote_target = |base_needed: bool| -> Result<String> {
        if base_needed {
            let base = src
                .file_name()
                .context("cannot determine local basename")?
                .to_string_lossy();
            Ok(PathBuf::from(rpath)
                .join(&*base)
                .to_string_lossy()
                .into_owned())
        } else {
            Ok(rpath.to_string())
        }
    };

    if meta.is_dir() {
        if !cli.recursive {
            bail!("{}: omitting directory (use -r)", src.display());
        }
        let root = remote_target(rdst_is_dir)?;
        upload_tree(client, src, &root).await
    } else {
        let remote = remote_target(rdst_is_dir)?;
        upload_file(client, src, &remote).await
    }
}

async fn upload_tree(client: &SftpClient, local_root: &Path, remote_root: &str) -> Result<()> {
    ensure_remote_dir(client, remote_root).await?;
    let mut work: Vec<(PathBuf, PathBuf)> =
        vec![(local_root.to_path_buf(), PathBuf::from(remote_root))];

    while let Some((ldir, rdir)) = work.pop() {
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        let mut rd = tokio::fs::read_dir(&ldir)
            .await
            .with_context(|| format!("read local dir {}", ldir.display()))?;
        while let Some(ent) = rd.next_entry().await? {
            let name = ent.file_name();
            let lchild = ldir.join(&name);
            let rchild = rdir.join(&name);
            let rchild_s = rchild.to_string_lossy().into_owned();
            if ent.file_type().await?.is_dir() {
                ensure_remote_dir(client, &rchild_s).await?;
                work.push((lchild, rchild));
            } else {
                files.push((lchild, rchild_s));
            }
        }
        for (lchild, rchild_s) in files {
            upload_file(client, &lchild, &rchild_s).await?;
        }
    }
    Ok(())
}

async fn upload_file(client: &SftpClient, local: &Path, remote: &str) -> Result<()> {
    let mut inp = tokio::fs::File::open(local)
        .await
        .with_context(|| format!("open local {}", local.display()))?;
    let mut wf = client
        .sftp
        .create(remote)
        .await
        .with_context(|| format!("create remote {remote}"))?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = inp.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        wf.write_all(&buf[..n]).await?;
    }
    wf.close().await?;
    eprintln!("sqcp: {} -> {remote}", local.display());
    Ok(())
}

/// `create_dir` that tolerates an already-existing directory (idempotent recursion).
async fn ensure_remote_dir(client: &SftpClient, path: &str) -> Result<()> {
    let mut fs = client.sftp.fs();
    if let Err(e) = fs.create_dir(path).await {
        // ponytail: no typed "already exists" error here, so confirm via stat;
        // a real dir means success, anything else propagates the create error.
        match fs.metadata(path).await {
            Ok(m) if m.file_type().map(|t| t.is_dir()).unwrap_or(false) => {}
            _ => return Err(e).with_context(|| format!("mkdir remote {path}")),
        }
    }
    Ok(())
}

/// Last path component of a remote path, falling back to canonicalization
/// (handles `.` / `/` where `file_name()` is `None`).
async fn remote_basename(client: &SftpClient, rpath: &str) -> Result<String> {
    if let Some(name) = Path::new(rpath).file_name() {
        return Ok(name.to_string_lossy().into_owned());
    }
    let real = client.sftp.fs().canonicalize(rpath).await?;
    real.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .context("cannot determine remote basename")
}

#[cfg(test)]
mod tests {
    use super::parse_remote;

    fn r(s: &str) -> Option<(String, String)> {
        parse_remote(s)
    }
    fn some(h: &str, p: &str) -> Option<(String, String)> {
        Some((h.to_string(), p.to_string()))
    }

    #[test]
    fn user_host_abs_path() {
        assert_eq!(r("user@host:/a/b"), some("user@host", "/a/b"));
    }

    #[test]
    fn host_rel_path() {
        assert_eq!(r("host:rel"), some("host", "rel"));
    }

    #[test]
    fn host_empty_path_is_home() {
        assert_eq!(r("host:"), some("host", "."));
    }

    #[test]
    fn local_slash_before_colon() {
        assert_eq!(r("./local:name"), None);
    }

    #[test]
    fn local_absolute() {
        assert_eq!(r("/abs/path"), None);
    }

    #[test]
    fn ipv6_host() {
        assert_eq!(r("[::1]:/p"), some("[::1]", "/p"));
    }

    #[test]
    fn user_at_ipv6_host() {
        assert_eq!(r("me@[::1]:/p"), some("me@[::1]", "/p"));
    }
}
