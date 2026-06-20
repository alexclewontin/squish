class Squish < Formula
  desc "Post-quantum SSH over QUIC (ML-DSA-65 auth, ML-KEM key exchange)"
  homepage "https://github.com/alexclewontin/squish"
  license "GPL-3.0-only"

  # Fill in url + sha256 at release time:
  #   url "https://github.com/alexclewontin/squish/archive/refs/tags/v0.1.0.tar.gz"
  #   sha256 "..."
  head "https://github.com/alexclewontin/squish.git", branch: "main"

  depends_on "cmake" => :build  # required by aws-lc-rs (TLS crypto)
  depends_on "rust" => :build

  def install
    # Install client binaries (sqsh, sqsh-keygen, sqsh-bootstrap)
    system "cargo", "install", *std_cargo_args(path: "crates/sqsh")
    # Install server daemon (sqshd)
    system "cargo", "install", *std_cargo_args(path: "crates/sqshd")

    # Install a default sqshd config into #{etc}/sqsh/ on first install.
    (etc/"sqsh").mkpath
    config = etc/"sqsh/sqshd.toml"
    config.write <<~EOS unless config.exist?
      bind_addr = "0.0.0.0"
      port = 2222
      host_key = "#{etc}/sqsh/host.key"
      host_cert = "#{etc}/sqsh/host.cert"
    EOS
  end

  # `brew services start squish` runs sqshd as a launchd daemon.
  service do
    run [opt_bin/"sqshd", "--config", etc/"sqsh/sqshd.toml"]
    keep_alive true
    log_path var/"log/sqshd.log"
    error_log_path var/"log/sqshd.log"
  end

  test do
    assert_match "SQSH client", shell_output("#{bin}/sqsh --help")
    assert_match "SQSH server daemon", shell_output("#{bin}/sqshd --help")
    assert_match "ML-DSA-65", shell_output("#{bin}/sqsh-keygen --help")
    assert_match "Bootstrap", shell_output("#{bin}/sqsh-bootstrap --help")
    assert_match "scp-like file copy", shell_output("#{bin}/sqcp --help")
    assert_match "Interactive SFTP", shell_output("#{bin}/sqftp --help")
  end
