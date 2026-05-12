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
    # Install client binaries (qssh + qssh-bootstrap)
    system "cargo", "install", *std_cargo_args(path: "crates/qssh")
    # Install server daemon (qsshd)
    system "cargo", "install", *std_cargo_args(path: "crates/qsshd")

    # Install a default qsshd config into #{etc}/qssh/ on first install.
    (etc/"qssh").mkpath
    config = etc/"qssh/qsshd.toml"
    config.write <<~EOS unless config.exist?
      bind_addr = "0.0.0.0"
      port = 2222
      host_key = "#{etc}/qssh/host.key"
      host_cert = "#{etc}/qssh/host.cert"
      authorized_keys = "#{etc}/qssh/authorized_keys"
    EOS
  end

  # `brew services start squish` runs qsshd as a launchd daemon.
  service do
    run [opt_bin/"qsshd", "--config", etc/"qssh/qsshd.toml"]
    keep_alive true
    log_path var/"log/qsshd.log"
    error_log_path var/"log/qsshd.log"
  end

  test do
    assert_match "QSSH client", shell_output("#{bin}/qssh --help")
    assert_match "QSSH server daemon", shell_output("#{bin}/qsshd --help")
    assert_match "qssh-bootstrap", shell_output("#{bin}/qssh-bootstrap --help")
  end
end
