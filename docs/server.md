# Server features

## CLI surface

`sqshd` currently supports:

```text
sqshd [OPTIONS]
```

Options:

- `-c, --config <PATH>` — path to the TOML config file.
- `--emit-fingerprint` — print the SHA-256 fingerprint of the live certificate loaded at startup and exit.

Default config path:

```text
/etc/sqsh/sqshd.toml
```

## Configuration file

Current fields:

- `bind_addr` — default `0.0.0.0`
- `port` — default `2222`
- `host_key` — path to the TLS private key
- `host_cert` — path to the TLS certificate
- `max_connections` — default `100`
- `idle_timeout_secs` — default `300`
- `direct_tcpip_allowlist` — default `[]`; exact-match `"host:port"` allowlist for `direct-tcpip` opens
- `remote_forward_allowlist` — default `[]`; exact-match `"bind_addr:bind_port"` exceptions for non-loopback remote forwards
- `max_channels_per_connection` — default `32`
- `max_remote_forwards_per_connection` — default `8`
- `accept_env` — default `["LANG", "LC_*"]`; client environment variables the server applies (exact name or trailing-`*` prefix), set before the fixed identity env so identity always wins
- `subsystems` — default `{}`; map of subsystem name to command line. `sftp` is auto-detected from common `sftp-server` paths when not configured

Minimal example:

```toml
bind_addr = "0.0.0.0"
port = 2222
host_key = "/etc/sqsh/host.key"
host_cert = "/etc/sqsh/host.cert"

# Deny-by-default for direct-tcpip; add exact host:port entries to permit.
direct_tcpip_allowlist = ["127.0.0.1:5432"]

# Remote forwards are loopback-only by default; add exact bind exceptions when needed.
remote_forward_allowlist = ["0.0.0.0:22222"]

# Per authenticated connection.
max_channels_per_connection = 32
max_remote_forwards_per_connection = 8

# Environment variables accepted from the client (exact name or trailing-* prefix).
accept_env = ["LANG", "LC_*"]

# Subsystems: name -> command line. `sftp` auto-detects sftp-server when omitted.
[subsystems]
sftp = "/usr/lib/openssh/sftp-server"
```

## Host key and certificate files

When `host_key`/`host_cert` do not exist, `sqshd` generates them at startup.

On Unix:
- the parent directory is created with mode `0700` when `sqshd` creates it,
- the new private key file is created owner-only with mode `0600` from first open (no write-then-chmod window).


## Authentication model

The server uses a two-stage model:

1. QUIC/TLS provides transport security and a presented server certificate.
2. Squish control-stream authentication proves possession of the user's ML-DSA-65 private key.

For user authentication the server:

- receives `ClientHello`,
- sends a random challenge nonce,
- checks the presented public key against the target user's `~/.squish/authorized_keys`,
- rebuilds the signed challenge payload (`SHA-512("sqsh-auth-challenge-v1" || nonce || server_cert_fingerprint || username_len_le_u16 || username_bytes)`),
- verifies the ML-DSA-65 signature,
- only then opens the session.

Authorized keys are scoped to the requested remote user. A key is only valid if it appears in that user's authorized key file, and each accepted line must use the exact `ml-dsa-65` key type.
The certificate fingerprint used in the signed auth challenge is cached from the exact certificate DER passed into rustls at startup; it is not re-read from `host_cert` during authentication.

## Authorized keys safety checks

Before reading `~/.squish/authorized_keys`, the server verifies:

- the file exists or else treats it as an empty key list,
- the file owner is the target user or root,
- the file is not group-writable or world-writable.

If those checks fail, the file is rejected.

## Session handling

Session channels support:

- PTY allocation,
- interactive shells,
- remote exec requests,
- subsystem requests (no PTY; stderr returned as extended data),
- allow-listed environment variables (locale by default),
- window-size changes,
- signals,
- stdout/stderr separation,
- explicit exit-status reporting.

The session implementation launches the child process under the target account, creates a PTY when needed, and relays bytes between the PTY/process and the QUIC stream.

## Port forwarding

### Direct TCP/IP

`direct-tcpip` is deny-by-default.

A request is accepted only when its exact `host:port` appears in `direct_tcpip_allowlist`.
No wildcard syntax is supported.

Unauthorized requests are rejected with channel open failure.

### Remote forwarding

Remote forwarding requests are loopback-only by default (`127.0.0.1`, `::1`, or `localhost`).

Non-loopback binds are accepted only when the exact `bind_addr:bind_port` appears in `remote_forward_allowlist`.
No wildcard syntax is supported.

Per authenticated connection, the server also enforces `max_remote_forwards_per_connection`.
Rejected requests return `TcpForwardFailure`.

When accepted, the server:

- binds a TCP listener on the remote machine,
- accepts inbound TCP connections,
- opens a `forwarded-tcpip` stream back to the client for each connection,
- relays data until either side closes.

The control stream also supports cancellation of remote forwards.

## Connection lifecycle

Per connection, the server uses:

- one initial bidirectional stream as the control stream,
- additional bidirectional streams as independent channels,
- a dispatcher that routes each new channel by type.

Current channel types:

- `session`
- `direct-tcpip`
- `forwarded-tcpip`

Per authenticated connection, channel opens are capped by `max_channels_per_connection`.
Over-limit opens are rejected with channel open failure.

## Operational notes

- `sqshd` is packaged to run as a service.
- Debian packaging includes a `sqshd.service` unit.
- Homebrew packaging exposes a `brew services` definition.
- `sqsh-bootstrap` writes the config, installs service files, starts the daemon, and records the certificate fingerprint locally.
