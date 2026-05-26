# Server features

## CLI surface

`qsshd` currently supports:

```text
qsshd [OPTIONS]
```

Options:

- `-c, --config <PATH>` — path to the TOML config file.
- `--emit-fingerprint` — print the SHA-256 fingerprint of the configured server certificate and exit.

Default config path:

```text
/etc/qssh/qsshd.toml
```

## Configuration file

Current fields:

- `bind_addr` — default `0.0.0.0`
- `port` — default `2222`
- `host_key` — path to the TLS private key
- `host_cert` — path to the TLS certificate
- `max_connections` — default `100`
- `idle_timeout_secs` — default `300`

Minimal example:

```toml
bind_addr = "0.0.0.0"
port = 2222
host_key = "/etc/qssh/host.key"
host_cert = "/etc/qssh/host.cert"
```

## Authentication model

The server uses a two-stage model:

1. QUIC/TLS provides transport security and a presented server certificate.
2. Squish control-stream authentication proves possession of the user's ML-DSA-65 private key.

For user authentication the server:

- receives `ClientHello`,
- sends a random challenge nonce,
- checks the presented public key against the target user's `~/.squish/authorized_keys`,
- rebuilds the signed challenge payload,
- verifies the ML-DSA-65 signature,
- only then opens the session.

Authorized keys are scoped to the requested remote user. A key is only valid if it appears in that user's authorized key file.

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
- window-size changes,
- signals,
- stdout/stderr separation,
- explicit exit-status reporting.

The session implementation launches the child process under the target account, creates a PTY when needed, and relays bytes between the PTY/process and the QUIC stream.

## Port forwarding

### Direct TCP/IP

When the client requests local forwarding, the server accepts a `direct-tcpip` channel, connects to the requested remote-side target, and relays data.

### Remote forwarding

When the client requests remote forwarding, the server:

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

## Operational notes

- `qsshd` is packaged to run as a service.
- Debian packaging includes a `qsshd.service` unit.
- Homebrew packaging exposes a `brew services` definition.
- `qssh-bootstrap` writes the config, installs service files, starts the daemon, and records the certificate fingerprint locally.
