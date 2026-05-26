# Client features

## CLI surface

`qssh` currently supports:

```text
qssh [OPTIONS] <TARGET> [COMMAND]...
```

Important options:

- `-p, --port <PORT>` — override the remote QUIC port.
- `-l, --user <USER>` — override the remote user.
- `-i, --identity <PATH>` — override the ML-DSA-65 private-key seed file.
- `-L <SPEC>` — local TCP forwarding.
- `-R <SPEC>` — remote TCP forwarding.
- `-N` — set up forwarding only; do not start a shell.
- `-S, --control-path <PATH>` — choose the local control socket path.
- `-M, --control-master` — run as the local master for that target.
- `--control-persist [DURATION]` — keep a master alive after client sessions disconnect.

Target format:

- `[user@]host[:port]`
- IPv6 literals use `[addr]:port`

## Session modes

`qssh` supports three main client modes:

1. interactive shell when no command is given,
2. remote exec when a command is given,
3. forwarding-only mode with `-N`.

Interactive sessions request a PTY, enable raw mode locally, propagate window-size changes, and restore cooked terminal mode on exit.

## Port forwarding

### Local forwarding

`-L [bind_addr:]local_port:host:remote_port`

The client listens locally, opens a `direct-tcpip` channel over QUIC, and the server connects to `host:remote_port` on the remote side.

### Remote forwarding

`-R [bind_addr:]remote_port:host:local_port`

The client asks the server to listen remotely. Each accepted TCP connection is carried back to the client over a `forwarded-tcpip` channel and then proxied into the local target.

## Host verification

The client uses trust-on-first-use pinning for the server TLS certificate fingerprint.

- pins are stored in `~/.config/qssh/known_hosts`,
- keys are stored by `host:port`,
- first contact records the presented fingerprint,
- later changes are rejected until the pin is updated manually.

This is not OpenSSH host-key parsing; it is Squish-specific fingerprint storage.

## Connection migration

After the QUIC connection is established, the client starts a network-change monitor.

Current behavior:

- watches local interface/address changes,
- skips loopback addresses,
- skips IPv6 link-local addresses unless the endpoint is already IPv6-bound,
- rebinds the local UDP socket and lets QUIC migrate the live connection.

This is the mechanism that lets long-running tunnels survive client network changes better than a plain TCP SSH transport.

## ControlMaster-style reuse

The client has a local master/slave model backed by a Unix-domain control socket.

### Explicit master

Use `-M` to run a master process for a target:

```text
qssh -M target
```

That process owns one authenticated QUIC connection and serves later local client requests through the control socket.

### Control path

Use `-S` to choose the control socket path explicitly. If not set, `qssh` generates a short hashed path under:

```text
~/.config/qssh/control/
```

### ControlPersist

`--control-persist` accepts:

- `yes`
- `no`
- raw seconds, for example `300`
- suffixed durations like `30s`, `5m`, `1h`

When enabled, `qssh` can start and reuse a background master automatically and keep it alive after client sessions disconnect.

### Current supported behavior from ssh config

`ControlPath`, `ControlMaster`, and `ControlPersist` are read from `~/.ssh/config` when present.

Current semantics are:

- `ControlPath` influences which local control socket is used,
- `ControlMaster` enables master-aware client behavior for that host,
- `ControlPersist` enables automatic background master startup and linger time,
- `-M` is still the explicit way to start a foreground master.

## `~/.ssh/config` support

The client reads per-host config from `~/.ssh/config` and ignores unsupported keys.

Supported keys:

- `Host`
- `HostName`
- `User`
- `Port`
- `IdentityFile`
- `LocalForward`
- `RemoteForward`
- `ControlPath`
- `ControlMaster`
- `ControlPersist`

Behavior:

- host matching supports `*`, `?`, and negated patterns such as `!blocked.example`,
- scalar values follow OpenSSH's first-match-wins behavior,
- CLI scalar options override ssh-config scalar values,
- forwarding rules from ssh config are loaded first and CLI forwarding rules are appended,
- unsupported keys are ignored.

Supported path substitutions in `IdentityFile` and `ControlPath`:

- `~`
- `%h` resolved host name
- `%n` original host token from the command line
- `%p` resolved port
- `%r` resolved remote user
- `%%`

## Authentication

User authentication is based on an ML-DSA-65 keypair derived from a 32-byte seed file.

The client signs a server challenge that is bound to:

- the server certificate fingerprint,
- the user name,
- the challenge nonce,
- the current time.

If public-key authentication is rejected, the client currently has a fallback path that uses the system `ssh` binary to append the generated public key to the remote user's `~/.squish/authorized_keys`, then retries.

## Examples

Interactive shell:

```text
qssh alice@example.com
```

Run one command:

```text
qssh alice@example.com uname -a
```

Local forwarding only:

```text
qssh -N -L 15432:127.0.0.1:5432 alice@example.com
```

Remote forwarding:

```text
qssh -R 8080:127.0.0.1:8080 alice@example.com
```

Start a master and keep it around for five minutes after the last client disconnects:

```text
qssh -M --control-persist 5m alice@example.com
```
