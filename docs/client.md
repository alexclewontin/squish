# Client features

## CLI surface

`sqsh` currently supports:

```text
sqsh [OPTIONS] <TARGET> [COMMAND]...
```

Important options:

- `-p, --port <PORT>` — override the remote QUIC port.
- `-l, --user <USER>` — override the remote user.
- `-i, --identity <PATH>` — override the ML-DSA-65 private-key seed file.
- `-L <SPEC>` — local TCP forwarding.
- `-R <SPEC>` — remote TCP forwarding.
- `-N` — set up forwarding only; do not start a shell.
- `-s, --subsystem <NAME>` — invoke a subsystem (e.g. `sftp`) instead of a shell or command.
- `-S, --control-path <PATH>` — choose the local control socket path.
- `-M, --control-master` — run as the local master for that target.
- `--control-persist [DURATION]` — keep a master alive after client sessions disconnect.
- `--ssh-port <PORT>` — SSH port to use if sqsh must fall back to installing your public key over SSH.

Target format:

- `[user@]host[:port]`
- IPv6 literals use `[addr]:port`

## Session modes

`sqsh` supports four main client modes:

1. interactive shell when no command is given,
2. remote exec when a command is given,
3. forwarding-only mode with `-N`.
4. subsystem mode with `-s NAME` (e.g. `sftp`), run without a PTY.

Interactive sessions request a PTY, enable raw mode locally, propagate window-size changes, and restore cooked terminal mode on exit.

Locale environment variables (`LANG` and `LC_*`) are forwarded to the remote session so terminal programs render correctly; the server applies them only if they pass its `accept_env` allow-list.

## Port forwarding

### Local forwarding

`-L [bind_addr:]local_port:host:remote_port`

The client listens locally, opens a `direct-tcpip` channel over QUIC, and the server connects to `host:remote_port` on the remote side.

### Remote forwarding

`-R [bind_addr:]remote_port:host:local_port`

The client asks the server to listen remotely. Each accepted TCP connection is carried back to the client over a `forwarded-tcpip` channel and then proxied into the local target.

## Host verification

The client uses trust-on-first-use pinning for the server TLS certificate fingerprint.

- pins are stored in `~/.config/sqsh/known_hosts`,
- keys are stored by `host:port`,
- first contact records the presented fingerprint,
- later changes are rejected until the pin is updated manually,
- group/other-accessible `known_hosts` files are rejected on Unix.

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
sqsh -M target
```

That process owns one authenticated QUIC connection and serves later local client requests through the control socket.

### Control path

Use `-S` to choose the control socket path explicitly. If not set, `sqsh` generates a short hashed path under:

```text
~/.config/sqsh/control/
```

### ControlPersist

`--control-persist` accepts:

- `yes`
- `no`
- raw seconds, for example `300`
- suffixed durations like `30s`, `5m`, `1h`

When enabled, `sqsh` can start and reuse a background master automatically and keep it alive after client sessions disconnect.

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

The client signs a server challenge payload defined as:

- `SHA-512("sqsh-auth-challenge-v1" || nonce || server_cert_fingerprint || username_len_le_u16 || username_bytes)`

This binds the proof to:

- the server certificate fingerprint,
- the user name (length-prefixed),
- the challenge nonce.

If public-key authentication is rejected, the client currently has a fallback path that uses the system `ssh` binary to append the generated public key to the remote user's `~/.squish/authorized_keys`, then retries.

## File transfer

Two companion binaries move files over the same authenticated QUIC transport, using the server's `sftp` subsystem (the daemon execs the OS `sftp-server`).

### `sqcp`

scp-style one-shot copy. Exactly one of source/destination is remote, written `[user@]host:path`:

```text
sqcp [-r] [-i identity] [-P port] <src> <dst>
```

- upload: `sqcp ./local.txt alice@example.com:/srv/local.txt`
- download: `sqcp alice@example.com:/srv/data.bin ./data.bin`
- recursive directory copy with `-r`
- if the destination is an existing directory, the source basename is appended

### `sqftp`

Interactive client, like OpenSSH `sftp`:

```text
sqftp [-i identity] [-P port] [user@]host
```

Commands: `ls`, `cd`, `pwd`, `get`, `put`, `mkdir`, `rmdir`, `rm`, `rename`, local `lls`/`lcd`/`lpwd`, `help`, and `quit` (also `exit`/`bye`). A failed command reports the error and keeps the session open.

Both require an `sftp-server` binary on the server; `sqshd` auto-detects the common locations or honors an explicit `[subsystems]` entry.

## Examples

Interactive shell:

```text
sqsh alice@example.com
```

Run one command:

```text
sqsh alice@example.com uname -a
```

Invoke the raw `sftp` subsystem directly (normally you would use `sqftp`/`sqcp` instead — see File transfer above):

```text
sqsh -s sftp alice@example.com
```

Local forwarding only:

```text
sqsh -N -L 15432:127.0.0.1:5432 alice@example.com
```

Remote forwarding:

```text
sqsh -R 8080:127.0.0.1:8080 alice@example.com
```

Start a master and keep it around for five minutes after the last client disconnects:

```text
sqsh -M --control-persist 5m alice@example.com
```
