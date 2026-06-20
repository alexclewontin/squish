# SQUISH

SQUISH (Secure QUIC Shell) is an SSH-like remote access system built on QUIC instead of TCP. The current implementation provides:

- authenticated client/server sessions using ML-DSA-65 user keys,
- trust-on-first-use pinning of the server TLS certificate fingerprint,
- interactive shell sessions and remote command execution,
- local and remote TCP port forwarding,
- QUIC connection migration when the client network changes,
- local ControlMaster-style connection reuse,
- SFTP file transfer via `sqcp` and `sqftp`,
- per-host configuration from `~/.ssh/config` for supported keys,
- remote bootstrap of the server daemon and local host pinning.

## Components

- `sqsh` — the interactive and non-interactive client.
- `sqshd` — the QUIC-based server daemon.
- `sqsh-keygen` — ML-DSA-65 key generation and public-key export.
- `sqsh-bootstrap` — remote installer for `sqshd` over an existing SSH connection.
- `sqcp` — scp-style one-shot file copy over the SFTP subsystem.
- `sqftp` — interactive SFTP client.
- `sqsh-core` — shared protocol, framing, and authentication types.

## Feature map

- [Client features](client.md)
- [Server features](server.md)
- [Bootstrap and key management](tooling.md)
- [Protocol and transport](protocol.md)

## Defaults and paths

Client-side defaults:

- identity: `~/.config/sqsh/id_ml_dsa_65`
- known hosts: `~/.config/sqsh/known_hosts`
- generated control sockets: `~/.config/sqsh/control/`

Server-side defaults:

- listen address: `0.0.0.0`
- listen port: `2222`
- sample config path: `/etc/sqsh/sqshd.toml`
- authorized keys path per user: `~/.squish/authorized_keys`
