# Squish documentation

This directory documents the project as it exists today.

## Components

- `qssh` — the interactive and non-interactive client.
- `qsshd` — the QUIC-based server daemon.
- `qssh-keygen` — ML-DSA-65 key generation and public-key export.
- `qssh-bootstrap` — remote installer for `qsshd` over an existing SSH connection.
- `qssh-core` — shared protocol, framing, and authentication types.

## Feature map

- [Client features](client.md)
- [Server features](server.md)
- [Bootstrap and key management](tooling.md)
- [Protocol and transport](protocol.md)

## High-level summary

Squish is an SSH-like remote access system built on QUIC instead of TCP. The current implementation provides:

- authenticated client/server sessions using ML-DSA-65 user keys,
- trust-on-first-use pinning of the server TLS certificate fingerprint,
- interactive shell sessions and remote command execution,
- local and remote TCP port forwarding,
- QUIC connection migration when the client network changes,
- local ControlMaster-style connection reuse,
- per-host configuration from `~/.ssh/config` for supported keys,
- remote bootstrap of the server daemon and local host pinning.

## Defaults and paths

Client-side defaults:

- identity: `~/.config/qssh/id_ml_dsa_65`
- known hosts: `~/.config/qssh/known_hosts`
- generated control sockets: `~/.config/qssh/control/`

Server-side defaults:

- listen address: `0.0.0.0`
- listen port: `2222`
- sample config path: `/etc/qssh/qsshd.toml`
- authorized keys path per user: `~/.squish/authorized_keys`
