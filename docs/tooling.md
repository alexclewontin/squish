# Bootstrap and key-management tooling

## `qssh-keygen`

`qssh-keygen` manages the user's ML-DSA-65 identity material.

### What it stores

The private identity file is a 32-byte ML-DSA-65 seed. The full signing keypair is derived from that seed when needed.

Default location:

```text
~/.config/qssh/id_ml_dsa_65
```

### Commands

Generate a new identity and print the public authorized-keys line:

```text
qssh-keygen
```

Write to a specific file:

```text
qssh-keygen -f /path/to/id_ml_dsa_65
```

Print the public key for an existing identity without regenerating it:

```text
qssh-keygen -y -f /path/to/id_ml_dsa_65
```

### Current behavior

- refuses to overwrite an existing key file,
- creates parent directories when needed,
- sets mode `0600` on Unix,
- prints a Squish authorized-keys line suitable for `~/.squish/authorized_keys`.

## `qssh-bootstrap`

`qssh-bootstrap` installs and starts `qsshd` on a remote host by using an existing traditional SSH connection for the first hop.

### CLI surface

```text
qssh-bootstrap [OPTIONS] <TARGET>
```

Important options:

- `--ssh-port <PORT>` — SSH port for the bootstrap connection, default `22`
- `--qsshd-port <PORT>` — resulting `qsshd` QUIC port, default `2222`
- `-u, --user <USER>` — override SSH login user
- `--squishd-version <VERSION>` — install a specific GitHub release
- `-i, --identity <PATH>` — use or create a specific local ML-DSA-65 identity

### What bootstrap currently does

For a target host, bootstrap performs the following sequence:

1. detects the remote OS and architecture,
2. downloads and installs `qsshd` from GitHub Releases if it is not already present,
3. writes the server config,
4. writes the user's Squish authorized key,
5. installs and starts the service,
6. emits the server certificate fingerprint,
7. pins that fingerprint into the local Squish known-hosts file.

### Outputs and side effects

On the local machine:

- uses or creates `~/.config/qssh/id_ml_dsa_65` unless overridden,
- updates `~/.config/qssh/known_hosts`.

On the remote machine:

- installs the `qsshd` binary,
- writes `/etc/qssh/qsshd.toml`,
- sets up the daemon/service integration,
- starts the service.

## Bootstrap and the trust model

Bootstrap exists to bridge from a normal SSH-managed machine into the Squish transport model.

After bootstrap:

- user authentication is handled by Squish ML-DSA-65 keys,
- server identity is pinned by the Squish known-hosts fingerprint,
- later access can use `qssh` directly over QUIC.
