# Bootstrap and key-management tooling

## `sqsh-keygen`

`sqsh-keygen` manages the user's ML-DSA-65 identity material.

### What it stores

The private identity file is a 32-byte ML-DSA-65 seed. The full signing keypair is derived from that seed when needed.

Default location:

```text
~/.config/sqsh/id_ml_dsa_65
```

### Commands

Generate a new identity and print the public authorized-keys line:

```text
sqsh-keygen
```

Write to a specific file:

```text
sqsh-keygen -f /path/to/id_ml_dsa_65
```

Print the public key for an existing identity without regenerating it:

```text
sqsh-keygen -y -f /path/to/id_ml_dsa_65
```

### Current behavior

- refuses to overwrite an existing key file,
- creates parent directories when needed (mode `0700` on Unix),
- creates new key files as mode `0600` on Unix from the initial open,
- rejects key files that are accessible by group/other,
- prints a Squish authorized-keys line suitable for `~/.squish/authorized_keys`.
## `sqsh-bootstrap`

`sqsh-bootstrap` installs and starts `sqshd` on a remote host by using an existing traditional SSH connection for the first hop.

### CLI surface

```text
sqsh-bootstrap [OPTIONS] <TARGET>
```

Important options:

- `--ssh-port <PORT>` — SSH port for the bootstrap connection, default `22`
- `--sqshd-port <PORT>` — resulting `sqshd` QUIC port, default `2222`
- `-u, --user <USER>` — override SSH login user
- `--squishd-version <VERSION>` — install a specific GitHub release
- `-i, --identity <PATH>` — use or create a specific local ML-DSA-65 identity

### What bootstrap currently does

For a target host, bootstrap performs the following sequence:

1. detects the remote OS and architecture,
2. downloads the matching release assets locally,
3. verifies the signed `SHA256SUMS` manifest against the embedded release-signing key and checks the tarball digest,
4. uploads the verified `sqshd` binary and installs it remotely,
5. writes the server config,
6. writes the user's Squish authorized key,
7. installs and starts the service,
8. emits the server certificate fingerprint,
9. pins that fingerprint into the local Squish known-hosts file.

### Outputs and side effects

On the local machine:

- uses or creates `~/.config/sqsh/id_ml_dsa_65` unless overridden (directory `0700`, key file `0600` on Unix),
- updates `~/.config/sqsh/known_hosts` (rejects group/other-accessible files on load; saved as `0600` on Unix).
On the remote machine:

- installs the `sqshd` binary,
- writes `/etc/sqsh/sqshd.toml`,
- sets up the daemon/service integration,
- starts the service.
- expects GitHub Releases to publish `SHA256SUMS` and `SHA256SUMS.minisig` alongside the tarballs.

## Bootstrap and the trust model

Bootstrap exists to bridge from a normal SSH-managed machine into the Squish transport model.

After bootstrap:

- user authentication is handled by Squish ML-DSA-65 keys,
- server identity is pinned by the Squish known-hosts fingerprint,
- later access can use `sqsh` directly over QUIC.
