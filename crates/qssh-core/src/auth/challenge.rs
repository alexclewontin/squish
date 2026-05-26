use sha2::{Digest, Sha512};

/// Construct the challenge payload that gets signed during authentication.
///
/// The signature covers:
///   SHA-512(
///     "qssh-auth-challenge-v1" ||
///     nonce ||
///     server_cert_fingerprint ||
///     username_len_le_u16 ||
///     username_bytes
///   )
///
/// This binds the auth to a specific TLS session (cert fingerprint),
/// prevents replay across challenge nonces, and prevents cross-user replay
/// (username).
pub fn build_challenge_payload(
    nonce: &[u8; 32],
    server_cert_fingerprint: &[u8; 32],
    username: &str,
) -> [u8; 64] {
    const DOMAIN_SEPARATOR: &[u8] = b"qssh-auth-challenge-v1";

    let username_bytes = username.as_bytes();
    let username_len = u16::try_from(username_bytes.len())
        .expect("username length must fit in u16 for challenge encoding");

    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(nonce);
    hasher.update(server_cert_fingerprint);
    hasher.update(username_len.to_le_bytes());
    hasher.update(username_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let nonce = [1u8; 32];
        let fingerprint = [2u8; 32];
        let a = build_challenge_payload(&nonce, &fingerprint, "alice");
        let b = build_challenge_payload(&nonce, &fingerprint, "alice");
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonce_different_payload() {
        let fingerprint = [0u8; 32];
        let a = build_challenge_payload(&[1u8; 32], &fingerprint, "alice");
        let b = build_challenge_payload(&[2u8; 32], &fingerprint, "alice");
        assert_ne!(a, b);
    }

    #[test]
    fn different_fingerprint_different_payload() {
        let nonce = [0u8; 32];
        let a = build_challenge_payload(&nonce, &[1u8; 32], "alice");
        let b = build_challenge_payload(&nonce, &[2u8; 32], "alice");
        assert_ne!(a, b);
    }

    #[test]
    fn different_username_different_payload() {
        let nonce = [0u8; 32];
        let fingerprint = [0u8; 32];
        let a = build_challenge_payload(&nonce, &fingerprint, "alice");
        let b = build_challenge_payload(&nonce, &fingerprint, "bob");
        assert_ne!(a, b);
    }

    #[test]
    fn username_is_length_prefixed() {
        let nonce = [7u8; 32];
        let fingerprint = [9u8; 32];

        let a = build_challenge_payload(&nonce, &fingerprint, "ab");
        let b = build_challenge_payload(&nonce, &fingerprint, "a\u{0000}b");
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_64_bytes() {
        let result = build_challenge_payload(&[0u8; 32], &[0u8; 32], "x");
        assert_eq!(result.len(), 64);
    }
}
