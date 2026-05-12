use sha2::{Digest, Sha512};

/// Construct the challenge payload that gets signed during authentication.
///
/// The signature covers:
///   SHA-512(nonce || server_cert_fingerprint || username || timestamp_secs)
///
/// This binds the auth to a specific TLS session (cert fingerprint),
/// prevents replay (nonce + timestamp), and prevents cross-user replay
/// (username).
pub fn build_challenge_payload(
    nonce: &[u8; 32],
    server_cert_fingerprint: &[u8; 32],
    username: &str,
    timestamp_secs: u64,
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(nonce);
    hasher.update(server_cert_fingerprint);
    hasher.update(username.as_bytes());
    hasher.update(timestamp_secs.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let nonce = [1u8; 32];
        let fingerprint = [2u8; 32];
        let a = build_challenge_payload(&nonce, &fingerprint, "alice", 1000);
        let b = build_challenge_payload(&nonce, &fingerprint, "alice", 1000);
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonce_different_payload() {
        let fingerprint = [0u8; 32];
        let a = build_challenge_payload(&[1u8; 32], &fingerprint, "alice", 1000);
        let b = build_challenge_payload(&[2u8; 32], &fingerprint, "alice", 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_fingerprint_different_payload() {
        let nonce = [0u8; 32];
        let a = build_challenge_payload(&nonce, &[1u8; 32], "alice", 1000);
        let b = build_challenge_payload(&nonce, &[2u8; 32], "alice", 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_username_different_payload() {
        let nonce = [0u8; 32];
        let fingerprint = [0u8; 32];
        let a = build_challenge_payload(&nonce, &fingerprint, "alice", 1000);
        let b = build_challenge_payload(&nonce, &fingerprint, "bob", 1000);
        assert_ne!(a, b);
    }

    #[test]
    fn different_timestamp_different_payload() {
        let nonce = [0u8; 32];
        let fingerprint = [0u8; 32];
        let a = build_challenge_payload(&nonce, &fingerprint, "alice", 1000);
        let b = build_challenge_payload(&nonce, &fingerprint, "alice", 1001);
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_64_bytes() {
        let result = build_challenge_payload(&[0u8; 32], &[0u8; 32], "x", 0);
        assert_eq!(result.len(), 64);
    }
}
