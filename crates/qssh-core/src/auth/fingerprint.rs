use sha2::{Digest, Sha256};

/// SHA-256 fingerprint of a DER-encoded TLS certificate.
///
/// This is the value bound into the authentication challenge payload
/// (see `auth::challenge::build_challenge_payload`) and stored in
/// `known_hosts` for TOFU pinning.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let cert = b"fake cert bytes";
        assert_eq!(cert_fingerprint(cert), cert_fingerprint(cert));
    }

    #[test]
    fn different_input_different_output() {
        assert_ne!(cert_fingerprint(b"cert-a"), cert_fingerprint(b"cert-b"));
    }

    #[test]
    fn output_is_32_bytes() {
        let fp = cert_fingerprint(b"x");
        assert_eq!(fp.len(), 32);
    }
}
