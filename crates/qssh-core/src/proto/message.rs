use serde::{Deserialize, Serialize};

/// Protocol version. Increment on breaking wire format changes.
pub const PROTOCOL_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// Control stream messages (stream 0)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    ClientHello {
        version: u16,
        username: String,
    },

    AuthChallenge {
        nonce: [u8; 32],
    },

    AuthResponse {
        /// ML-DSA-65 encoded verifying (public) key
        pubkey: Vec<u8>,
        /// ML-DSA-65 signature over:
        /// SHA-512("qssh-auth-challenge-v1" || nonce || server_cert_fingerprint || username_len_le_u16 || username_bytes)
        signature: Vec<u8>,
    },

    AuthResult(AuthOutcome),

    Disconnect {
        reason: DisconnectReason,
        description: String,
    },

    KeepAlive {
        seq: u64,
    },

    KeepAliveAck {
        seq: u64,
    },

    /// Client → server: start listening on the server for remote forwarding (-R).
    TcpForwardRequest {
        bind_addr: String,
        bind_port: u16,
    },

    /// Server → client: remote forward listener started.
    TcpForwardConfirm {
        bound_port: u16,
    },

    /// Server → client: remote forward request rejected.
    TcpForwardFailure {
        description: String,
    },

    /// Client → server: stop listening on the server.
    TcpForwardCancel {
        bind_addr: String,
        bind_port: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthOutcome {
    Success,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectReason {
    ByApplication,
    ProtocolError,
    AuthFailed,
    Timeout,
}
