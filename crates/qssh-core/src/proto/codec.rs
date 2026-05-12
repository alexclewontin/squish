use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::QsshError;

/// Maximum frame size: 64 KiB. Generous for auth payloads (ML-DSA-65 sigs
/// are ~3.3 KB) while preventing unbounded allocations.
const MAX_FRAME_SIZE: u32 = 64 * 1024;

/// Write a length-prefixed postcard-encoded message to an async writer.
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> Result<(), QsshError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = to_allocvec(msg).map_err(|e| QsshError::Codec(format!("serialize: {e}")))?;

    let len =
        u32::try_from(payload.len()).map_err(|_| QsshError::Codec("message too large".into()))?;

    writer
        .write_all(&len.to_le_bytes())
        .await
        .map_err(QsshError::Io)?;
    writer.write_all(&payload).await.map_err(QsshError::Io)?;

    Ok(())
}

/// Read a length-prefixed postcard-encoded message from an async reader.
pub async fn read_message<R, T>(reader: &mut R) -> Result<T, QsshError>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(QsshError::Io)?;

    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(QsshError::Codec(format!(
            "frame too large: {len} bytes (max {MAX_FRAME_SIZE})"
        )));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await.map_err(QsshError::Io)?;

    from_bytes(&buf).map_err(|e| QsshError::Codec(format!("deserialize: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::channel::*;
    use crate::proto::message::*;

    /// Helper: write a message then read it back from an in-memory buffer.
    async fn roundtrip<T>(msg: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let mut buf = Vec::new();
        write_message(&mut buf, msg).await.unwrap();
        let mut cursor = &buf[..];
        read_message(&mut cursor).await.unwrap()
    }

    #[tokio::test]
    async fn roundtrip_client_hello() {
        let msg = ControlMessage::ClientHello {
            version: PROTOCOL_VERSION,
            username: "alice".into(),
        };
        let decoded: ControlMessage = roundtrip(&msg).await;
        match decoded {
            ControlMessage::ClientHello { version, username } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(username, "alice");
            }
            other => panic!("expected ClientHello, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_auth_challenge() {
        let nonce = [42u8; 32];
        let msg = ControlMessage::AuthChallenge { nonce };
        let decoded: ControlMessage = roundtrip(&msg).await;
        match decoded {
            ControlMessage::AuthChallenge { nonce: n } => assert_eq!(n, nonce),
            other => panic!("expected AuthChallenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_auth_response_large_payload() {
        // ML-DSA-65: ~1952 byte pubkey, ~3293 byte signature
        let msg = ControlMessage::AuthResponse {
            pubkey: vec![0xAB; 1952],
            signature: vec![0xCD; 3293],
        };
        let decoded: ControlMessage = roundtrip(&msg).await;
        match decoded {
            ControlMessage::AuthResponse { pubkey, signature } => {
                assert_eq!(pubkey.len(), 1952);
                assert_eq!(signature.len(), 3293);
                assert!(pubkey.iter().all(|&b| b == 0xAB));
                assert!(signature.iter().all(|&b| b == 0xCD));
            }
            other => panic!("expected AuthResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_channel_open_session() {
        let msg = ChannelMessage::Open {
            channel_type: ChannelType::Session,
            params: ChannelParams::Session,
        };
        let decoded: ChannelMessage = roundtrip(&msg).await;
        match decoded {
            ChannelMessage::Open {
                channel_type: ChannelType::Session,
                params: ChannelParams::Session,
            } => {}
            other => panic!("expected Session open, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_channel_data() {
        let payload = b"hello from the shell\n".to_vec();
        let msg = ChannelMessage::Data {
            data: payload.clone(),
        };
        let decoded: ChannelMessage = roundtrip(&msg).await;
        match decoded {
            ChannelMessage::Data { data } => assert_eq!(data, payload),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_pty_request() {
        let msg = ChannelMessage::Request {
            request_type: RequestType::PtyReq(PtyReqParams {
                term: "xterm-256color".into(),
                width_cols: 120,
                height_rows: 40,
                width_px: 0,
                height_px: 0,
            }),
            want_reply: true,
        };
        let decoded: ChannelMessage = roundtrip(&msg).await;
        match decoded {
            ChannelMessage::Request {
                request_type: RequestType::PtyReq(params),
                want_reply,
            } => {
                assert_eq!(params.term, "xterm-256color");
                assert_eq!(params.width_cols, 120);
                assert_eq!(params.height_rows, 40);
                assert!(want_reply);
            }
            other => panic!("expected PtyReq, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn roundtrip_direct_tcpip() {
        let msg = ChannelMessage::Open {
            channel_type: ChannelType::DirectTcpip,
            params: ChannelParams::DirectTcpip(TcpipParams {
                host: "localhost".into(),
                port: 8080,
                originator_addr: "127.0.0.1".into(),
                originator_port: 54321,
            }),
        };
        let decoded: ChannelMessage = roundtrip(&msg).await;
        match decoded {
            ChannelMessage::Open {
                channel_type: ChannelType::DirectTcpip,
                params: ChannelParams::DirectTcpip(p),
            } => {
                assert_eq!(p.host, "localhost");
                assert_eq!(p.port, 8080);
            }
            other => panic!("expected DirectTcpip open, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn multiple_messages_on_same_stream() {
        let messages: Vec<ChannelMessage> = vec![
            ChannelMessage::Data {
                data: b"first".to_vec(),
            },
            ChannelMessage::Data {
                data: b"second".to_vec(),
            },
            ChannelMessage::Eof,
            ChannelMessage::Close,
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            write_message(&mut buf, msg).await.unwrap();
        }

        let mut cursor = &buf[..];
        for expected in &messages {
            let decoded: ChannelMessage = read_message(&mut cursor).await.unwrap();
            // Compare debug representations for simplicity
            assert_eq!(format!("{decoded:?}"), format!("{expected:?}"));
        }
    }

    #[tokio::test]
    async fn reject_oversized_frame() {
        // Craft a frame header claiming MAX_FRAME_SIZE + 1 bytes
        let bad_len = (MAX_FRAME_SIZE + 1).to_le_bytes();
        let mut cursor = &bad_len[..];
        let result: Result<ControlMessage, _> = read_message(&mut cursor).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("frame too large"), "got: {err}");
    }
}
