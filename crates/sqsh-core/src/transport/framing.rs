use quinn::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::error::SqshError;
use crate::proto::codec;

/// Typed wrapper for sending messages over a QUIC send stream.
pub struct FramedSender {
    inner: SendStream,
}

impl FramedSender {
    pub fn new(stream: SendStream) -> Self {
        Self { inner: stream }
    }

    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), SqshError> {
        codec::write_message(&mut self.inner, msg).await
    }

    pub async fn finish(mut self) -> Result<(), SqshError> {
        self.inner
            .finish()
            .map_err(|e| SqshError::Protocol(format!("failed to finish stream: {e}")))
    }
}

/// Typed wrapper for receiving messages from a QUIC recv stream.
pub struct FramedReceiver {
    inner: RecvStream,
}

impl FramedReceiver {
    pub fn new(stream: RecvStream) -> Self {
        Self { inner: stream }
    }

    pub async fn recv<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T, SqshError> {
        codec::read_message(&mut self.inner).await
    }
}

/// A bidirectional framed channel over a QUIC bidi stream.
pub struct FramedBiStream {
    pub sender: FramedSender,
    pub receiver: FramedReceiver,
}

impl FramedBiStream {
    pub fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            sender: FramedSender::new(send),
            receiver: FramedReceiver::new(recv),
        }
    }
}
