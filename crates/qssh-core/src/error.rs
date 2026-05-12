use thiserror::Error;

#[derive(Debug, Error)]
pub enum QsshError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("channel error: {0}")]
    Channel(String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
