//! Unified error types for the crate.

use thiserror::Error;

/// Errors that any ping operation may return.
#[derive(Debug, Error)]
pub enum PingError {
    /// A low-level network I/O error (connection failure, read/write error,
    /// DNS resolution failure, etc.).
    #[error("network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A JSON parsing / serialization error (for the Java Edition SLP response).
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A protocol error: mismatched packet ID, missing field, malformed
    /// VarInt, magic mismatch, etc.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, PingError>;
