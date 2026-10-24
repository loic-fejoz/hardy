//! Error types for the HQFBP Convergence Layer Adapter.

use std::io;

use thiserror::Error;

use hardy_bpa::cla::{ClaAddress, Error as ClaError};

/// Errors that can occur within the HQFBP CLA.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// HQFBP protocol or codec error.
    #[error("HQFBP error: {0}")]
    Hqfbp(String),

    /// BPA CLA error.
    #[error("CLA error: {0}")]
    Cla(#[from] ClaError),

    /// The CLA has not been registered with the BPA yet.
    #[error("CLA is not registered")]
    NotRegistered,

    /// No peer mapping could be found for the given address.
    #[error("unknown peer: {0:?}")]
    UnknownPeer(ClaAddress),

    /// The driver task has terminated.
    #[error("driver task channel closed")]
    DriverClosed,

    /// Buffer stream error.
    #[error("buffer stream error: {0}")]
    Buffer(#[from] hardy_bpa::stream::BufferError),

    /// Serial transport requested but serial support is not compiled or failed to initialize.
    #[error("serial transport error: {0}")]
    Serial(String),

    /// Invalid content encoding parameter string.
    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    /// Forwarded bundle exceeds maximum allowed size.
    #[error("bundle payload too large: {size} bytes exceeds maximum {max} bytes")]
    PayloadTooLarge {
        /// Actual size of the bundle in bytes.
        size: u64,
        /// Maximum allowed size in bytes.
        max: u64,
    },

    /// Receiver in-flight memory allocation exceeded.
    #[error("receiver in-flight memory cap exceeded: {current} bytes exceeds limit {max} bytes")]
    MemoryCapExceeded {
        /// Current buffered bytes in memory.
        current: usize,
        /// Configured limit in bytes.
        max: usize,
    },
}

/// A specialized `Result` type for HQFBP CLA operations.
pub type Result<T> = core::result::Result<T, Error>;

impl From<Error> for ClaError {
    fn from(err: Error) -> Self {
        match err {
            Error::Cla(e) => e,
            Error::Buffer(e) => ClaError::from(e),
            Error::PayloadTooLarge { size, max } => ClaError::PayloadTooLarge { size, max },
            other => ClaError::Internal(Box::new(other)),
        }
    }
}
