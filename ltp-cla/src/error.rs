//! Error types for the LTP Convergence Layer Adapter.

use std::io;

use thiserror::Error;

use hardy_bpa::cla::{ClaAddress, Error as ClaError};
use hardy_ltp::engine::Error as LtpError;

/// Errors that can occur within the LTP CLA.
#[derive(Debug, Error)]
pub enum Error {
    /// Underlying I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// LTP protocol engine error.
    #[error("LTP protocol error: {0}")]
    Ltp(#[from] LtpError),

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
}

/// A specialized `Result` type for LTP CLA operations.
pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for ClaError {
    fn from(err: Error) -> Self {
        match err {
            Error::Cla(e) => e,
            Error::Buffer(e) => ClaError::from(e),
            other => ClaError::Internal(Box::new(other)),
        }
    }
}
