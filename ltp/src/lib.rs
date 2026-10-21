//! Licklider Transmission Protocol (LTP) implementation for Hardy (RFC 5326).
//!
//! This crate implements the core LTP protocol and KISS framing in pure `no_std` + `alloc`.
//! Network transport and Tokio-based CLA adapters live in `hardy-ltp-cla`.

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod engine;
pub mod range;
pub mod sdnv;
pub mod segment;
pub mod types;

#[cfg(feature = "kiss")]
pub mod kiss;
