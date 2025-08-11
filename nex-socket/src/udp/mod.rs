//! UDP socket.
//!
//! Provides synchronous and asynchronous UDP APIs along with
//! configuration utilities for common socket options.
mod async_impl;
mod config;
mod sync_impl;

pub use async_impl::*;
pub use config::*;
pub use sync_impl::*;
