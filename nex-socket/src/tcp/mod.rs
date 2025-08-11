//! TCP socket.
//!
//! Includes synchronous and asynchronous functionality and configuration
//! helpers for TCP sockets.
mod async_impl;
mod config;
mod sync_impl;

pub use async_impl::*;
pub use config::*;
pub use sync_impl::*;
