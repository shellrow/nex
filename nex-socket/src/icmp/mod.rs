//! ICMP socket.
//!
//! Supplies synchronous and asynchronous interfaces for sending and
//! receiving Internet Control Message Protocol packets.
mod async_impl;
mod config;
mod sync_impl;

pub use async_impl::*;
pub use config::*;
pub use sync_impl::*;
