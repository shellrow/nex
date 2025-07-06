//! Convenience sockets built on top of `socket2` and `tokio`.
//!
//! This crate provides synchronous and asynchronous helpers for TCP, UDP and
//! ICMP. The goal is to simplify lower level socket configuration across
//! platforms while still allowing direct access when needed.

pub mod icmp;
pub mod tcp;
pub mod udp;
