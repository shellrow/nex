//! Core network types and helpers shared across the `nex` crates.
//! Includes interface, MAC/IP, and bitfield utilities used by low-level networking code.

pub use netdev;

pub mod bitfield;
pub mod interface;
pub mod ip;
pub mod mac;
