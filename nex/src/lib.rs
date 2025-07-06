//! Entry point for the nex-next collection of crates.
//!
//! This crate re-exports the core modules so applications can simply depend on
//! `nex` and gain access to packet parsing, datalink channels and socket helpers.
//! It is intended to be a convenient facade for the underlying crates.
/// Provides core network types and functionality.
pub mod net {
    pub use nex_core::*;
}

/// Provides functionality for interacting with the data link layer, support for sending and receiving packets.
pub mod datalink {
    pub use nex_datalink::*;
}

/// Support for packet parsing and manipulation. Enables users to work with packets at a granular level.
pub mod packet {
    pub use nex_packet::*;
}

/// Support for sending and receiving transport layer packets.
pub mod socket {
    pub use nex_socket::*;
}
