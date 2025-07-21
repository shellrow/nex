//! Cross-platform low-level networking library.
//!
//! `nex` is composed of four core modules (sub-crates), providing a unified interface
//! for packet parsing, manipulation, data link access, and transport layer sockets.
//! By depending on the top-level `nex` crate, applications can access all of these capabilities
//! through a convenient facade.
//!
//! - `net` (`nex-core`): Provides core networking types and utilities.
//! - `datalink` (`nex-datalink`): Interfaces with the data link layer; supports raw packet send/receive.
//! - `packet` (`nex-packet`): Enables parsing and building of packets at multiple protocol layers.
//! - `socket` (`nex-socket`): Provides sockets for working with transport protocols such as TCP, UDP, and ICMP (but L3).

/// Provides core networking types and utilities.
pub mod net {
    pub use nex_core::*;
}

/// Interfaces with the data link layer; supports raw packet send/receive.
pub mod datalink {
    pub use nex_datalink::*;
}

/// Enables parsing and building of packets at multiple protocol layers.
pub mod packet {
    pub use nex_packet::*;
}

/// Provides sockets for working with transport protocols such as TCP, UDP, and ICMP (but L3).
pub mod socket {
    pub use nex_socket::*;
}
