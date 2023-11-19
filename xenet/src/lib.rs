/// Provides core network types and functionality.
/// Mainly for xenet, but also for extensions to standard net module.
pub mod net {
    pub use xenet_core::*;
}

/// Support for sending and receiving data link layer packets.
pub mod datalink {
    pub use xenet_datalink::*;
}

/// Support for packet parsing and manipulation.
pub mod packet {
    pub use xenet_packet::*;
}

/// Support for sending and receiving transport layer packets.
pub mod socket {
    pub use xenet_socket::*;
}

/// Utilities for working with Packet with high-level APIs.
/// For more low-level APIs, use `packet`, `datalink`, and `socket` modules instead
pub mod util {
    pub mod packet_builder {
        pub use xenet_packet_builder::*;
    }
}
