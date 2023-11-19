/// Provides core network types and functionality.
pub mod net {
    pub use xenet_core::*;
}

/// Provides functionality for interacting with the data link layer, support for sending and receiving packets.
pub mod datalink {
    pub use xenet_datalink::*;
}

/// Support for packet parsing and manipulation. Enables users to work with packets at a granular level.
pub mod packet {
    pub use xenet_packet::*;
}

/// Support for sending and receiving transport layer packets.
pub mod socket {
    pub use xenet_socket::*;
}

/// Utilities designed to work with packets through high-level APIs.
pub mod util {
    pub mod packet_builder {
        pub use xenet_packet_builder::*;
    }
}
