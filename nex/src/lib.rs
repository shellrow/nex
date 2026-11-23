//! Network interfaces, packet parsing and construction, raw datalink I/O,
//! and TCP, UDP, and ICMP sockets.
//!
//! Enable `async` for asynchronous datalink and socket APIs. The `pcap`
//! feature adds libpcap capture, and `winptap` enables receive-only Windows
//! Packet Monitor capture.

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

/// TCP, UDP, and ICMP sockets.
pub mod socket {
    pub use nex_socket::*;
}
