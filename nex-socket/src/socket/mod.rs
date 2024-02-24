mod async_impl;
mod sync_impl;

use socket2::{Domain, Type};
use nex_packet::ip::IpNextLevelProtocol;

use crate::sys;

pub use async_impl::*;
pub use sync_impl::*;

/// IP version. IPv4 or IPv6.
#[derive(Clone, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

impl IpVersion {
    /// IP Version number as u8.
    pub fn version_u8(&self) -> u8 {
        match self {
            IpVersion::V4 => 4,
            IpVersion::V6 => 6,
        }
    }
    /// Return true if IP version is IPv4.
    pub fn is_ipv4(&self) -> bool {
        match self {
            IpVersion::V4 => true,
            IpVersion::V6 => false,
        }
    }
    /// Return true if IP version is IPv6.
    pub fn is_ipv6(&self) -> bool {
        match self {
            IpVersion::V4 => false,
            IpVersion::V6 => true,
        }
    }
    pub(crate) fn to_domain(&self) -> Domain {
        match self {
            IpVersion::V4 => Domain::IPV4,
            IpVersion::V6 => Domain::IPV6,
        }
    }
}

/// Socket type
#[derive(Clone, Debug)]
pub enum SocketType {
    /// Raw socket
    Raw,
    /// Datagram socket. Usualy used for UDP.
    Datagram,
    /// Stream socket. Used for TCP.
    Stream,
}

impl SocketType {
    pub(crate) fn to_type(&self) -> Type {
        match self {
            SocketType::Raw => Type::RAW,
            SocketType::Datagram => Type::DGRAM,
            SocketType::Stream => Type::STREAM,
        }
    }
    pub (crate) fn from_type(t: Type) -> SocketType {
        match t {
            Type::RAW => SocketType::Raw,
            Type::DGRAM => SocketType::Datagram,
            Type::STREAM => SocketType::Stream,
            _ => SocketType::Stream,
        }
    }
}

/// Socket option.
#[derive(Clone, Debug)]
pub struct SocketOption {
    /// IP version
    pub ip_version: IpVersion,
    /// Socket type
    pub socket_type: SocketType,
    /// Protocol. TCP, UDP, ICMP, etc.
    pub protocol: Option<IpNextLevelProtocol>,
    /// Non-blocking mode
    pub non_blocking: bool,
}

impl SocketOption {
    /// Constructs a new SocketOption.
    pub fn new(
        ip_version: IpVersion,
        socket_type: SocketType,
        protocol: Option<IpNextLevelProtocol>,
    ) -> SocketOption {
        SocketOption {
            ip_version,
            socket_type,
            protocol,
            non_blocking: false,
        }
    }
    /// Check socket option.
    /// Return Ok(()) if socket option is valid.
    pub fn is_valid(&self) -> Result<(), String> {
        sys::check_socket_option(self.clone())
    }
}

fn to_socket_protocol(protocol: IpNextLevelProtocol) -> socket2::Protocol {
    match protocol {
        IpNextLevelProtocol::Tcp => socket2::Protocol::TCP,
        IpNextLevelProtocol::Udp => socket2::Protocol::UDP,
        IpNextLevelProtocol::Icmp => socket2::Protocol::ICMPV4,
        IpNextLevelProtocol::Icmpv6 => socket2::Protocol::ICMPV6,
        _ => socket2::Protocol::TCP,
    }
}
