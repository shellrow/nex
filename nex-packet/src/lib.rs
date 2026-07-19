//! Low-level packet parsing and serialization primitives for common network protocols.
//!
//! Packet APIs distinguish borrowed views, mutable borrowed views, owned
//! decoded packets, and validated builders. See `docs/PACKET_MODEL.md` in the
//! repository for ownership, allocation, and mutable-layout semantics.
#![allow(deprecated)]

pub mod arp;
pub mod builder;
pub mod checksum;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod flowcontrol;
pub mod frame;
pub mod gre;
pub mod icmp;
pub mod icmpv6;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod parse;
pub mod tcp;
pub mod udp;
pub mod util;
pub mod vlan;
pub mod vxlan;

pub use builder::BuildError;
