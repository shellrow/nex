# nex

Packet parsing, raw datalink I/O, and TCP, UDP, and ICMP sockets for Rust.

[![Crates.io](https://img.shields.io/crates/v/nex.svg)](https://crates.io/crates/nex)
[![Documentation](https://docs.rs/nex/badge.svg)](https://docs.rs/nex)
[![License](https://img.shields.io/crates/l/nex.svg)](https://github.com/shellrow/nex/blob/main/LICENSE)

## Getting started

Install with `cargo add nex`. The minimum supported Rust version is 1.88.

```rust
use nex::packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;

fn source_address(packet: &[u8]) -> Option<Ipv4Addr> {
    Ipv4Packet::try_from_buf(packet).ok().map(|ip| ip.header.source)
}
```

| Module | Standalone crate | Purpose |
| --- | --- | --- |
| `nex::net` | `nex-core` | Interfaces, addresses, and gateway discovery |
| `nex::packet` | `nex-packet` | Packet parsing, in-place editing, and construction |
| `nex::datalink` | `nex-datalink` | Link-layer capture and transmission |
| `nex::socket` | `nex-socket` | Socket configuration and I/O |

See the [examples](https://github.com/shellrow/nex/tree/main/examples) for packet capture and socket usage. The [packet guide](https://github.com/shellrow/nex/blob/main/docs/PACKET_MODEL.md) covers parsing, buffer ownership, and migrating DNS records to 0.29.

Applications using conversions between `nex-core` and `netdev` interface types should use `netdev` 0.48 with nex 0.29.

## Features

The top-level crate has no default features. Enable features with, for example, `cargo add nex --features async`.

| Feature | Available on | Effect |
| --- | --- | --- |
| `async` | `nex`, `nex-datalink`, `nex-socket` | Runtime-independent datalink streams and Tokio socket APIs |
| `pcap` | `nex`, `nex-datalink` | Live capture and injection through libpcap, and offline capture-file reading |
| `winptap` | `nex`, `nex-datalink` | Receive-only Windows Packet Monitor capture |
| `serde` | `nex`, `nex-core`, `nex-packet`, `nex-datalink` | Serialization for supported networking types |
| `gateway` | `nex-core` | Default interface and gateway discovery, enabled by default on this crate |

## Platform requirements

Packet parsing works without capture privileges. Raw socket and datalink access depend on the platform.

- **Linux** uses packet sockets. Grant the capturing process `CAP_NET_RAW` or run it as root.
- **macOS and BSD** use BPF devices. The process needs read/write access to a `/dev/bpf*` device.
- **Windows** loads [Npcap](https://npcap.com/#download) at runtime for Ethernet capture and transmission. The default backend works with the standard Npcap installation. The optional `pcap` feature also needs the Npcap SDK import library for the target architecture.
- **Windows Packet Monitor** requires administrator privileges. Enable `winptap` and call `nex::datalink::winptap::open`, or enable both `winptap` and `async` and call `open_async`. The Pktmon backend observes incoming and outgoing traffic. The native IOCTL backend observes incoming traffic. Both provide receive-only capture without Npcap.

On Unix, install the platform's libpcap development files to build with `pcap` (for example, `libpcap-dev` on Ubuntu).
