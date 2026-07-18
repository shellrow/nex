# nex

Cross-platform low-level networking library in Rust

[![Crates.io](https://img.shields.io/crates/v/nex.svg)](https://crates.io/crates/nex)
[![Documentation](https://docs.rs/nex/badge.svg)](https://docs.rs/nex)
[![License](https://img.shields.io/crates/l/nex.svg)](https://github.com/shellrow/nex/blob/main/LICENSE)

## Overview

`nex` is a Rust library that provides cross-platform low-level networking capabilities.   
It includes sub-crates with responsibilities:

- `nex-packet`: Low-level packet parsing and serialization.
- `nex-datalink`: Raw datalink send/receive backends across platforms.
- `nex-socket`: Low-level socket operations with cross-platform option handling.

The project aims to expose portable low-level primitives.  

## Usage

To use `nex`, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
nex = "0.26"
```

## Using Specific Sub-crates
You can also directly use specific sub-crates by importing them individually.
- `nex-datalink`
- `nex-packet`
- `nex-socket`

If you want to focus on network interfaces, you can use the [netdev](https://github.com/shellrow/netdev).

## Features

All optional features are disabled by default in `nex`, `nex-packet`,
`nex-datalink`, and `nex-socket`. `nex-core` keeps `gateway` enabled by default
because gateway discovery is part of its primary interface functionality.

| Feature | Crate | Purpose |
| --- | --- | --- |
| `async` | `nex`, `nex-datalink`, `nex-socket` | Enables asynchronous datalink I/O and Tokio-based socket APIs. |
| `pcap` | `nex`, `nex-datalink` | Enables the libpcap backend. |
| `serde` | `nex`, `nex-core`, `nex-packet`, `nex-datalink` | Enables serialization support for public data types. |
| `gateway` | `nex-core` | Enables default gateway discovery through `netdev`. |

To use asynchronous APIs through the facade:

```toml
[dependencies]
nex = { version = "0.26", features = ["async"] }
```

## Privileges
`nex-datalink` uses a raw socket which may require elevated privileges depending on your system's configuration.  
Execute with administrator privileges if necessary.

## For Windows Users
Please note that in order to send and receive raw packets using `nex-datalink` on Windows, [Npcap](https://npcap.com/#download) is required.

1. Install Npcap, making sure to check Install Npcap in WinPcap API-compatible Mode during the installation.

2. Download the Npcap SDK. Add the SDK's /Lib/x64 (or /Lib) folder to your LIB environment variable.

## For macOS Users
On macOS, managing access to the Berkeley Packet Filter (BPF) devices is necessary to send and receive raw packets using `nex-datalink`.
You can use [chmod-bpf](https://github.com/shellrow/chmod-bpf) to automatically manage permissions for BPF devices.
Alternatively, of course, you can also use `sudo` to temporarily grant the necessary permissions.
