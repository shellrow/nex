# nex

Cross-platform low-level networking library in Rust

[![Crates.io](https://img.shields.io/crates/v/nex.svg)](https://crates.io/crates/nex)
[![Documentation](https://docs.rs/nex/badge.svg)](https://docs.rs/nex)
[![License](https://img.shields.io/crates/l/nex.svg)](https://github.com/shellrow/nex/blob/main/LICENSE)

## Overview

`nex` is a Rust library that provides cross-platform low-level networking capabilities.   
It includes a set of modules, each with a specific focus:

- `datalink`: Datalink layer networking. 
- `packet`: Low-level packet parsing and building. 
- `packet-builder`: High-level packet building. 
- `socket`: Socket-related functionality.

## Upcoming Features
The project has plans to enhance nex with the following features:  
- More Protocol Support: Expanding protocol support to include additional network protocols and standards.
- Performance Improvements: Continuously working on performance enhancements for faster network operations.

## Usage

To use `nex`, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
nex = "0.14"
```

## Using Specific Sub-crates
You can also directly use specific sub-crates by importing them individually.
- `nex-datalink`
- `nex-packet`
- `nex-packet-builder`
- `nex-socket`

If you want to focus on network interfaces, you can use the [netdev](https://github.com/shellrow/netdev).


## for Windows Users
Please note that in order to send and receive raw packets using `nex-datalink` on Windows, `npcap` is required.

1. Install Npcap, making sure to check Install Npcap in WinPcap API-compatible Mode during the installation.

2. Download the Npcap SDK. Add the SDK's /Lib/x64 (or /Lib) folder to your LIB environment variable.

To simplify the process of downloading and installing `npcap`, you can use `nex-npcap-helper`. This crate facilitates the download and installation process, which can be helpful when distributing applications that utilize `nex-datalink` on Windows.

## Build time requirements for optional feature
The cryptography provider for `nex-socket`'s optional `tls-aws-lc` feature use `aws-lc-rs`. Note that this has some implications on [build-time tool requirements](https://aws.github.io/aws-lc-rs/requirements/index.html), such as requiring cmake on all platforms and nasm on Windows.  
**You can use `ring` as the cryptography provider (without additional dependencies) by specifying the `tls` feature.**

## Acknowledgment
### Inspired by
This library was heavily inspired by `pnet`, which catalyzed my journey into Rust development.  
I am grateful to everyone involved in `pnet` for their pioneering efforts and significant contributions to networking in Rust.  

Additionally, thank you to all contributors and maintainers of the projects `nex` depends on for your invaluable work and support.
