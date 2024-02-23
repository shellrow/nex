# nex

Cross-platform networking library for Rust

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
- XDP Support: Adding support for eBPF, specifically XDP (eXpress Data Path), for high-performance packet processing and filtering.
- More Protocol Support: Expanding protocol support to include additional network protocols and standards.
- Performance Improvements: Continuously working on performance enhancements for faster network operations.

## Usage

To use `nex`, add it as a dependency in your `Cargo.toml`:

```toml
[dependencies]
nex = "0.5"
```

## Using Specific Sub-crates
You can also directly use specific sub-crates by importing them individually.
- `nex-datalink`
- `nex-packet`
- `nex-packet-builder`
- `nex-socket`

If you want to focus on network interfaces, you can use the [default-net](https://github.com/shellrow/default-net).
