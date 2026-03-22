# Fuzz Targets

This directory contains minimal `cargo-fuzz` targets for malformed-input hardening.

Examples:

```bash
cargo +nightly fuzz run frame_parse
cargo +nightly fuzz run ipv4_parse
cargo +nightly fuzz run ipv6_parse
cargo +nightly fuzz run tcp_options
cargo +nightly fuzz run dns_name
```

Targets focus on parser totality and malformed-input robustness. Panics and unbounded traversal are considered bugs.
