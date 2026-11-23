# Contributing

Use Rust 1.88 or later. Install libpcap development files for all-feature builds. On Windows, enable the Npcap SDK import library path and make the runtime DLLs available before running the tests.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Include a regression test for each bug fix. Changes to raw socket or datalink I/O should also exercise the affected [platform tests](docs/PRIVILEGED_TESTING.md). For parser changes, see the [fuzz targets](fuzz/README.md) and [benchmarks](docs/BENCHMARKING.md).
