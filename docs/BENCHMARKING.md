# Benchmarking

Run packet benchmarks on an otherwise idle machine:

```sh
cargo bench -p nex-packet
```

`packet_parse` compares owned, decoded-view, and allocation-free slice parsing.
`packet_operations`
tracks Ethernet/VLAN, IPv4/IPv6, TCP/UDP, and DNS-name parsing together with
IPv4 serialization and checksum throughput. Criterion stores baselines under
`target/criterion`; compare changes with:

```sh
cargo bench -p nex-packet -- --save-baseline before
cargo bench -p nex-packet -- --baseline before
```

`FrameSlice` avoids packet-byte copies and heap allocation. `FrameView` may
allocate decoded variable-length options; owned parsing and serialization may
allocate or increment a `Bytes` reference count. Use an allocation profiler
such as DHAT, heaptrack, or Instruments when changing parser ownership.
Datalink send/receive throughput depends on kernel,
driver, interface, and privileges, so measure it manually using the matrix in
`PRIVILEGED_TESTING.md`; do not compare those results across hosts.

Benchmark changes are reviewed locally rather than gated by a fixed CI
percentage. Record the command, CPU, OS, Rust version, and Criterion comparison
when a change intentionally affects a hot path.
