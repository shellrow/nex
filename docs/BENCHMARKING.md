# Packet benchmarks

Run `cargo bench -p nex-packet` on an idle machine. The `packet_parse` benchmark compares owned frames, decoded headers with a borrowed payload, and allocation-free slices. `packet_operations` measures protocol parsing, serialization, and checksums.

To compare revisions, run the first command before a change and the second afterward on the same machine and Rust toolchain.

```sh
cargo bench -p nex-packet --bench packet_operations -- --save-baseline before
cargo bench -p nex-packet --bench packet_operations -- --baseline before
```
