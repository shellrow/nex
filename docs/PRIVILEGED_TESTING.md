# Testing raw network I/O

Use an isolated test network. Set `NEX_TEST_INTERFACE` to the interface name on Unix or the adapter GUID on Windows. Run the tests with raw socket privileges and access to the platform capture driver.

```sh
cargo test -p nex-socket --test privileged_socket -- --ignored --test-threads=1
cargo test -p nex-datalink --all-features --test privileged_channel -- --ignored --test-threads=1
```

The channel tests include a 1,000-cycle lifecycle check and a 60-second bidirectional capture on Linux and Windows. Allow several minutes for the suite. The capture tests transmit experimental Ethernet frames.

- **Linux** uses a veth pair for Layer 2, Layer 3, and fanout tests. Set `NEX_TEST_INTERFACE` and `NEX_TEST_PEER_INTERFACE` to the two ends. In the `linux_loopback` test binary, run the two `loopback_duplicates` tests on `lo` and `non_loopback_outgoing_is_preserved` on the isolated veth.
- **macOS** requires access to BPF. Run `cargo test -p nex-datalink --features async --test macos_loopback -- --ignored` for IPv4 and IPv6 loopback traffic.
- **Windows** requires Npcap for the default backend and the Npcap SDK for the libpcap tests. Run `cargo test -p nex-datalink --all-features --lib post_allocation_failure -- --ignored --test-threads=1` to check adapter cleanup after failed setup.
- **Windows Packet Monitor** uses `cargo test -p nex --features async,winptap --test winptap_live -- --ignored --test-threads=1`. While the test runs, send UDP datagrams containing `nex-winptap-controlled-fixture-v1` to port 48932 on the chosen adapter from another host. Both the Pktmon and native IOCTL backends must observe incoming traffic.
