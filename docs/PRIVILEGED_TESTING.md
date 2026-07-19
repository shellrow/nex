# Manual Privileged Test Matrix

Run this matrix before a release on dedicated hosts or disposable virtual
machines. Do not run it on an untrusted shared network. Record the OS version,
Rust version, interface name, command, and result in the release checklist.

| Platform | Prerequisites | Synchronous checks | Asynchronous checks | Expected result |
| --- | --- | --- | --- | --- |
| Linux | Root or `CAP_NET_RAW`; loopback plus a veth pair | `dump`, `arp`, `icmp_ping`, `tcp_ping`, `udp_ping`; Layer2 and Layer3 channels; promiscuous off/on; fanout with two receivers | `async_datalink`, `async_dump`, async ICMP/TCP/UDP socket examples | Packets transmit and receive, timeouts are honored, and all processes exit without leaked descriptors. |
| macOS | Root; one Ethernet or Wi-Fi interface plus loopback; available `/dev/bpf*` devices | `dump`, `arp`, `icmp_ping`, `tcp_ping`, `udp_ping`; loopback and non-loopback BPF; repeated open/close beyond one BPF descriptor | `async_datalink`, `async_dump`, async socket examples | BPF headers are decoded, loopback header translation is correct, and descriptors return to the pre-test count. |
| FreeBSD/OpenBSD/NetBSD | Root; BPF enabled; loopback plus one test interface | Same BPF examples as macOS, including immediate mode and configured timeouts | `async_datalink` and `async_dump` | Device selection and BPF alignment work without truncated frames or descriptor leaks. |
| Windows | Administrator; current Npcap in WinPcap-compatible mode | `dump`, `arp`, `icmp_ping`, `tcp_ping`, `udp_ping`; repeated channel creation; concurrent sender and receiver | `async_datalink`, `async_dump`, async socket examples; repeatedly create and drop channels | Adapter names resolve, send/receive operations remain serialized, worker threads stop on drop, and Npcap handles are freed once. |

## Error-path leak check

For each backend, capture the process handle count before the test, repeatedly
open a channel with a deliberately invalid interface or configuration after the
first resource allocation point, and capture the count again. Linux and BSD
hosts should inspect `/proc/<pid>/fd` or `lsof -p <pid>` as available. Windows
hosts should use Process Explorer or `Get-Process`.

The count must return to baseline after every iteration. Run at least 1,000
iterations. Any monotonically increasing handle count, double-close diagnostic,
sanitizer report, or worker thread surviving channel drop is a release blocker.

## Sanitizers and Miri

Run pure logic under Miri:

```sh
cargo +nightly miri test -p nex-core --lib
cargo +nightly miri test -p nex-packet --lib
```

Run Linux parsing and datalink tests under AddressSanitizer and LeakSanitizer on
a nightly toolchain:

```sh
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p nex-packet -p nex-datalink --lib --target x86_64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=leak" cargo +nightly test -p nex-packet -p nex-datalink --lib --target x86_64-unknown-linux-gnu
```

Rust does not currently expose LLVM UndefinedBehaviorSanitizer through
`-Zsanitizer`; Miri supplies the pure-Rust undefined-behavior check instead.
Privileged datalink examples must also be exercised under each available
sanitizer on the Linux test host.
