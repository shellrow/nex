# Changelog

## 0.29.0

### Breaking changes

- `DnsResponsePacket::name_tag: u16` was replaced by `name: Vec<u8>`. The field stores the complete wire encoding of the owner name, including literal labels, the root name, or a compression pointer. Convert an existing pointer with `name_tag.to_be_bytes().to_vec()`. Apply the same conversion to stored Serde records.
- `nex-core` now uses `netdev` 0.48. Applications that convert between the two crates' interface types must update their direct `netdev` dependency to 0.48.

### Packets and sockets

- DNS messages preserve encoded names and trailing bytes on a parse and serialize round trip. Use `DnsName::try_from_message(message, offset)` to resolve compressed names against the original message. Parsing now rejects truncated records and invalid owner-name pointers. Extended DNS response codes use their registered values.
- Frame parsing preserves Ethernet padding after ARP packets and retains payload bytes when an IP payload cannot be decoded.
- Asynchronous UDP and ICMP operations honor configured read and write timeouts.
- TCP sockets imported into Tokio enter nonblocking mode before connecting, listening, or converting to a stream. Synchronous timed connects restore the configured socket mode on success and failure. On Windows, sockets imported from `socket2` return to blocking mode.
- On Windows, low-level socket send and receive errors now report the Winsock error code.

### Datalink

- Unix asynchronous channels wait for OS readiness when idle. Synchronous BPF channels can use descriptors above the `select` limit. Fixed Android packet-socket compilation and the BPF interface request size on NetBSD.
- On Windows, Npcap loads `Packet.dll` from the system or installed Npcap directory. Batch sends transmit each frame, and the asynchronous receiver buffers at most one capture batch.
- Npcap and libpcap senders can transmit while a synchronous receive is blocked. The libpcap backend reports OS interface indices where available and returns `UnexpectedEof` at the end of a capture file.
- Closing a Windows Packet Monitor receiver from its own waker no longer attempts to join the current thread.

### Packaging

- All six crates now include the MIT license text in their packages.

## 0.28.1

- Linux packet sockets gained opt-in loopback duplicate suppression for synchronous and asynchronous capture. Set `Config::linux_suppress_loopback_duplicates` to `true` to discard the outgoing copy on the bound loopback interface. The default is `false`.
- On macOS BPF loopback interfaces (`DLT_NULL`), `send`, `build_and_send`, and asynchronous sends encode the correct address family for IPv4 and IPv6. Malformed or truncated Ethernet/IP frames return `InvalidInput`.
