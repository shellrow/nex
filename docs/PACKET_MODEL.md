# Packet Model

`nex-packet` separates packet handling into four categories:

| Category | Ownership | Mutation | Typical types |
| --- | --- | --- | --- |
| Borrowed view | Borrows caller bytes | No | `FrameSlice<'a>`, `FrameView<'a>` |
| Mutable borrowed view | Exclusively borrows caller bytes | In place | `MutableIpv4Packet<'a>`, `GenericMutablePacket<'a, P>` |
| Owned decoded packet | Owns serialized `Bytes` and decoded fields | By replacing owned fields | `Ipv4Packet`, `TcpPacket`, `DnsPacket` |
| Builder | Owns construction state | Validated setters/build | Types under `builder` |

Use allocation-free `FrameSlice` for layer boundaries on a hot path.
`FrameView` retains decoded header compatibility and may allocate for variable
options. Use a mutable view when editing an existing buffer, an owned packet
when data must outlive the input, and a builder when constructing new wire
data.

## Mutable layout and freeze

Protocol-specific mutable views validate their minimum layout on construction.
`GenericMutablePacket` additionally caches header and payload boundaries after
one parse. Ordinary field and payload edits do not cause another parse.
Changing a structural field through `packet_mut()` does not update the cached
boundaries; call `refresh_layout()` before requesting slices under the new
layout.

`freeze()` is the commit point. It parses the current bytes again and returns
an owned packet only when the complete layout is valid. The parse is deliberate:
it prevents stale or inconsistent mutable bytes from becoming an owned packet.

The allocation-returning `Packet::to_bytes_mut`, `header_mut`, and
`payload_mut` compatibility methods are deprecated. Their explicit
`copy_*_to_bytes_mut` replacements make the allocation visible at call sites.

## Generated representation details

The `nex_core::bitfield` aliases are `#[doc(hidden)]` implementation details
shared by packet field representations. They are public for cross-crate code
generation only and carry no independent semantic contract.

## Variable-length protocol data

IPv4 options, IPv6 extension headers, TCP options, DNS compression, and DHCP
options are length-delimited and reject truncated structural fields. Parsers
that distinguish capture truncation expose `ParseMode`: lenient mode preserves
available captured payload where documented, while strict mode rejects data
shorter than its declared protocol length. Fuzz and property tests exercise
both arbitrary input and valid parse/serialize round trips.
