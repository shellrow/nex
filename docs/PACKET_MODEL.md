# Packet types

| Type | Use |
| --- | --- |
| `FrameSlice<'a>` | Inspect layer boundaries in the original buffer without allocation. |
| `FrameView<'a>` | Read decoded headers and borrow the payload. Parsing currently makes a temporary copy of the input. |
| `Frame` and protocol packet types | Keep decoded fields and owned payloads. Parsers that accept `Bytes` can share its storage. |
| `MutablePacket` implementations | Edit an existing buffer in place. |
| Protocol builders | Construct a new packet and validate field sizes before encoding. |

`GenericMutablePacket` caches header and payload boundaries. After changing a length or another structural field through `packet_mut()`, call `refresh_layout()` before using the slices. `freeze()` reparses the bytes to produce an owned packet.

Use `try_from_buf` or `try_from_bytes` for structured parse errors. For IP captures, `ParseMode::Lenient` accepts available payload bytes when a capture ends early. `ParseMode::Strict` checks the declared IP length.

## DNS wire names in 0.29

`DnsResponsePacket::name` stores the complete encoded owner name. It replaces the two-byte `name_tag` field. To migrate a compression pointer, use `name_tag.to_be_bytes().to_vec()`. A root name is `vec![0]`. Persisted Serde records also need this field conversion.

Compression offsets refer to the start of the original DNS message. Use `DnsName::try_from_message(message, offset)` to decode a name at a known offset. Parsed records retain their wire encoding, so an unmodified message can be serialized again. When editing the layout, the caller must update affected pointers, section counts, and RDATA lengths.

For an individual question or resource record, `header()` returns that record and `payload()` returns the bytes that follow it. `to_bytes()` includes both. On a complete `DnsPacket`, the header slice includes all declared sections and the payload contains trailing bytes.
