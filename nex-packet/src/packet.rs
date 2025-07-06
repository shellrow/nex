use bytes::{Bytes, BytesMut};

/// Represents a generic network packet.
pub trait Packet: Sized {
    type Header;

    /// Parse from a byte slice.
    fn from_buf(buf: &[u8]) -> Option<Self>;

    /// Parse from raw bytes. (with ownership)
    fn from_bytes(bytes: Bytes) -> Option<Self>;

    /// Serialize into raw bytes.
    fn to_bytes(&self) -> Bytes;

    /// Get the header of the packet.
    fn header(&self) -> Bytes;

    /// Get the payload of the packet.
    fn payload(&self) -> Bytes;

    /// Get the length of the header.
    fn header_len(&self) -> usize;

    /// Get the length of the payload.
    fn payload_len(&self) -> usize;
    /// Get the total length of the packet (header + payload).
    fn total_len(&self) -> usize;
    /// Convert the packet to a mutable byte buffer.
    fn to_bytes_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.total_len());
        buf.extend_from_slice(&self.to_bytes());
        buf
    }
    /// Get a mutable byte buffer for the header.
    fn header_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.header_len());
        buf.extend_from_slice(&self.header());
        buf
    }
    /// Get a mutable byte buffer for the payload.
    fn payload_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.payload_len());
        buf.extend_from_slice(&self.payload());
        buf
    }

    fn into_parts(self) -> (Self::Header, Bytes);
    
}
