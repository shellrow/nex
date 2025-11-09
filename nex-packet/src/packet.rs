use std::marker::PhantomData;
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

/// Represents a mutable network packet that can be parsed and modified in place.
///
/// Types implementing this trait work on top of the same backing buffer and allow
/// layered packet parsing to be chained without additional allocations.
pub trait MutablePacket<'a>: Sized {
    /// The immutable packet type associated with this mutable view.
    type Packet: Packet;

    /// Construct a mutable packet from the provided buffer.
    fn new(buffer: &'a mut [u8]) -> Option<Self>;

    /// Get a shared view over the entire packet buffer.
    fn packet(&self) -> &[u8];

    /// Get a mutable view over the entire packet buffer.
    fn packet_mut(&mut self) -> &mut [u8];

    /// Get the serialized header bytes of the packet.
    fn header(&self) -> &[u8];

    /// Get a mutable view over the serialized header bytes of the packet.
    fn header_mut(&mut self) -> &mut [u8];

    /// Get the payload bytes of the packet.
    fn payload(&self) -> &[u8];

    /// Get a mutable view over the payload bytes of the packet.
    fn payload_mut(&mut self) -> &mut [u8];

    /// Convert the mutable packet into its immutable counterpart.
    fn freeze(&self) -> Option<Self::Packet> {
        Self::Packet::from_buf(self.packet())
    }
}

/// A generic mutable packet wrapper that validates using the immutable packet
/// parser and exposes the raw buffer for in-place mutation.
pub struct GenericMutablePacket<'a, P: Packet> {
    buffer: &'a mut [u8],
    _marker: PhantomData<P>,
}

impl<'a, P: Packet> MutablePacket<'a> for GenericMutablePacket<'a, P> {
    type Packet = P;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        P::from_buf(buffer)?;
        Some(Self {
            buffer,
            _marker: PhantomData,
        })
    }

    fn packet(&self) -> &[u8] {
        &*self.buffer
    }

    fn packet_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn header(&self) -> &[u8] {
        let (header_len, _) = self.lengths();
        &self.packet()[..header_len]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let (header_len, _) = self.lengths();
        let (header, _) = (&mut *self.buffer).split_at_mut(header_len);
        header
    }

    fn payload(&self) -> &[u8] {
        let (header_len, payload_len) = self.lengths();
        &self.packet()[header_len..header_len + payload_len]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let (header_len, payload_len) = self.lengths();
        let (_, payload) = (&mut *self.buffer).split_at_mut(header_len);
        &mut payload[..payload_len]
    }
}

impl<'a, P: Packet> GenericMutablePacket<'a, P> {
    /// Construct a mutable packet without running additional validation.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            _marker: PhantomData,
        }
    }

    fn lengths(&self) -> (usize, usize) {
        if let Some(packet) = P::from_buf(self.packet()) {
            let header_len = packet.header_len();
            let payload_len = packet.payload_len();
            (header_len, payload_len)
        } else {
            (self.buffer.len(), 0)
        }
    }
}
