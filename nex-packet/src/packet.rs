use bytes::{Bytes, BytesMut};
use std::marker::PhantomData;

/// An owned, decoded network packet.
///
/// Implementations own their serialized bytes and expose decoded header data.
/// For allocation-free inspection use a protocol's borrowed view type. For
/// in-place editing use [`MutablePacket`], and for constructing a new packet use
/// the types in [`crate::builder`].
pub trait Packet: Sized {
    type Header;

    /// Parse from a borrowed byte slice with structured diagnostics.
    fn try_from_buf(buf: &[u8]) -> Result<Self, crate::parse::ParseError>;

    /// Parse from owned bytes with structured diagnostics.
    fn try_from_bytes(bytes: Bytes) -> Result<Self, crate::parse::ParseError>;

    /// Parse from a byte slice, discarding structured diagnostics.
    #[deprecated(note = "use Packet::try_from_buf or the packet type's inherent try_from_buf")]
    fn from_buf(buf: &[u8]) -> Option<Self> {
        Self::try_from_buf(buf).ok()
    }

    /// Parse from owned bytes, discarding structured diagnostics.
    #[deprecated(note = "use Packet::try_from_bytes or the packet type's inherent try_from_bytes")]
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::try_from_bytes(bytes).ok()
    }

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

    /// Returns true when the serialized packet is empty.
    fn is_empty(&self) -> bool {
        self.total_len() == 0
    }
    /// Copy the packet into a new mutable byte buffer.
    ///
    /// This allocates. In new code, prefer [`copy_to_bytes_mut`] so the copy is
    /// explicit at the call site.
    #[deprecated(note = "use packet::copy_to_bytes_mut to make the allocation explicit")]
    #[allow(clippy::wrong_self_convention)]
    fn to_bytes_mut(&self) -> BytesMut {
        copy_to_bytes_mut(self)
    }
    /// Copy the header into a new mutable byte buffer.
    ///
    /// This does not mutate the packet. In new code, prefer
    /// [`copy_header_to_bytes_mut`].
    #[deprecated(note = "use packet::copy_header_to_bytes_mut to make the allocation explicit")]
    fn header_mut(&self) -> BytesMut {
        copy_header_to_bytes_mut(self)
    }
    /// Copy the payload into a new mutable byte buffer.
    ///
    /// This does not mutate the packet. In new code, prefer
    /// [`copy_payload_to_bytes_mut`].
    #[deprecated(note = "use packet::copy_payload_to_bytes_mut to make the allocation explicit")]
    fn payload_mut(&self) -> BytesMut {
        copy_payload_to_bytes_mut(self)
    }

    fn into_parts(self) -> (Self::Header, Bytes);
}

/// Copy an owned packet's complete serialization into a mutable buffer.
pub fn copy_to_bytes_mut<P: Packet>(packet: &P) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(packet.total_len());
    buffer.extend_from_slice(&packet.to_bytes());
    buffer
}

/// Copy an owned packet's serialized header into a mutable buffer.
pub fn copy_header_to_bytes_mut<P: Packet>(packet: &P) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(packet.header_len());
    buffer.extend_from_slice(&packet.header());
    buffer
}

/// Copy an owned packet's payload into a mutable buffer.
pub fn copy_payload_to_bytes_mut<P: Packet>(packet: &P) -> BytesMut {
    let mut buffer = BytesMut::with_capacity(packet.payload_len());
    buffer.extend_from_slice(&packet.payload());
    buffer
}

/// Represents a mutable network packet that can be parsed and modified in place.
///
/// Types implementing this trait work on top of the same backing buffer and allow
/// layered packet parsing to be chained without additional allocations. A mutable
/// view borrows its backing storage; it is distinct from both an owned [`Packet`]
/// and a builder.
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

    /// Returns true when the packet buffer is empty.
    fn is_empty(&self) -> bool {
        self.packet().is_empty()
    }

    /// Parse the current buffer into an owned immutable packet.
    ///
    /// This is a commit point: the current bytes are validated again, and the
    /// returned packet owns its serialization. Mutations that make a length or
    /// discriminant field inconsistent cause this method to return `None`.
    fn freeze(&self) -> Option<Self::Packet> {
        Self::Packet::try_from_buf(self.packet()).ok()
    }
}

/// A generic mutable packet wrapper that validates using the immutable packet
/// parser and exposes the raw buffer for in-place mutation.
///
/// Header and payload boundaries are parsed once at construction and cached.
/// Mutating bytes through [`MutablePacket::packet_mut`] does not update those
/// boundaries. If a structural field changes, call [`Self::refresh_layout`]
/// before requesting header or payload slices. [`MutablePacket::freeze`] always
/// validates the current bytes independently of the cached layout.
pub struct GenericMutablePacket<'a, P: Packet> {
    buffer: &'a mut [u8],
    header_len: usize,
    payload_len: usize,
    _marker: PhantomData<P>,
}

impl<'a, P: Packet> MutablePacket<'a> for GenericMutablePacket<'a, P> {
    type Packet = P;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        let packet = P::try_from_buf(buffer).ok()?;
        let header_len = packet.header_len();
        let payload_len = packet.payload_len();
        if header_len.checked_add(payload_len)? > buffer.len() {
            return None;
        }
        Some(Self {
            buffer,
            header_len,
            payload_len,
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
        &self.packet()[..self.header_len]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let (header, _) = self.buffer.split_at_mut(self.header_len);
        header
    }

    fn payload(&self) -> &[u8] {
        &self.packet()[self.header_len..self.header_len + self.payload_len]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let (_, payload) = self.buffer.split_at_mut(self.header_len);
        &mut payload[..self.payload_len]
    }
}

impl<'a, P: Packet> GenericMutablePacket<'a, P> {
    /// Construct a mutable packet without requiring a valid packet layout.
    ///
    /// A valid packet is parsed once and uses its decoded boundaries. Invalid
    /// input is exposed conservatively as an all-header, empty-payload view.
    /// Prefer [`MutablePacket::new`] when invalid input should be rejected.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        let (header_len, payload_len) = Self::parse_lengths(buffer).unwrap_or((buffer.len(), 0));
        Self {
            buffer,
            header_len,
            payload_len,
            _marker: PhantomData,
        }
    }

    /// Re-parse the current bytes and refresh the cached header/payload layout.
    ///
    /// Use this after changing a structural field through
    /// [`MutablePacket::packet_mut`]. On error, the previous cached boundaries
    /// remain unchanged.
    pub fn refresh_layout(&mut self) -> Result<(), crate::parse::ParseError> {
        let (header_len, payload_len) = Self::parse_lengths(self.buffer)?;
        self.header_len = header_len;
        self.payload_len = payload_len;
        Ok(())
    }

    fn parse_lengths(buffer: &[u8]) -> Result<(usize, usize), crate::parse::ParseError> {
        let packet = P::try_from_buf(buffer)?;
        let header_len = packet.header_len();
        let payload_len = packet.payload_len();
        match header_len
            .checked_add(payload_len)
            .filter(|total| *total <= buffer.len())
        {
            Some(_) => Ok((header_len, payload_len)),
            None => Err(crate::parse::ParseError::InvalidLength {
                context: "generic mutable packet layout",
                value: header_len.saturating_add(payload_len),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GenericMutablePacket, MutablePacket, Packet};
    use crate::parse::ParseError;
    use bytes::Bytes;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    static PARSE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct CountingPacket {
        bytes: Bytes,
    }

    impl Packet for CountingPacket {
        type Header = ();

        fn try_from_buf(buf: &[u8]) -> Result<Self, ParseError> {
            PARSE_COUNT.fetch_add(1, Ordering::Relaxed);
            if buf.len() < 2 {
                return Err(ParseError::BufferTooShort {
                    context: "counting packet",
                    minimum: 2,
                    actual: buf.len(),
                });
            }
            Ok(Self {
                bytes: Bytes::copy_from_slice(buf),
            })
        }

        fn try_from_bytes(bytes: Bytes) -> Result<Self, ParseError> {
            Self::try_from_buf(&bytes)
        }

        fn to_bytes(&self) -> Bytes {
            self.bytes.clone()
        }

        fn header(&self) -> Bytes {
            self.bytes.slice(..2)
        }

        fn payload(&self) -> Bytes {
            self.bytes.slice(2..)
        }

        fn header_len(&self) -> usize {
            2
        }

        fn payload_len(&self) -> usize {
            self.bytes.len() - 2
        }

        fn total_len(&self) -> usize {
            self.bytes.len()
        }

        fn into_parts(self) -> (Self::Header, Bytes) {
            ((), self.bytes.slice(2..))
        }
    }

    #[test]
    fn generic_mutable_packet_caches_layout_until_refresh_or_freeze() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        PARSE_COUNT.store(0, Ordering::Relaxed);
        let mut bytes = [0, 1, 2, 3];
        let mut packet =
            GenericMutablePacket::<CountingPacket>::new(&mut bytes).expect("valid packet");

        assert_eq!(PARSE_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(packet.header(), &[0, 1]);
        assert_eq!(packet.payload(), &[2, 3]);
        packet.header_mut()[0] = 9;
        packet.payload_mut()[0] = 8;
        assert_eq!(PARSE_COUNT.load(Ordering::Relaxed), 1);

        packet.refresh_layout().expect("refresh layout");
        assert_eq!(PARSE_COUNT.load(Ordering::Relaxed), 2);
        assert!(packet.freeze().is_some());
        assert_eq!(PARSE_COUNT.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn unchecked_invalid_packet_uses_safe_conservative_layout() {
        let _guard = TEST_LOCK.lock().expect("test lock");
        PARSE_COUNT.store(0, Ordering::Relaxed);
        let mut bytes = [1];
        let packet = GenericMutablePacket::<CountingPacket>::new_unchecked(&mut bytes);

        assert_eq!(packet.header(), &[1]);
        assert!(packet.payload().is_empty());
    }
}
