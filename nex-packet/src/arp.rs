//! ARP packet abstraction.

use crate::{
    ethernet::{ETHERNET_HEADER_LEN, EtherType},
    packet::{MutablePacket, Packet},
};

use bytes::{Bytes, BytesMut};
use core::fmt;
use nex_core::mac::MacAddr;
use std::net::Ipv4Addr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ARP Header Length.
pub const ARP_HEADER_LEN: usize = 28;
/// ARP Minimum Packet Length.
pub const ARP_PACKET_LEN: usize = ETHERNET_HEADER_LEN + ARP_HEADER_LEN;

/// Represents the ARP operation types.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ArpOperation {
    /// ARP request
    Request = 1,
    /// ARP reply
    Reply = 2,
    /// RARP request
    RarpRequest = 3,
    /// RARP reply
    RarpReply = 4,
    /// InARP request
    InRequest = 8,
    /// InARP reply
    InReply = 9,
    /// ARP NAK
    Nak = 10,
    /// Unknown ARP operation
    Unknown(u16),
}

impl ArpOperation {
    /// Constructs a new ArpOperation from u16
    pub fn new(value: u16) -> ArpOperation {
        match value {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            3 => ArpOperation::RarpRequest,
            4 => ArpOperation::RarpReply,
            8 => ArpOperation::InRequest,
            9 => ArpOperation::InReply,
            10 => ArpOperation::Nak,
            _ => ArpOperation::Unknown(value),
        }
    }
    /// Return the name of the ArpOperation
    pub fn name(&self) -> &str {
        match self {
            ArpOperation::Request => "ARP Request",
            ArpOperation::Reply => "ARP Reply",
            ArpOperation::RarpRequest => "RARP Request",
            ArpOperation::RarpReply => "RARP Reply",
            ArpOperation::InRequest => "InARP Request",
            ArpOperation::InReply => "InARP Reply",
            ArpOperation::Nak => "ARP NAK",
            ArpOperation::Unknown(_) => "Unknown ARP Operation",
        }
    }
    /// Return the value of the ArpOperation
    pub fn value(&self) -> u16 {
        match self {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::RarpRequest => 3,
            ArpOperation::RarpReply => 4,
            ArpOperation::InRequest => 8,
            ArpOperation::InReply => 9,
            ArpOperation::Nak => 10,
            ArpOperation::Unknown(value) => *value,
        }
    }
}

/// Represents the ARP hardware types.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ArpHardwareType {
    /// Ethernet (10Mb)
    Ethernet = 1,
    /// Experimental Ethernet (3Mb)
    ExperimentalEthernet = 2,
    /// Amateur Radio AX.25
    AmateurRadioAX25 = 3,
    /// Proteon ProNET Token Ring
    ProteonProNETTokenRing = 4,
    /// Chaos
    Chaos = 5,
    /// IEEE 802 Networks
    IEEE802Networks = 6,
    /// ARCNET
    ARCNET = 7,
    /// Hyperchannel
    Hyperchannel = 8,
    /// Lanstar
    Lanstar = 9,
    /// Autonet Short Address
    AutonetShortAddress = 10,
    /// LocalTalk
    LocalTalk = 11,
    /// LocalNet (IBM PCNet or SYTEK LocalNET)
    LocalNet = 12,
    /// Ultra link
    UltraLink = 13,
    /// SMDS
    SMDS = 14,
    /// Frame Relay
    FrameRelay = 15,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode = 16,
    /// HDLC
    HDLC = 17,
    /// Fibre Channel
    FibreChannel = 18,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode2 = 19,
    /// Serial Line
    SerialLine = 20,
    /// Asynchronous Transmission Mode (ATM)
    AsynchronousTransmissionMode3 = 21,
    /// MIL-STD-188-220
    MILSTD188220 = 22,
    /// Metricom
    Metricom = 23,
    /// IEEE 1394.1995
    IEEE13941995 = 24,
    /// MAPOS
    MAPOS = 25,
    /// Twinaxial
    Twinaxial = 26,
    /// EUI-64
    EUI64 = 27,
    /// HIPARP
    HIPARP = 28,
    /// IP and ARP over ISO 7816-3
    IPandARPoverISO78163 = 29,
    /// ARPSec
    ARPSec = 30,
    /// IPsec tunnel
    IPsecTunnel = 31,
    /// InfiniBand (TM)
    InfiniBand = 32,
    /// TIA-102 Project 25 Common Air Interface
    TIA102Project25CommonAirInterface = 16384,
    /// Wiegand Interface
    WiegandInterface = 16385,
    /// Pure IP
    PureIP = 16386,
    /// HW_EXP1
    HWEXP1 = 65280,
    /// HW_EXP2
    HWEXP2 = 65281,
    /// AEthernet
    AEthernet = 65282,
    /// Unknown ARP hardware type
    Unknown(u16),
}

impl ArpHardwareType {
    pub fn new(value: u16) -> ArpHardwareType {
        match value {
            1 => ArpHardwareType::Ethernet,
            2 => ArpHardwareType::ExperimentalEthernet,
            3 => ArpHardwareType::AmateurRadioAX25,
            4 => ArpHardwareType::ProteonProNETTokenRing,
            5 => ArpHardwareType::Chaos,
            6 => ArpHardwareType::IEEE802Networks,
            7 => ArpHardwareType::ARCNET,
            8 => ArpHardwareType::Hyperchannel,
            9 => ArpHardwareType::Lanstar,
            10 => ArpHardwareType::AutonetShortAddress,
            11 => ArpHardwareType::LocalTalk,
            12 => ArpHardwareType::LocalNet,
            13 => ArpHardwareType::UltraLink,
            14 => ArpHardwareType::SMDS,
            15 => ArpHardwareType::FrameRelay,
            16 => ArpHardwareType::AsynchronousTransmissionMode,
            17 => ArpHardwareType::HDLC,
            18 => ArpHardwareType::FibreChannel,
            19 => ArpHardwareType::AsynchronousTransmissionMode2,
            20 => ArpHardwareType::SerialLine,
            21 => ArpHardwareType::AsynchronousTransmissionMode3,
            22 => ArpHardwareType::MILSTD188220,
            23 => ArpHardwareType::Metricom,
            24 => ArpHardwareType::IEEE13941995,
            25 => ArpHardwareType::MAPOS,
            26 => ArpHardwareType::Twinaxial,
            27 => ArpHardwareType::EUI64,
            28 => ArpHardwareType::HIPARP,
            29 => ArpHardwareType::IPandARPoverISO78163,
            30 => ArpHardwareType::ARPSec,
            31 => ArpHardwareType::IPsecTunnel,
            32 => ArpHardwareType::InfiniBand,
            16384 => ArpHardwareType::TIA102Project25CommonAirInterface,
            16385 => ArpHardwareType::WiegandInterface,
            16386 => ArpHardwareType::PureIP,
            65280 => ArpHardwareType::HWEXP1,
            65281 => ArpHardwareType::HWEXP2,
            65282 => ArpHardwareType::AEthernet,
            _ => ArpHardwareType::Unknown(value),
        }
    }
    /// Return the name of the ARP hardware type
    pub fn name(&self) -> &str {
        match self {
            ArpHardwareType::Ethernet => "Ethernet",
            ArpHardwareType::ExperimentalEthernet => "Experimental Ethernet",
            ArpHardwareType::AmateurRadioAX25 => "Amateur Radio AX.25",
            ArpHardwareType::ProteonProNETTokenRing => "Proteon ProNET Token Ring",
            ArpHardwareType::Chaos => "Chaos",
            ArpHardwareType::IEEE802Networks => "IEEE 802 Networks",
            ArpHardwareType::ARCNET => "ARCNET",
            ArpHardwareType::Hyperchannel => "Hyperchannel",
            ArpHardwareType::Lanstar => "Lanstar",
            ArpHardwareType::AutonetShortAddress => "Autonet Short Address",
            ArpHardwareType::LocalTalk => "LocalTalk",
            ArpHardwareType::LocalNet => "LocalNet (IBM PCNet or SYTEK LocalNET)",
            ArpHardwareType::UltraLink => "Ultra link",
            ArpHardwareType::SMDS => "SMDS",
            ArpHardwareType::FrameRelay => "Frame Relay",
            ArpHardwareType::AsynchronousTransmissionMode => "Asynchronous Transmission Mode (ATM)",
            ArpHardwareType::HDLC => "HDLC",
            ArpHardwareType::FibreChannel => "Fibre Channel",
            ArpHardwareType::AsynchronousTransmissionMode2 => {
                "Asynchronous Transmission Mode (ATM) 2"
            }
            ArpHardwareType::SerialLine => "Serial Line",
            ArpHardwareType::AsynchronousTransmissionMode3 => {
                "Asynchronous Transmission Mode (ATM) 3"
            }
            ArpHardwareType::MILSTD188220 => "MIL-STD-188-220",
            ArpHardwareType::Metricom => "Metricom",
            ArpHardwareType::IEEE13941995 => "IEEE 1394.1995",
            ArpHardwareType::MAPOS => "MAPOS",
            ArpHardwareType::Twinaxial => "Twinaxial",
            ArpHardwareType::EUI64 => "EUI-64",
            ArpHardwareType::HIPARP => "HIPARP",
            ArpHardwareType::IPandARPoverISO78163 => "IP and ARP over ISO 7816-3",
            ArpHardwareType::ARPSec => "ARPSec",
            ArpHardwareType::IPsecTunnel => "IPsec Tunnel",
            ArpHardwareType::InfiniBand => "InfiniBand (TM)",
            ArpHardwareType::TIA102Project25CommonAirInterface => {
                "TIA-102 Project 25 Common Air Interface"
            }
            ArpHardwareType::WiegandInterface => "Wiegand Interface",
            ArpHardwareType::PureIP => "Pure IP",
            ArpHardwareType::HWEXP1 => "HW_EXP1",
            ArpHardwareType::HWEXP2 => "HW_EXP2",
            ArpHardwareType::AEthernet => "AEthernet",
            ArpHardwareType::Unknown(_) => "Unknown ARP Hardware Type",
        }
    }
    /// Return the value of the ARP hardware type
    pub fn value(&self) -> u16 {
        match self {
            ArpHardwareType::Ethernet => 1,
            ArpHardwareType::ExperimentalEthernet => 2,
            ArpHardwareType::AmateurRadioAX25 => 3,
            ArpHardwareType::ProteonProNETTokenRing => 4,
            ArpHardwareType::Chaos => 5,
            ArpHardwareType::IEEE802Networks => 6,
            ArpHardwareType::ARCNET => 7,
            ArpHardwareType::Hyperchannel => 8,
            ArpHardwareType::Lanstar => 9,
            ArpHardwareType::AutonetShortAddress => 10,
            ArpHardwareType::LocalTalk => 11,
            ArpHardwareType::LocalNet => 12,
            ArpHardwareType::UltraLink => 13,
            ArpHardwareType::SMDS => 14,
            ArpHardwareType::FrameRelay => 15,
            ArpHardwareType::AsynchronousTransmissionMode => 16,
            ArpHardwareType::HDLC => 17,
            ArpHardwareType::FibreChannel => 18,
            ArpHardwareType::AsynchronousTransmissionMode2 => 19,
            ArpHardwareType::SerialLine => 20,
            ArpHardwareType::AsynchronousTransmissionMode3 => 21,
            ArpHardwareType::MILSTD188220 => 22,
            ArpHardwareType::Metricom => 23,
            ArpHardwareType::IEEE13941995 => 24,
            ArpHardwareType::MAPOS => 25,
            ArpHardwareType::Twinaxial => 26,
            ArpHardwareType::EUI64 => 27,
            ArpHardwareType::HIPARP => 28,
            ArpHardwareType::IPandARPoverISO78163 => 29,
            ArpHardwareType::ARPSec => 30,
            ArpHardwareType::IPsecTunnel => 31,
            ArpHardwareType::InfiniBand => 32,
            ArpHardwareType::TIA102Project25CommonAirInterface => 16384,
            ArpHardwareType::WiegandInterface => 16385,
            ArpHardwareType::PureIP => 16386,
            ArpHardwareType::HWEXP1 => 65280,
            ArpHardwareType::HWEXP2 => 65281,
            ArpHardwareType::AEthernet => 65282,
            ArpHardwareType::Unknown(value) => *value,
        }
    }
}

/// Represents the ARP header.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArpHeader {
    pub hardware_type: ArpHardwareType,
    pub protocol_type: EtherType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: ArpOperation,
    pub sender_hw_addr: MacAddr,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddr,
    pub target_proto_addr: Ipv4Addr,
}

/// Represents an ARP Packet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArpPacket {
    /// The ARP header.
    pub header: ArpHeader,
    /// The payload of the ARP packet.
    pub payload: Bytes,
}

impl Packet for ArpPacket {
    type Header = ArpHeader;
    fn from_buf(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < ARP_HEADER_LEN {
            return None;
        }
        let hardware_type = ArpHardwareType::new(u16::from_be_bytes([bytes[0], bytes[1]]));
        let protocol_type = EtherType::new(u16::from_be_bytes([bytes[2], bytes[3]]));
        let hw_addr_len = bytes[4];
        let proto_addr_len = bytes[5];
        let operation = ArpOperation::new(u16::from_be_bytes([bytes[6], bytes[7]]));
        let sender_hw_addr = MacAddr::from_octets(bytes[8..14].try_into().unwrap());
        let sender_proto_addr = Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]);
        let target_hw_addr = MacAddr::from_octets(bytes[18..24].try_into().unwrap());
        let target_proto_addr = Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]);
        let payload = Bytes::copy_from_slice(&bytes[ARP_HEADER_LEN..]);

        Some(ArpPacket {
            header: ArpHeader {
                hardware_type,
                protocol_type,
                hw_addr_len,
                proto_addr_len,
                operation,
                sender_hw_addr,
                sender_proto_addr,
                target_hw_addr,
                target_proto_addr,
            },
            payload,
        })
    }
    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = Vec::with_capacity(ARP_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&self.header.hardware_type.value().to_be_bytes());
        buf.extend_from_slice(&self.header.protocol_type.value().to_be_bytes());
        buf.push(self.header.hw_addr_len);
        buf.push(self.header.proto_addr_len);
        buf.extend_from_slice(&self.header.operation.value().to_be_bytes());
        buf.extend_from_slice(&self.header.sender_hw_addr.octets());
        buf.extend_from_slice(&self.header.sender_proto_addr.octets());
        buf.extend_from_slice(&self.header.target_hw_addr.octets());
        buf.extend_from_slice(&self.header.target_proto_addr.octets());
        buf.extend_from_slice(&self.payload);

        Bytes::from(buf)
    }

    fn header(&self) -> Bytes {
        self.to_bytes()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        ARP_HEADER_LEN
    }
    fn payload_len(&self) -> usize {
        self.payload.len()
    }
    fn total_len(&self) -> usize {
        ARP_HEADER_LEN + self.payload.len()
    }
    fn to_bytes_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.total_len());
        buf.extend_from_slice(&self.to_bytes());
        buf
    }
    fn header_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.header_len());
        buf.extend_from_slice(&self.header());
        buf
    }
    fn payload_mut(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.payload_len());
        buf.extend_from_slice(&self.payload());
        buf
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        (self.header, self.payload)
    }
}

impl ArpPacket {
    /// Create a new ARP packet.
    pub fn new(header: ArpHeader, payload: Bytes) -> Self {
        ArpPacket { header, payload }
    }
}

impl fmt::Display for ArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ArpPacket {{ hardware_type: {}, protocol_type: {}, hw_addr_len: {}, proto_addr_len: {}, operation: {}, sender_hw_addr: {}, sender_proto_addr: {}, target_hw_addr: {}, target_proto_addr: {} }}",
            self.header.hardware_type.name(),
            self.header.protocol_type.name(),
            self.header.hw_addr_len,
            self.header.proto_addr_len,
            self.header.operation.name(),
            self.header.sender_hw_addr,
            self.header.sender_proto_addr,
            self.header.target_hw_addr,
            self.header.target_proto_addr
        )
    }
}

/// Represents a mutable ARP Packet.
pub struct MutableArpPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> MutablePacket<'a> for MutableArpPacket<'a> {
    type Packet = ArpPacket;

    fn new(buffer: &'a mut [u8]) -> Option<Self> {
        if buffer.len() < ARP_HEADER_LEN {
            None
        } else {
            Some(Self { buffer })
        }
    }

    fn packet(&self) -> &[u8] {
        &*self.buffer
    }

    fn packet_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    fn header(&self) -> &[u8] {
        &self.packet()[..ARP_HEADER_LEN]
    }

    fn header_mut(&mut self) -> &mut [u8] {
        let (header, _) = (&mut *self.buffer).split_at_mut(ARP_HEADER_LEN);
        header
    }

    fn payload(&self) -> &[u8] {
        &self.packet()[ARP_HEADER_LEN..]
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let (_, payload) = (&mut *self.buffer).split_at_mut(ARP_HEADER_LEN);
        payload
    }
}

impl<'a> MutableArpPacket<'a> {
    /// Create a packet without performing length checks.
    pub fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    fn raw(&self) -> &[u8] {
        &*self.buffer
    }

    fn raw_mut(&mut self) -> &mut [u8] {
        &mut *self.buffer
    }

    pub fn get_hardware_type(&self) -> ArpHardwareType {
        ArpHardwareType::new(u16::from_be_bytes([self.raw()[0], self.raw()[1]]))
    }

    pub fn set_hardware_type(&mut self, ty: ArpHardwareType) {
        self.raw_mut()[0..2].copy_from_slice(&ty.value().to_be_bytes());
    }

    pub fn get_protocol_type(&self) -> EtherType {
        EtherType::new(u16::from_be_bytes([self.raw()[2], self.raw()[3]]))
    }

    pub fn set_protocol_type(&mut self, ty: EtherType) {
        self.raw_mut()[2..4].copy_from_slice(&ty.value().to_be_bytes());
    }

    pub fn get_hw_addr_len(&self) -> u8 {
        self.raw()[4]
    }

    pub fn set_hw_addr_len(&mut self, len: u8) {
        self.raw_mut()[4] = len;
    }

    pub fn get_proto_addr_len(&self) -> u8 {
        self.raw()[5]
    }

    pub fn set_proto_addr_len(&mut self, len: u8) {
        self.raw_mut()[5] = len;
    }

    pub fn get_operation(&self) -> ArpOperation {
        ArpOperation::new(u16::from_be_bytes([self.raw()[6], self.raw()[7]]))
    }

    pub fn set_operation(&mut self, op: ArpOperation) {
        self.raw_mut()[6..8].copy_from_slice(&op.value().to_be_bytes());
    }

    pub fn get_sender_hw_addr(&self) -> MacAddr {
        MacAddr::from_octets(self.raw()[8..14].try_into().unwrap())
    }

    pub fn set_sender_hw_addr(&mut self, addr: MacAddr) {
        self.raw_mut()[8..14].copy_from_slice(&addr.octets());
    }

    pub fn get_sender_proto_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.raw()[14],
            self.raw()[15],
            self.raw()[16],
            self.raw()[17],
        )
    }

    pub fn set_sender_proto_addr(&mut self, addr: Ipv4Addr) {
        self.raw_mut()[14..18].copy_from_slice(&addr.octets());
    }

    pub fn get_target_hw_addr(&self) -> MacAddr {
        MacAddr::from_octets(self.raw()[18..24].try_into().unwrap())
    }

    pub fn set_target_hw_addr(&mut self, addr: MacAddr) {
        self.raw_mut()[18..24].copy_from_slice(&addr.octets());
    }

    pub fn get_target_proto_addr(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.raw()[24],
            self.raw()[25],
            self.raw()[26],
            self.raw()[27],
        )
    }

    pub fn set_target_proto_addr(&mut self, addr: Ipv4Addr) {
        self.raw_mut()[24..28].copy_from_slice(&addr.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_valid_arp_packet() {
        let raw = [
            0x00, 0x01, // Hardware Type: Ethernet
            0x08, 0x00, // Protocol Type: IPv4
            0x06, // HW Addr Len
            0x04, // Proto Addr Len
            0x00, 0x01, // Operation: Request
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
            192, 168, 1, 1, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            192, 168, 1, 2, // Target IP
        ];

        let padded = [&raw[..], &[0xde, 0xad, 0xbe, 0xef]].concat();
        let packet = ArpPacket::from_bytes(Bytes::copy_from_slice(&padded)).unwrap();

        assert_eq!(packet.header.hardware_type, ArpHardwareType::Ethernet);
        assert_eq!(packet.header.protocol_type, EtherType::Ipv4);
        assert_eq!(packet.header.hw_addr_len, 6);
        assert_eq!(packet.header.proto_addr_len, 4);
        assert_eq!(packet.header.operation, ArpOperation::Request);
        assert_eq!(
            packet.header.sender_hw_addr,
            MacAddr::from_octets([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            packet.header.sender_proto_addr,
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            packet.header.target_hw_addr,
            MacAddr::from_octets([0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            packet.header.target_proto_addr,
            Ipv4Addr::new(192, 168, 1, 2)
        );
        assert_eq!(
            packet.payload,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn test_serialize_roundtrip() {
        let original = ArpPacket {
            header: ArpHeader {
                hardware_type: ArpHardwareType::Ethernet,
                protocol_type: EtherType::Ipv4,
                hw_addr_len: 6,
                proto_addr_len: 4,
                operation: ArpOperation::Reply,
                sender_hw_addr: MacAddr::from_octets([1, 2, 3, 4, 5, 6]),
                sender_proto_addr: Ipv4Addr::new(10, 0, 0, 1),
                target_hw_addr: MacAddr::from_octets([10, 20, 30, 40, 50, 60]),
                target_proto_addr: Ipv4Addr::new(10, 0, 0, 2),
            },
            payload: Bytes::from_static(&[0xbe, 0xef]),
        };

        let bytes = original.to_bytes();
        let parsed = ArpPacket::from_bytes(bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_parse_invalid_short_packet() {
        let short = Bytes::from_static(&[0u8; 10]);
        assert!(ArpPacket::from_bytes(short).is_none());
    }

    #[test]
    fn test_unknown_operation_and_hw_type() {
        let raw = [
            0x99, 0x99, // Hardware Type: unknown
            0x08, 0x00, // Protocol Type: IPv4
            0x06, 0x04, 0x99, 0x99, // Operation: unknown
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 192, 168, 1, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            192, 168, 1, 2, 0x00, 0x01, 0x02, 0x03,
        ];

        let packet = ArpPacket::from_bytes(Bytes::copy_from_slice(&raw)).unwrap();
        match packet.header.hardware_type {
            ArpHardwareType::Unknown(v) => assert_eq!(v, 0x9999),
            _ => panic!("Expected unknown hardware type"),
        }
        match packet.header.operation {
            ArpOperation::Unknown(v) => assert_eq!(v, 0x9999),
            _ => panic!("Expected unknown operation"),
        }
    }

    #[test]
    fn test_mutable_arp_packet_updates() {
        let mut raw = [
            0x00, 0x01, // Hardware Type: Ethernet
            0x08, 0x00, // Protocol Type: IPv4
            0x06, // HW Addr Len
            0x04, // Proto Addr Len
            0x00, 0x01, // Operation: Request
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Sender MAC
            192, 168, 1, 1, // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC
            192, 168, 1, 2, // Target IP
            0xde, 0xad, 0xbe, 0xef, // payload
        ];

        let mut packet = MutableArpPacket::new(&mut raw).expect("mutable arp");
        assert_eq!(packet.get_operation(), ArpOperation::Request);
        packet.set_operation(ArpOperation::Reply);
        packet.set_sender_proto_addr(Ipv4Addr::new(10, 0, 0, 1));
        packet.payload_mut()[0] = 0xaa;

        let frozen = packet.freeze().expect("freeze");
        assert_eq!(frozen.header.operation, ArpOperation::Reply);
        assert_eq!(frozen.header.sender_proto_addr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(frozen.payload[0], 0xaa);
    }
}
