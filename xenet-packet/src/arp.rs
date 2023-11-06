//! ARP packet abstraction.

use crate::ethernet::{EtherType, ETHERNET_HEADER_LEN};
use crate::PrimitiveValues;

use alloc::vec::Vec;

use std::net::Ipv4Addr;
use xenet_core::mac::MacAddr;
use xenet_macro::packet;

/// ARP Header Length.
pub const ARP_HEADER_LEN: usize = 28;
/// ARP Minimum Packet Length.
pub const ARP_PACKET_LEN: usize = ETHERNET_HEADER_LEN + ARP_HEADER_LEN;

/// Represents the ARP header.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// Represents the ARP operation types.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl PrimitiveValues for ArpOperation {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        match *self {
            ArpOperation::Request => (1,),
            ArpOperation::Reply => (2,),
            ArpOperation::RarpRequest => (3,),
            ArpOperation::RarpReply => (4,),
            ArpOperation::InRequest => (8,),
            ArpOperation::InReply => (9,),
            ArpOperation::Nak => (10,),
            ArpOperation::Unknown(n) => (n,),
        }
    }
}

/// Represents the ARP hardware types.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

impl PrimitiveValues for ArpHardwareType {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        match *self {
            ArpHardwareType::Ethernet => (1,),
            ArpHardwareType::ExperimentalEthernet => (2,),
            ArpHardwareType::AmateurRadioAX25 => (3,),
            ArpHardwareType::ProteonProNETTokenRing => (4,),
            ArpHardwareType::Chaos => (5,),
            ArpHardwareType::IEEE802Networks => (6,),
            ArpHardwareType::ARCNET => (7,),
            ArpHardwareType::Hyperchannel => (8,),
            ArpHardwareType::Lanstar => (9,),
            ArpHardwareType::AutonetShortAddress => (10,),
            ArpHardwareType::LocalTalk => (11,),
            ArpHardwareType::LocalNet => (12,),
            ArpHardwareType::UltraLink => (13,),
            ArpHardwareType::SMDS => (14,),
            ArpHardwareType::FrameRelay => (15,),
            ArpHardwareType::AsynchronousTransmissionMode => (16,),
            ArpHardwareType::HDLC => (17,),
            ArpHardwareType::FibreChannel => (18,),
            ArpHardwareType::AsynchronousTransmissionMode2 => (19,),
            ArpHardwareType::SerialLine => (20,),
            ArpHardwareType::AsynchronousTransmissionMode3 => (21,),
            ArpHardwareType::MILSTD188220 => (22,),
            ArpHardwareType::Metricom => (23,),
            ArpHardwareType::IEEE13941995 => (24,),
            ArpHardwareType::MAPOS => (25,),
            ArpHardwareType::Twinaxial => (26,),
            ArpHardwareType::EUI64 => (27,),
            ArpHardwareType::HIPARP => (28,),
            ArpHardwareType::IPandARPoverISO78163 => (29,),
            ArpHardwareType::ARPSec => (30,),
            ArpHardwareType::IPsecTunnel => (31,),
            ArpHardwareType::InfiniBand => (32,),
            ArpHardwareType::TIA102Project25CommonAirInterface => (16384,),
            ArpHardwareType::WiegandInterface => (16385,),
            ArpHardwareType::PureIP => (16386,),
            ArpHardwareType::HWEXP1 => (65280,),
            ArpHardwareType::HWEXP2 => (65281,),
            ArpHardwareType::AEthernet => (65282,),
            ArpHardwareType::Unknown(n) => (n,),
        }
    }
}

/// Represents an ARP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Arp {
    #[construct_with(u16)]
    pub hardware_type: ArpHardwareType,
    #[construct_with(u16)]
    pub protocol_type: EtherType,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    #[construct_with(u16)]
    pub operation: ArpOperation,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub sender_hw_addr: MacAddr,
    #[construct_with(u8, u8, u8, u8)]
    pub sender_proto_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub target_hw_addr: MacAddr,
    #[construct_with(u8, u8, u8, u8)]
    pub target_proto_addr: Ipv4Addr,
    #[payload]
    #[length = "0"]
    pub payload: Vec<u8>,
}
