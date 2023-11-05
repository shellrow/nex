use crate::PrimitiveValues;

use alloc::vec::Vec;

use std::net::Ipv4Addr;
use xenet_core::mac::MacAddr;
use xenet_macro::packet;
use xenet_macro_helper::types::*;

/// Represents an DHCP operation.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DhcpOperation {
    Request = 1,
    Reply = 2,
    Unknown(u8),
}

impl DhcpOperation {
    /// Constructs a new DhcpOperation from u8.
    pub fn new(value: u8) -> DhcpOperation {
        match value {
            1 => DhcpOperation::Request,
            2 => DhcpOperation::Reply,
            _ => DhcpOperation::Unknown(value),
        }
    }
}

impl PrimitiveValues for DhcpOperation {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match self {
            &DhcpOperation::Request => (1,),
            &DhcpOperation::Reply => (2,),
            &DhcpOperation::Unknown(n) => (n,),
        }
    }
}

/// Represents the Dhcp hardware types.
#[allow(non_snake_case)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DhcpHardwareType {
    Ethernet = 1,
    ExperimentalEthernet = 2,
    AmateurRadioAX25 = 3,
    ProteonProNETTokenRing = 4,
    Chaos = 5,
    IEEE802Networks = 6,
    ARCNET = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddress = 10,
    LocalTalk = 11,
    LocalNet = 12,
    UltraLink = 13,
    SMDS = 14,
    FrameRelay = 15,
    AsynchronousTransmissionMode = 16,
    HDLC = 17,
    FibreChannel = 18,
    AsynchronousTransmissionMode1 = 19,
    PropPointToPointSerial = 20,
    PPP = 21,
    SoftwareLoopback = 24,
    EON = 25,
    Ethernet3MB = 26,
    NSIP = 27,
    Slip = 28,
    ULTRALink = 29,
    DS3 = 30,
    SIP = 31,
    FrameRelayInterconnect = 32,
    AsynchronousTransmissionMode2 = 33,
    MILSTD188220 = 34,
    Metricom = 35,
    IEEE1394 = 37,
    MAPOS = 39,
    Twinaxial = 40,
    EUI64 = 41,
    HIPARP = 42,
    IPandARPoverISO7816_3 = 43,
    ARPSec = 44,
    IPsecTunnel = 45,
    InfiniBand = 47,
    TIA102Project25CommonAirInterface = 48,
    WiegandInterface = 49,
    PureIP = 50,
    HWExp1 = 51,
    HFI = 52,
    HWExp2 = 53,
    AEthernet = 54,
    HWExp3 = 55,
    IPsecTransport = 56,
    SDLCRadio = 57,
    SDLCMultipoint = 58,
    IWARP = 59,
    SixLoWPAN = 61,
    VLAN = 62,
    ProviderBridging = 63,
    IEEE802154 = 64,
    MAPOSinIPv4 = 65,
    MAPOSinIPv6 = 66,
    IEEE802154NonASKPHY = 70,
    Unknown(u8),
}

impl DhcpHardwareType {
    /// Constructs a new DhcpHardwareType from u8
    pub fn new(n: u8) -> DhcpHardwareType {
        match n {
            1 => DhcpHardwareType::Ethernet,
            2 => DhcpHardwareType::ExperimentalEthernet,
            3 => DhcpHardwareType::AmateurRadioAX25,
            4 => DhcpHardwareType::ProteonProNETTokenRing,
            5 => DhcpHardwareType::Chaos,
            6 => DhcpHardwareType::IEEE802Networks,
            7 => DhcpHardwareType::ARCNET,
            8 => DhcpHardwareType::Hyperchannel,
            9 => DhcpHardwareType::Lanstar,
            10 => DhcpHardwareType::AutonetShortAddress,
            11 => DhcpHardwareType::LocalTalk,
            12 => DhcpHardwareType::LocalNet,
            13 => DhcpHardwareType::UltraLink,
            14 => DhcpHardwareType::SMDS,
            15 => DhcpHardwareType::FrameRelay,
            16 => DhcpHardwareType::AsynchronousTransmissionMode,
            17 => DhcpHardwareType::HDLC,
            18 => DhcpHardwareType::FibreChannel,
            19 => DhcpHardwareType::AsynchronousTransmissionMode1,
            20 => DhcpHardwareType::PropPointToPointSerial,
            21 => DhcpHardwareType::PPP,
            24 => DhcpHardwareType::SoftwareLoopback,
            25 => DhcpHardwareType::EON,
            26 => DhcpHardwareType::Ethernet3MB,
            27 => DhcpHardwareType::NSIP,
            28 => DhcpHardwareType::Slip,
            29 => DhcpHardwareType::ULTRALink,
            30 => DhcpHardwareType::DS3,
            31 => DhcpHardwareType::SIP,
            32 => DhcpHardwareType::FrameRelayInterconnect,
            33 => DhcpHardwareType::AsynchronousTransmissionMode2,
            34 => DhcpHardwareType::MILSTD188220,
            35 => DhcpHardwareType::Metricom,
            37 => DhcpHardwareType::IEEE1394,
            39 => DhcpHardwareType::MAPOS,
            40 => DhcpHardwareType::Twinaxial,
            41 => DhcpHardwareType::EUI64,
            42 => DhcpHardwareType::HIPARP,
            43 => DhcpHardwareType::IPandARPoverISO7816_3,
            44 => DhcpHardwareType::ARPSec,
            45 => DhcpHardwareType::IPsecTunnel,
            47 => DhcpHardwareType::InfiniBand,
            48 => DhcpHardwareType::TIA102Project25CommonAirInterface,
            49 => DhcpHardwareType::WiegandInterface,
            50 => DhcpHardwareType::PureIP,
            51 => DhcpHardwareType::HWExp1,
            52 => DhcpHardwareType::HFI,
            53 => DhcpHardwareType::HWExp2,
            54 => DhcpHardwareType::AEthernet,
            55 => DhcpHardwareType::HWExp3,
            56 => DhcpHardwareType::IPsecTransport,
            57 => DhcpHardwareType::SDLCRadio,
            58 => DhcpHardwareType::SDLCMultipoint,
            59 => DhcpHardwareType::IWARP,
            61 => DhcpHardwareType::SixLoWPAN,
            62 => DhcpHardwareType::VLAN,
            63 => DhcpHardwareType::ProviderBridging,
            64 => DhcpHardwareType::IEEE802154,
            65 => DhcpHardwareType::MAPOSinIPv4,
            66 => DhcpHardwareType::MAPOSinIPv6,
            70 => DhcpHardwareType::IEEE802154NonASKPHY,
            _ => DhcpHardwareType::Unknown(n),
        }
    }
}

impl PrimitiveValues for DhcpHardwareType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        match self {
            &DhcpHardwareType::Ethernet => (1,),
            &DhcpHardwareType::ExperimentalEthernet => (2,),
            &DhcpHardwareType::AmateurRadioAX25 => (3,),
            &DhcpHardwareType::ProteonProNETTokenRing => (4,),
            &DhcpHardwareType::Chaos => (5,),
            &DhcpHardwareType::IEEE802Networks => (6,),
            &DhcpHardwareType::ARCNET => (7,),
            &DhcpHardwareType::Hyperchannel => (8,),
            &DhcpHardwareType::Lanstar => (9,),
            &DhcpHardwareType::AutonetShortAddress => (10,),
            &DhcpHardwareType::LocalTalk => (11,),
            &DhcpHardwareType::LocalNet => (12,),
            &DhcpHardwareType::UltraLink => (13,),
            &DhcpHardwareType::SMDS => (14,),
            &DhcpHardwareType::FrameRelay => (15,),
            &DhcpHardwareType::AsynchronousTransmissionMode => (16,),
            &DhcpHardwareType::HDLC => (17,),
            &DhcpHardwareType::FibreChannel => (18,),
            &DhcpHardwareType::AsynchronousTransmissionMode1 => (19,),
            &DhcpHardwareType::PropPointToPointSerial => (20,),
            &DhcpHardwareType::PPP => (21,),
            &DhcpHardwareType::SoftwareLoopback => (24,),
            &DhcpHardwareType::EON => (25,),
            &DhcpHardwareType::Ethernet3MB => (26,),
            &DhcpHardwareType::NSIP => (27,),
            &DhcpHardwareType::Slip => (28,),
            &DhcpHardwareType::ULTRALink => (29,),
            &DhcpHardwareType::DS3 => (30,),
            &DhcpHardwareType::SIP => (31,),
            &DhcpHardwareType::FrameRelayInterconnect => (32,),
            &DhcpHardwareType::AsynchronousTransmissionMode2 => (33,),
            &DhcpHardwareType::MILSTD188220 => (34,),
            &DhcpHardwareType::Metricom => (35,),
            &DhcpHardwareType::IEEE1394 => (37,),
            &DhcpHardwareType::MAPOS => (39,),
            &DhcpHardwareType::Twinaxial => (40,),
            &DhcpHardwareType::EUI64 => (41,),
            &DhcpHardwareType::HIPARP => (42,),
            &DhcpHardwareType::IPandARPoverISO7816_3 => (43,),
            &DhcpHardwareType::ARPSec => (44,),
            &DhcpHardwareType::IPsecTunnel => (45,),
            &DhcpHardwareType::InfiniBand => (47,),
            &DhcpHardwareType::TIA102Project25CommonAirInterface => (48,),
            &DhcpHardwareType::WiegandInterface => (49,),
            &DhcpHardwareType::PureIP => (50,),
            &DhcpHardwareType::HWExp1 => (51,),
            &DhcpHardwareType::HFI => (52,),
            &DhcpHardwareType::HWExp2 => (53,),
            &DhcpHardwareType::AEthernet => (54,),
            &DhcpHardwareType::HWExp3 => (55,),
            &DhcpHardwareType::IPsecTransport => (56,),
            &DhcpHardwareType::SDLCRadio => (57,),
            &DhcpHardwareType::SDLCMultipoint => (58,),
            &DhcpHardwareType::IWARP => (59,),
            &DhcpHardwareType::SixLoWPAN => (61,),
            &DhcpHardwareType::VLAN => (62,),
            &DhcpHardwareType::ProviderBridging => (63,),
            &DhcpHardwareType::IEEE802154 => (64,),
            &DhcpHardwareType::MAPOSinIPv4 => (65,),
            &DhcpHardwareType::MAPOSinIPv6 => (66,),
            &DhcpHardwareType::IEEE802154NonASKPHY => (70,),
            &DhcpHardwareType::Unknown(n) => (n,),
        }
    }
}

/// Represents an DHCP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Dhcp {
    #[construct_with(u8)]
    pub op: DhcpOperation,
    #[construct_with(u8)]
    pub htype: DhcpHardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32be,
    pub secs: u16be,
    pub flags: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub ciaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub yiaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub siaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub giaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub chaddr: MacAddr,
    #[length = "10"]
    pub chaddr_pad: Vec<u8>,
    #[length = "64"]
    pub sname: Vec<u8>,
    #[length = "128"]
    pub file: Vec<u8>,
    #[payload]
    pub options: Vec<u8>,
}
