use bytes::{Buf, BufMut, Bytes, BytesMut};
use nex_core::mac::MacAddr;
use std::net::Ipv4Addr;

use crate::packet::Packet;

/// Minimum size of an DHCP packet.
/// Options field is not included in this size.
pub const DHCP_MIN_PACKET_SIZE: usize = 236;

// DHCP Operation Codes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DhcpOperation {
    Request = 1,
    Reply = 2,
    Unknown(u8),
}

impl DhcpOperation {
    pub fn new(value: u8) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            other => Self::Unknown(other),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
            Self::Unknown(v) => *v,
        }
    }
}

// DHCP Hardware Types
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
    ATM = 16,
    HDLC = 17,
    FibreChannel = 18,
    ATM1 = 19,
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
    ATM2 = 33,
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
    TIA102CAI = 48,
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
    pub fn new(value: u8) -> Self {
        use DhcpHardwareType::*;
        match value {
            1 => Ethernet,
            2 => ExperimentalEthernet,
            3 => AmateurRadioAX25,
            4 => ProteonProNETTokenRing,
            5 => Chaos,
            6 => IEEE802Networks,
            7 => ARCNET,
            8 => Hyperchannel,
            9 => Lanstar,
            10 => AutonetShortAddress,
            11 => LocalTalk,
            12 => LocalNet,
            13 => UltraLink,
            14 => SMDS,
            15 => FrameRelay,
            16 => ATM,
            17 => HDLC,
            18 => FibreChannel,
            19 => ATM1,
            20 => PropPointToPointSerial,
            21 => PPP,
            24 => SoftwareLoopback,
            25 => EON,
            26 => Ethernet3MB,
            27 => NSIP,
            28 => Slip,
            29 => ULTRALink,
            30 => DS3,
            31 => SIP,
            32 => FrameRelayInterconnect,
            33 => ATM2,
            34 => MILSTD188220,
            35 => Metricom,
            37 => IEEE1394,
            39 => MAPOS,
            40 => Twinaxial,
            41 => EUI64,
            42 => HIPARP,
            43 => IPandARPoverISO7816_3,
            44 => ARPSec,
            45 => IPsecTunnel,
            47 => InfiniBand,
            48 => TIA102CAI,
            49 => WiegandInterface,
            50 => PureIP,
            51 => HWExp1,
            52 => HFI,
            53 => HWExp2,
            54 => AEthernet,
            55 => HWExp3,
            56 => IPsecTransport,
            57 => SDLCRadio,
            58 => SDLCMultipoint,
            59 => IWARP,
            61 => SixLoWPAN,
            62 => VLAN,
            63 => ProviderBridging,
            64 => IEEE802154,
            65 => MAPOSinIPv4,
            66 => MAPOSinIPv6,
            70 => IEEE802154NonASKPHY,
            other => Unknown(other),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            DhcpHardwareType::Ethernet => 1,
            DhcpHardwareType::ExperimentalEthernet => 2,
            DhcpHardwareType::AmateurRadioAX25 => 3,
            DhcpHardwareType::ProteonProNETTokenRing => 4,
            DhcpHardwareType::Chaos => 5,
            DhcpHardwareType::IEEE802Networks => 6,
            DhcpHardwareType::ARCNET => 7,
            DhcpHardwareType::Hyperchannel => 8,
            DhcpHardwareType::Lanstar => 9,
            DhcpHardwareType::AutonetShortAddress => 10,
            DhcpHardwareType::LocalTalk => 11,
            DhcpHardwareType::LocalNet => 12,
            DhcpHardwareType::UltraLink => 13,
            DhcpHardwareType::SMDS => 14,
            DhcpHardwareType::FrameRelay => 15,
            DhcpHardwareType::ATM => 16,
            DhcpHardwareType::HDLC => 17,
            DhcpHardwareType::FibreChannel => 18,
            DhcpHardwareType::ATM1 => 19,
            DhcpHardwareType::PropPointToPointSerial => 20,
            DhcpHardwareType::PPP => 21,
            DhcpHardwareType::SoftwareLoopback => 24,
            DhcpHardwareType::EON => 25,
            DhcpHardwareType::Ethernet3MB => 26,
            DhcpHardwareType::NSIP => 27,
            DhcpHardwareType::Slip => 28,
            DhcpHardwareType::ULTRALink => 29,
            DhcpHardwareType::DS3 => 30,
            DhcpHardwareType::SIP => 31,
            DhcpHardwareType::FrameRelayInterconnect => 32,
            DhcpHardwareType::ATM2 => 33,
            DhcpHardwareType::MILSTD188220 => 34,
            DhcpHardwareType::Metricom => 35,
            DhcpHardwareType::IEEE1394 => 37,
            DhcpHardwareType::MAPOS => 39,
            DhcpHardwareType::Twinaxial => 40,
            DhcpHardwareType::EUI64 => 41,
            DhcpHardwareType::HIPARP => 42,
            DhcpHardwareType::IPandARPoverISO7816_3 => 43,
            DhcpHardwareType::ARPSec => 44,
            DhcpHardwareType::IPsecTunnel => 45,
            DhcpHardwareType::InfiniBand => 47,
            DhcpHardwareType::TIA102CAI => 48,
            DhcpHardwareType::WiegandInterface => 49,
            DhcpHardwareType::PureIP => 50,
            DhcpHardwareType::HWExp1 => 51,
            DhcpHardwareType::HFI => 52,
            DhcpHardwareType::HWExp2 => 53,
            DhcpHardwareType::AEthernet => 54,
            DhcpHardwareType::HWExp3 => 55,
            DhcpHardwareType::IPsecTransport => 56,
            DhcpHardwareType::SDLCRadio => 57,
            DhcpHardwareType::SDLCMultipoint => 58,
            DhcpHardwareType::IWARP => 59,
            DhcpHardwareType::SixLoWPAN => 61,
            DhcpHardwareType::VLAN => 62,
            DhcpHardwareType::ProviderBridging => 63,
            DhcpHardwareType::IEEE802154 => 64,
            DhcpHardwareType::MAPOSinIPv4 => 65,
            DhcpHardwareType::MAPOSinIPv6 => 66,
            DhcpHardwareType::IEEE802154NonASKPHY => 70,
            DhcpHardwareType::Unknown(n) => *n,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DhcpHeader {
    pub op: DhcpOperation,
    pub htype: DhcpHardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub chaddr_pad: [u8; 10],
    pub sname: [u8; 64],
    pub file: [u8; 128],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpPacket {
    pub header: DhcpHeader,
    pub payload: Bytes,
}

impl Packet for DhcpPacket {
    type Header = DhcpHeader;

    fn from_buf(mut bytes: &[u8]) -> Option<Self> {
        if bytes.len() < DHCP_MIN_PACKET_SIZE {
            return None;
        }

        let op = DhcpOperation::new(bytes.get_u8());
        let htype = DhcpHardwareType::new(bytes.get_u8());
        let hlen = bytes.get_u8();
        let hops = bytes.get_u8();
        let xid = bytes.get_u32();
        let secs = bytes.get_u16();
        let flags = bytes.get_u16();

        let ciaddr = Ipv4Addr::from(bytes.get_u32());
        let yiaddr = Ipv4Addr::from(bytes.get_u32());
        let siaddr = Ipv4Addr::from(bytes.get_u32());
        let giaddr = Ipv4Addr::from(bytes.get_u32());

        let mut chaddr = [0u8; 6];
        bytes.copy_to_slice(&mut chaddr);
        let chaddr = MacAddr::from_octets(chaddr);

        let mut chaddr_pad = [0u8; 10];
        bytes.copy_to_slice(&mut chaddr_pad);

        let mut sname = [0u8; 64];
        bytes.copy_to_slice(&mut sname);

        let mut file = [0u8; 128];
        bytes.copy_to_slice(&mut file);

        let header = DhcpHeader {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            chaddr_pad,
            sname,
            file,
        };

        Some(Self {
            header,
            payload: Bytes::copy_from_slice(bytes),
        })
    }

    fn from_bytes(bytes: Bytes) -> Option<Self> {
        Self::from_buf(&bytes)
    }

    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DHCP_MIN_PACKET_SIZE + self.payload.len());

        buf.put_u8(self.header.op.value());
        buf.put_u8(self.header.htype.value());
        buf.put_u8(self.header.hlen);
        buf.put_u8(self.header.hops);
        buf.put_u32(self.header.xid);
        buf.put_u16(self.header.secs);
        buf.put_u16(self.header.flags);

        buf.put_slice(&self.header.ciaddr.octets());
        buf.put_slice(&self.header.yiaddr.octets());
        buf.put_slice(&self.header.siaddr.octets());
        buf.put_slice(&self.header.giaddr.octets());

        buf.put_slice(&self.header.chaddr.octets());
        buf.put_slice(&self.header.chaddr_pad);
        buf.put_slice(&self.header.sname);
        buf.put_slice(&self.header.file);

        buf.extend_from_slice(&self.payload);

        buf.freeze()
    }
    fn header(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DHCP_MIN_PACKET_SIZE);

        buf.put_u8(self.header.op.value());
        buf.put_u8(self.header.htype.value());
        buf.put_u8(self.header.hlen);
        buf.put_u8(self.header.hops);
        buf.put_u32(self.header.xid);
        buf.put_u16(self.header.secs);
        buf.put_u16(self.header.flags);

        buf.put_slice(&self.header.ciaddr.octets());
        buf.put_slice(&self.header.yiaddr.octets());
        buf.put_slice(&self.header.siaddr.octets());
        buf.put_slice(&self.header.giaddr.octets());

        buf.put_slice(&self.header.chaddr.octets());
        buf.put_slice(&self.header.chaddr_pad);
        buf.put_slice(&self.header.sname);
        buf.put_slice(&self.header.file);

        buf.freeze()
    }

    fn payload(&self) -> Bytes {
        self.payload.clone()
    }

    fn header_len(&self) -> usize {
        DHCP_MIN_PACKET_SIZE
    }

    fn payload_len(&self) -> usize {
        self.payload.len()
    }

    fn total_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    fn into_parts(self) -> (Self::Header, Bytes) {
        (self.header, self.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_core::mac::MacAddr;

    #[test]
    fn test_dhcp_packet_from_bytes_and_to_bytes() {
        let raw = {
            let mut buf = BytesMut::with_capacity(DHCP_MIN_PACKET_SIZE);
            buf.put_u8(1); // op: Request
            buf.put_u8(1); // htype: Ethernet
            buf.put_u8(6); // hlen
            buf.put_u8(0); // hops
            buf.put_u32(0x12345678); // xid
            buf.put_u16(0); // secs
            buf.put_u16(0); // flags
            buf.put_slice(&[0, 0, 0, 0]); // ciaddr
            buf.put_slice(&[0, 0, 0, 0]); // yiaddr
            buf.put_slice(&[0, 0, 0, 0]); // siaddr
            buf.put_slice(&[0, 0, 0, 0]); // giaddr
            buf.put_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // chaddr
            buf.extend_from_slice(&[0u8; 10]); // chaddr_pad
            buf.extend_from_slice(&[0u8; 64]); // sname
            buf.extend_from_slice(&[0u8; 128]); // file
            buf.freeze()
        };

        let packet = DhcpPacket::from_bytes(raw.clone()).expect("Failed to parse DHCP packet");

        assert_eq!(packet.header.op, DhcpOperation::Request);
        assert_eq!(packet.header.htype, DhcpHardwareType::Ethernet);
        assert_eq!(packet.header.hlen, 6);
        assert_eq!(packet.header.xid, 0x12345678);
        assert_eq!(packet.header.chaddr, MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55));

        let rebuilt = packet.to_bytes();
        assert_eq!(rebuilt, raw);
    }
}
