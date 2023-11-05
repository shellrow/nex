use crate::PrimitiveValues;

/// IP Next Level Protocol
#[repr(u8)]
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum IpNextLevelProtocol {
    /// IPv6 Hop-by-Hop Option \[RFC2460\]
    Hopopt = 0,
    /// Internet Control Message [RFC792]
    Icmp = 1,
    /// Internet Group Management [RFC1112]
    Igmp = 2,
    /// Gateway-to-Gateway [RFC823]
    Ggp = 3,
    /// IPv4 encapsulation [RFC2003]
    Ipv4 = 4,
    /// Stream [RFC1190][RFC1819]
    St = 5,
    /// Transmission Control [RFC793]
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol [RFC888]
    Egp = 8,
    /// any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol [RFC741]
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// User Datagram [RFC768]
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring [RFC869]
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    XnsIdp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol [RFC908]
    Rdp = 27,
    /// Internet Reliable Transaction [RFC938]
    Irtp = 28,
    /// ISO Transport Protocol Class 4 [RFC905]
    IsoTp4 = 29,
    /// Bulk Data Transfer Protocol [RFC969]
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol [RFC4340]
    Dccp = 33,
    /// Third Party Connect Protocol
    ThreePc = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation [RFC2473]
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol [RFC2205][RFC3209]
    Rsvp = 46,
    /// Generic Routing Encapsulation [RFC1701]
    Gre = 47,
    /// Dynamic Source Routing Protocol [RFC4728]
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload [RFC4303]
    Esp = 50,
    /// Authentication Header [RFC4302]
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    INlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol [RFC1735]
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// ICMPv6 [RFC4443]
    Icmpv6 = 58,
    /// No Next Header for IPv6 [RFC2460]
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6 [RFC2460]
    Ipv6Opts = 60,
    /// any host internal protocol
    HostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// any local network
    LocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// any distributed file system
    DistributedFs = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol/IP Traffic Manager
    TtpOrIptm = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP [RFC1583][RFC2328][RFC5340]
    OspfigP = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    IpIp = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation [RFC3378]
    Etherip = 97,
    /// Encapsulation Header [RFC1241]
    Encap = 98,
    /// any private encryption scheme
    PrivEncryption = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast [RFC4601]
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    AN = 107,
    /// IP Payload Compression Protocol [RFC2393]
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol [RFC5798]
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// any 0-hop protocol
    ZeroHop = 114,
    /// Layer Two Tunneling Protocol [RFC3931]
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    ///
    IsisOverIpv4 = 124,
    ///
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    ///
    Sscopmce = 128,
    ///
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel [RFC6172]
    Fc = 133,
    /// [RFC3175]
    RsvpE2eIgnore = 134,
    /// [RFC6275]
    MobilityHeader = 135,
    /// [RFC3828]
    UdpLite = 136,
    /// [RFC4023]
    MplsInIp = 137,
    /// MANET Protocols [RFC5498]
    Manet = 138,
    /// Host Identity Protocol [RFC5201]
    Hip = 139,
    /// Shim6 Protocol [RFC5533]
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload [RFC5840]
    Wesp = 141,
    /// Robust Header Compression [RFC5858]
    Rohc = 142,
    /// Use for experimentation and testing [RFC3692]
    Test1 = 253,
    /// Use for experimentation and testing [RFC3692]
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}

impl IpNextLevelProtocol {
    /// IpNextLevelProtocol from u8
    pub fn new(n: u8) -> Self {
        match n {
            0 => Self::Hopopt,
            1 => Self::Icmp,
            2 => Self::Igmp,
            3 => Self::Ggp,
            4 => Self::Ipv4,
            5 => Self::St,
            6 => Self::Tcp,
            7 => Self::Cbt,
            8 => Self::Egp,
            9 => Self::Igp,
            10 => Self::BbnRccMon,
            11 => Self::NvpII,
            12 => Self::Pup,
            13 => Self::Argus,
            14 => Self::Emcon,
            15 => Self::Xnet,
            16 => Self::Chaos,
            17 => Self::Udp,
            18 => Self::Mux,
            19 => Self::DcnMeas,
            20 => Self::Hmp,
            21 => Self::Prm,
            22 => Self::XnsIdp,
            23 => Self::Trunk1,
            24 => Self::Trunk2,
            25 => Self::Leaf1,
            26 => Self::Leaf2,
            27 => Self::Rdp,
            28 => Self::Irtp,
            29 => Self::IsoTp4,
            30 => Self::Netblt,
            31 => Self::MfeNsp,
            32 => Self::MeritInp,
            33 => Self::Dccp,
            34 => Self::ThreePc,
            35 => Self::Idpr,
            36 => Self::Xtp,
            37 => Self::Ddp,
            38 => Self::IdprCmtp,
            39 => Self::TpPlusPlus,
            40 => Self::Il,
            41 => Self::Ipv6,
            42 => Self::Sdrp,
            43 => Self::Ipv6Route,
            44 => Self::Ipv6Frag,
            45 => Self::Idrp,
            46 => Self::Rsvp,
            47 => Self::Gre,
            48 => Self::Dsr,
            49 => Self::Bna,
            50 => Self::Esp,
            51 => Self::Ah,
            52 => Self::INlsp,
            53 => Self::Swipe,
            54 => Self::Narp,
            55 => Self::Mobile,
            56 => Self::Tlsp,
            57 => Self::Skip,
            58 => Self::Icmpv6,
            59 => Self::Ipv6NoNxt,
            60 => Self::Ipv6Opts,
            61 => Self::HostInternal,
            62 => Self::Cftp,
            63 => Self::LocalNetwork,
            64 => Self::SatExpak,
            65 => Self::Kryptolan,
            66 => Self::Rvd,
            67 => Self::Ippc,
            68 => Self::DistributedFs,
            69 => Self::SatMon,
            70 => Self::Visa,
            71 => Self::Ipcv,
            72 => Self::Cpnx,
            73 => Self::Cphb,
            74 => Self::Wsn,
            75 => Self::Pvp,
            76 => Self::BrSatMon,
            77 => Self::SunNd,
            78 => Self::WbMon,
            79 => Self::WbExpak,
            80 => Self::IsoIp,
            81 => Self::Vmtp,
            82 => Self::SecureVmtp,
            83 => Self::Vines,
            84 => Self::TtpOrIptm,
            85 => Self::NsfnetIgp,
            86 => Self::Dgp,
            87 => Self::Tcf,
            88 => Self::Eigrp,
            89 => Self::OspfigP,
            90 => Self::SpriteRpc,
            91 => Self::Larp,
            92 => Self::Mtp,
            93 => Self::Ax25,
            94 => Self::IpIp,
            95 => Self::Micp,
            96 => Self::SccSp,
            97 => Self::Etherip,
            98 => Self::Encap,
            99 => Self::PrivEncryption,
            100 => Self::Gmtp,
            101 => Self::Ifmp,
            102 => Self::Pnni,
            103 => Self::Pim,
            104 => Self::Aris,
            105 => Self::Scps,
            106 => Self::Qnx,
            107 => Self::AN,
            108 => Self::IpComp,
            109 => Self::Snp,
            110 => Self::CompaqPeer,
            111 => Self::IpxInIp,
            112 => Self::Vrrp,
            113 => Self::Pgm,
            114 => Self::ZeroHop,
            115 => Self::L2tp,
            116 => Self::Ddx,
            117 => Self::Iatp,
            118 => Self::Stp,
            119 => Self::Srp,
            120 => Self::Uti,
            121 => Self::Smp,
            122 => Self::Sm,
            123 => Self::Ptp,
            124 => Self::IsisOverIpv4,
            125 => Self::Fire,
            126 => Self::Crtp,
            127 => Self::Crudp,
            128 => Self::Sscopmce,
            129 => Self::Iplt,
            130 => Self::Sps,
            131 => Self::Pipe,
            132 => Self::Sctp,
            133 => Self::Fc,
            134 => Self::RsvpE2eIgnore,
            135 => Self::MobilityHeader,
            136 => Self::UdpLite,
            137 => Self::MplsInIp,
            138 => Self::Manet,
            139 => Self::Hip,
            140 => Self::Shim6,
            141 => Self::Wesp,
            142 => Self::Rohc,
            253 => Self::Test1,
            254 => Self::Test2,
            _ => Self::Reserved,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            IpNextLevelProtocol::Hopopt => "Hopopt",
            IpNextLevelProtocol::Icmp => "Icmp",
            IpNextLevelProtocol::Igmp => "Igmp",
            IpNextLevelProtocol::Ggp => "Ggp",
            IpNextLevelProtocol::Ipv4 => "Ipv4",
            IpNextLevelProtocol::St => "St",
            IpNextLevelProtocol::Tcp => "Tcp",
            IpNextLevelProtocol::Cbt => "Cbt",
            IpNextLevelProtocol::Egp => "Egp",
            IpNextLevelProtocol::Igp => "Igp",
            IpNextLevelProtocol::BbnRccMon => "BbnRccMon",
            IpNextLevelProtocol::NvpII => "NvpII",
            IpNextLevelProtocol::Pup => "Pup",
            IpNextLevelProtocol::Argus => "Argus",
            IpNextLevelProtocol::Emcon => "Emcon",
            IpNextLevelProtocol::Xnet => "Xnet",
            IpNextLevelProtocol::Chaos => "Chaos",
            IpNextLevelProtocol::Udp => "Udp",
            IpNextLevelProtocol::Mux => "Mux",
            IpNextLevelProtocol::DcnMeas => "DcnMeas",
            IpNextLevelProtocol::Hmp => "Hmp",
            IpNextLevelProtocol::Prm => "Prm",
            IpNextLevelProtocol::XnsIdp => "XnsIdp",
            IpNextLevelProtocol::Trunk1 => "Trunk1",
            IpNextLevelProtocol::Trunk2 => "Trunk2",
            IpNextLevelProtocol::Leaf1 => "Leaf1",
            IpNextLevelProtocol::Leaf2 => "Leaf2",
            IpNextLevelProtocol::Rdp => "Rdp",
            IpNextLevelProtocol::Irtp => "Irtp",
            IpNextLevelProtocol::IsoTp4 => "IsoTp4",
            IpNextLevelProtocol::Netblt => "Netblt",
            IpNextLevelProtocol::MfeNsp => "MfeNsp",
            IpNextLevelProtocol::MeritInp => "MeritInp",
            IpNextLevelProtocol::Dccp => "Dccp",
            IpNextLevelProtocol::ThreePc => "ThreePc",
            IpNextLevelProtocol::Idpr => "Idpr",
            IpNextLevelProtocol::Xtp => "Xtp",
            IpNextLevelProtocol::Ddp => "Ddp",
            IpNextLevelProtocol::IdprCmtp => "IdprCmtp",
            IpNextLevelProtocol::TpPlusPlus => "TpPlusPlus",
            IpNextLevelProtocol::Il => "Il",
            IpNextLevelProtocol::Ipv6 => "Ipv6",
            IpNextLevelProtocol::Sdrp => "Sdrp",
            IpNextLevelProtocol::Ipv6Route => "Ipv6Route",
            IpNextLevelProtocol::Ipv6Frag => "Ipv6Frag",
            IpNextLevelProtocol::Idrp => "Idrp",
            IpNextLevelProtocol::Rsvp => "Rsvp",
            IpNextLevelProtocol::Gre => "Gre",
            IpNextLevelProtocol::Dsr => "Dsr",
            IpNextLevelProtocol::Bna => "Bna",
            IpNextLevelProtocol::Esp => "Esp",
            IpNextLevelProtocol::Ah => "Ah",
            IpNextLevelProtocol::INlsp => "INlsp",
            IpNextLevelProtocol::Swipe => "Swipe",
            IpNextLevelProtocol::Narp => "Narp",
            IpNextLevelProtocol::Mobile => "Mobile",
            IpNextLevelProtocol::Tlsp => "Tlsp",
            IpNextLevelProtocol::Skip => "Skip",
            IpNextLevelProtocol::Icmpv6 => "Icmpv6",
            IpNextLevelProtocol::Ipv6NoNxt => "Ipv6NoNxt",
            IpNextLevelProtocol::Ipv6Opts => "Ipv6Opts",
            IpNextLevelProtocol::HostInternal => "HostInternal",
            IpNextLevelProtocol::Cftp => "Cftp",
            IpNextLevelProtocol::LocalNetwork => "LocalNetwork",
            IpNextLevelProtocol::SatExpak => "SatExpak",
            IpNextLevelProtocol::Kryptolan => "Kryptolan",
            IpNextLevelProtocol::Rvd => "Rvd",
            IpNextLevelProtocol::Ippc => "Ippc",
            IpNextLevelProtocol::DistributedFs => "DistributedFs",
            IpNextLevelProtocol::SatMon => "SatMon",
            IpNextLevelProtocol::Visa => "Visa",
            IpNextLevelProtocol::Ipcv => "Ipcv",
            IpNextLevelProtocol::Cpnx => "Cpnx",
            IpNextLevelProtocol::Cphb => "Cphb",
            IpNextLevelProtocol::Wsn => "Wsn",
            IpNextLevelProtocol::Pvp => "Pvp",
            IpNextLevelProtocol::BrSatMon => "BrSatMon",
            IpNextLevelProtocol::SunNd => "SunNd",
            IpNextLevelProtocol::WbMon => "WbMon",
            IpNextLevelProtocol::WbExpak => "WbExpak",
            IpNextLevelProtocol::IsoIp => "IsoIp",
            IpNextLevelProtocol::Vmtp => "Vmtp",
            IpNextLevelProtocol::SecureVmtp => "SecureVmtp",
            IpNextLevelProtocol::Vines => "Vines",
            IpNextLevelProtocol::TtpOrIptm => "TtpOrIptm",
            IpNextLevelProtocol::NsfnetIgp => "NsfnetIgp",
            IpNextLevelProtocol::Dgp => "Dgp",
            IpNextLevelProtocol::Tcf => "Tcf",
            IpNextLevelProtocol::Eigrp => "Eigrp",
            IpNextLevelProtocol::OspfigP => "OspfigP",
            IpNextLevelProtocol::SpriteRpc => "SpriteRpc",
            IpNextLevelProtocol::Larp => "Larp",
            IpNextLevelProtocol::Mtp => "Mtp",
            IpNextLevelProtocol::Ax25 => "Ax25",
            IpNextLevelProtocol::IpIp => "IpIp",
            IpNextLevelProtocol::Micp => "Micp",
            IpNextLevelProtocol::SccSp => "SccSp",
            IpNextLevelProtocol::Etherip => "Etherip",
            IpNextLevelProtocol::Encap => "Encap",
            IpNextLevelProtocol::PrivEncryption => "PrivEncryption",
            IpNextLevelProtocol::Gmtp => "Gmtp",
            IpNextLevelProtocol::Ifmp => "Ifmp",
            IpNextLevelProtocol::Pnni => "Pnni",
            IpNextLevelProtocol::Pim => "Pim",
            IpNextLevelProtocol::Aris => "Aris",
            IpNextLevelProtocol::Scps => "Scps",
            IpNextLevelProtocol::Qnx => "Qnx",
            IpNextLevelProtocol::AN => "AN",
            IpNextLevelProtocol::IpComp => "IpComp",
            IpNextLevelProtocol::Snp => "Snp",
            IpNextLevelProtocol::CompaqPeer => "CompaqPeer",
            IpNextLevelProtocol::IpxInIp => "IpxInIp",
            IpNextLevelProtocol::Vrrp => "Vrrp",
            IpNextLevelProtocol::Pgm => "Pgm",
            IpNextLevelProtocol::ZeroHop => "ZeroHop",
            IpNextLevelProtocol::L2tp => "L2tp",
            IpNextLevelProtocol::Ddx => "Ddx",
            IpNextLevelProtocol::Iatp => "Iatp",
            IpNextLevelProtocol::Stp => "Stp",
            IpNextLevelProtocol::Srp => "Srp",
            IpNextLevelProtocol::Uti => "Uti",
            IpNextLevelProtocol::Smp => "Smp",
            IpNextLevelProtocol::Sm => "Sm",
            IpNextLevelProtocol::Ptp => "Ptp",
            IpNextLevelProtocol::IsisOverIpv4 => "IsisOverIpv4",
            IpNextLevelProtocol::Fire => "Fire",
            IpNextLevelProtocol::Crtp => "Crtp",
            IpNextLevelProtocol::Crudp => "Crudp",
            IpNextLevelProtocol::Sscopmce => "Sscopmce",
            IpNextLevelProtocol::Iplt => "Iplt",
            IpNextLevelProtocol::Sps => "Sps",
            IpNextLevelProtocol::Pipe => "Pipe",
            IpNextLevelProtocol::Sctp => "Sctp",
            IpNextLevelProtocol::Fc => "Fc",
            IpNextLevelProtocol::RsvpE2eIgnore => "RsvpE2eIgnore",
            IpNextLevelProtocol::MobilityHeader => "MobilityHeader",
            IpNextLevelProtocol::UdpLite => "UdpLite",
            IpNextLevelProtocol::MplsInIp => "MplsInIp",
            IpNextLevelProtocol::Manet => "Manet",
            IpNextLevelProtocol::Hip => "Hip",
            IpNextLevelProtocol::Shim6 => "Shim6",
            IpNextLevelProtocol::Wesp => "Wesp",
            IpNextLevelProtocol::Rohc => "Rohc",
            IpNextLevelProtocol::Test1 => "Test1",
            IpNextLevelProtocol::Test2 => "Test2",
            IpNextLevelProtocol::Reserved => "Reserved",
        }
    }
}

impl PrimitiveValues for IpNextLevelProtocol {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (*self as u8,)
    }
}
