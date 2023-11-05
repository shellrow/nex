use xenet_core::mac::MacAddr;
use xenet_packet::ethernet::{ETHERNET_HEADER_LEN, EtherType, MutableEthernetPacket};
use xenet_packet::ipv4::Ipv4Packet;
use xenet_packet::Packet;

/// Build Ethernet packet.
pub(crate) fn build_ethernet_packet(
    eth_packet: &mut MutableEthernetPacket,
    src_mac: MacAddr,
    dst_mac: MacAddr,
    ether_type: EtherType,
) {
    eth_packet.set_source(src_mac);
    eth_packet.set_destination(dst_mac);
    match ether_type {
        EtherType::Arp => {
            eth_packet.set_ethertype(EtherType::Arp);
        }
        EtherType::Ipv4 => {
            eth_packet.set_ethertype(EtherType::Ipv4);
        }
        EtherType::Ipv6 => {
            eth_packet.set_ethertype(EtherType::Ipv6);
        }
        _ => {
            // TODO
        }
    }
}

/// Build Ethernet ARP packet.
pub(crate) fn build_ethernet_arp_packet(
    eth_packet: &mut MutableEthernetPacket,
    src_mac: MacAddr,
) {
    eth_packet.set_source(src_mac);
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_ethertype(EtherType::Arp);
}

/// Ethernet Packet Builder.
#[derive(Clone, Debug)]
pub struct EthernetPacketBuilder {
    /// Source MAC address.
    pub src_mac: MacAddr,
    /// Destination MAC address.
    pub dst_mac: MacAddr,
    /// EtherType.
    pub ether_type: EtherType,
}

impl EthernetPacketBuilder {
    /// Constructs a new EthernetPacketBuilder.
    pub fn new() -> EthernetPacketBuilder {
        EthernetPacketBuilder {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            ether_type: EtherType::Ipv4,
        }
    }
    /// Build Ethernet packet and return bytes.
    pub fn build(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; ETHERNET_HEADER_LEN];
        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer).unwrap();
        build_ethernet_packet(
            &mut eth_packet,
            self.src_mac.clone(),
            self.dst_mac.clone(),
            self.ether_type,
        );
        eth_packet.to_immutable().packet().to_vec()
    }
}

/// Create Dummy Ethernet Frame.
#[allow(dead_code)]
pub(crate) fn create_dummy_ethernet_frame(
    payload_offset: usize,
    packet: &[u8],
) -> Vec<u8> {
    if packet.len() <= payload_offset {
        return packet.to_vec();
    }
    let buffer_size: usize = packet.len() + ETHERNET_HEADER_LEN - payload_offset;
    let mut buffer: Vec<u8> = vec![0; buffer_size];
    let src_mac: MacAddr = MacAddr::zero();
    let dst_mac: MacAddr = MacAddr::zero();
    let mut ether_type: EtherType = EtherType::Unknown(0);
    let mut eth_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    if let Some (ip_packet) = Ipv4Packet::new(&packet[payload_offset..]) {
        let version = ip_packet.get_version();
        if version == 4 {
            ether_type = EtherType::Ipv4;
        }
        else if version == 6 {
            ether_type = EtherType::Ipv6;
        }
    }
    build_ethernet_packet(&mut eth_packet, src_mac, dst_mac, ether_type);
    eth_packet.set_payload(&packet[payload_offset..]);
    eth_packet.to_immutable().packet().to_vec()
}
