use nex_core::mac::MacAddr;
use nex_packet::dhcp::DHCP_MIN_PACKET_SIZE;
use nex_packet::dhcp::{DhcpHardwareType, DhcpOperation, MutableDhcpPacket};
use nex_packet::Packet;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct DhcpPacketBuilder {
    pub operation: DhcpOperation,
    pub htype: DhcpHardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Option<Ipv4Addr>,
    pub yiaddr: Option<Ipv4Addr>,
    pub siaddr: Option<Ipv4Addr>,
    pub giaddr: Option<Ipv4Addr>,
    pub chaddr: MacAddr,
    pub options: Vec<u8>,
}

impl DhcpPacketBuilder {
    pub fn new(transaction_id: u32, client_mac: MacAddr) -> Self {
        Self {
            operation: DhcpOperation::Request,
            htype: DhcpHardwareType::Ethernet,
            hlen: 6,
            hops: 0,
            xid: transaction_id,
            secs: 0,
            flags: 0,
            ciaddr: None,
            yiaddr: None,
            siaddr: None,
            giaddr: None,
            chaddr: client_mac,
            options: Vec::new(),
        }
    }

    /// Set DHCPDISCOVER options
    pub fn set_discover_options(&mut self) {
        self.operation = DhcpOperation::Request;
        self.options.clear();
        self.options.extend_from_slice(&[
            53, 1, 1, // DHCP Message Type: DHCPDISCOVER (1)
            55, 2, 1, 3,   // Parameter Request List: Subnet Mask (1), Router (3)
            255, // End
        ]);
    }

    /// Set DHCPDISCOVER options with builder pattern
    pub fn with_discover_options(mut self) -> Self {
        self.set_discover_options();
        self
    }

    /// Set DHCPREQUEST options
    pub fn set_request_options(&mut self, requested_ip: Ipv4Addr, server_id: Ipv4Addr) {
        self.operation = DhcpOperation::Request;
        self.options.clear();
        self.options.extend_from_slice(&[
            53,
            1,
            3, // DHCP Message Type: DHCPREQUEST (3)
            50,
            4, // Requested IP Address
            requested_ip.octets()[0],
            requested_ip.octets()[1],
            requested_ip.octets()[2],
            requested_ip.octets()[3],
            54,
            4, // DHCP Server Identifier
            server_id.octets()[0],
            server_id.octets()[1],
            server_id.octets()[2],
            server_id.octets()[3],
            55,
            2,
            1,
            3,   // Parameter Request List
            255, // End
        ]);
    }

    /// Set DHCPREQUEST options with builder pattern
    pub fn with_request_options(mut self, requested_ip: Ipv4Addr, server_id: Ipv4Addr) -> Self {
        self.set_request_options(requested_ip, server_id);
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; DHCP_MIN_PACKET_SIZE + self.options.len()];
        let mut dhcp_packet = MutableDhcpPacket::new(&mut buffer).unwrap();

        dhcp_packet.set_op(self.operation);
        dhcp_packet.set_htype(self.htype);
        dhcp_packet.set_hlen(self.hlen);
        dhcp_packet.set_hops(self.hops);
        dhcp_packet.set_xid(self.xid);
        dhcp_packet.set_secs(self.secs);
        dhcp_packet.set_flags(self.flags);
        dhcp_packet.set_ciaddr(self.ciaddr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)));
        dhcp_packet.set_yiaddr(self.yiaddr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)));
        dhcp_packet.set_siaddr(self.siaddr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)));
        dhcp_packet.set_giaddr(self.giaddr.unwrap_or(Ipv4Addr::new(0, 0, 0, 0)));
        dhcp_packet.set_chaddr(self.chaddr);

        dhcp_packet.set_chaddr_pad(&[0u8; 10]);
        dhcp_packet.set_sname(&[0u8; 64]);
        dhcp_packet.set_file(&[0u8; 128]);

        dhcp_packet.set_options(&self.options);

        dhcp_packet.packet().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_core::mac::MacAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_dhcp_discover_builder() {
        let transaction_id = 0x12345678;
        let client_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let builder = DhcpPacketBuilder::new(transaction_id, client_mac).with_discover_options();
        let packet = builder.build();

        assert!(packet.len() >= DHCP_MIN_PACKET_SIZE);
        assert_eq!(packet[0], 1);
        assert_eq!(
            u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            transaction_id
        );
        assert_eq!(&packet[28..34], &client_mac.octets());
    }

    #[test]
    fn test_dhcp_request_builder() {
        let transaction_id = 0x87654321;
        let client_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let requested_ip = Ipv4Addr::new(192, 168, 1, 100);
        let server_id = Ipv4Addr::new(192, 168, 1, 1);
        let builder = DhcpPacketBuilder::new(transaction_id, client_mac)
            .with_request_options(requested_ip, server_id);
        let packet = builder.build();

        assert!(packet.len() >= DHCP_MIN_PACKET_SIZE);
        assert_eq!(packet[0], 1);
        assert_eq!(
            u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            transaction_id
        );
        assert_eq!(&packet[28..34], &client_mac.octets());
        assert_eq!(packet[DHCP_MIN_PACKET_SIZE], 53);
        assert_eq!(packet[DHCP_MIN_PACKET_SIZE + 2], 3);
    }
}
