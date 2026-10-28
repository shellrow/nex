//! Minimal next-hop resolution for the raw packet examples.

use nex_core::{interface::Interface, mac::MacAddr};
use nex_datalink::{Channel, Config, channel};
use nex_packet::{
    arp::ArpOperation,
    builder::{
        arp::ArpPacketBuilder, ethernet::EthernetPacketBuilder, ipv6::Ipv6PacketBuilder,
        ndp::NdpPacketBuilder,
    },
    ethernet::EtherType,
    frame::{Frame, ParseOption},
    icmpv6::{self, Icmpv6Type},
    ip::IpNextProtocol,
    packet::Packet,
};
use std::{
    io,
    net::{IpAddr, Ipv6Addr},
    time::{Duration, Instant},
};

/// Resolve on-link destinations directly; use the gateway only for routed traffic.
pub fn destination_mac(
    interface: &Interface,
    source: IpAddr,
    target: IpAddr,
) -> io::Result<MacAddr> {
    if interface.is_tun() || interface.is_loopback() {
        return Ok(MacAddr::zero());
    }
    let on_link = match target {
        IpAddr::V4(ip) => interface.ipv4.iter().any(|network| network.contains(&ip)),
        IpAddr::V6(ip) => {
            ip.is_unicast_link_local() || interface.ipv6.iter().any(|network| network.contains(&ip))
        }
    };
    if !on_link {
        return interface
            .gateway
            .as_ref()
            .map(|gateway| gateway.mac_addr)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no gateway on the selected interface",
                )
            });
    }
    let mac = interface
        .mac_addr
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface has no MAC address"))?;
    let ethernet = EthernetPacketBuilder::new().source(mac);
    let request = match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => ethernet
            .destination(MacAddr::broadcast())
            .ethertype(EtherType::Arp)
            .payload(
                ArpPacketBuilder::new(mac, source, target)
                    .build()
                    .map_err(io::Error::other)?
                    .to_bytes(),
            )
            .build()
            .to_bytes(),
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            let octets = target.octets();
            let multicast = Ipv6Addr::new(
                0xff02,
                0,
                0,
                0,
                0,
                1,
                0xff00 | u16::from(octets[13]),
                u16::from_be_bytes([octets[14], octets[15]]),
            );
            let mut solicitation = NdpPacketBuilder::new(mac, source, target)
                .build()
                .map_err(io::Error::other)?;
            solicitation.header.checksum = icmpv6::checksum(&solicitation, &source, &multicast);
            let ip = Ipv6PacketBuilder::new()
                .source(source)
                .destination(multicast)
                .next_header(IpNextProtocol::Icmpv6)
                .hop_limit(255)
                .payload(solicitation.to_bytes())
                .build()
                .map_err(io::Error::other)?;
            ethernet
                .destination(MacAddr::new(
                    0x33, 0x33, 0xff, octets[13], octets[14], octets[15],
                ))
                .ethertype(EtherType::Ipv6)
                .payload(ip.to_bytes())
                .build()
                .to_bytes()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and target address families differ",
            ));
        }
    };
    let Channel::Ethernet(mut tx, mut rx) = channel(
        interface,
        Config::default()
            .with_read_buffer_size(1_048_576)
            .with_promiscuous(false)
            .with_read_timeout(Some(Duration::from_millis(100))),
    )
    .map_err(io::Error::other)?
    else {
        unreachable!()
    };
    for _ in 0..3 {
        tx.send(&request)
            .ok_or_else(|| io::Error::other("neighbor request exceeds send buffer"))??;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let packet = match rx.next() {
                Ok(packet) => packet,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Ok(frame) = Frame::try_from_buf(packet, ParseOption::default()) else {
                continue;
            };
            let Some(link) = frame.datalink else { continue };
            match target {
                IpAddr::V4(target) => {
                    if let Some(arp) = link.arp
                        && arp.operation == ArpOperation::Reply
                        && arp.sender_proto_addr == target
                        && IpAddr::V4(arp.target_proto_addr) == source
                    {
                        return Ok(arp.sender_hw_addr);
                    }
                }
                IpAddr::V6(target) => {
                    if let Some(ip) = frame.ip
                        && let Some(ipv6) = ip.ipv6
                        && ipv6.hop_limit == 255
                        && let Some(icmp) = ip.icmpv6
                        && icmp.icmpv6_type == Icmpv6Type::NeighborAdvertisement
                        && frame.payload.get(4..20) == Some(target.octets().as_slice())
                        && let Some(ethernet) = link.ethernet
                    {
                        return Ok(ethernet.source);
                    }
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("neighbor resolution timed out for {target}"),
    ))
}
