use std::net::{Ipv4Addr, Ipv6Addr};

pub use netdev::ip::*;

pub fn is_global_ipv4(ipv4_addr: &Ipv4Addr) -> bool {
    !(ipv4_addr.octets()[0] == 0 // "This network"
        || ipv4_addr.is_private()
        || matches!(ipv4_addr.octets(), [169, 254, ..])
        || ipv4_addr.is_loopback()
        || ipv4_addr.is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        ||(ipv4_addr.octets()[0] == 192 && ipv4_addr.octets()[1] == 0 && ipv4_addr.octets()[2] == 0)
        || ipv4_addr.is_documentation()
        || ipv4_addr.octets()[0] == 198 && (ipv4_addr.octets()[1] & 0xfe) == 18
        || ipv4_addr.octets()[0] & 240 == 240 && !ipv4_addr.is_broadcast()
        || ipv4_addr.is_broadcast())
}

pub fn is_global_ipv6(ipv6_addr: &Ipv6Addr) -> bool {
    !(ipv6_addr.is_unspecified()
        || ipv6_addr.is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(ipv6_addr.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(ipv6_addr.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(ipv6_addr.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
            && !(
                // Port Control Protocol Anycast (`2001:1::1`)
                u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                || u128::from_be_bytes(ipv6_addr.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                // AMT (`2001:3::/32`)
                || matches!(ipv6_addr.segments(), [0x2001, 3, _, _, _, _, _, _])
                // AS112-v6 (`2001:4:112::/48`)
                || matches!(ipv6_addr.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                // ORCHIDv2 (`2001:20::/28`)
                || matches!(ipv6_addr.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
            ))
        // Reserved for documentation
        || ((ipv6_addr.segments()[0] == 0x2001) && (ipv6_addr.segments()[1] == 0x2) && (ipv6_addr.segments()[2] == 0))
        // Unique Local Address
        || ((ipv6_addr.segments()[0] & 0xfe00) == 0xfc00)
        // unicast address with link-local scope (`fc00::/7`)
        || ((ipv6_addr.segments()[0] & 0xffc0) == 0xfe80))
}
