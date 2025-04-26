//! This example shows all interfaces and their properties.
//!
//! If you want to focus on network interfaces,
//! you can use the netdev
//! https://github.com/shellrow/netdev

fn main() {
    let interfaces = nex::net::interface::get_interfaces();
    for interface in interfaces {
        println!("Interface:");
        println!("\tIndex: {}", interface.index);
        println!("\tName: {}", interface.name);
        println!("\tFriendly Name: {:?}", interface.friendly_name);
        println!("\tDescription: {:?}", interface.description);
        println!("\tType: {}", interface.if_type.name());
        println!("\tFlags: {:?}", interface.flags);
        println!("\t\tis UP {}", interface.is_up());
        println!("\t\tis LOOPBACK {}", interface.is_loopback());
        println!("\t\tis MULTICAST {}", interface.is_multicast());
        println!("\t\tis BROADCAST {}", interface.is_broadcast());
        println!("\t\tis POINT TO POINT {}", interface.is_point_to_point());
        println!("\t\tis TUN {}", interface.is_tun());
        println!("\t\tis RUNNING {}", interface.is_running());
        println!("\t\tis PHYSICAL {}", interface.is_physical());
        if let Some(mac_addr) = interface.mac_addr {
            println!("\tMAC Address: {}", mac_addr);
        } else {
            println!("\tMAC Address: (Failed to get mac address)");
        }
        println!("\tIPv4: {:?}", interface.ipv4);

        // Print the IPv6 addresses with the scope ID after them as a suffix
        let ipv6_strs: Vec<String> = interface
            .ipv6
            .iter()
            .zip(interface.ipv6_scope_ids)
            .map(|(ipv6, scope_id)| format!("{:?}%{}", ipv6, scope_id))
            .collect();
        println!("\tIPv6: [{}]", ipv6_strs.join(", "));

        println!("\tTransmit Speed: {:?}", interface.transmit_speed);
        println!("\tReceive Speed: {:?}", interface.receive_speed);
        println!("MTU: {:?}", interface.mtu);
        println!("Default: {}", interface.default);
        println!();
    }
}
