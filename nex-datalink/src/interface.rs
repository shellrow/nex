use nex_core::{Gateway, Ipv4Net, Ipv6Net, MacAddr};

use std::convert::TryFrom;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Type of Network Interface
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InterfaceType {
    /// Unknown interface type
    Unknown,
    /// The network interface using an Ethernet connection
    Ethernet,
    /// The network interface using a Token-Ring connection
    TokenRing,
    /// The network interface using a Fiber Distributed Data Interface (FDDI) connection
    Fddi,
    /// The network interface using a basic rate interface Integrated Services Digital Network (ISDN) connection
    BasicIsdn,
    /// The network interface using a primary rate interface Integrated Services Digital Network (ISDN) connection
    PrimaryIsdn,
    /// The network interface using a Point-To-Point protocol (PPP) connection
    Ppp,
    /// The loopback interface (often used for testing)
    Loopback,
    /// The network interface using an Ethernet 3 megabit/second connection
    Ethernet3Megabit,
    /// The network interface using a Serial Line Internet Protocol (SLIP) connection
    Slip,
    /// The network interface using asynchronous transfer mode (ATM) for data transmission
    Atm,
    /// The network interface using a modem
    GenericModem,
    /// The network interface using a Fast Ethernet connection over twisted pair and provides a data rate of 100 megabits per second (100BASE-T)
    FastEthernetT,
    /// The network interface using a connection configured for ISDN and the X.25 protocol.
    Isdn,
    /// The network interface using a Fast Ethernet connection over optical fiber and provides a data rate of 100 megabits per second (100Base-FX)
    FastEthernetFx,
    /// The network interface using a wireless LAN connection (IEEE 802.11)
    Wireless80211,
    /// The network interface using an Asymmetric Digital Subscriber Line (ADSL)
    AsymmetricDsl,
    /// The network interface using a Rate Adaptive Digital Subscriber Line (RADSL)
    RateAdaptDsl,
    /// The network interface using a Symmetric Digital Subscriber Line (SDSL)
    SymmetricDsl,
    /// The network interface using a Very High Data Rate Digital Subscriber Line (VDSL)
    VeryHighSpeedDsl,
    /// The network interface using the Internet Protocol (IP) in combination with asynchronous transfer mode (ATM) for data transmission
    IPOverAtm,
    /// The network interface using a gigabit Ethernet connection and provides a data rate of 1,000 megabits per second (1 gigabit per second)
    GigabitEthernet,
    /// The network interface using a tunnel connection
    Tunnel,
    /// The network interface using a Multirate Digital Subscriber Line
    MultiRateSymmetricDsl,
    /// The network interface using a High Performance Serial Bus
    HighPerformanceSerialBus,
    /// The network interface using a mobile broadband interface for WiMax devices
    Wman,
    /// The network interface using a mobile broadband interface for GSM-based devices
    Wwanpp,
    /// The network interface using a mobile broadband interface for CDMA-based devices
    Wwanpp2,
}

impl InterfaceType {
    /// Returns OS-specific value of InterfaceType
    #[cfg(target_os = "windows")]
    pub fn value(&self) -> u32 {
        match *self {
            InterfaceType::Unknown => 1,
            InterfaceType::Ethernet => 6,
            InterfaceType::TokenRing => 9,
            InterfaceType::Fddi => 15,
            InterfaceType::BasicIsdn => 20,
            InterfaceType::PrimaryIsdn => 21,
            InterfaceType::Ppp => 23,
            InterfaceType::Loopback => 24,
            InterfaceType::Ethernet3Megabit => 26,
            InterfaceType::Slip => 28,
            InterfaceType::Atm => 37,
            InterfaceType::GenericModem => 48,
            InterfaceType::FastEthernetT => 62,
            InterfaceType::Isdn => 63,
            InterfaceType::FastEthernetFx => 69,
            InterfaceType::Wireless80211 => 71,
            InterfaceType::AsymmetricDsl => 94,
            InterfaceType::RateAdaptDsl => 95,
            InterfaceType::SymmetricDsl => 96,
            InterfaceType::VeryHighSpeedDsl => 97,
            InterfaceType::IPOverAtm => 114,
            InterfaceType::GigabitEthernet => 117,
            InterfaceType::Tunnel => 131,
            InterfaceType::MultiRateSymmetricDsl => 143,
            InterfaceType::HighPerformanceSerialBus => 144,
            InterfaceType::Wman => 237,
            InterfaceType::Wwanpp => 243,
            InterfaceType::Wwanpp2 => 244,
        }
    }
    /// Returns OS-specific value of InterfaceType
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn value(&self) -> u32 {
        match *self {
            InterfaceType::Ethernet => 1,
            InterfaceType::TokenRing => 4,
            InterfaceType::Fddi => 774,
            InterfaceType::Ppp => 512,
            InterfaceType::Loopback => 772,
            InterfaceType::Ethernet3Megabit => 2,
            InterfaceType::Slip => 256,
            InterfaceType::Atm => 19,
            InterfaceType::Wireless80211 => 801,
            InterfaceType::Tunnel => 768,
            _ => u32::MAX,
        }
    }
    /// Returns OS-specific value of InterfaceType
    #[cfg(any(
        target_os = "macos",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "ios"
    ))]
    pub fn value(&self) -> u32 {
        // TODO
        match *self {
            _ => 0,
        }
    }
    /// Returns name of InterfaceType
    pub fn name(&self) -> String {
        match *self {
            InterfaceType::Unknown => String::from("Unknown"),
            InterfaceType::Ethernet => String::from("Ethernet"),
            InterfaceType::TokenRing => String::from("Token Ring"),
            InterfaceType::Fddi => String::from("FDDI"),
            InterfaceType::BasicIsdn => String::from("Basic ISDN"),
            InterfaceType::PrimaryIsdn => String::from("Primary ISDN"),
            InterfaceType::Ppp => String::from("PPP"),
            InterfaceType::Loopback => String::from("Loopback"),
            InterfaceType::Ethernet3Megabit => String::from("Ethernet 3 megabit"),
            InterfaceType::Slip => String::from("SLIP"),
            InterfaceType::Atm => String::from("ATM"),
            InterfaceType::GenericModem => String::from("Generic Modem"),
            InterfaceType::FastEthernetT => String::from("Fast Ethernet T"),
            InterfaceType::Isdn => String::from("ISDN"),
            InterfaceType::FastEthernetFx => String::from("Fast Ethernet FX"),
            InterfaceType::Wireless80211 => String::from("Wireless IEEE 802.11"),
            InterfaceType::AsymmetricDsl => String::from("Asymmetric DSL"),
            InterfaceType::RateAdaptDsl => String::from("Rate Adaptive DSL"),
            InterfaceType::SymmetricDsl => String::from("Symmetric DSL"),
            InterfaceType::VeryHighSpeedDsl => String::from("Very High Data Rate DSL"),
            InterfaceType::IPOverAtm => String::from("IP over ATM"),
            InterfaceType::GigabitEthernet => String::from("Gigabit Ethernet"),
            InterfaceType::Tunnel => String::from("Tunnel"),
            InterfaceType::MultiRateSymmetricDsl => String::from("Multi-Rate Symmetric DSL"),
            InterfaceType::HighPerformanceSerialBus => String::from("High Performance Serial Bus"),
            InterfaceType::Wman => String::from("WMAN"),
            InterfaceType::Wwanpp => String::from("WWANPP"),
            InterfaceType::Wwanpp2 => String::from("WWANPP2"),
        }
    }
}

impl TryFrom<u32> for InterfaceType {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            x if x == InterfaceType::Unknown.value() => Ok(InterfaceType::Unknown),
            x if x == InterfaceType::Ethernet.value() => Ok(InterfaceType::Ethernet),
            x if x == InterfaceType::TokenRing.value() => Ok(InterfaceType::TokenRing),
            x if x == InterfaceType::Fddi.value() => Ok(InterfaceType::Fddi),
            x if x == InterfaceType::BasicIsdn.value() => Ok(InterfaceType::BasicIsdn),
            x if x == InterfaceType::PrimaryIsdn.value() => Ok(InterfaceType::PrimaryIsdn),
            x if x == InterfaceType::Ppp.value() => Ok(InterfaceType::Ppp),
            x if x == InterfaceType::Loopback.value() => Ok(InterfaceType::Loopback),
            x if x == InterfaceType::Ethernet3Megabit.value() => {
                Ok(InterfaceType::Ethernet3Megabit)
            }
            x if x == InterfaceType::Slip.value() => Ok(InterfaceType::Slip),
            x if x == InterfaceType::Atm.value() => Ok(InterfaceType::Atm),
            x if x == InterfaceType::GenericModem.value() => Ok(InterfaceType::GenericModem),
            x if x == InterfaceType::FastEthernetT.value() => Ok(InterfaceType::FastEthernetT),
            x if x == InterfaceType::Isdn.value() => Ok(InterfaceType::Isdn),
            x if x == InterfaceType::FastEthernetFx.value() => Ok(InterfaceType::FastEthernetFx),
            x if x == InterfaceType::Wireless80211.value() => Ok(InterfaceType::Wireless80211),
            x if x == InterfaceType::AsymmetricDsl.value() => Ok(InterfaceType::AsymmetricDsl),
            x if x == InterfaceType::RateAdaptDsl.value() => Ok(InterfaceType::RateAdaptDsl),
            x if x == InterfaceType::SymmetricDsl.value() => Ok(InterfaceType::SymmetricDsl),
            x if x == InterfaceType::VeryHighSpeedDsl.value() => {
                Ok(InterfaceType::VeryHighSpeedDsl)
            }
            x if x == InterfaceType::IPOverAtm.value() => Ok(InterfaceType::IPOverAtm),
            x if x == InterfaceType::GigabitEthernet.value() => Ok(InterfaceType::GigabitEthernet),
            x if x == InterfaceType::Tunnel.value() => Ok(InterfaceType::Tunnel),
            x if x == InterfaceType::MultiRateSymmetricDsl.value() => {
                Ok(InterfaceType::MultiRateSymmetricDsl)
            }
            x if x == InterfaceType::HighPerformanceSerialBus.value() => {
                Ok(InterfaceType::HighPerformanceSerialBus)
            }
            x if x == InterfaceType::Wman.value() => Ok(InterfaceType::Wman),
            x if x == InterfaceType::Wwanpp.value() => Ok(InterfaceType::Wwanpp),
            x if x == InterfaceType::Wwanpp2.value() => Ok(InterfaceType::Wwanpp2),
            _ => Err(()),
        }
    }
}

/// Structure of Network Interface information
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetworkInterface {
    /// Index of network interface
    pub index: u32,
    /// Name of network interface
    pub name: String,
    /// Friendly Name of network interface
    pub friendly_name: Option<String>,
    /// Description of the network interface
    pub description: Option<String>,
    /// Interface Type
    pub if_type: InterfaceType,
    /// MAC address of network interface
    pub mac_addr: Option<MacAddr>,
    /// List of Ipv4Net for the network interface
    pub ipv4: Vec<Ipv4Net>,
    /// List of Ipv6Net for the network interface
    pub ipv6: Vec<Ipv6Net>,
    /// Flags for the network interface (OS Specific)
    pub flags: u32,
    /// Speed in bits per second of the transmit for the network interface
    pub transmit_speed: Option<u64>,
    /// Speed in bits per second of the receive for the network interface
    pub receive_speed: Option<u64>,
    /// Default gateway for the network interface
    pub gateway: Option<Gateway>,
}

impl NetworkInterface {
    pub fn new() -> NetworkInterface {
        NetworkInterface {
            index: 0,
            name: String::new(),
            friendly_name: None,
            description: None,
            if_type: InterfaceType::Unknown,
            mac_addr: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: 0,
            transmit_speed: None,
            receive_speed: None,
            gateway: None,
        }
    }
    pub fn from_default_net_type(interface: default_net::Interface) -> NetworkInterface {
        let mut net_interface = NetworkInterface::new();
        net_interface.index = interface.index;
        net_interface.name = interface.name;
        net_interface.friendly_name = interface.friendly_name;
        net_interface.description = interface.description;
        net_interface.if_type =
            InterfaceType::try_from(interface.if_type.value()).unwrap_or(InterfaceType::Unknown);
        if let Some(mac) = interface.mac_addr {
            net_interface.mac_addr = Some(MacAddr::from_octet(mac.octets()));
        }
        for ipv4 in interface.ipv4 {
            net_interface
                .ipv4
                .push(Ipv4Net::new(ipv4.addr, ipv4.prefix_len));
        }
        for ipv6 in interface.ipv6 {
            net_interface
                .ipv6
                .push(Ipv6Net::new(ipv6.addr, ipv6.prefix_len));
        }
        net_interface.flags = interface.flags;
        net_interface.transmit_speed = interface.transmit_speed;
        net_interface.receive_speed = interface.receive_speed;
        if let Some(gateway) = interface.gateway {
            net_interface.gateway = Some(Gateway {
                mac_addr: MacAddr::from_octet(gateway.mac_addr.octets()),
                ip_addr: gateway.ip_addr,
            });
        }
        net_interface
    }
    pub fn default() -> NetworkInterface {
        let default_interface: default_net::Interface = default_net::get_default_interface().unwrap();
        NetworkInterface::from_default_net_type(default_interface)
    }
    pub fn dummy() -> NetworkInterface {
        NetworkInterface {
            index: 0,
            name: String::new(),
            friendly_name: None,
            description: None,
            if_type: InterfaceType::Unknown,
            mac_addr: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            flags: 0,
            transmit_speed: None,
            receive_speed: None,
            gateway: None,
        }
    }
    /// Check if the network interface is up
    pub fn is_up(&self) -> bool {
        self.flags & (nex_sys::IFF_UP as u32) != 0
    }
    /// Check if the network interface is a Loopback interface
    pub fn is_loopback(&self) -> bool {
        self.flags & (nex_sys::IFF_LOOPBACK as u32) != 0
    }
    /// Check if the network interface is a Point-to-Point interface
    pub fn is_point_to_point(&self) -> bool {
        self.flags & (nex_sys::IFF_POINTOPOINT as u32) != 0
    }
    /// Check if the network interface is a Multicast interface
    pub fn is_multicast(&self) -> bool {
        self.flags & (nex_sys::IFF_MULTICAST as u32) != 0
    }
    /// Check if the network interface is a Broadcast interface
    pub fn is_broadcast(&self) -> bool {
        self.flags & (nex_sys::IFF_BROADCAST as u32) != 0
    }
    /// Check if the network interface is a TUN interface
    pub fn is_tun(&self) -> bool {
        self.is_up() && self.is_point_to_point() && !self.is_broadcast() && !self.is_loopback()
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn get_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces: Vec<NetworkInterface> = vec![];
    for iface in default_net::get_interfaces() {
        interfaces.push(NetworkInterface::from_default_net_type(iface));
    }
    interfaces
}
