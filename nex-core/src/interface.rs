use crate::ip::{is_global_ip, is_global_ipv4, is_global_ipv6};
use crate::mac::MacAddr;
pub use ipnet::{self, Ipv4Net, Ipv6Net};
use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(unix)]
pub const IFF_UP: u32 = nex_sys::IFF_UP as u32;
#[cfg(windows)]
pub const IFF_UP: u32 = nex_sys::IFF_UP;

#[cfg(unix)]
pub const IFF_BROADCAST: u32 = nex_sys::IFF_BROADCAST as u32;
#[cfg(windows)]
pub const IFF_BROADCAST: u32 = nex_sys::IFF_BROADCAST;

#[cfg(unix)]
pub const IFF_LOOPBACK: u32 = nex_sys::IFF_LOOPBACK as u32;
#[cfg(windows)]
pub const IFF_LOOPBACK: u32 = nex_sys::IFF_LOOPBACK;

#[cfg(unix)]
pub const IFF_POINTOPOINT: u32 = nex_sys::IFF_POINTOPOINT as u32;
#[cfg(windows)]
pub const IFF_POINTOPOINT: u32 = nex_sys::IFF_POINTOPOINT;

#[cfg(unix)]
pub const IFF_MULTICAST: u32 = nex_sys::IFF_MULTICAST as u32;
#[cfg(windows)]
pub const IFF_MULTICAST: u32 = nex_sys::IFF_MULTICAST;

#[cfg(unix)]
pub const IFF_RUNNING: u32 = libc::IFF_RUNNING as u32;

/// Operational state of a network interface.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OperState {
    Unknown,
    NotPresent,
    Down,
    LowerLayerDown,
    Testing,
    Dormant,
    Up,
}

impl OperState {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperState::Unknown => "unknown",
            OperState::NotPresent => "notpresent",
            OperState::Down => "down",
            OperState::LowerLayerDown => "lowerlayerdown",
            OperState::Testing => "testing",
            OperState::Dormant => "dormant",
            OperState::Up => "up",
        }
    }

    pub fn from_if_flags(if_flags: u32) -> Self {
        #[cfg(unix)]
        {
            if if_flags & IFF_UP != 0 {
                if if_flags & IFF_RUNNING != 0 {
                    OperState::Up
                } else {
                    OperState::Dormant
                }
            } else {
                OperState::Down
            }
        }

        #[cfg(windows)]
        {
            if if_flags & IFF_UP != 0 {
                OperState::Up
            } else {
                OperState::Down
            }
        }
    }
}

impl std::fmt::Display for OperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for OperState {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(OperState::Unknown),
            "notpresent" => Ok(OperState::NotPresent),
            "down" => Ok(OperState::Down),
            "lowerlayerdown" => Ok(OperState::LowerLayerDown),
            "testing" => Ok(OperState::Testing),
            "dormant" => Ok(OperState::Dormant),
            "up" => Ok(OperState::Up),
            _ => Err(()),
        }
    }
}

impl From<netdev::interface::state::OperState> for OperState {
    fn from(value: netdev::interface::state::OperState) -> Self {
        match value {
            netdev::interface::state::OperState::Unknown => OperState::Unknown,
            netdev::interface::state::OperState::NotPresent => OperState::NotPresent,
            netdev::interface::state::OperState::Down => OperState::Down,
            netdev::interface::state::OperState::LowerLayerDown => OperState::LowerLayerDown,
            netdev::interface::state::OperState::Testing => OperState::Testing,
            netdev::interface::state::OperState::Dormant => OperState::Dormant,
            netdev::interface::state::OperState::Up => OperState::Up,
        }
    }
}

/// Cross-platform classification of a network interface.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum InterfaceType {
    Unknown,
    Ethernet,
    TokenRing,
    Fddi,
    BasicIsdn,
    PrimaryIsdn,
    Ppp,
    Loopback,
    Ethernet3Megabit,
    Slip,
    Atm,
    GenericModem,
    ProprietaryVirtual,
    FastEthernetT,
    Isdn,
    FastEthernetFx,
    Wireless80211,
    AsymmetricDsl,
    RateAdaptDsl,
    SymmetricDsl,
    VeryHighSpeedDsl,
    IPOverAtm,
    GigabitEthernet,
    Tunnel,
    MultiRateSymmetricDsl,
    HighPerformanceSerialBus,
    Wman,
    Wwanpp,
    Wwanpp2,
    Bridge,
    Can,
    PeerToPeerWireless,
    UnknownWithValue(u32),
}

impl InterfaceType {
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
            InterfaceType::ProprietaryVirtual => String::from("Proprietary Virtual/Internal"),
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
            InterfaceType::Bridge => String::from("Bridge"),
            InterfaceType::Can => String::from("CAN"),
            InterfaceType::PeerToPeerWireless => String::from("Peer-to-Peer Wireless"),
            InterfaceType::UnknownWithValue(v) => format!("Unknown ({v})"),
        }
    }
}

impl From<netdev::interface::types::InterfaceType> for InterfaceType {
    fn from(value: netdev::interface::types::InterfaceType) -> Self {
        match value {
            netdev::interface::types::InterfaceType::Unknown => InterfaceType::Unknown,
            netdev::interface::types::InterfaceType::Ethernet => InterfaceType::Ethernet,
            netdev::interface::types::InterfaceType::TokenRing => InterfaceType::TokenRing,
            netdev::interface::types::InterfaceType::Fddi => InterfaceType::Fddi,
            netdev::interface::types::InterfaceType::BasicIsdn => InterfaceType::BasicIsdn,
            netdev::interface::types::InterfaceType::PrimaryIsdn => InterfaceType::PrimaryIsdn,
            netdev::interface::types::InterfaceType::Ppp => InterfaceType::Ppp,
            netdev::interface::types::InterfaceType::Loopback => InterfaceType::Loopback,
            netdev::interface::types::InterfaceType::Ethernet3Megabit => {
                InterfaceType::Ethernet3Megabit
            }
            netdev::interface::types::InterfaceType::Slip => InterfaceType::Slip,
            netdev::interface::types::InterfaceType::Atm => InterfaceType::Atm,
            netdev::interface::types::InterfaceType::GenericModem => InterfaceType::GenericModem,
            netdev::interface::types::InterfaceType::ProprietaryVirtual => {
                InterfaceType::ProprietaryVirtual
            }
            netdev::interface::types::InterfaceType::FastEthernetT => InterfaceType::FastEthernetT,
            netdev::interface::types::InterfaceType::Isdn => InterfaceType::Isdn,
            netdev::interface::types::InterfaceType::FastEthernetFx => {
                InterfaceType::FastEthernetFx
            }
            netdev::interface::types::InterfaceType::Wireless80211 => InterfaceType::Wireless80211,
            netdev::interface::types::InterfaceType::AsymmetricDsl => InterfaceType::AsymmetricDsl,
            netdev::interface::types::InterfaceType::RateAdaptDsl => InterfaceType::RateAdaptDsl,
            netdev::interface::types::InterfaceType::SymmetricDsl => InterfaceType::SymmetricDsl,
            netdev::interface::types::InterfaceType::VeryHighSpeedDsl => {
                InterfaceType::VeryHighSpeedDsl
            }
            netdev::interface::types::InterfaceType::IPOverAtm => InterfaceType::IPOverAtm,
            netdev::interface::types::InterfaceType::GigabitEthernet => {
                InterfaceType::GigabitEthernet
            }
            netdev::interface::types::InterfaceType::Tunnel => InterfaceType::Tunnel,
            netdev::interface::types::InterfaceType::MultiRateSymmetricDsl => {
                InterfaceType::MultiRateSymmetricDsl
            }
            netdev::interface::types::InterfaceType::HighPerformanceSerialBus => {
                InterfaceType::HighPerformanceSerialBus
            }
            netdev::interface::types::InterfaceType::Wman => InterfaceType::Wman,
            netdev::interface::types::InterfaceType::Wwanpp => InterfaceType::Wwanpp,
            netdev::interface::types::InterfaceType::Wwanpp2 => InterfaceType::Wwanpp2,
            netdev::interface::types::InterfaceType::Bridge => InterfaceType::Bridge,
            netdev::interface::types::InterfaceType::Can => InterfaceType::Can,
            netdev::interface::types::InterfaceType::PeerToPeerWireless => {
                InterfaceType::PeerToPeerWireless
            }
            netdev::interface::types::InterfaceType::UnknownWithValue(v) => {
                InterfaceType::UnknownWithValue(v)
            }
        }
    }
}

impl TryFrom<u32> for InterfaceType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(InterfaceType::from(
            netdev::interface::types::InterfaceType::try_from(v)?,
        ))
    }
}

/// Address information for a related network device.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NetworkDevice {
    pub mac_addr: MacAddr,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

impl NetworkDevice {
    pub fn new() -> NetworkDevice {
        NetworkDevice {
            mac_addr: MacAddr::zero(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }
}

impl Default for NetworkDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl From<netdev::NetworkDevice> for NetworkDevice {
    fn from(value: netdev::NetworkDevice) -> Self {
        NetworkDevice {
            mac_addr: value.mac_addr,
            ipv4: value.ipv4,
            ipv6: value.ipv6,
        }
    }
}

/// Interface traffic statistics at a given point in time.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub timestamp: Option<SystemTime>,
}

impl From<netdev::stats::counters::InterfaceStats> for InterfaceStats {
    fn from(value: netdev::stats::counters::InterfaceStats) -> Self {
        InterfaceStats {
            rx_bytes: value.rx_bytes,
            tx_bytes: value.tx_bytes,
            timestamp: value.timestamp,
        }
    }
}

/// A network interface.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub if_type: InterfaceType,
    pub mac_addr: Option<MacAddr>,
    pub ipv4: Vec<Ipv4Net>,
    pub ipv6: Vec<Ipv6Net>,
    pub ipv6_scope_ids: Vec<u32>,
    pub flags: u32,
    pub oper_state: OperState,
    pub transmit_speed: Option<u64>,
    pub receive_speed: Option<u64>,
    pub stats: Option<InterfaceStats>,
    #[cfg(feature = "gateway")]
    pub gateway: Option<NetworkDevice>,
    #[cfg(feature = "gateway")]
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u32>,
    #[cfg(feature = "gateway")]
    pub default: bool,
}

impl Interface {
    #[cfg(feature = "gateway")]
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> Result<Interface, String> {
        get_default_interface()
    }

    pub fn dummy() -> Interface {
        Interface {
            index: 0,
            name: String::new(),
            friendly_name: None,
            description: None,
            if_type: InterfaceType::Unknown,
            mac_addr: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            ipv6_scope_ids: Vec::new(),
            flags: 0,
            oper_state: OperState::Unknown,
            transmit_speed: None,
            receive_speed: None,
            stats: None,
            #[cfg(feature = "gateway")]
            gateway: None,
            #[cfg(feature = "gateway")]
            dns_servers: Vec::new(),
            mtu: None,
            #[cfg(feature = "gateway")]
            default: false,
        }
    }

    /// Refresh all interface fields from the operating system.
    ///
    /// This performs a fresh system lookup and may be more expensive than
    /// the accessor methods on `Interface`.
    pub fn refresh(&mut self) -> io::Result<()> {
        let refreshed = lookup_interface(&self.name, self.index).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "interface could not be refreshed")
        })?;
        *self = refreshed.into();
        Ok(())
    }

    pub fn is_up(&self) -> bool {
        self.flags & IFF_UP != 0
    }

    pub fn is_loopback(&self) -> bool {
        self.flags & IFF_LOOPBACK != 0
    }

    pub fn is_point_to_point(&self) -> bool {
        self.flags & IFF_POINTOPOINT != 0
    }

    pub fn is_multicast(&self) -> bool {
        self.flags & IFF_MULTICAST != 0
    }

    pub fn is_broadcast(&self) -> bool {
        self.flags & IFF_BROADCAST != 0
    }

    pub fn is_tun(&self) -> bool {
        self.is_up() && self.is_point_to_point() && !self.is_broadcast() && !self.is_loopback()
    }

    pub fn is_running(&self) -> bool {
        #[cfg(unix)]
        {
            self.flags & IFF_RUNNING != 0
        }
        #[cfg(windows)]
        {
            self.is_up()
        }
    }

    pub fn is_physical(&self) -> bool {
        lookup_interface(&self.name, self.index)
            .map(|iface| iface.is_physical())
            .unwrap_or_else(|| {
                self.is_up() && self.is_running() && !self.is_tun() && !self.is_loopback()
            })
    }

    pub fn oper_state(&self) -> OperState {
        self.oper_state
    }

    pub fn is_oper_up(&self) -> bool {
        self.oper_state == OperState::Up
    }

    /// Refresh the operational state from the operating system.
    ///
    /// This may perform a fresh interface lookup.
    pub fn refresh_oper_state(&mut self) -> io::Result<()> {
        if let Some(iface) = lookup_interface(&self.name, self.index) {
            self.oper_state = iface.oper_state.into();
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "interface operational state could not be refreshed",
        ))
    }

    /// Refresh the operational state from the operating system.
    ///
    /// This may perform a fresh interface lookup.
    pub fn update_oper_state(&mut self) {
        let _ = self.refresh_oper_state();
    }

    /// Iterate IPv4 addresses without allocating a new vector.
    pub fn ipv4_addr_iter(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.ipv4.iter().map(|net| net.addr())
    }

    pub fn ipv4_addrs(&self) -> Vec<Ipv4Addr> {
        self.ipv4_addr_iter().collect()
    }

    /// Iterate IPv6 addresses without allocating a new vector.
    pub fn ipv6_addr_iter(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.ipv6.iter().map(|net| net.addr())
    }

    pub fn ipv6_addrs(&self) -> Vec<Ipv6Addr> {
        self.ipv6_addr_iter().collect()
    }

    /// Iterate IP addresses without allocating a new vector.
    pub fn ip_addr_iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ipv4_addr_iter()
            .map(IpAddr::V4)
            .chain(self.ipv6_addr_iter().map(IpAddr::V6))
    }

    pub fn ip_addrs(&self) -> Vec<IpAddr> {
        self.ip_addr_iter().collect()
    }

    pub fn has_ipv4(&self) -> bool {
        !self.ipv4.is_empty()
    }

    pub fn has_ipv6(&self) -> bool {
        !self.ipv6.is_empty()
    }

    pub fn has_global_ipv4(&self) -> bool {
        self.ipv4_addrs().iter().any(is_global_ipv4)
    }

    pub fn has_global_ipv6(&self) -> bool {
        self.ipv6_addrs().iter().any(is_global_ipv6)
    }

    pub fn has_global_ip(&self) -> bool {
        self.ip_addrs().iter().any(is_global_ip)
    }

    pub fn global_ipv4_addrs(&self) -> Vec<Ipv4Addr> {
        self.ipv4_addr_iter().filter(is_global_ipv4).collect()
    }

    pub fn global_ipv6_addrs(&self) -> Vec<Ipv6Addr> {
        self.ipv6_addr_iter().filter(is_global_ipv6).collect()
    }

    pub fn global_ip_addrs(&self) -> Vec<IpAddr> {
        self.ip_addr_iter().filter(is_global_ip).collect()
    }

    /// Refresh interface statistics from the operating system.
    ///
    /// This may perform a fresh interface lookup.
    pub fn refresh_stats(&mut self) -> io::Result<()> {
        if let Some(iface) = lookup_interface(&self.name, self.index) {
            self.stats = iface.stats.map(Into::into);
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "interface statistics could not be refreshed",
        ))
    }

    /// Refresh interface statistics from the operating system.
    ///
    /// This may perform a fresh interface lookup.
    pub fn update_stats(&mut self) -> io::Result<()> {
        self.refresh_stats()
    }
}

impl From<netdev::Interface> for Interface {
    fn from(value: netdev::Interface) -> Self {
        Interface {
            index: value.index,
            name: value.name,
            friendly_name: value.friendly_name,
            description: value.description,
            if_type: value.if_type.into(),
            mac_addr: value.mac_addr,
            ipv4: value.ipv4,
            ipv6: value.ipv6,
            ipv6_scope_ids: value.ipv6_scope_ids,
            flags: value.flags,
            oper_state: value.oper_state.into(),
            transmit_speed: value.transmit_speed,
            receive_speed: value.receive_speed,
            stats: value.stats.map(Into::into),
            #[cfg(feature = "gateway")]
            gateway: value.gateway.map(Into::into),
            #[cfg(feature = "gateway")]
            dns_servers: value.dns_servers,
            mtu: value.mtu,
            #[cfg(feature = "gateway")]
            default: value.default,
        }
    }
}

pub fn get_interfaces() -> Vec<Interface> {
    netdev::get_interfaces()
        .into_iter()
        .map(Into::into)
        .collect()
}

#[cfg(feature = "gateway")]
pub fn get_default_interface() -> Result<Interface, String> {
    netdev::get_default_interface().map(Into::into)
}

#[cfg(feature = "gateway")]
pub fn get_default_gateway() -> Result<NetworkDevice, String> {
    netdev::get_default_gateway().map(Into::into)
}

fn lookup_interface(name: &str, index: u32) -> Option<netdev::Interface> {
    netdev::get_interfaces()
        .into_iter()
        .find(|iface| iface.index == index || iface.name == name)
}
