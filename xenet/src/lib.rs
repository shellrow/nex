/// Provides core network types and functionality.
/// Mainly for xenet, but also for extensions to standard net module.
pub mod net {
    pub use xenet_core::*;
}

/// Support for sending and receiving data link layer packets.
pub mod datalink {
    pub use xenet_datalink::*;
}

/// Support for packet parsing and manipulation.
pub mod packet {
    pub use xenet_packet::*;
}

/// Support for sending and receiving transport layer packets.
pub mod socket {
    pub use xenet_socket::*;
}

pub fn is_supported_os() -> bool {
    cfg!(target_os = "linux")
        || cfg!(target_os = "windows")
        || cfg!(target_os = "macos")
        || cfg!(target_os = "android")
        || cfg!(target_os = "freebsd")
        || cfg!(target_os = "fuchsia")
        || cfg!(target_os = "netbsd")
        || (cfg!(target_os = "redox") && cfg!(nightly))
        || (cfg!(target_os = "solaris") && !cfg!(target_vendor = "apple"))
        || cfg!(target_os = "ios")
        || cfg!(target_os = "illumos")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_supported_os() {
        assert!(is_supported_os());
    }
}
