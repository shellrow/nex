//! Utilities for tracking checksum recalculation state.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Controls how and when checksum recalculation happens for a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumMode {
    /// Checksum updates are handled manually by the caller.
    Manual,
    /// Checksum updates happen automatically whenever a tracked field changes.
    Automatic,
}

impl Default for ChecksumMode {
    fn default() -> Self {
        ChecksumMode::Manual
    }
}

/// Tracks whether a packet's checksum needs to be recomputed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChecksumState {
    mode: ChecksumMode,
    dirty: bool,
}

impl ChecksumState {
    /// Creates a new checksum state with manual recalculation enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current mode controlling checksum updates.
    pub fn mode(&self) -> ChecksumMode {
        self.mode
    }

    /// Sets how checksum updates should be handled.
    pub fn set_mode(&mut self, mode: ChecksumMode) {
        self.mode = mode;
    }

    /// Enables automatic checksum recomputation.
    pub fn enable_automatic(&mut self) {
        self.mode = ChecksumMode::Automatic;
    }

    /// Disables automatic checksum recomputation.
    pub fn disable_automatic(&mut self) {
        self.mode = ChecksumMode::Manual;
    }

    /// Returns true if checksum recomputation is automatic.
    pub fn automatic(&self) -> bool {
        matches!(self.mode, ChecksumMode::Automatic)
    }

    /// Marks the checksum as stale due to a field mutation.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Clears the dirty flag after a successful recomputation.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Returns true if the checksum needs to be recomputed.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
}

/// Captures the pseudo-header inputs required for transport checksum calculations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportChecksumContext {
    /// Transport checksum associated with an IPv4 pseudo-header.
    Ipv4 {
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    /// Transport checksum associated with an IPv6 pseudo-header.
    Ipv6 {
        source: Ipv6Addr,
        destination: Ipv6Addr,
    },
}

impl TransportChecksumContext {
    /// Builds an IPv4 checksum context.
    pub fn ipv4(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        TransportChecksumContext::Ipv4 {
            source,
            destination,
        }
    }

    /// Builds an IPv6 checksum context.
    pub fn ipv6(source: Ipv6Addr, destination: Ipv6Addr) -> Self {
        TransportChecksumContext::Ipv6 {
            source,
            destination,
        }
    }
}
