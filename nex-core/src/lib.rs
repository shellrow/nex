//! Core network types and helpers shared across the `nex` crates.
//! Includes interface, MAC/IP, and bitfield utilities used by low-level networking code.

/// Implementation-detail integer aliases used by generated packet accessors.
///
/// These aliases are public only so packet crates can share the generated
/// representation. They are not part of the stable application-facing API.
#[doc(hidden)]
pub mod bitfield;
pub mod interface;
pub mod ip;
pub mod mac;
