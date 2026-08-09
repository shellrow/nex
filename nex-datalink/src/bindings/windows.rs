#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
// These type names mirror `Packet32.h` / the Win32 SDK verbatim so the FFI
// declarations can be diffed against the upstream headers.
#![allow(clippy::upper_case_acronyms)]

use std::io;
use std::mem;
use std::ptr;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryA;
use windows_sys::core::PCWSTR;

#[repr(C)]
pub struct _ADAPTER;
pub type ADAPTER = _ADAPTER;
pub type LPADAPTER = *mut _ADAPTER;

#[repr(C)]
pub struct _PACKET {
    pub hEvent: HANDLE,
    pub OverLapped: OVERLAPPED,
    pub Buffer: PVOID,
    pub Length: UINT,
    pub ulBytesReceived: u32,
    pub bIoComplete: BOOLEAN,
}
pub type PACKET = _PACKET;
pub type LPPACKET = *mut _PACKET;

pub type TCHAR = libc::c_char;
pub type PTSTR = *mut TCHAR;
pub type BOOLEAN = u8;

pub type PVOID = *mut std::ffi::c_void;
pub type PCHAR = *mut libc::c_char;
pub type PWCHAR = *mut PCWSTR;
pub type UINT = libc::c_uint;
pub type ULONG = libc::c_ulong;
pub type PULONG = *mut ULONG;
pub type ULONG64 = u64;
pub type UINT32 = u32;
pub type UINT8 = u8;
pub type INT = i32;

const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
const MAX_ADAPTER_NAME_LENGTH: usize = 256;
const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

// from ntddndis.h
pub const NDIS_PACKET_TYPE_DIRECTED: ULONG = 0x00000001;
pub const NDIS_PACKET_TYPE_MULTICAST: ULONG = 0x00000002;
pub const NDIS_PACKET_TYPE_BROADCAST: ULONG = 0x00000008;
pub const NDIS_PACKET_TYPE_PROMISCUOUS: ULONG = 0x00000020;

/// The filter set matching what a normal host stack would receive, used when
/// promiscuous capture is not requested.
pub const NDIS_PACKET_TYPE_NON_PROMISCUOUS: ULONG =
    NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST | NDIS_PACKET_TYPE_MULTICAST;

/// Select the Npcap hardware filter for the requested capture mode.
pub fn hw_filter_for(promiscuous: bool) -> ULONG {
    if promiscuous {
        NDIS_PACKET_TYPE_PROMISCUOUS
    } else {
        NDIS_PACKET_TYPE_NON_PROMISCUOUS
    }
}

// Convert interface name to NPF device name
pub fn to_npf_name(name: &str) -> String {
    format!("\\Device\\NPF_{}", name)
}

// Packet.dll is resolved at run time rather than through an import library.
//
// A static `#[link(name = "Packet")]` import would make *every* binary built
// against nex fail to start on a machine without Npcap: the loader resolves
// imports before `main` runs, so the process dies with a message the program
// can never intercept. Npcap is an optional third-party driver, and its
// default (non "WinPcap API-compatible") install places Packet.dll in
// `System32\Npcap\` rather than on the default DLL search path, so even an
// Npcap-equipped machine could fail that way.
//
// Loading lazily turns "Npcap is missing" into an ordinary `io::Error` from
// `channel()`, and lets callers that never touch the datalink layer run with
// no Npcap at all. It also drops the Npcap SDK build-time requirement.

/// Build the `PacketApi` struct and its symbol-resolving loader from one list
/// of `Packet32.h` prototypes, so the two cannot drift apart.
macro_rules! packet_api {
    ($( fn $name:ident($($arg:ty),* $(,)?) $(-> $ret:ty)?; )+) => {
        /// Resolved entry points into Packet.dll.
        #[derive(Debug, Clone, Copy)]
        #[allow(non_snake_case)]
        pub struct PacketApi {
            $( pub $name: unsafe extern "C" fn($($arg),*) $(-> $ret)?, )+
        }

        impl PacketApi {
            /// # Safety
            ///
            /// `module` must be a live handle to a Packet.dll whose exports
            /// match the `Packet32.h` prototypes listed here.
            unsafe fn resolve(module: HMODULE) -> Result<Self, &'static str> {
                Ok(Self {
                    $( $name: {
                        // SAFETY: `module` is live per this function's contract
                        // and the name is a NUL-terminated literal.
                        let symbol = unsafe {
                            GetProcAddress(
                                module,
                                concat!(stringify!($name), "\0").as_ptr(),
                            )
                        };
                        match symbol {
                            // SAFETY: The symbol resolved from Packet.dll, whose
                            // prototype is reproduced verbatim above. Packet32.h
                            // declares no calling convention, so these are cdecl
                            // on every Windows architecture.
                            Some(symbol) => unsafe {
                                mem::transmute::<
                                    unsafe extern "system" fn() -> isize,
                                    unsafe extern "C" fn($($arg),*) $(-> $ret)?,
                                >(symbol)
                            },
                            None => return Err(stringify!($name)),
                        }
                    }, )+
                })
            }
        }
    };
}

// from Packet32.h
packet_api! {
    fn PacketSendPacket(LPADAPTER, LPPACKET, BOOLEAN) -> BOOLEAN;
    fn PacketReceivePacket(LPADAPTER, LPPACKET, BOOLEAN) -> BOOLEAN;
    fn PacketAllocatePacket() -> LPPACKET;
    fn PacketInitPacket(LPPACKET, PVOID, UINT);
    fn PacketFreePacket(LPPACKET);
    fn PacketOpenAdapter(PCHAR) -> LPADAPTER;
    fn PacketCloseAdapter(LPADAPTER);
    fn PacketSetHwFilter(LPADAPTER, ULONG) -> BOOLEAN;
    fn PacketSetMinToCopy(LPADAPTER, libc::c_int) -> BOOLEAN;
    fn PacketSetBuff(LPADAPTER, libc::c_int) -> BOOLEAN;
    fn PacketSetReadTimeout(LPADAPTER, libc::c_int) -> BOOLEAN;
}

/// Cached result of the one-time load attempt. `Err` holds a message rather
/// than an `io::Error` because the latter is not cloneable.
static PACKET_API: OnceLock<Result<PacketApi, String>> = OnceLock::new();

/// Candidate locations for Packet.dll, most specific first.
///
/// Npcap's default install puts the DLLs in `System32\Npcap\`, which is *not*
/// on the DLL search path. Only a "WinPcap API-compatible mode" install (or a
/// legacy WinPcap) puts them where a bare name resolves.
fn packet_dll_candidates() -> Vec<Vec<u8>> {
    let mut candidates = Vec::new();

    // SAFETY: Passing a null buffer with length 0 asks only for the required
    // size, which is the documented way to size the buffer.
    let needed = unsafe { GetSystemDirectoryA(ptr::null_mut(), 0) } as usize;
    if needed > 0 {
        let mut buffer = vec![0u8; needed];
        // SAFETY: `buffer` is writable for `needed` bytes, which the call above
        // reported as sufficient including the NUL terminator.
        let written = unsafe { GetSystemDirectoryA(buffer.as_mut_ptr(), needed as u32) } as usize;
        if written > 0 && written < needed {
            buffer.truncate(written);
            let mut path = buffer;
            path.extend_from_slice(br"\Npcap\Packet.dll");
            path.push(0);
            candidates.push(path);
        }
    }

    // Falls back to the standard search order for WinPcap-compatible installs.
    candidates.push(b"Packet.dll\0".to_vec());
    candidates
}

fn load_packet_api() -> Result<PacketApi, String> {
    let mut last_error = None;
    for candidate in packet_dll_candidates() {
        // SAFETY: `candidate` is a NUL-terminated path built above.
        let module = unsafe { LoadLibraryA(candidate.as_ptr()) };
        if module.is_null() {
            last_error = Some(io::Error::last_os_error());
            continue;
        }
        // The module is deliberately never freed: the resolved function
        // pointers are cached for the lifetime of the process, so unloading
        // would dangle them. One leaked module handle is the intended
        // trade-off for a process-lifetime lazy load.
        //
        // SAFETY: `module` is a live handle just returned by LoadLibraryA.
        return unsafe { PacketApi::resolve(module) }.map_err(|symbol| {
            format!("Packet.dll is missing the required symbol `{symbol}`; it is likely too old")
        });
    }

    let detail = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "no candidate path could be built".to_string());
    Err(format!(
        "failed to load Packet.dll; install Npcap (https://npcap.com) to use the datalink layer: {detail}"
    ))
}

/// Return the lazily loaded Packet.dll entry points.
///
/// The load is attempted once per process; the outcome, success or failure, is
/// cached. Fails with [`io::ErrorKind::NotFound`] when Npcap is not installed.
pub fn packet_api() -> io::Result<&'static PacketApi> {
    match PACKET_API.get_or_init(load_packet_api) {
        Ok(api) => Ok(api),
        Err(message) => Err(io::Error::new(io::ErrorKind::NotFound, message.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npf_name_uses_the_device_namespace() {
        // netdev reports the adapter GUID as `Interface::name` on Windows,
        // which is exactly what the NPF device path expects.
        assert_eq!(
            to_npf_name("{B27C4B1D-0000-0000-0000-000000000000}"),
            r"\Device\NPF_{B27C4B1D-0000-0000-0000-000000000000}"
        );
    }

    #[test]
    fn dll_candidates_prefer_the_npcap_directory() {
        let candidates = packet_dll_candidates();
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            assert_eq!(
                candidate.last(),
                Some(&0),
                "LoadLibraryA requires a NUL-terminated path"
            );
            assert_eq!(
                candidate.iter().filter(|byte| **byte == 0).count(),
                1,
                "an interior NUL would truncate the path"
            );
        }
        // The bare name is the last resort, after the Npcap-specific path.
        assert_eq!(candidates.last().unwrap(), b"Packet.dll\0");
        if candidates.len() > 1 {
            let preferred = String::from_utf8_lossy(&candidates[0]).to_lowercase();
            assert!(
                preferred.contains(r"\npcap\packet.dll"),
                "unexpected preferred candidate: {preferred}"
            );
        }
    }

    #[test]
    fn packet_api_load_is_cached_and_consistent() {
        // Whether Npcap is installed depends on the machine, so assert on the
        // properties that must hold either way rather than on success.
        let first = packet_api();
        let second = packet_api();
        match (first, second) {
            (Ok(a), Ok(b)) => {
                assert!(std::ptr::eq(a, b), "the load result must be cached");
            }
            (Err(a), Err(b)) => {
                assert_eq!(a.kind(), io::ErrorKind::NotFound);
                assert_eq!(a.to_string(), b.to_string());
                assert!(
                    a.to_string().contains("npcap.com"),
                    "the error should tell the user how to fix it: {a}"
                );
            }
            _ => panic!("packet_api() must not flip between success and failure"),
        }
    }
}
