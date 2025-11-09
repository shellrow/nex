#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE};
use windows_sys::Win32::System::IO::OVERLAPPED;
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
pub const NDIS_PACKET_TYPE_PROMISCUOUS: ULONG = 0x00000020;

// Convert interface name to NPF device name
pub fn to_npf_name(name: &str) -> String {
    format!("\\Device\\NPF_{}", name)
}

#[link(name = "Packet")]
#[allow(improper_ctypes)]
unsafe extern "C" {
    // from Packet32.h
    pub fn PacketSendPacket(AdapterObject: LPADAPTER, pPacket: LPPACKET, Sync: BOOLEAN) -> BOOLEAN;
    pub fn PacketReceivePacket(
        AdapterObject: LPADAPTER,
        lpPacket: LPPACKET,
        Sync: BOOLEAN,
    ) -> BOOLEAN;
    pub fn PacketAllocatePacket() -> LPPACKET;
    pub fn PacketInitPacket(lpPacket: LPPACKET, Buffer: PVOID, Length: UINT);
    pub fn PacketFreePacket(lpPacket: LPPACKET);
    pub fn PacketOpenAdapter(AdapterName: PCHAR) -> LPADAPTER;
    pub fn PacketCloseAdapter(lpAdapter: LPADAPTER);
    pub fn PacketGetAdapterNames(pStr: PTSTR, BufferSize: PULONG) -> BOOLEAN;
    pub fn PacketSetHwFilter(AdapterObject: LPADAPTER, Filter: ULONG) -> BOOLEAN;
    pub fn PacketSetMinToCopy(AdapterObject: LPADAPTER, nbytes: libc::c_int) -> BOOLEAN;
    pub fn PacketSetBuff(AdapterObject: LPADAPTER, dim: libc::c_int) -> BOOLEAN;
    pub fn PacketSetReadTimeout(AdapterObject: LPADAPTER, timeout: libc::c_int) -> BOOLEAN;
}
