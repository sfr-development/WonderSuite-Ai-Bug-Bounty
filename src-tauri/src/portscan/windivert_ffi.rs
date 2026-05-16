// Manual FFI bindings to WinDivert.dll via libloading. Avoids the static
// dynamic-link that the `windivert` / `windivert-sys` crates impose, which
// makes Windows refuse to start the .exe on machines that don't already
// have WinDivert.dll on the standard search path.
//
// Workflow:
//   1. App starts (no WinDivert references in our binary at load time).
//   2. User clicks "Install network driver" → portscan_driver_install
//      copies WinDivert.dll from `<resources>/drivers/windivert/` to
//      `<exe>/WinDivert.dll`, then registers WinDivert64.sys as a service.
//   3. First SYN scan → `WinDivertApi::load()` calls libloading::Library::new()
//      on the deployed DLL → resolves the four functions we need → returns
//      a callable handle.
//
// Spec reference: https://reqrypt.org/windivert-doc.html
// Header: src-tauri/resources/drivers/windivert/windivert.h

#![cfg(target_os = "windows")]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use libloading::{Library, Symbol};
use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::path::Path;

// ── WinDivert types ──────────────────────────────────────────────────────

pub type Handle = *mut c_void;
pub const INVALID_HANDLE: Handle = -1isize as *mut c_void;

/// WINDIVERT_LAYER enum values from windivert.h
pub const LAYER_NETWORK: i32 = 0;
pub const LAYER_NETWORK_FORWARD: i32 = 1;
pub const LAYER_FLOW: i32 = 2;
pub const LAYER_SOCKET: i32 = 3;
pub const LAYER_REFLECT: i32 = 4;

/// WinDivert open flags (UINT64 mask)
pub const FLAG_DEFAULT: u64 = 0x0000;
pub const FLAG_SNIFF: u64 = 0x0001; // read-only, don't divert
pub const FLAG_DROP: u64 = 0x0002;
pub const FLAG_RECV_ONLY: u64 = 0x0004;
pub const FLAG_READ_ONLY: u64 = FLAG_RECV_ONLY;
pub const FLAG_SEND_ONLY: u64 = 0x0008;
pub const FLAG_WRITE_ONLY: u64 = FLAG_SEND_ONLY;
pub const FLAG_NO_INSTALL: u64 = 0x0010;
pub const FLAG_FRAGMENTS: u64 = 0x0020;

/// WINDIVERT_ADDRESS layout (windivert.h):
///   INT64  Timestamp;
///   UINT32 packed-bitfield {  // bit ordering MSVC LE
///     Layer:8       // bits 0..7
///     Event:8       // bits 8..15
///     Sniffed:1     // bit 16
///     Outbound:1    // bit 17  ← we toggle this for TX injection
///     Loopback:1    // bit 18
///     Impostor:1    // bit 19
///     IPv6:1        // bit 20
///     IPChecksum:1  // bit 21
///     TCPChecksum:1 // bit 22
///     UDPChecksum:1 // bit 23
///     Reserved1:8   // bits 24..31
///   };
///   UINT32 Reserved2;
///   UINT8  Data[64];  // union of layer-specific data
///
/// Total: 8 + 4 + 4 + 64 = 80 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub data: [u8; 64],
}

impl Default for Address {
    fn default() -> Self {
        Self { timestamp: 0, flags: 0, reserved2: 0, data: [0u8; 64] }
    }
}

impl Address {
    /// Build a zeroed Network-layer outbound address with valid IP+TCP
    /// checksums declared — these are the flags we want for SYN injection.
    pub fn outbound_network_tcp() -> Self {
        let mut a = Self::default();
        // Layer = NETWORK (0) → bits 0..7 already 0.
        // Outbound = 1 → bit 17
        // IPChecksum = 1 → bit 21 (we already filled it correctly)
        // TCPChecksum = 1 → bit 22
        a.flags = (1 << 17) | (1 << 21) | (1 << 22);
        a
    }

    pub fn set_outbound(&mut self, on: bool) {
        if on {
            self.flags |= 1 << 17;
        } else {
            self.flags &= !(1 << 17);
        }
    }
}

// ── Function pointer types ──────────────────────────────────────────────

pub type FnWinDivertOpen = unsafe extern "system" fn(
    filter: *const c_char,
    layer: i32,
    priority: i16,
    flags: u64,
) -> Handle;

pub type FnWinDivertSend = unsafe extern "system" fn(
    handle: Handle,
    packet: *const c_void,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const Address,
) -> i32; // BOOL

pub type FnWinDivertRecv = unsafe extern "system" fn(
    handle: Handle,
    packet: *mut c_void,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut Address,
) -> i32; // BOOL

pub type FnWinDivertClose = unsafe extern "system" fn(handle: Handle) -> i32;

pub type FnWinDivertSetParam = unsafe extern "system" fn(
    handle: Handle,
    param: i32,
    value: u64,
) -> i32;

// ── Loaded API ──────────────────────────────────────────────────────────

pub struct WinDivertApi {
    _lib: Library, // keep alive
    pub open: FnWinDivertOpen,
    pub send: FnWinDivertSend,
    pub recv: FnWinDivertRecv,
    pub close: FnWinDivertClose,
    pub set_param: FnWinDivertSetParam,
}

impl WinDivertApi {
    /// Load WinDivert.dll from the given path and resolve the entry points.
    /// Returns `Err(...)` with a human-readable message if anything fails
    /// (DLL missing, driver service not running, etc.).
    pub fn load(dll_path: &Path) -> Result<Self, String> {
        // SAFETY: we control the DLL path (resource dir) and the function
        // signatures match the WinDivert ABI documented in windivert.h.
        unsafe {
            let lib = Library::new(dll_path)
                .map_err(|e| format!("LoadLibrary {}: {}", dll_path.display(), e))?;

            let open: Symbol<FnWinDivertOpen> = lib
                .get(b"WinDivertOpen\0")
                .map_err(|e| format!("get WinDivertOpen: {}", e))?;
            let send: Symbol<FnWinDivertSend> = lib
                .get(b"WinDivertSend\0")
                .map_err(|e| format!("get WinDivertSend: {}", e))?;
            let recv: Symbol<FnWinDivertRecv> = lib
                .get(b"WinDivertRecv\0")
                .map_err(|e| format!("get WinDivertRecv: {}", e))?;
            let close: Symbol<FnWinDivertClose> = lib
                .get(b"WinDivertClose\0")
                .map_err(|e| format!("get WinDivertClose: {}", e))?;
            let set_param: Symbol<FnWinDivertSetParam> = lib
                .get(b"WinDivertSetParam\0")
                .map_err(|e| format!("get WinDivertSetParam: {}", e))?;

            let api = WinDivertApi {
                open: *open,
                send: *send,
                recv: *recv,
                close: *close,
                set_param: *set_param,
                _lib: lib,
            };
            Ok(api)
        }
    }

    pub fn open_handle(
        &self,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> Result<Handle, String> {
        let cfilter = CString::new(filter).map_err(|e| format!("filter cstring: {}", e))?;
        let h = unsafe { (self.open)(cfilter.as_ptr(), layer, priority, flags) };
        if h == INVALID_HANDLE {
            return Err(format!(
                "WinDivertOpen failed (Win32 error {}). Driver service not running, \
                 filter '{}' invalid, or HVCI blocked the driver.",
                last_error(),
                filter
            ));
        }
        Ok(h)
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

extern "system" {
    fn GetLastError() -> u32;
}
