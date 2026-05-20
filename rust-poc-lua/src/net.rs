//! IPv4 enumeration via `GetAdaptersAddresses`.
//!
//! Returns an array of `{name, ipv4[]}` objects. Loopback interfaces are
//! filtered out so the collector sees only "real" addresses.

// `GetAdaptersAddresses` writes into a raw byte buffer we then walk as a
// linked list. The `buf.as_mut_ptr().cast()` and `&mut size` sites are the
// idiomatic FFI shape — rewriting with `std::ptr::from_mut` is noisier and
// no safer.
#![allow(clippy::borrow_as_ptr, clippy::ref_as_ptr)]

use serde_json::{Value, json};
use std::ffi::OsString;
use std::net::Ipv4Addr;
use std::os::windows::ffi::OsStringExt;

use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

pub(super) fn interfaces() -> Result<Vec<Value>, String> {
    let mut size: u32 = 15_000;
    let mut buf = vec![0u8; size as usize];
    // SAFETY: the buffer is contiguous; size is updated by the API on
    // ERROR_BUFFER_OVERFLOW so we can resize and retry.
    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
            flags,
            None,
            Some(buf.as_mut_ptr().cast()),
            &mut size,
        )
    };
    if rc == windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0 {
        buf.resize(size as usize, 0);
        rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
    }
    if rc != 0
    /* NO_ERROR */
    {
        return Err(format!("GetAdaptersAddresses rc={rc}"));
    }

    // Walk the linked list.
    let mut out = Vec::new();
    let mut cur: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr().cast();
    while !cur.is_null() {
        // SAFETY: cur comes from the buffer GetAdaptersAddresses wrote;
        // fields are valid as long as the buffer lives (buf is held here).
        let ad = unsafe { &*cur };
        // Skip loopback.
        if ad.IfType == 24
        /* IF_TYPE_SOFTWARE_LOOPBACK */
        {
            cur = ad.Next;
            continue;
        }
        let name = adapter_name(ad);
        let mut ipv4 = Vec::new();
        let mut addr = ad.FirstUnicastAddress;
        while !addr.is_null() {
            // SAFETY: FirstUnicastAddress list is owned by the buffer.
            let ua = unsafe { &*addr };
            // SAFETY: SOCKADDR_IN when sa_family == AF_INET.
            let sa = unsafe { &*ua.Address.lpSockaddr };
            if sa.sa_family == AF_INET {
                // SAFETY: reinterpret as SOCKADDR_IN for AF_INET.
                let sin: &SOCKADDR_IN = unsafe { &*ua.Address.lpSockaddr.cast() };
                let octets = unsafe { sin.sin_addr.S_un.S_un_b };
                let ip = Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                if !ip.is_loopback() {
                    ipv4.push(Value::String(ip.to_string()));
                }
            }
            addr = ua.Next;
        }
        if !ipv4.is_empty() {
            out.push(json!({ "name": name, "ipv4": ipv4 }));
        }
        cur = ad.Next;
    }
    Ok(out)
}

fn adapter_name(ad: &IP_ADAPTER_ADDRESSES_LH) -> String {
    // AdapterName is ANSI; FriendlyName is wide (but we skipped it).
    // SAFETY: pointer is valid UTF-8 ANSI in the buffer.
    let p = ad.AdapterName.0;
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: AdapterName is NUL-terminated.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
    }
    let bytes = unsafe { std::slice::from_raw_parts(p, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

#[allow(dead_code)]
fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees NUL termination.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(p, len) };
    OsString::from_wide(slice).to_string_lossy().into_owned()
}
