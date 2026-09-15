//! Local IPv4 address enumeration (for heartbeat endpoint hints).

use std::net::Ipv4Addr;

/// All IPv4 unicast addresses of up interfaces, excluding link-local
/// 169.254.x.x and loopback; deduplicated.
pub fn local_ipv4_addrs() -> Vec<String> {
    #[cfg(windows)]
    {
        windows_local_ipv4_addrs()
    }
    #[cfg(not(windows))]
    {
        unix_local_ipv4_addrs()
    }
}

fn is_link_local(v4: &Ipv4Addr) -> bool {
    v4.octets()[0] == 169 && v4.octets()[1] == 254
}

#[cfg(windows)]
fn windows_local_ipv4_addrs() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut out: Vec<String> = Vec::new();
    unsafe {
        let mut size: u32 = 16 * 1024;
        let mut buffer: Vec<u8>;
        loop {
            buffer = vec![0u8; size as usize];
            let rc = GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
            if rc == 0 {
                break;
            }
            if rc != 111 {
                return out; // 111 = ERROR_BUFFER_OVERFLOW
            }
        }
        let mut cur = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let addr = &*cur;
            // IfOperStatusUp == 1
            if addr.IfType != IF_TYPE_SOFTWARE_LOOPBACK && addr.OperStatus.0 == 1 {
                let mut ua = addr.FirstUnicastAddress;
                while !ua.is_null() {
                    let u = &*ua;
                    let sa = u.Address.lpSockaddr as *const u8;
                    if !sa.is_null() {
                        let bytes = std::slice::from_raw_parts(
                            sa,
                            u.Address.iSockaddrLength.max(8) as usize,
                        );
                        // sockaddr_in: family(2) port(2) addr(4)
                        if bytes.len() >= 8 && u16::from_ne_bytes([bytes[0], bytes[1]]) == AF_INET.0
                        {
                            let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                            if !is_link_local(&ip) && !ip.is_loopback() && !ip.is_unspecified() {
                                out.push(ip.to_string());
                            }
                        }
                    }
                    ua = u.Next;
                }
            }
            cur = addr.Next;
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(not(windows))]
fn unix_local_ipv4_addrs() -> Vec<String> {
    // getifaddrs via libc-compatible extern declarations.
    #[repr(C)]
    struct IfAddrs {
        ifa_next: *mut IfAddrs,
        ifa_name: *mut u8,
        ifa_flags: u32,
        ifa_addr: *mut SockAddr,
        ifa_netmask: *mut SockAddr,
        ifa_dstaddr: *mut SockAddr,
        ifa_data: *mut u8,
    }
    #[repr(C)]
    struct SockAddr {
        family: u16,
        data: [u8; 14],
    }
    unsafe extern "C" {
        fn getifaddrs(ifap: *mut *mut IfAddrs) -> i32;
        fn freeifaddrs(ifa: *mut IfAddrs);
    }

    let mut out: Vec<String> = Vec::new();
    unsafe {
        let mut list: *mut IfAddrs = std::ptr::null_mut();
        if getifaddrs(&mut list) != 0 {
            return out;
        }
        let mut cur = list;
        while !cur.is_null() {
            let e = &*cur;
            let addr_ptr = e.ifa_addr;
            if !addr_ptr.is_null() && (*addr_ptr).family == 2 {
                // AF_INET sockaddr_in: family(2) + port(2) + addr(4)
                let bytes = std::slice::from_raw_parts(addr_ptr as *const u8, 8);
                let ip = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
                if !is_link_local(&ip) && !ip.is_loopback() && !ip.is_unspecified() {
                    out.push(ip.to_string());
                }
            }
            cur = e.ifa_next;
        }
        freeifaddrs(list);
    }
    out.sort();
    out.dedup();
    out
}
