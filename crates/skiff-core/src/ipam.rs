//! IPv4 subnet math and address allocation.

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// An IPv4 CIDR block. `network` is the masked network address in host byte
/// order of the big-endian dotted representation (10.10.0.0 -> 0x0A0A0000).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: u32,
    pub prefix: u32,
}

impl Cidr {
    pub fn parse(text: &str) -> Result<Cidr, String> {
        let Some((addr_part, prefix_part)) = text.split_once('/') else {
            return Err(format!("invalid CIDR '{text}': expected a.b.c.d/prefix"));
        };
        let addr: Ipv4Addr = addr_part
            .parse()
            .map_err(|_| format!("invalid IPv4 address '{addr_part}'"))?;
        let prefix: u32 = prefix_part
            .parse()
            .map_err(|_| format!("invalid prefix '{prefix_part}'"))?;
        if prefix > 32 {
            return Err(format!("invalid prefix /{prefix}: must be 0..=32"));
        }
        Ok(Cidr::new(u32::from(addr), prefix))
    }

    /// Build from raw network + prefix, masking host bits to zero.
    pub fn new(network: u32, prefix: u32) -> Cidr {
        let mask = Self::mask_of(prefix);
        Cidr {
            network: network & mask,
            prefix,
        }
    }

    pub fn mask_of(prefix: u32) -> u32 {
        debug_assert!(prefix <= 32);
        if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    }

    pub fn netmask(&self) -> u32 {
        Self::mask_of(self.prefix)
    }

    pub fn broadcast(&self) -> u32 {
        self.network | !self.netmask()
    }

    pub fn host_count(&self) -> u64 {
        if self.prefix >= 31 {
            1u64 << (32 - self.prefix)
        } else {
            (1u64 << (32 - self.prefix)) - 2
        }
    }

    /// First usable host (the network address itself for /31+).
    pub fn first_host(&self) -> u32 {
        if self.prefix >= 31 {
            self.network
        } else {
            self.network + 1
        }
    }

    /// Last usable host (the broadcast address itself for /31+).
    pub fn last_host(&self) -> u32 {
        if self.prefix >= 31 {
            self.broadcast()
        } else {
            self.broadcast() - 1
        }
    }

    pub fn contains(&self, addr: u32) -> bool {
        addr & self.netmask() == self.network
    }

    pub fn network_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network_addr(), self.prefix)
    }
}

/// Sequential lowest-free allocation and manual-assignment validation.
pub struct IpPool;

impl IpPool {
    /// Allocate the lowest free host address; `None` when exhausted or /31+.
    pub fn allocate(cidr: &Cidr, used: &HashSet<u32>) -> Option<u32> {
        if cidr.prefix >= 31 {
            return None;
        }
        let start = cidr.network + 1;
        let end = cidr.broadcast(); // exclusive: broadcast itself is not assignable
        let mut candidate = start;
        while candidate < end {
            if !used.contains(&candidate) {
                return Some(candidate);
            }
            candidate += 1;
        }
        None
    }

    /// Validate a manually requested IP; returns the address or a user-facing error.
    pub fn validate_manual(
        ip_text: &str,
        cidr: &Cidr,
        used: &HashSet<u32>,
        current: Option<u32>,
    ) -> Result<u32, String> {
        let addr: Ipv4Addr = ip_text
            .parse()
            .map_err(|_| format!("'{ip_text}' 不是合法的 IPv4 地址"))?;
        let bits = u32::from(addr);
        if !cidr.contains(bits) {
            return Err(format!(
                "{} 不在网段 {}/{} 内",
                addr,
                cidr.network_addr(),
                cidr.prefix
            ));
        }
        if bits == cidr.network {
            return Err(format!("{} 是网络地址，不能分配给设备", addr));
        }
        if cidr.prefix < 31 && bits == cidr.broadcast() {
            return Err(format!("{} 是广播地址，不能分配给设备", addr));
        }
        if Some(bits) != current && used.contains(&bits) {
            return Err(format!("{} 已被其他设备占用", addr));
        }
        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ips: &[&str]) -> HashSet<u32> {
        ips.iter()
            .map(|s| u32::from(s.parse::<Ipv4Addr>().unwrap()))
            .collect()
    }

    #[test]
    fn parse_and_mask() {
        let c = Cidr::parse("10.10.0.77/24").unwrap();
        assert_eq!(c.network, u32::from(Ipv4Addr::new(10, 10, 0, 0)));
        assert_eq!(c.prefix, 24);
        assert!(Cidr::parse("10.10.0.77/33").is_err());
        assert!(Cidr::parse("300.1.1.1/8").is_err());
        assert!(Cidr::parse("10.0.0.0").is_err());
    }

    #[test]
    fn boundaries() {
        let c = Cidr::parse("10.0.0.0/24").unwrap();
        assert_eq!(c.first_host(), u32::from(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(c.last_host(), u32::from(Ipv4Addr::new(10, 0, 0, 254)));
        assert_eq!(c.netmask(), u32::from(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(c.host_count(), 254);
        assert!(c.contains(u32::from(Ipv4Addr::new(10, 0, 0, 199))));
        assert!(!c.contains(u32::from(Ipv4Addr::new(10, 0, 1, 1))));
    }

    #[test]
    fn sequential_allocation() {
        let cidr = Cidr::parse("10.99.0.0/24").unwrap();
        let used = HashSet::new();
        assert_eq!(
            IpPool::allocate(&cidr, &used).map(Ipv4Addr::from),
            Some("10.99.0.1".parse::<Ipv4Addr>().unwrap())
        );
        let used = set(&["10.99.0.1"]);
        assert_eq!(
            IpPool::allocate(&cidr, &used).map(Ipv4Addr::from),
            Some("10.99.0.2".parse::<Ipv4Addr>().unwrap())
        );
        // /30: only .1 and .2 usable, exhaustion returns None.
        let small = Cidr::parse("192.168.4.0/30").unwrap();
        let used = set(&["192.168.4.1", "192.168.4.2"]);
        assert_eq!(IpPool::allocate(&small, &used), None);
        // /31 and /32 never allocate.
        assert_eq!(
            IpPool::allocate(&Cidr::parse("1.2.3.4/31").unwrap(), &HashSet::new()),
            None
        );
    }

    #[test]
    fn manual_validation() {
        let cidr = Cidr::parse("10.99.0.0/24").unwrap();
        let used = set(&["10.99.0.1"]);
        assert!(IpPool::validate_manual("10.99.0.200", &cidr, &used, None).is_ok());
        // Own current IP may be re-requested.
        assert!(
            IpPool::validate_manual(
                "10.99.0.1",
                &cidr,
                &used,
                Some(u32::from(Ipv4Addr::new(10, 99, 0, 1)))
            )
            .is_ok()
        );
        assert!(IpPool::validate_manual("10.99.0.1", &cidr, &used, None).is_err());
        assert!(IpPool::validate_manual("10.99.0.0", &cidr, &used, None).is_err());
        assert!(IpPool::validate_manual("10.99.0.255", &cidr, &used, None).is_err());
        assert!(IpPool::validate_manual("10.100.0.5", &cidr, &used, None).is_err());
        assert!(IpPool::validate_manual("not-an-ip", &cidr, &used, None).is_err());
    }
}
