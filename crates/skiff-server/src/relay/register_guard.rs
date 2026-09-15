//! REGISTER 防重放：REGISTER 的 nonce 已被 HMAC 覆盖，但 HMAC key 静态
//! 不轮换，报文本身无法证明新鲜度——服务端必须记忆已用 (deviceId, nonce)。
//! 重放 REGISTER 可把设备的中继注册地址改写到攻击者地址（劫持中继
//! 流量、踢掉在线 TCP 连接、污染观测端点），此校验不可移除。

use dashmap::DashMap;
use skiff_core::logging::unix_ms;

/// nonce 记忆时长：远超正常重注册周期（节点约 30s 重注册一次，每次新
/// nonce），同时限定内存占用（条目按注册频率线性增长，10 分钟内自然过期）。
const NONCE_TTL_MS: i64 = 10 * 60_000;

/// Clone 共享同一份记忆（DashMap 的 Clone 是快照深拷贝，必须用 Arc 包住
/// 才能在 UDP/TCP 两个中继间共享）。
#[derive(Clone, Default)]
pub struct RegisterGuard {
    seen: std::sync::Arc<DashMap<(u64, [u8; 16]), i64>>,
}

impl RegisterGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// 首次出现（或 TTL 已过期）记录并放行；TTL 内重复出现返回 false。
    pub fn admit(&self, device_id: u64, nonce: &[u8; 16]) -> bool {
        let key = (device_id, *nonce);
        let now = unix_ms();
        match self.seen.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                if *e.get() > now {
                    false
                } else {
                    e.insert(now + NONCE_TTL_MS);
                    true
                }
            }
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(now + NONCE_TTL_MS);
                true
            }
        }
    }

    /// Reclaim memory for expired entries (expiry is also re-checked lazily
    /// in admit, so this only bounds size).
    pub fn sweep(&self) {
        let now = unix_ms();
        self.seen.retain(|_, exp| *exp > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_nonce_rejected() {
        let g = RegisterGuard::new();
        let n = [7u8; 16];
        assert!(g.admit(1, &n));
        assert!(!g.admit(1, &n)); // 同设备重复
        assert!(g.admit(2, &n)); // 不同设备相同 nonce 互不影响
    }

    #[test]
    fn expired_nonce_readmitted_and_swept() {
        let g = RegisterGuard::new();
        let n = [9u8; 16];
        assert!(g.admit(1, &n));
        *g.seen.get_mut(&(1, n)).unwrap() = 0; // 模拟 TTL 流逝
        assert!(g.admit(1, &n)); // 过期后重新放行
        g.sweep();
        assert!(!g.admit(1, &n)); // sweep 只清理过期条目，不影响在期条目
    }
}
