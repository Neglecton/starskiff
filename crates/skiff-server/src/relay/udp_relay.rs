//! UDP relay (port 24931): REGISTER/ACK/ERROR/RELAY control protocol plus
//! verbatim forwarding of encrypted wire frames between registered nodes.
//!
//! Anti-spoofing invariants (must not be removed):
//! - only traffic between registered endpoints is forwarded;
//! - a RELAY packet's source address must equal the address srcId registered
//!   from;
//! - the registration itself is HMAC-authenticated with the device relay key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use skiff_core::consts::PRESENCE_TIMEOUT;
use skiff_core::logging::unix_ms;
use skiff_core::protocol::relay_udp::{self, REGISTER_PACKET_SIZE, RelayPacket};
use tokio::net::UdpSocket;

use crate::presence::Presence;

const KEY_CACHE_TTL_MS: i64 = 300_000;
/// Registration validity: presence timeout + slack.
const REGISTRATION_TTL_MS: i64 = PRESENCE_TIMEOUT.as_millis() as i64 + 15_000;

pub struct UdpRelay {
    registrations: DashMap<u64, Registration>,
    key_cache: DashMap<u64, KeyCacheEntry>,
    presence: Presence,
    /// device_id -> relay key (32 raw bytes), from the devices table.
    lookup_key: Arc<dyn Fn(u64) -> Option<[u8; 32]> + Send + Sync>,
    /// REGISTER 防重放（与 TCP 中继共享同一份 nonce 记忆）。
    register_guard: crate::relay::register_guard::RegisterGuard,
    pub forwarded_bytes: AtomicU64,
    pub forwarded_packets: AtomicU64,
    pub dropped_packets: AtomicU64,
    pub register_count: AtomicU64,
}

struct Registration {
    endpoint: SocketAddr,
    expires_ms: i64,
}

struct KeyCacheEntry {
    key: [u8; 32],
    expires_ms: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct RelayStats {
    pub forwarded_bytes: u64,
    pub forwarded_packets: u64,
    pub dropped_packets: u64,
    pub registers: u64,
    pub active: usize,
}

impl UdpRelay {
    pub fn new(
        presence: Presence,
        lookup_key: Arc<dyn Fn(u64) -> Option<[u8; 32]> + Send + Sync>,
        register_guard: crate::relay::register_guard::RegisterGuard,
    ) -> Arc<UdpRelay> {
        Arc::new(UdpRelay {
            registrations: DashMap::new(),
            key_cache: DashMap::new(),
            presence,
            lookup_key,
            register_guard,
            forwarded_bytes: AtomicU64::new(0),
            forwarded_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            register_count: AtomicU64::new(0),
        })
    }

    fn relay_key_of(&self, device_id: u64) -> Option<[u8; 32]> {
        let now = unix_ms();
        if let Some(hit) = self.key_cache.get(&device_id)
            && hit.expires_ms > now
        {
            return Some(hit.key);
        }
        let key = (self.lookup_key)(device_id)?;
        self.key_cache.insert(
            device_id,
            KeyCacheEntry {
                key,
                expires_ms: now + KEY_CACHE_TTL_MS,
            },
        );
        Some(key)
    }

    pub async fn serve(self: Arc<Self>, socket: UdpSocket) {
        // Registration cleanup: entries expire lazily on use; this sweeper
        // only reclaims memory.
        {
            let relay = Arc::clone(&self);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(120)).await;
                    let now = unix_ms();
                    relay.registrations.retain(|_, r| r.expires_ms > now);
                    relay.key_cache.retain(|_, k| k.expires_ms > now);
                    relay.register_guard.sweep();
                }
            });
        }
        let mut buf = vec![0u8; skiff_core::consts::UDP_BUFFER_SIZE];
        loop {
            let (len, from) = match socket.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue, // ICMP port unreachable on Windows
                Err(_) => {
                    // A malformed datagram must never kill the relay loop.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let packet = &buf[..len];
            self.handle(&socket, from, packet).await;
        }
    }

    async fn handle(&self, socket: &UdpSocket, from: SocketAddr, packet: &[u8]) {
        let Some(parsed) = relay_udp::parse(packet) else {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match parsed {
            RelayPacket::Register { device_id } => {
                let Some(key) = self.relay_key_of(device_id) else {
                    let _ = socket
                        .send_to(
                            &relay_udp::build_error_packet("unknown device or bad auth"),
                            from,
                        )
                        .await;
                    return;
                };
                if packet.len() != REGISTER_PACKET_SIZE || !relay_udp::verify_register(packet, &key)
                {
                    let _ = socket
                        .send_to(
                            &relay_udp::build_error_packet("unknown device or bad auth"),
                            from,
                        )
                        .await;
                    return;
                }
                // 防重放：nonce 已用过即静默丢弃（不回 ACK/ERROR，避免被
                // 当作存在性探针）。重放 REGISTER 会把注册地址改写到
                // 攻击者地址，劫持该设备的全部中继流量。
                let Some(nonce) = relay_udp::register_nonce(packet) else {
                    return;
                };
                if !self.register_guard.admit(device_id, &nonce) {
                    self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                self.registrations.insert(
                    device_id,
                    Registration {
                        endpoint: from,
                        expires_ms: unix_ms() + REGISTRATION_TTL_MS,
                    },
                );
                self.register_count.fetch_add(1, Ordering::Relaxed);
                self.presence.touch_relay_udp(device_id, &from.to_string());
                let ip = from.ip().to_string();
                let _ = socket
                    .send_to(&relay_udp::build_ack_packet(&ip, from.port()), from)
                    .await;
            }
            RelayPacket::Relay { src, dst, frame } => {
                let now = unix_ms();
                // Anti-spoof: src must be registered from this exact address
                // and the registration must still be valid. Note: DashMap
                // refs must never overlap on the same key (shard write lock
                // would deadlock the caller), so access src then dst strictly
                // sequentially.
                {
                    let mut src_reg = match self.registrations.get_mut(&src) {
                        Some(r) => r,
                        None => {
                            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                    if src_reg.expires_ms < now || src_reg.endpoint != from {
                        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Forwarding activity keeps the source registration alive.
                    src_reg.expires_ms = now + REGISTRATION_TTL_MS;
                }
                let dst_endpoint = match self.registrations.get(&dst) {
                    Some(d) if d.expires_ms > now => d.endpoint,
                    _ => {
                        self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                self.presence.touch_relay_udp(src, &from.to_string());
                if socket.send_to(frame, dst_endpoint).await.is_ok() {
                    self.forwarded_packets.fetch_add(1, Ordering::Relaxed);
                    self.forwarded_bytes
                        .fetch_add(frame.len() as u64, Ordering::Relaxed);
                } else {
                    self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
            RelayPacket::Ack { .. } => { /* clients should not receive here */ }
            RelayPacket::Error { .. } => {}
        }
    }

    pub fn observed_endpoint(&self, device_id: u64) -> Option<String> {
        self.registrations
            .get(&device_id)
            .map(|r| r.endpoint.to_string())
    }

    pub fn unregister(&self, device_id: u64) {
        self.registrations.remove(&device_id);
        self.key_cache.remove(&device_id);
    }

    pub fn stats(&self) -> RelayStats {
        RelayStats {
            forwarded_bytes: self.forwarded_bytes.load(Ordering::Relaxed),
            forwarded_packets: self.forwarded_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            registers: self.register_count.load(Ordering::Relaxed),
            active: self.registrations.len(),
        }
    }
}
