//! In-memory presence records. Online = WS connected, or seen (relay/WS/
//! heartbeat) within PRESENCE_TIMEOUT. Online transitions are forwarded on a
//! channel so the realtime hub can broadcast device_online/device_offline.

use std::sync::Arc;

use dashmap::DashMap;
use skiff_core::consts::PRESENCE_TIMEOUT;
use skiff_core::logging::unix_ms;
use skiff_core::models::{HeartbeatRequest, NetId, PeerPathReport, ws_events};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Default)]
pub struct PresenceRecord {
    pub last_seen_ms: i64,
    pub observed_udp_endpoint: Option<String>,
    pub local_addrs: Vec<String>,
    pub udp_port: Option<u16>,
    pub tcp_port: Option<u16>,
    pub ws_count: i32,
    pub paths: Vec<PeerPathReport>,
    /// 节点心跳上报的已应用 settings revision（旧节点不上报）。
    pub applied_settings_revision: Option<i64>,
    /// 节点心跳上报的重启待生效标志。
    pub restart_pending: bool,
    /// 节点心跳上报的运行模式（"tun"/"proxy"）——强制 join 预检用。
    pub mode: Option<skiff_core::models::ClientMode>,
}

impl PresenceRecord {
    fn is_online(&self) -> bool {
        self.ws_count > 0 || unix_ms() - self.last_seen_ms < PRESENCE_TIMEOUT.as_millis() as i64
    }
}

pub struct PresenceStore {
    map: DashMap<u64, PresenceRecord>,
    /// (device_id, now_online) transitions.
    online_tx: mpsc::UnboundedSender<(u64, bool)>,
}

pub type Presence = Arc<PresenceStore>;

/// Sidecar task converting presence transitions into network broadcasts.
pub fn spawn_online_broadcaster(
    mut rx: mpsc::UnboundedReceiver<(u64, bool)>,
    presence: Presence,
    hub: crate::events_hub::Hub,
    networks_of: impl Fn(u64) -> Vec<NetId> + Send + 'static,
) {
    tokio::spawn(async move {
        while let Some((device_id, online)) = rx.recv().await {
            let event_type = if online {
                ws_events::DEVICE_ONLINE
            } else {
                ws_events::DEVICE_OFFLINE
            };
            for network_id in networks_of(device_id) {
                hub.broadcast_network(
                    &network_id,
                    skiff_core::models::WsEvent {
                        event_type: event_type.to_string(),
                        network_id: Some(network_id),
                        device_id: Some(device_id),
                        message: None,
                    },
                );
                hub.broadcast_network(
                    &network_id,
                    skiff_core::models::WsEvent {
                        event_type: ws_events::PEERS_CHANGED.to_string(),
                        network_id: Some(network_id),
                        device_id: Some(device_id),
                        message: None,
                    },
                );
            }
            let _ = presence; // kept alive for symmetry; no further use
        }
    });
}

impl PresenceStore {
    pub fn new() -> (Presence, mpsc::UnboundedReceiver<(u64, bool)>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Arc::new(PresenceStore {
                map: DashMap::new(),
                online_tx: tx,
            }),
            rx,
        )
    }

    fn apply(&self, device_id: u64, mutate: impl FnOnce(&mut PresenceRecord)) {
        let (was, now) = {
            let mut entry = self.map.entry(device_id).or_default();
            let was = entry.is_online();
            mutate(&mut entry);
            (was, entry.is_online())
        };
        if was != now {
            let _ = self.online_tx.send((device_id, now));
        }
    }

    /// UDP 中继观测到设备地址：更新存活时间与观测端点。
    /// observed_udp_endpoint 是 /api/peers 中 udpEndpoints[0] 的来源
    /// （契约要求它必须始终是 UDP 中继观测端点），只能由 UDP 路径写入。
    pub fn touch_relay_udp(&self, device_id: u64, observed_endpoint: &str) {
        let ep = observed_endpoint.to_string();
        self.apply(device_id, |p| {
            p.last_seen_ms = unix_ms();
            p.observed_udp_endpoint = Some(ep);
        });
    }

    /// TCP 中继存活信号：只刷新存活时间。绝不写 observed_udp_endpoint——
    /// 一旦被 TCP 地址污染，节点的邻近端口探测会围绕错误端口进行。
    pub fn touch_relay_tcp(&self, device_id: u64) {
        self.apply(device_id, |p| {
            p.last_seen_ms = unix_ms();
        });
    }

    pub fn touch_heartbeat(&self, device_id: u64, req: &HeartbeatRequest) {
        // Sanitize: IPv4 only, dedup, cap at 8; ports 1..=65535; paths cap 64.
        let mut addrs: Vec<String> = Vec::new();
        for a in &req.local_addrs {
            if a.parse::<std::net::Ipv4Addr>().is_ok() && !addrs.iter().any(|x| x == a) {
                addrs.push(a.clone());
                if addrs.len() == 8 {
                    break;
                }
            }
        }
        let udp = req.listen_udp_port.filter(|p| (1..=65535).contains(p));
        let tcp = req.listen_tcp_port.filter(|p| (1..=65535).contains(p));
        let paths = req.paths.clone().map(|mut v| {
            v.truncate(64);
            v
        });
        self.apply(device_id, |p| {
            p.last_seen_ms = unix_ms();
            if !addrs.is_empty() {
                p.local_addrs = addrs;
            }
            p.udp_port = udp;
            p.tcp_port = tcp;
            if let Some(paths) = paths {
                p.paths = paths;
            }
            if let Some(rev) = req.settings_revision {
                p.applied_settings_revision = Some(rev);
            }
            if let Some(pending) = req.restart_pending {
                p.restart_pending = pending;
            }
            if let Some(mode) = &req.mode {
                p.mode = Some(*mode);
            }
        });
    }

    pub fn ws_connected(&self, device_id: u64) {
        self.apply(device_id, |p| {
            p.last_seen_ms = unix_ms();
            p.ws_count += 1;
        });
    }

    pub fn ws_disconnected(&self, device_id: u64) {
        self.apply(device_id, |p| {
            p.ws_count = (p.ws_count - 1).max(0);
        });
    }

    pub fn remove(&self, device_id: u64) {
        self.map.remove(&device_id);
    }

    pub fn is_online(&self, device_id: u64) -> bool {
        self.map
            .get(&device_id)
            .map(|p| p.is_online())
            .unwrap_or(false)
    }

    pub fn observed_endpoint(&self, device_id: u64) -> Option<String> {
        self.map
            .get(&device_id)
            .and_then(|p| p.observed_udp_endpoint.clone())
    }

    pub fn record(&self, device_id: u64) -> Option<PresenceRecord> {
        self.map.get(&device_id).map(|p| p.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TCP 中继信号不得污染 observed_udp_endpoint（udpEndpoints[0] 契约）。
    #[test]
    fn tcp_touch_keeps_udp_endpoint_clean() {
        let (presence, _rx) = PresenceStore::new();
        presence.touch_relay_tcp(7);
        assert_eq!(presence.observed_endpoint(7), None);

        presence.touch_relay_udp(7, "1.2.3.4:5000");
        assert_eq!(presence.observed_endpoint(7).as_deref(), Some("1.2.3.4:5000"));

        // TCP 中继活跃时不得覆盖已有的 UDP 观测端点。
        presence.touch_relay_tcp(7);
        assert_eq!(presence.observed_endpoint(7).as_deref(), Some("1.2.3.4:5000"));
    }
}
