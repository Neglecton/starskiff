//! Realtime event hub: one WS sender per (device, network) — a node joined
//! to several networks keeps one socket each and they do not evict one
//! another. Sends are best-effort; the receiving WS task owns socket
//! lifetime and unregisters on close.

use dashmap::DashMap;
use skiff_core::models::{NetId, WsEvent};
use tokio::sync::mpsc;

pub enum HubMessage {
    Ws(WsEvent),
    Close,
}

struct Entry {
    tx: mpsc::UnboundedSender<HubMessage>,
}

#[derive(Default)]
pub struct EventsHub {
    map: DashMap<(u64, NetId), Entry>,
}

pub type Hub = std::sync::Arc<EventsHub>;

impl EventsHub {
    pub fn new() -> Hub {
        std::sync::Arc::new(EventsHub::default())
    }

    /// Register the socket for (device, network); replaces any previous
    /// socket for the same pair only. 返回 (rx, tx 克隆)：WS 任务退出时用
    /// tx 调 unregister_if_current——**不能按 key 无条件注销**（快重连场景
    /// 新连接已顶掉同 key 旧条目，旧任务收尾会误杀新连接，形成"任何同
    /// key 双注册都自杀"的闪断链）。
    pub fn register(
        &self,
        device_id: u64,
        network_id: NetId,
    ) -> (mpsc::UnboundedReceiver<HubMessage>, mpsc::UnboundedSender<HubMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        self.map.insert((device_id, network_id), Entry { tx: tx.clone() });
        (rx, tx)
    }

    /// 仅当 `tx` 仍是当前注册条目时注销（同 key 新注册已顶掉旧条目的
    /// 情况下为 no-op）——WS 任务退出路径专用。
    pub fn unregister_if_current(
        &self,
        device_id: u64,
        network_id: NetId,
        tx: &mpsc::UnboundedSender<HubMessage>,
    ) {
        if let Some(entry) = self.map.get(&(device_id, network_id))
            && entry.tx.same_channel(tx)
        {
            drop(entry);
            self.map.remove(&(device_id, network_id));
        }
    }

    /// 按 key 无条件注销并关闭当前连接（管理端强制踢线用）。
    pub fn unregister(&self, device_id: u64, network_id: NetId) {
        if let Some((_, entry)) = self.map.remove(&(device_id, network_id)) {
            let _ = entry.tx.send(HubMessage::Close);
        }
    }

    /// Drop every socket of a device (device removal).
    pub fn unregister_device(&self, device_id: u64) {
        let keys: Vec<(u64, NetId)> = self.map.iter().filter(|e| e.key().0 == device_id).map(|e| *e.key()).collect();
        for key in keys {
            if let Some((_, entry)) = self.map.remove(&key) {
                let _ = entry.tx.send(HubMessage::Close);
            }
        }
    }

    /// Send to every socket of the device across all its networks; the
    /// client matches events by networkId.
    pub fn send_to_device(&self, device_id: u64, evt: WsEvent) {
        for entry in self.map.iter() {
            if entry.key().0 == device_id {
                let _ = entry.value().tx.send(HubMessage::Ws(evt.clone()));
            }
        }
    }

    pub fn broadcast_network(&self, network_id: &NetId, evt: WsEvent) {
        for entry in self.map.iter() {
            if entry.key().1 == *network_id {
                let _ = entry.value().tx.send(HubMessage::Ws(evt.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 代际注销守护：快重连的新注册顶掉旧条目后，旧任务收尾只允许清理
    /// 自己的注册——按 key 无条件注销会误杀新连接（曾形成同 key 双注册
    /// 必闪断的自杀链）。
    #[test]
    fn teardown_only_removes_own_registration() {
        let hub = EventsHub::new();
        let net = NetId::random();
        let (_rx1, tx1) = hub.register(7, net);
        let (mut rx2, _tx2) = hub.register(7, net); // 新连接顶掉旧条目
        // 旧任务收尾：不得误杀新条目。
        hub.unregister_if_current(7, net, &tx1);
        // 新条目仍在：按 key 注销能找到并送达 Close。
        hub.unregister(7, net);
        assert!(matches!(rx2.try_recv(), Ok(HubMessage::Close)));
    }
}
