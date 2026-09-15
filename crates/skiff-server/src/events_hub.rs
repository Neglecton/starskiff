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
    /// socket for the same pair only.
    pub fn register(
        &self,
        device_id: u64,
        network_id: NetId,
    ) -> mpsc::UnboundedReceiver<HubMessage> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.map.insert((device_id, network_id), Entry { tx });
        rx
    }

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
