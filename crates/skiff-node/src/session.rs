//! Per-peer session: keys, codec, path state machine, telemetry.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use skiff_core::crypto::SessionKeys;
use skiff_core::models::NetId;
use skiff_core::protocol::wire::PacketCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    RelayUdp,
    DirectUdp,
    RelayTcp,
    DirectTcp,
}

impl PathKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PathKind::RelayUdp => "RelayUdp",
            PathKind::DirectUdp => "DirectUdp",
            PathKind::RelayTcp => "RelayTcp",
            PathKind::DirectTcp => "DirectTcp",
        }
    }
}

pub struct PeerSession {
    pub id: u64,
    /// Owning network (set at creation; informational for status output).
    pub network_id_hint: NetId,
    pub name: Mutex<String>,
    pub virtual_ip: Mutex<Ipv4Addr>,
    pub dh_pubkey: [u8; 32],
    pub online: AtomicBool,
    pub tcp_listen_port: Mutex<Option<u16>>,
    pub endpoints: Mutex<Vec<SocketAddr>>,
    pub codec: Mutex<PacketCodec>,
    pub tcp_conn: Mutex<Option<Arc<crate::transport::peer_tcp::PeerTcpConnection>>>,
    pub current_path: Mutex<PathKind>,
    pub direct_endpoint: Mutex<Option<SocketAddr>>,
    pub last_pong_ms: AtomicI64,
    pub tcp_cooldown_until_ms: AtomicI64,
    pub rtt_ms: AtomicI64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
}

impl PeerSession {
    pub fn new(
        id: u64,
        network_id_hint: NetId,
        name: String,
        virtual_ip: Ipv4Addr,
        dh_pubkey: [u8; 32],
        keys: SessionKeys,
    ) -> Arc<PeerSession> {
        Arc::new(PeerSession {
            id,
            network_id_hint,
            name: Mutex::new(name),
            virtual_ip: Mutex::new(virtual_ip),
            dh_pubkey,
            online: AtomicBool::new(false),
            tcp_listen_port: Mutex::new(None),
            endpoints: Mutex::new(Vec::new()),
            codec: Mutex::new(PacketCodec::new(keys)),
            tcp_conn: Mutex::new(None),
            current_path: Mutex::new(PathKind::RelayUdp),
            direct_endpoint: Mutex::new(None),
            last_pong_ms: AtomicI64::new(0),
            tcp_cooldown_until_ms: AtomicI64::new(0),
            rtt_ms: AtomicI64::new(-1),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
        })
    }

    pub fn name(&self) -> String {
        self.name.lock().unwrap().clone()
    }

    pub fn virtual_ip(&self) -> Ipv4Addr {
        *self.virtual_ip.lock().unwrap()
    }

    pub fn path(&self) -> PathKind {
        *self.current_path.lock().unwrap()
    }

    pub fn online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    pub fn add_tx(&self, bytes: usize) {
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: usize) {
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
    }
}
