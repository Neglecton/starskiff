//! NodeEngine: the orchestration core, multi-network capable. A central
//! event loop consumes frames from all transports; companion loops drive
//! heartbeat / probing / status / stop-flag.
//!
//! Network dimension: `networks` holds per-network context (cidr, self ip,
//! ip_map); `peers` is keyed by (network, device) — session keys are derived
//! with the network id as salt, so the same peer device gets a distinct
//! codec per network. Inbound frames carry no network field: the engine
//! resolves the network by trying each candidate codec (safe since
//! `try_open` is side-effect free on decryption failure).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use dashmap::DashMap;
use skiff_core::crypto::SessionKeys;
use skiff_core::ipam::Cidr;
use skiff_core::logging::{LogFn, unix_ms};
use skiff_core::models::*;
use skiff_core::protocol::wire::{self, FRAME_DATA, FRAME_FLOW, FRAME_PING, FRAME_PONG};
use tokio::sync::{mpsc, watch};

use crate::control::ControlClient;
use crate::flow::FlowManager;
use crate::proxy;
use crate::session::{PathKind, PeerSession};
use crate::transport::peer_tcp::PeerTcpConnection;
use crate::transport::relay_tcp::RelayTcpClient;
use crate::transport::udp_mesh::UdpMesh;

/// How a frame arrived — determines the PONG return path and upgrade rules.
pub enum Arrival {
    DirectUdp(SocketAddr),
    DirectTcp(Arc<PeerTcpConnection>),
    RelayUdp,
    RelayTcp,
}

impl Arrival {
    pub fn direct_udp(from: SocketAddr) -> Arrival {
        Arrival::DirectUdp(from)
    }
    pub fn direct_tcp(conn: Arc<PeerTcpConnection>) -> Arrival {
        Arrival::DirectTcp(conn)
    }
    pub fn relay_udp() -> Arrival {
        Arrival::RelayUdp
    }
    pub fn relay_tcp() -> Arrival {
        Arrival::RelayTcp
    }
}

pub enum EngineEvent {
    Frame { arrival: Arrival, packet: Vec<u8> },
    ObservedEndpoint(String),
    Log(String),
    /// OS-origin packet from the TUN device (engine outbound).
    TunPacket(Vec<u8>),
}

/// Sink for decrypted inbound DATA frames (TUN mode); no-op in proxy mode.
pub type DataSink = Box<dyn Fn(&[u8]) + Send + Sync>;

/// Per-network runtime context.
pub struct NetworkCtx {
    pub name: String,
    pub cidr: Option<Cidr>,
    pub self_ip: Option<Ipv4Addr>,
    /// virtual-ip bits -> device id (within this network).
    pub ip_map: HashMap<u32, u64>,
}

pub type NetworksMap = Arc<DashMap<NetId, NetworkCtx>>;

/// 引擎停止原因——worker 宿主据此决定退出码（见 supervisor.rs）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// 正常停止（stop.flag / 信号 / 外部调用）→ worker 退出码 0。
    Stopped,
    /// 远程重启请求（WS restart_requested）→ worker 退出码 3，master
    /// 以最新配置文件重新拉起。
    Restart,
}

pub struct EngineShared {
    pub cfg: Mutex<NodeConfig>,
    pub config_path: PathBuf,
    pub networks: NetworksMap,
    /// network name -> id (config order defines the primary view).
    pub name_to_id: RwLock<HashMap<String, NetId>>,
    pub dh_priv: [u8; 32],
    pub dh_pub: [u8; 32],
    pub device_id: AtomicU64,
    pub control: Arc<ControlClient>,
    pub udp: Arc<UdpMesh>,
    pub relay_tcp: Arc<RelayTcpClient>,
    /// (network, device) -> session. Session keys are per-network.
    pub peers: DashMap<(NetId, u64), Arc<PeerSession>>,
    pub flows: Arc<FlowManager>,
    pub data_sink: DataSink,
    pub events: mpsc::UnboundedSender<EngineEvent>,
    pub log: LogFn,
    pub started_ms: i64,
    refresh_pending: AtomicBool,
    refresh_lock: tokio::sync::Mutex<()>,
    pub observed_endpoint: Mutex<Option<String>>,
    pub socks_port: AtomicU16,
    pub forward_ports: Mutex<Vec<u16>>,
    pub stopping: AtomicBool,
    /// 已应用的服务端托管配置 revision（幂等去重：多网络节点每网络一条
    /// WS，settings 推送会重复到达）。
    pub applied_settings_revision: AtomicU64,
    /// 有重启类托管配置已写入文件但尚未重启生效（心跳上报给管理页）。
    pub restart_pending: AtomicBool,
    /// 热改 force 开关（服务端托管，运行中每次现读）。
    pub force_relay: AtomicBool,
    pub force_direct: AtomicBool,
    /// 启动时实际生效的 SOCKS/forwards/MTU（状态展示 + 托管变更的
    /// restart_pending 比对基准）——行为配置不再落文件。
    pub runtime_socks: Mutex<Option<String>>,
    pub runtime_forwards: Mutex<Vec<ForwardRule>>,
    pub runtime_mtu: AtomicU32,
    /// 停止原因（首次触发时锁定）；worker 宿主据此映射退出码。
    pub stop_reason: Mutex<Option<StopReason>>,
    /// 服务端权威的网络名单（启动与 networks_changed 时刷新；prune 与
    /// 成员变化比对都以此为准——节点文件 networks[] 仅作展示缓存）。
    pub roster: Mutex<std::collections::HashSet<NetId>>,
    /// stopped 广播通道（下沉到 shared 使任意持有者都能请求停止）。
    /// 常驻接收者：tokio watch 在零接收者时 send 会失败且不存储值，
    /// 必须保留一个使 stop 信号对"事后订阅者"也可见。
    pub stopped_tx: watch::Sender<bool>,
    stopped_rx: watch::Receiver<bool>,
}

impl EngineShared {
    /// Resolve a virtual IP to a peer across all networks (first hit wins;
    /// overlapping CIDRs are warned about at startup).
    pub fn peer_by_ip(&self, ip: Ipv4Addr) -> Option<(NetId, Arc<PeerSession>)> {
        let bits = u32::from(ip);
        for ctx in self.networks.iter() {
            if let Some(dev) = ctx.value().ip_map.get(&bits) {
                let key = (*ctx.key(), *dev);
                drop(ctx);
                return self.peers.get(&key).map(|p| (key.0, Arc::clone(p.value())));
            }
        }
        None
    }

    pub fn network_name(&self, id: &NetId) -> String {
        self.networks.get(id).map(|c| c.value().name.clone()).unwrap_or_else(|| id.to_hex())
    }

    pub fn data_dir(&self) -> PathBuf {
        let cfg = self.cfg.lock().unwrap();
        if cfg.data_dir.is_empty() {
            crate::default_data_dir()
        } else {
            PathBuf::from(&cfg.data_dir)
        }
    }

    /// 热改 force 开关：服务端托管值（或默认 false），运行中每次现读。
    fn force_flags(&self) -> (bool, bool) {
        (
            self.force_relay.load(Ordering::Relaxed),
            self.force_direct.load(Ordering::Relaxed),
        )
    }

    /// Seal + route one frame to a peer on its network (RouteSealed).
    fn route_sealed(&self, net_id: &NetId, peer: &Arc<PeerSession>, frame: &[u8]) {
        if self.stopping.load(Ordering::Relaxed) {
            return;
        }
        let self_id = self.device_id.load(Ordering::Relaxed);
        let (force_relay, force_direct) = self.force_flags();
        if force_direct && !matches!(peer.path(), PathKind::DirectUdp | PathKind::DirectTcp) {
            let ep = peer
                .direct_endpoint
                .lock()
                .unwrap()
                .or_else(|| peer.endpoints.lock().unwrap().first().copied());
            // No direct endpoint: drop rather than leak via relay.
            if let Some(ep) = ep {
                self.udp.send_direct(ep, frame);
                peer.add_tx(frame.len());
            }
            return;
        }
        let path = if force_relay { PathKind::RelayUdp } else { peer.path() };
        match path {
            PathKind::DirectUdp => {
                let ep = peer
                    .direct_endpoint
                    .lock()
                    .unwrap()
                    .or_else(|| peer.endpoints.lock().unwrap().first().copied());
                match ep {
                    Some(ep) => self.udp.send_direct(ep, frame),
                    None => self.udp.send_relay(self_id, peer.id, frame),
                }
                peer.add_tx(frame.len());
            }
            PathKind::DirectTcp => {
                let conn = peer.tcp_conn.lock().unwrap().clone();
                match conn {
                    Some(conn) if !conn.is_closed() => {
                        conn.send(frame);
                        peer.add_tx(frame.len());
                    }
                    _ => {
                        self.udp.send_relay(self_id, peer.id, frame);
                        peer.add_tx(frame.len());
                    }
                }
            }
            PathKind::RelayTcp => {
                let relay = Arc::clone(&self.relay_tcp);
                let udp = Arc::clone(&self.udp);
                let events = self.events.clone();
                let dst = peer.id;
                let payload = frame.to_vec();
                peer.add_tx(frame.len());
                tokio::spawn(async move {
                    if !relay.send(dst, &payload, &events).await {
                        udp.send_relay(self_id, dst, &payload);
                    }
                });
            }
            PathKind::RelayUdp => {
                self.udp.send_relay(self_id, peer.id, frame);
                peer.add_tx(frame.len());
            }
        }
        let _ = net_id;
    }

    /// Reply on the arrival path — the PONG invariant that makes direct
    /// path upgrades work (the reply must leave through the same socket /
    /// NAT mapping the request used).
    fn reply_on_arrival(&self, peer: &Arc<PeerSession>, arrival: &Arrival, frame: &[u8]) {
        match arrival {
            Arrival::DirectUdp(ep) => self.udp.send_direct(*ep, frame),
            Arrival::DirectTcp(conn) => {
                let _ = conn.send(frame);
            }
            Arrival::RelayTcp => {
                let relay = Arc::clone(&self.relay_tcp);
                let events = self.events.clone();
                let dst = peer.id;
                let payload = frame.to_vec();
                tokio::spawn(async move {
                    let _ = relay.send(dst, &payload, &events).await;
                });
            }
            Arrival::RelayUdp => self.udp.send_relay(self.device_id.load(Ordering::Relaxed), peer.id, frame),
        }
        peer.add_tx(frame.len());
    }

    /// Send a FLOW plaintext payload to a peer on a network (sealed + routed).
    pub fn send_flow_payload(&self, net_id: NetId, peer_id: u64, payload: &[u8]) {
        let key = (net_id, peer_id);
        if let Some(peer) = self.peers.get(&key).map(|p| Arc::clone(p.value())) {
            let frame = peer
                .codec
                .lock()
                .unwrap()
                .seal(self.device_id.load(Ordering::Relaxed), FRAME_FLOW, payload);
            self.route_sealed(&net_id, &peer, &frame);
        }
    }

    /// Attach an inbound/outbound direct TCP connection to its peer.
    pub fn attach_peer_tcp(&self, net_id: &NetId, peer: &Arc<PeerSession>, conn: Arc<PeerTcpConnection>) {
        let should_upgrade = {
            let mut slot = peer.tcp_conn.lock().unwrap();
            let replace = match slot.as_ref() {
                Some(existing) => existing.is_closed() || !Arc::ptr_eq(existing, &conn),
                None => true,
            };
            if replace {
                *slot = Some(Arc::clone(&conn));
            }
            let (force_relay, _) = self.force_flags();
            !force_relay && matches!(*peer.current_path.lock().unwrap(), PathKind::RelayUdp | PathKind::RelayTcp)
        };
        if should_upgrade {
            *peer.current_path.lock().unwrap() = PathKind::DirectTcp;
            (self.log)(&format!("PATH_UP peer={} net={} type=DirectTcp", peer.name(), self.network_name(net_id)));
        }
    }

    /// Central inbound-frame processing (OnWireFrame): resolve the network
    /// by trying each candidate codec for the sender.
    pub fn handle_frame(&self, arrival: Arrival, packet: &[u8]) {
        let Some(raw) = wire::RawFrame::try_parse(packet) else { return };
        // Collect this sender's sessions across networks.
        let candidates: Vec<(NetId, Arc<PeerSession>)> = self
            .peers
            .iter()
            .filter(|e| e.key().1 == raw.sender_id)
            .map(|e| (e.key().0, Arc::clone(e.value())))
            .collect();
        if candidates.is_empty() {
            return; // unknown sender: drop silently
        }
        let mut matched: Option<(NetId, Arc<PeerSession>, u8, Vec<u8>)> = None;
        for (net_id, peer) in &candidates {
            if let Some((_sender, frame_type, payload)) = peer.codec.lock().unwrap().try_open(packet) {
                matched = Some((*net_id, Arc::clone(peer), frame_type, payload));
                break;
            }
        }
        let Some((net_id, peer, frame_type, payload)) = matched else {
            return; // no codec accepted: drop silently
        };
        peer.add_rx(packet.len());
        if let Arrival::DirectTcp(conn) = &arrival {
            self.attach_peer_tcp(&net_id, &peer, Arc::clone(conn));
        }
        let self_id = self.device_id.load(Ordering::Relaxed);
        match frame_type {
            FRAME_PING => {
                let pong = peer.codec.lock().unwrap().seal(self_id, FRAME_PONG, &payload);
                self.reply_on_arrival(&peer, &arrival, &pong);
            }
            FRAME_PONG => {
                let now = unix_ms();
                if payload.len() >= 8 {
                    let sent = i64::from_le_bytes(payload[..8].try_into().unwrap());
                    let rtt = now - sent;
                    if (0..600_000).contains(&rtt) {
                        peer.rtt_ms.store(rtt, Ordering::Relaxed);
                    }
                }
                peer.last_pong_ms.store(now, Ordering::Relaxed);
                if let Arrival::DirectUdp(from) = &arrival {
                    let (force_relay, _) = self.force_flags();
                    if !force_relay && peer.path() != PathKind::DirectUdp {
                        *peer.direct_endpoint.lock().unwrap() = Some(*from);
                        *peer.current_path.lock().unwrap() = PathKind::DirectUdp;
                        (self.log)(&format!(
                            "PATH_UP peer={} net={} type=DirectUdp ep={}",
                            peer.name(),
                            self.network_name(&net_id),
                            from
                        ));
                    }
                }
            }
            FRAME_DATA => (self.data_sink)(&payload),
            FRAME_FLOW => {
                let flows = Arc::clone(&self.flows);
                let peer_id = peer.id;
                let payload = payload.clone();
                tokio::spawn(async move {
                    flows.on_frame(net_id, peer_id, &payload).await;
                });
            }
            _ => {}
        }
    }
}

pub struct NodeEngine {
    pub shared: Arc<EngineShared>,
    #[allow(dead_code)]
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl NodeEngine {
    pub async fn start(
        config_path: PathBuf,
        cfg: NodeConfig,
        data_sink: DataSink,
        log: LogFn,
    ) -> anyhow::Result<Arc<NodeEngine>> {
        cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
        let dh_priv: [u8; 32] = hex::decode(cfg.identity.dh_private_key.expose())
            .map_err(|_| anyhow::anyhow!("身份中的 DH 私钥无效"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("身份中的 DH 私钥不是 32 字节"))?;
        let dh_pub: [u8; 32] = hex::decode(&cfg.identity.dh_public_key)
            .map_err(|_| anyhow::anyhow!("身份中的 DH 公钥无效"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("身份中的 DH 公钥不是 32 字节"))?;
        let server_url = cfg.server.clone();
        let device_id = cfg.identity.device_id;

        let (stopped_tx, stopped_rx) = watch::channel(false);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel::<EngineEvent>();
        let udp = UdpMesh::bind(cfg.listen_udp_port, events_tx.clone()).await?;
        if udp.fallback_used() {
            (log)(&format!("UDP 端口 {} 已被占用，已回退随机端口 {}", cfg.listen_udp_port, udp.local_port));
        }
        let control = Arc::new(ControlClient::new(&server_url, cfg.identity.device_token.expose(), cfg.identity.server_cert_pin.as_deref()));
        if control.insecure_http {
            (log)("警告：控制面使用明文 http://（服务器 --no-tls 模式？）");
        }

        let relay_key = skiff_core::protocol::relay_udp::relay_key_from_token(cfg.identity.device_token.expose());
        let relay_tcp = RelayTcpClient::new(device_id, &relay_key);

        let (flow_out_tx, mut flow_out_rx) = mpsc::unbounded_channel::<(NetId, u64, Vec<u8>)>();
        let networks: NetworksMap = Arc::new(DashMap::new());
        let flows = FlowManager::new(flow_out_tx, Arc::clone(&networks), log.clone());

        let shared = Arc::new(EngineShared {
            cfg: Mutex::new(cfg.clone()),
            config_path,
            networks: Arc::clone(&networks),
            name_to_id: RwLock::new(HashMap::new()),
            dh_priv,
            dh_pub,
            device_id: AtomicU64::new(device_id),
            control: Arc::clone(&control),
            udp: Arc::clone(&udp),
            relay_tcp: Arc::clone(&relay_tcp),
            peers: DashMap::new(),
            flows: Arc::clone(&flows),
            data_sink,
            events: events_tx.clone(),
            log: log.clone(),
            started_ms: unix_ms(),
            refresh_pending: AtomicBool::new(false),
            refresh_lock: tokio::sync::Mutex::new(()),
            observed_endpoint: Mutex::new(None),
            socks_port: AtomicU16::new(0),
            forward_ports: Mutex::new(Vec::new()),
            stopping: AtomicBool::new(false),
            applied_settings_revision: AtomicU64::new(0),
            restart_pending: AtomicBool::new(false),
            force_relay: AtomicBool::new(false),
            force_direct: AtomicBool::new(false),
            runtime_socks: Mutex::new(None),
            runtime_forwards: Mutex::new(Vec::new()),
            runtime_mtu: AtomicU32::new(cfg.mtu),
            stop_reason: Mutex::new(None),
            roster: Mutex::new(std::collections::HashSet::new()),
            stopped_tx: stopped_tx.clone(),
            stopped_rx,
        });

        // FetchConfigOrFail：服务端权威名单 → 逐网络配置（无限重试）。
        let configs = fetch_configs_or_fail(&shared).await;
        let Some(first_cfg) = configs.first().cloned() else {
            anyhow::bail!("配置中没有网络");
        };
        // TUN 限单网络（服务端名单口径；服务端强制 join 已预检，兜底）。
        if shared.cfg.lock().unwrap().mode == ClientMode::Tun && configs.len() > 1 {
            anyhow::bail!(
                "TUN 模式当前仅支持单网络，但服务端名单包含 {} 个网络（请在管理页移出多余网络后重启）",
                configs.len()
            );
        }
        let relay_host = resolve_relay_host(&server_url)?;
        udp.configure_relay(
            SocketAddr::new(std::net::IpAddr::V4(relay_host), first_cfg.relay_udp_port),
            device_id,
            &relay_key,
        );
        relay_tcp.configure(SocketAddr::new(std::net::IpAddr::V4(relay_host), first_cfg.relay_tcp_port));
        udp.send_register();

        warn_overlapping_cidrs(&shared);

        // Optional direct TCP listener (disabled on bind failure — no fallback).
        let tcp_listener = if cfg.listen_tcp_port > 0 {
            match tokio::net::TcpListener::bind(("0.0.0.0", cfg.listen_tcp_port)).await {
                Ok(l) => Some(l),
                Err(_) => {
                    (log)(&format!("TCP 端口 {} 已被占用，直连 TCP 监听已禁用", cfg.listen_tcp_port));
                    None
                }
            }
        } else {
            None
        };

        refresh_peers(&shared).await;

        // 托管配置收敛：遗留文件值收编（仅填未托管字段）→ 拉取权威值 →
        // 应用运行态。SOCKS/forwarders/MTU 以生效值在此确定——行为配置
        // 不落文件，重启时重新拉取。
        let settings = bootstrap_settings(&shared).await;
        apply_runtime_settings(&shared, &settings, true);
        let effective_socks = match settings.socks_listen.as_deref() {
            // 托管空串 = 显式禁用；未托管沿用默认开启。
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some("127.0.0.1:1080".to_string()),
        };
        let effective_forwards = settings.forwards.clone().unwrap_or_default();
        *shared.runtime_socks.lock().unwrap() = effective_socks.clone();
        *shared.runtime_forwards.lock().unwrap() = effective_forwards.clone();
        shared.runtime_mtu.store(settings.mtu.unwrap_or(cfg.mtu), Ordering::Relaxed);

        // Proxy-mode listeners: SOCKS5 + forwarders.
        if cfg.mode == ClientMode::Proxy {
            if let Some(socks) = &effective_socks {
                match proxy::socks5::spawn(socks, Arc::clone(&shared)).await {
                    Ok(port) => shared.socks_port.store(port, Ordering::Relaxed),
                    Err(e) => (log)(&format!("SOCKS5 启动失败: {e}")),
                }
            }
            let ports = proxy::forwarders::spawn_all(&effective_forwards, Arc::clone(&shared))
                .await
                .unwrap_or_default();
            *shared.forward_ports.lock().unwrap() = ports;
        }

        let mut tasks = Vec::new();

        // Inbound direct TCP accept loop.
        if let Some(listener) = tcp_listener {
            let events = events_tx.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            PeerTcpConnection::wrap(stream, events.clone());
                            // Attachment happens when a frame identifies (network, peer).
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    }
                }
            }));
        }

        // Central event loop: transports in, flow payloads out.
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        ev = events_rx.recv() => match ev {
                            None => break,
                            Some(EngineEvent::Frame { arrival, packet }) => {
                                shared2.handle_frame(arrival, &packet);
                            }
                            Some(EngineEvent::ObservedEndpoint(ep)) => {
                                *shared2.observed_endpoint.lock().unwrap() = Some(ep);
                            }
                            Some(EngineEvent::Log(msg)) => (shared2.log)(&msg),
                            Some(EngineEvent::TunPacket(pkt)) => {
                                // IPv4 only by design; unknown destinations drop.
                                if pkt.len() >= 20 && pkt[0] >> 4 == 4 {
                                    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                                    if let Some((net_id, peer)) = shared2.peer_by_ip(dst) {
                                        let frame = peer.codec.lock().unwrap().seal(
                                            shared2.device_id.load(Ordering::Relaxed),
                                            FRAME_DATA,
                                            &pkt,
                                        );
                                        shared2.route_sealed(&net_id, &peer, &frame);
                                    }
                                }
                            }
                        },
                        out = flow_out_rx.recv() => match out {
                            None => break,
                            Some((net, peer, payload)) => shared2.send_flow_payload(net, peer, &payload),
                        },
                    }
                }
            }));
        }

        // WS events per network -> engine reactions（名单以服务端为准）.
        for net_name in configs.iter().map(|c| c.network_name.clone()) {
            let shared2 = Arc::clone(&shared);
            let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<WsEvent>();
            control.spawn_event_loop(&net_name, ws_tx, shared.stopped_rx.clone());
            tasks.push(tokio::spawn(async move {
                while let Some(evt) = ws_rx.recv().await {
                    // Route by the event's network when present.
                    let target_net: Option<NetId> = evt
                        .network_id
                        .or_else(|| shared2.name_to_id.read().unwrap().get(&net_name).copied());
                    match evt.event_type.as_str() {
                        ws_events::CONNECTED => {
                            // 必须走 single-flight 的 refresh_peers：直调
                            // refresh_peers_for 会与并发刷新竞态，旧快照可能
                            // 覆盖新数据（probe backstop 本就每 5s 全网刷，
                            // 全网刷新的开销可接受）。
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                refresh_peers(&s).await;
                            });
                            // settings 推送是 at-most-once：连接（含重连）
                            // 建立时自拉一次兜底，revision 守卫保证幂等。
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                apply_settings(&s).await;
                            });
                            // 名单推送同理：重连时对账服务端 roster，补回
                            // 连接期间丢失的 networks_changed。
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                reconcile_roster(&s).await;
                            });
                        }
                        ws_events::PEERS_CHANGED
                        | ws_events::DEVICE_ONLINE
                        | ws_events::DEVICE_OFFLINE => {
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                refresh_peers(&s).await;
                            });
                        }
                        ws_events::SETTINGS_CHANGED => {
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                apply_settings(&s).await;
                            });
                        }
                        ws_events::RECONNECT_REQUESTED => {
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                s.udp.send_register();
                                s.relay_tcp.keepalive().await;
                                refresh_peers(&s).await;
                                (s.log)("已执行远程重连指令（重发中继注册并刷新 peers）");
                            });
                        }
                        ws_events::NETWORKS_CHANGED => {
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                reconcile_roster(&s).await;
                            });
                        }
                        ws_events::RESTART_REQUESTED => {
                            // 优雅停止（reason=Restart → worker 退出码 3），
                            // 由 master 进程以最新配置文件重新拉起新 worker。
                            let s = Arc::clone(&shared2);
                            tokio::spawn(async move {
                                (s.log)("收到远程重启指令：优雅停止，master 将以新配置重新拉起");
                                request_stop(&s, StopReason::Restart);
                            });
                        }
                        ws_events::CONFIG_CHANGED => {
                            let s = Arc::clone(&shared2);
                            let net = target_net;
                            tokio::spawn(async move {
                                apply_config_change(&s, net).await;
                            });
                        }
                        _ => {}
                    }
                }
            }));
        }

        // Heartbeat loop (15s; every 2nd tick re-registers with the relays).
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                let mut tick: u64 = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    heartbeat_tick(&shared2).await;
                    tick += 1;
                    if tick.is_multiple_of(2) {
                        shared2.udp.send_register();
                        shared2.relay_tcp.keepalive().await;
                    }
                }
            }));
        }

        // TOFU 指纹写回：无 pin 时自签首连被接受后，把指纹固化进
        // node.json（docs/protocol.md 承诺的"TOFU 首连固定 + 写回"）；
        // 内存 pin 已由 verifier 在握手时即时固化。
        {
            let shared2 = Arc::clone(&shared);
            let control = Arc::clone(&control);
            tasks.push(tokio::spawn(async move {
                if shared2.cfg.lock().unwrap().identity.server_cert_pin.is_some() {
                    return; // 已固定：TOFU 分支不可达
                }
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let Some(fp) = control.tofu_fingerprint.lock().unwrap().clone() else {
                        continue;
                    };
                    {
                        let mut cfg = shared2.cfg.lock().unwrap();
                        if cfg.identity.server_cert_pin.is_none() {
                            cfg.identity.server_cert_pin = Some(fp);
                            let path = shared2.config_path.clone();
                            let _ = crate::node_config::save(&path, &cfg);
                        }
                    }
                    (shared2.log)("TOFU：自签服务器证书指纹已固定并写入配置");
                    return;
                }
            }));
        }

        // Probe loop (5s).
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(skiff_core::consts::PATH_PROBE_INTERVAL).await;
                    probe_tick(&shared2).await;
                    let s = Arc::clone(&shared2);
                    tokio::spawn(async move {
                        refresh_peers(&s).await; // poll backstop for lost WS pushes
                    });
                }
            }));
        }

        // Status loop (5s write; 5 min STATS).
        {
            let shared2 = Arc::clone(&shared);
            let status_path = shared2.data_dir().join("status.json");
            tasks.push(tokio::spawn(async move {
                let mut tick: u64 = 0;
                loop {
                    write_status(&shared2, &status_path);
                    if tick.is_multiple_of(60) {
                        log_stats(&shared2);
                    }
                    tick += 1;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }));
        }

        // stop.flag watcher (1s).
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let flag = shared2.data_dir().join("stop.flag");
                    if flag.exists() {
                        let _ = std::fs::remove_file(&flag);
                        (shared2.log)("检测到 stop.flag，正在停止引擎……");
                        request_stop(&shared2, StopReason::Stopped);
                        break;
                    }
                }
            }));
        }

        Ok(Arc::new(NodeEngine { shared, tasks }))
    }

    /// Resolves when the engine stops (stop.flag / shutdown / 远程重启).
    /// 复用常驻接收者的克隆（与 subscribe 等价：以当前值为已见基线，
    /// 先查再等，停止后调用也能立即返回）。
    pub async fn stopped(&self) {
        let mut rx = self.shared.stopped_rx.clone();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                break;
            }
        }
    }

    pub fn shutdown(&self) {
        request_stop(&self.shared, StopReason::Stopped);
    }

    /// worker 宿主使用的退出码：远程重启 = 3，其余 = 0（见 supervisor.rs）。
    pub fn exit_code(&self) -> i32 {
        match *self.shared.stop_reason.lock().unwrap() {
            Some(StopReason::Restart) => crate::supervisor::EXIT_RESTART,
            _ => crate::supervisor::EXIT_OK,
        }
    }

    /// Test/introspection helpers.
    pub fn peers(&self) -> Vec<(NetId, Arc<PeerSession>)> {
        self.shared.peers.iter().map(|p| (p.key().0, Arc::clone(p.value()))).collect()
    }

    pub fn peer_by_ip(&self, ip: Ipv4Addr) -> Option<Arc<PeerSession>> {
        self.shared.peer_by_ip(ip).map(|(_, p)| p)
    }

    pub fn flows(&self) -> Arc<FlowManager> {
        Arc::clone(&self.shared.flows)
    }

    pub fn socks_port(&self) -> u16 {
        self.shared.socks_port.load(Ordering::Relaxed)
    }

    pub fn forward_ports(&self) -> Vec<u16> {
        self.shared.forward_ports.lock().unwrap().clone()
    }

    pub fn refresh_peers(&self) {
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            refresh_peers(&shared).await;
        });
    }
}

/// 请求引擎停止并广播 stopped（幂等；首次触发时锁定停止原因）。
pub fn request_stop(shared: &Arc<EngineShared>, reason: StopReason) {
    if shared.stopping.swap(true, Ordering::Relaxed) {
        return;
    }
    shared.stop_reason.lock().unwrap().get_or_insert(reason);
    (shared.log)("引擎停止中……");
    let _ = std::fs::remove_file(shared.data_dir().join("status.json"));
    let _ = shared.stopped_tx.send(true);
}

fn warn_overlapping_cidrs(shared: &Arc<EngineShared>) {
    let cidrs: Vec<(String, Cidr)> = shared
        .networks
        .iter()
        .filter_map(|c| c.value().cidr.map(|cidr| (c.value().name.clone(), cidr)))
        .collect();
    for i in 0..cidrs.len() {
        for j in (i + 1)..cidrs.len() {
            let (an, a) = &cidrs[i];
            let (bn, b) = &cidrs[j];
            if a.contains(b.network) || b.contains(a.network) {
                (shared.log)(&format!(
                    "警告：网络 {an}（{a}）与 {bn}（{b}）网段重叠，虚拟 IP 解析将取先命中者"
                ));
            }
        }
    }
}

/// 对账服务端名单：与本地 roster 不一致时更新并触发修剪/标记待重启。
/// 由 networks_changed 推送与每次 WS 连接（含重连）触发——推送是
/// at-most-once，重连自拉补回丢失的变更。
async fn reconcile_roster(shared: &Arc<EngineShared>) {
    let Some(list) = shared.control.get_memberships().await else {
        return; // 拉取失败：等下次推送/重连兜底
    };
    let new_ids: std::collections::HashSet<NetId> = list.iter().map(|m| m.network_id).collect();
    let changed = {
        let mut r = shared.roster.lock().unwrap();
        if *r == new_ids {
            false
        } else {
            *r = new_ids;
            true
        }
    };
    if changed {
        shared.restart_pending.store(true, Ordering::Relaxed);
        (shared.log)(
            "网络成员关系已变化：离开的网络数秒内自动修剪；新加入的网络需重启引擎生效（管理页可远程重启）",
        );
    }
    // prune（roster 已更新）会移除已离开的网络。
    refresh_peers(shared).await;
}

async fn fetch_configs_or_fail(shared: &Arc<EngineShared>) -> Vec<ConfigResponse> {
    // 服务端权威名单（无限重试：服务器不可达时节点无法工作）。
    let roster = fetch_memberships_or_fail(shared).await;
    fetch_configs_for_roster(shared, &roster).await
}

/// 拉取服务端成员名单，直到成功且非空。
async fn fetch_memberships_or_fail(shared: &Arc<EngineShared>) -> Vec<MembershipInfo> {
    let mut attempt: u32 = 0;
    loop {
        match shared.control.get_memberships().await {
            Some(list) if !list.is_empty() => return list,
            Some(_) => {
                (shared.log)("服务器返回空的网络名单（成员关系已被清空？）3s 后重试");
            }
            None => {
                attempt += 1;
                (shared.log)(&format!("cannot reach control plane (attempt {attempt}); retrying in 3s"));
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 按服务端名单逐网络拉配置并构建运行态；成功时登记 roster、热注册
/// exposes、把名单回写为文件缓存。
async fn fetch_configs_for_roster(
    shared: &Arc<EngineShared>,
    roster: &[MembershipInfo],
) -> Vec<ConfigResponse> {
    let mut out = Vec::new();
    let mut attempt: u32 = 0;
    loop {
        let mut all_ok = true;
        out.clear();
        for m in roster {
            if let Some(c) = shared.control.get_config(&m.network_name).await {
                shared.networks.entry(c.network_id).or_insert_with(|| NetworkCtx {
                    name: c.network_name.clone(),
                    cidr: None,
                    self_ip: None,
                    ip_map: HashMap::new(),
                });
                {
                    let mut ctx = shared.networks.get_mut(&c.network_id).unwrap();
                    ctx.cidr = Cidr::parse(&c.cidr).ok();
                    ctx.self_ip = c.ip.parse::<Ipv4Addr>().ok();
                }
                shared.name_to_id.write().unwrap().insert(c.network_name.clone(), c.network_id);
                out.push(c);
            } else {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            {
                let mut r = shared.roster.lock().unwrap();
                r.clear();
                r.extend(roster.iter().map(|m| m.network_id));
            }
            return out;
        }
        attempt += 1;
        (shared.log)(&format!("cannot reach control plane (attempt {attempt}); retrying in 3s"));
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

async fn apply_config_change(shared: &Arc<EngineShared>, net: Option<NetId>) {
    // Re-fetch the affected network (or all runtime networks when unknown).
    let names: Vec<String> = match net {
        Some(id) => vec![shared.network_name(&id)],
        None => shared.networks.iter().map(|c| c.value().name.clone()).collect(),
    };
    for name in names {
        if let Some(c) = shared.control.get_config(&name).await {
            if let Some(mut ctx) = shared.networks.get_mut(&c.network_id) {
                ctx.cidr = Cidr::parse(&c.cidr).ok();
                ctx.self_ip = c.ip.parse::<Ipv4Addr>().ok();
            }
            (shared.log)(&format!("配置已变更（网络 {} 的虚拟 IP 可能已更新）", c.network_name));
        }
    }
    refresh_peers(shared).await;
}

/// 启动时的托管配置收敛：先尝试把遗留文件值收编为服务端托管（仅填
/// 未托管字段，收编响应即合并后的权威值），失败或无遗留则直接拉取。
/// 无限重试——行为配置已不落文件，拉不到就无法确定 SOCKS/forwards。
async fn bootstrap_settings(shared: &Arc<EngineShared>) -> DeviceSettings {
    let candidate = legacy_seed(&shared.config_path);
    if !candidate.is_empty()
        && let Some(merged) = shared.control.adopt_settings(&candidate).await
    {
        (shared.log)("遗留本地配置已收编为服务端托管");
        return merged;
    }
    // 收编失败（罕见）：继续走拉取，下次启动再收编。
    loop {
        if let Some(s) = shared.control.get_settings().await {
            return s;
        }
        (shared.log)("cannot fetch settings; retrying in 3s");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 从配置文件原始 JSON 提取遗留行为字段的**非默认值**作为收编候选
///（NodeConfig 已不解析这些字段，此处按原始键读取；默认值不收编，
/// 保持服务端托管面最小）。文件被重写后遗留键消失，收编自动停止。
fn legacy_seed(path: &std::path::Path) -> DeviceSettings {
    let mut out = DeviceSettings::default();
    let Ok(text) = std::fs::read_to_string(path) else { return out };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return out };
    if v["forceRelay"].as_bool() == Some(true) {
        out.force_relay = Some(true);
    }
    if v["forceDirect"].as_bool() == Some(true) {
        out.force_direct = Some(true);
    }
    if let Some(mtu) = v["mtu"].as_u64().filter(|m| *m != u64::from(skiff_core::consts::DEFAULT_MTU)) {
        out.mtu = Some(mtu as u32);
    }
    if let Some(socks) = v["socksListen"].as_str().filter(|s| *s != "127.0.0.1:1080") {
        out.socks_listen = Some(socks.to_string());
    }
    if let Some(fwd) = v["forwards"].as_array().filter(|a| !a.is_empty())
        && let Ok(rules) = serde_json::from_value::<Vec<ForwardRule>>(serde_json::Value::Array(fwd.clone()))
    {
        out.forwards = Some(rules);
    }
    if let Some(nets) = v["networks"].as_array() {
        let mut list = Vec::new();
        for n in nets {
            let Some(rules_v) = n["exposes"].as_array().filter(|a| !a.is_empty()) else { continue };
            let Some(id) = n["networkId"].as_str().and_then(NetId::from_hex) else { continue };
            if let Ok(rules) = serde_json::from_value::<Vec<ExposeRule>>(serde_json::Value::Array(rules_v.clone()))
                && !rules.is_empty()
            {
                list.push(NetworkExposes { network_id: id, rules });
            }
        }
        if !list.is_empty() {
            out.exposes = Some(list);
        }
    }
    out
}

/// 把托管配置应用到运行态。热改字段（force 开关 / exposes）立即生效；
/// 重启类字段（mtu / socks / forwards）不落文件——与启动时实际生效值
/// 比对，有差异即置 restart_pending，重启时按拉取值重建。
fn apply_runtime_settings(shared: &Arc<EngineShared>, settings: &DeviceSettings, startup: bool) {
    if let Some(v) = settings.force_relay {
        shared.force_relay.store(v, Ordering::Relaxed);
    }
    if let Some(v) = settings.force_direct {
        shared.force_direct.store(v, Ordering::Relaxed);
    }
    if let Some(list) = &settings.exposes {
        for ne in list {
            // 热应用：对新入站连接立即生效（已建立的旧 flow 不受影响）。
            if shared.networks.contains_key(&ne.network_id) {
                shared.flows.set_exposes(ne.network_id, ne.rules.clone());
            }
        }
    }
    if !startup {
        let mut pending = shared.restart_pending.load(Ordering::Relaxed);
        if let Some(v) = settings.mtu
            && v != shared.runtime_mtu.load(Ordering::Relaxed)
        {
            pending = true;
        }
        if let Some(v) = settings.socks_listen.as_deref() {
            let desired = if v.is_empty() { None } else { Some(v.to_string()) };
            if *shared.runtime_socks.lock().unwrap() != desired {
                pending = true;
            }
        }
        if let Some(v) = &settings.forwards
            && &*shared.runtime_forwards.lock().unwrap() != v
        {
            pending = true;
        }
        shared.restart_pending.store(pending, Ordering::Relaxed);
        if pending {
            (shared.log)("托管配置已更新：mtu/socks/forwards 将在引擎重启后生效");
        }
    }
}

/// 拉取并应用服务端托管配置（WS settings_changed / 重连自拉触发）。
async fn apply_settings(shared: &Arc<EngineShared>) {
    let Some(settings) = shared.control.get_settings().await else {
        return; // 拉取失败：等下次推送/重连/心跳周期重试
    };
    let rev = settings.revision;
    if shared.applied_settings_revision.load(Ordering::Relaxed) >= rev as u64 {
        return; // 已应用（重复投递 / 旧版本晚到）
    }
    apply_runtime_settings(shared, &settings, false);
    shared.applied_settings_revision.store(rev as u64, Ordering::Relaxed);
    // 立即上报一次心跳，让管理页快速看到 appliedRevision 收敛。
    heartbeat_tick(shared).await;
}

/// Single-flight peers refresh: concurrent triggers collapse; a trigger
/// arriving mid-refresh is absorbed by the pending flag.
pub async fn refresh_peers(shared: &Arc<EngineShared>) {
    shared.refresh_pending.store(true, Ordering::Relaxed);
    let Ok(_guard) = shared.refresh_lock.try_lock() else { return };
    while shared.refresh_pending.swap(false, Ordering::Relaxed) {
        refresh_peers_for(shared, None).await;
    }
}

/// Refresh one network (net = None means all). In the all-sweep, networks
/// absent from the configured list are pruned entirely (contexts, peers,
/// flows) — the config file is the source of truth for participation.
pub async fn refresh_peers_for(shared: &Arc<EngineShared>, net: Option<NetId>) {
    let names: Vec<(NetId, String)> = match net {
        Some(id) => shared
            .networks
            .iter()
            .filter(|c| *c.key() == id)
            .map(|c| (*c.key(), c.value().name.clone()))
            .collect(),
        None => shared.networks.iter().map(|c| (*c.key(), c.value().name.clone())).collect(),
    };
    for (net_id, name) in names {
        refresh_one_network(shared, net_id, &name).await;
    }
    if net.is_none() {
        // 以服务端名单为准（cfg.networks 只是展示缓存）。
        let configured: std::collections::HashSet<NetId> = shared.roster.lock().unwrap().clone();
        let stale: Vec<NetId> = shared
            .networks
            .iter()
            .filter(|c| !configured.contains(c.key()))
            .map(|c| *c.key())
            .collect();
        for id in stale {
            let name = shared.network_name(&id);
            shared.networks.remove(&id);
            let victims: Vec<u64> = shared
                .peers
                .iter()
                .filter(|e| e.key().0 == id)
                .map(|e| e.key().1)
                .collect();
            for dev in victims {
                if let Some((_, p)) = shared.peers.remove(&(id, dev)) {
                    shared.flows.close_peer(id, dev);
                    *p.tcp_conn.lock().unwrap() = None;
                }
            }
            (shared.log)(&format!("left network {name} (no longer in config)"));
        }
    }
}

async fn refresh_one_network(shared: &Arc<EngineShared>, net_id: NetId, name: &str) {
    let Some(list) = shared.control.get_peers(name).await else { return };

    let mut next_ip_map: HashMap<u32, u64> = HashMap::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for info in list {
        let Ok(vip) = info.ip.parse::<Ipv4Addr>() else { continue };
        let Ok(dh_bytes) = hex::decode(&info.dh_pubkey) else { continue };
        let Ok(dh_pub): Result<[u8; 32], _> = dh_bytes.try_into() else { continue };
        next_ip_map.insert(u32::from(vip), info.device_id);

        let mut endpoints = Vec::new();
        for ep in &info.udp_endpoints {
            if let Ok(addr) = ep.parse::<SocketAddr>()
                && addr.ip() != std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    && addr.ip() != std::net::IpAddr::V4(Ipv4Addr::BROADCAST)
                {
                    endpoints.push(addr);
                }
        }

        let key = (net_id, info.device_id);
        let peer = match shared.peers.get(&key) {
            Some(existing) => {
                let p = Arc::clone(existing.value());
                *p.name.lock().unwrap() = info.name.clone();
                *p.virtual_ip.lock().unwrap() = vip;
                p.online.store(info.online, Ordering::Relaxed);
                *p.tcp_listen_port.lock().unwrap() = info.tcp_listen_port;
                *p.endpoints.lock().unwrap() = endpoints;
                p
            }
            None => {
                let keys = SessionKeys::derive(&shared.dh_priv, &shared.dh_pub, &dh_pub, &net_id.0)
                    .expect("peer session keys derive");
                let p = PeerSession::new(info.device_id, net_id, info.name.clone(), vip, dh_pub, keys);
                p.online.store(info.online, Ordering::Relaxed);
                *p.tcp_listen_port.lock().unwrap() = info.tcp_listen_port;
                *p.endpoints.lock().unwrap() = endpoints;
                shared.peers.insert(key, Arc::clone(&p));
                (shared.log)(&format!("peer {} joined network {} ({})", info.name, name, vip));
                p
            }
        };
        seen.insert(peer.id);
    }

    // Remove peers that disappeared from THIS network only.
    let gone: Vec<u64> = shared
        .peers
        .iter()
        .filter(|e| e.key().0 == net_id && !seen.contains(&e.key().1))
        .map(|e| e.key().1)
        .collect();
    for dev in gone {
        if let Some((_, p)) = shared.peers.remove(&(net_id, dev)) {
            shared.flows.close_peer(net_id, dev);
            *p.tcp_conn.lock().unwrap() = None; // dropped socket closes
            (shared.log)(&format!("peer {} left network {}", p.name(), name));
        }
    }
    if let Some(mut ctx) = shared.networks.get_mut(&net_id) {
        ctx.ip_map = next_ip_map;
    }
}

async fn heartbeat_tick(shared: &Arc<EngineShared>) {
    let (force_relay, _force_direct) = shared.force_flags();
    // Only report peers we have actually interacted with (rtt recorded):
    // a never-answered peer would report its initial RelayUdp state, which
    // misleads the topology view into drawing phantom relay edges.
    let paths: Vec<PeerPathReport> = shared
        .peers
        .iter()
        .filter_map(|p| {
            let rtt = p.value().rtt_ms.load(Ordering::Relaxed);
            if rtt < 0 {
                return None;
            }
            let path = if force_relay {
                "RelayUdp(forced)".to_string()
            } else {
                p.value().path().as_str().to_string()
            };
            Some(PeerPathReport {
                device_id: p.key().1,
                path,
                rtt_ms: Some(rtt),
            })
        })
        .collect();
    let (listen_tcp_port, mode_str) = {
        let cfg = shared.cfg.lock().unwrap();
        (
            if cfg.listen_tcp_port > 0 { Some(cfg.listen_tcp_port) } else { None },
            cfg.mode.as_str().to_string(),
        )
    };
    let req = HeartbeatRequest {
        local_addrs: crate::local_ipv4_addrs(),
        listen_udp_port: Some(shared.udp.local_port),
        listen_tcp_port,
        paths: Some(paths),
        settings_revision: Some(shared.applied_settings_revision.load(Ordering::Relaxed) as i64),
        restart_pending: Some(shared.restart_pending.load(Ordering::Relaxed)),
        mode: Some(mode_str),
    };
    match shared.control.heartbeat(&req).await {
        Some(resp) => {
            if let Some(ep) = resp.observed_udp_endpoint {
                *shared.observed_endpoint.lock().unwrap() = Some(ep);
            }
        }
        None => {
            (shared.log)(&format!(
                "HEARTBEAT_ERR uptime_s={} err=request failed",
                (unix_ms() - shared.started_ms) / 1000
            ));
        }
    }
}

async fn probe_tick(shared: &Arc<EngineShared>) {
    let peers: Vec<(NetId, Arc<PeerSession>)> = shared
        .peers
        .iter()
        .filter(|p| p.value().online())
        .map(|p| (p.key().0, Arc::clone(p.value())))
        .collect();
    for (net_id, peer) in peers {
        probe_peer(shared, net_id, peer).await;
    }
}

async fn probe_peer(shared: &Arc<EngineShared>, net_id: NetId, peer: Arc<PeerSession>) {
    let self_id = shared.device_id.load(Ordering::Relaxed);
    let ping = {
        let mut codec = peer.codec.lock().unwrap();
        let now = unix_ms();
        codec.seal(self_id, FRAME_PING, &now.to_le_bytes())
    };
    // Keep the current path alive.
    shared.route_sealed(&net_id, &peer, &ping);

    let (force_relay, force_direct) = shared.force_flags();
    if force_relay {
        return;
    }
    let path = peer.path();
    let now = unix_ms();
    if path != PathKind::DirectUdp {
        // Direct UDP probes: known endpoints (up to 4) + neighbour-port
        // prediction around the relay-observed endpoint (symmetric NATs
        // allocate ports sequentially).
        let endpoints = peer.endpoints.lock().unwrap().clone();
        for ep in endpoints.iter().take(4) {
            shared.udp.send_direct(*ep, &ping);
        }
        if let Some(observed) = endpoints.first() {
            for d in 1u16..=4 {
                if let Some(p) = observed.port().checked_add(d) {
                    shared.udp.send_direct(SocketAddr::new(observed.ip(), p), &ping);
                }
                if observed.port() > d + 1024 {
                    shared.udp.send_direct(SocketAddr::new(observed.ip(), observed.port() - d), &ping);
                }
            }
        }
        try_direct_tcp_probe(shared, &peer, &endpoints).await;
    } else {
        let dead_after = (skiff_core::consts::PEER_PING_INTERVAL
            * skiff_core::consts::PEER_PING_MISS_LIMIT)
            .as_millis() as i64;
        // 直连升级只在收到 PONG 时发生（升级前必已写入 last_pong_ms），
        // 因此 DirectUdp 路径下 last 恒 > 0；last==0 表示从未直连成功。
        let last = peer.last_pong_ms.load(Ordering::Relaxed);
        if last > 0 && now - last > dead_after && !force_direct {
            *peer.current_path.lock().unwrap() = PathKind::RelayUdp;
            *peer.direct_endpoint.lock().unwrap() = None;
            (shared.log)(&format!(
                "PATH_DOWN peer={} net={} from=DirectUdp to=RelayUdp reason=timeout",
                peer.name(),
                shared.network_name(&net_id)
            ));
        }
    }
}

async fn try_direct_tcp_probe(shared: &Arc<EngineShared>, peer: &Arc<PeerSession>, endpoints: &[SocketAddr]) {
    let Some(tcp_port) = *peer.tcp_listen_port.lock().unwrap() else { return };
    if peer.tcp_conn.lock().unwrap().is_some() {
        return;
    }
    let Some(first) = endpoints.first() else { return };
    let now = unix_ms();
    if now < peer.tcp_cooldown_until_ms.load(Ordering::Relaxed) {
        return;
    }
    peer.tcp_cooldown_until_ms.store(now + 60_000, Ordering::Relaxed);
    let target = SocketAddr::new(first.ip(), tcp_port);
    let shared = Arc::clone(shared);
    let peer = Arc::clone(peer);
    // The connection's frames feed the central loop; the network binding
    // resolves on the first successfully decrypted frame.
    let (tx, mut rx) = mpsc::unbounded_channel::<EngineEvent>();
    {
        let shared2 = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                if let EngineEvent::Frame { arrival, packet } = ev {
                    shared2.handle_frame(arrival, &packet);
                }
            }
        });
    }
    tokio::spawn(async move {
        // Silent on connect failure: the cooldown throttles retries.
        if let Ok(conn) = PeerTcpConnection::connect(target, Duration::from_secs(3), tx).await {
            let nets: Vec<NetId> = shared.peers.iter().filter(|e| e.key().1 == peer.id).map(|e| e.key().0).collect();
            if let Some(net_id) = nets.first() {
                shared.attach_peer_tcp(net_id, &peer, Arc::clone(&conn));
            }
            let self_id = shared.device_id.load(Ordering::Relaxed);
            let ping = {
                let mut codec = peer.codec.lock().unwrap();
                codec.seal(self_id, FRAME_PING, &unix_ms().to_le_bytes())
            };
            conn.send(&ping);
            peer.add_tx(ping.len());
        }
    });
}

fn resolve_relay_host(server_url: &str) -> anyhow::Result<Ipv4Addr> {
    let host = server_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let v4 = match ip {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => Ipv4Addr::LOCALHOST,
        };
        return Ok(if v4 == Ipv4Addr::UNSPECIFIED { Ipv4Addr::LOCALHOST } else { v4 });
    }
    use std::net::ToSocketAddrs;
    for a in (host.as_str(), 80).to_socket_addrs()? {
        if let std::net::IpAddr::V4(v4) = a.ip() {
            return Ok(v4);
        }
    }
    Err(anyhow::anyhow!("无法解析服务器地址 {host}"))
}

fn write_status(shared: &Arc<EngineShared>, path: &std::path::Path) {
    let networks: Vec<NetworkStatus> = shared
        .networks
        .iter()
        .map(|c| NetworkStatus {
            network: c.value().name.clone(),
            ip: c.value().self_ip.map(|i| i.to_string()).unwrap_or_default(),
            cidr: c.value().cidr.map(|c| c.to_string()).unwrap_or_default(),
        })
        .collect();
    let peers: Vec<PeerStatus> = shared
        .peers
        .iter()
        .map(|p| {
            let p = p.value();
            let endpoint = p
                .direct_endpoint
                .lock()
                .unwrap()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "relay".to_string());
            PeerStatus {
                network: shared.network_name(&p.network_id_hint),
                name: p.name(),
                ip: p.virtual_ip().to_string(),
                online: p.online(),
                path: p.path().as_str().to_string(),
                endpoint,
                rtt_ms: p.rtt_ms.load(Ordering::Relaxed),
                tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
                rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
                tx_packets: p.tx_packets.load(Ordering::Relaxed),
                rx_packets: p.rx_packets.load(Ordering::Relaxed),
            }
        })
        .collect();
    let (server, mode) = {
        let cfg = shared.cfg.lock().unwrap();
        (cfg.server.clone(), cfg.mode.as_str().to_string())
    };
    let forwards = shared
        .runtime_forwards
        .lock()
        .unwrap()
        .iter()
        .map(|f| format!("{} {}->{}", f.proto, f.listen, f.dest))
        .collect::<Vec<_>>();
    let socks_port = shared.socks_port.load(Ordering::Relaxed);
    let report = StatusReport {
        running: true,
        pid: std::process::id(),
        started_at: shared.started_ms,
        uptime_sec: (unix_ms() - shared.started_ms) / 1000,
        server,
        networks,
        mode,
        udp_port: shared.udp.local_port,
        observed_endpoint: shared.observed_endpoint.lock().unwrap().clone(),
        socks: (socks_port > 0).then(|| format!("127.0.0.1:{socks_port}")),
        forwards,
        peers,
    };
    let _ = std::fs::write(path, serde_json::to_string_pretty(&report).unwrap_or_default());
}

fn log_stats(shared: &Arc<EngineShared>) {
    let uptime = (unix_ms() - shared.started_ms) / 1000;
    let peers: Vec<(NetId, Arc<PeerSession>)> =
        shared.peers.iter().map(|p| (p.key().0, Arc::clone(p.value()))).collect();
    if peers.is_empty() {
        (shared.log)(&format!("STATS peers=0 uptime_s={uptime}"));
        return;
    }
    for (net_id, p) in peers {
        let endpoint = p
            .direct_endpoint
            .lock()
            .unwrap()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "relay".to_string());
        (shared.log)(&format!(
            "STATS peer={} net={} ip={} online={} path={} ep={} rtt_ms={} tx={} rx={} tx_pkts={} rx_pkts={} uptime_s={}",
            p.name(),
            shared.network_name(&net_id),
            p.virtual_ip(),
            p.online(),
            p.path().as_str(),
            endpoint,
            p.rtt_ms.load(Ordering::Relaxed),
            p.tx_bytes.load(Ordering::Relaxed),
            p.rx_bytes.load(Ordering::Relaxed),
            p.tx_packets.load(Ordering::Relaxed),
            p.rx_packets.load(Ordering::Relaxed),
            uptime,
        ));
    }
}
