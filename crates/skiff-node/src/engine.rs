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
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU32, AtomicU64, Ordering};
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
use crate::session::{PathKind, PeerSession, policy_allows};
use crate::transport::peer_tcp::PeerTcpConnection;
use crate::transport::relay_tcp::RelayTcpClient;
use crate::transport::udp_mesh::UdpMesh;

/// How a frame arrived — determines the PONG return path and upgrade rules.
pub enum Arrival {
    /// (对端地址, 本地绑定地址)——PONG 沿到达 socket 回复、直连数据经
    /// 学习到端点的 socket 发送（多绑定下保持 NAT 映射一致）。
    DirectUdp(SocketAddr, SocketAddr),
    DirectTcp(Arc<PeerTcpConnection>),
    RelayUdp,
    RelayTcp,
}

impl Arrival {
    pub fn direct_udp(from: SocketAddr, local_bind: SocketAddr) -> Arrival {
        Arrival::DirectUdp(from, local_bind)
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

/// RelayTcp 出站队列项（见 EngineShared.relay_tcp_tx 注释）。
pub struct RelayTcpOut {
    pub peer: Arc<PeerSession>,
    pub frame: Vec<u8>,
    /// Auto（残留态）失败回落 UDP 中继；pin 档失败即丢帧计数。
    pub fallback: bool,
    pub policy: PathPolicy,
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

/// 心跳差分基线的每对端计数快照：字节速率（tx/rx）与帧缺口率
/// （rx_seen/rx_lost，来自 wire 重放窗口统计）共用同一基线时钟。
#[derive(Clone, Copy, Debug)]
pub struct HbCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub rx_seen: u64,
    pub rx_lost: u64,
}

/// 心跳差分基线：device_id → 上次采样时的累计计数快照。
type HbRateMap = HashMap<u64, HbCounters>;

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
    /// RelayTcp 出站 FIFO（单消费者任务顺序发送——每帧 tokio::spawn 在
    /// multi_thread 下不保序，会引入 TCP 本身不会有的帧乱序，FLOW
    /// DATA/CLOSE 乱序将静默截断流；且 ensure_connected 内联 10s 连接
    /// 超时，不能在中央事件循环直接 await）。
    pub relay_tcp_tx: mpsc::UnboundedSender<RelayTcpOut>,
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
    /// 服务端建议的心跳间隔（自适应：管理页被查看时快档）。心跳循环
    /// 睡前读取、响应后更新；建议随每次心跳重发，无需额外同步协议。
    pub heartbeat_secs: AtomicU32,
    /// 上次心跳的速率差分基线：每对端累计 (tx,rx) 快照 + 采样时刻。
    /// 每次心跳对差分得 txBps/rxBps 后整体替换；对端消失随之清理。
    pub hb_rate_baseline: Mutex<Option<(std::time::Instant, HbRateMap)>>,
    /// 心跳失败日志节流（60s 一条 + 期间计数；差链路下不刷屏）与恢复补报。
    pub hb_err_last_log_ms: AtomicI64,
    pub hb_err_count: AtomicU64,
    /// 生效路径策略：对端覆盖 ?? 全局默认 ?? Auto（服务端托管，热生效，
    /// 每帧现读）。只决定本端出口；接收方全路径接收。
    pub path_policy: Mutex<PathPolicy>,
    /// 按对端覆盖表（device_id → 策略）。
    pub peer_policies: DashMap<u64, PathPolicy>,
    /// 启动时实际生效的 SOCKS/forwards/MTU（状态展示 + 托管变更的
    /// restart_pending 比对基准）——行为配置不再落文件。
    pub runtime_socks: Mutex<Option<String>>,
    pub runtime_forwards: Mutex<Vec<ForwardRule>>,
    pub runtime_mtu: AtomicU32,
    /// 启动时实际生效的运行模式与监听地址（托管 diff 的比对基准）。
    pub runtime_mode: Mutex<ClientMode>,
    pub runtime_listen: Mutex<Vec<String>>,
    /// primary TCP 监听端口（心跳上报实际值；0=无监听）。
    pub tcp_listen_port: AtomicU16,
    /// 全部成功绑定的 TCP 监听端口（运行时防火墙规则同步用）。
    pub tcp_listen_ports: Mutex<Vec<u16>>,
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
    /// 按对端当前出口路径选 FLOW DATA 分块：UDP 路径（直连/中继）用
    /// FLOW_CHUNK_UDP（密封后不分片——32KiB 分 ~23 片在公网丢包下丢失
    /// 放大 ~23 倍）；TCP 路径用 FLOW_CHUNK 大块省开销。peer 未建立
    /// （查不到）保守走小块——初期流量经中继 UDP 的概率高。
    pub fn flow_chunk_for(&self, net_id: NetId, peer: u64) -> usize {
        let udp_path = self
            .peers
            .get(&(net_id, peer))
            .map(|p| {
                matches!(
                    p.value().path(),
                    PathKind::DirectUdp | PathKind::RelayUdp
                )
            })
            .unwrap_or(true);
        if udp_path {
            skiff_core::consts::FLOW_CHUNK_UDP
        } else {
            skiff_core::consts::FLOW_CHUNK
        }
    }

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

    fn policy_for(&self, peer_id: u64) -> PathPolicy {
        if let Some(hit) = self.peer_policies.get(&peer_id) {
            return *hit;
        }
        *self.path_policy.lock().unwrap()
    }

    /// Seal + route one frame to a peer on its network (RouteSealed)。
    /// 路径 = 按策略解析；中继回退仅 Auto 允许（手动 pin 确定性优先，
    /// 资源缺失丢帧并靠探测重建）。
    fn route_sealed(&self, net_id: &NetId, peer: &Arc<PeerSession>, frame: &[u8]) {
        if self.stopping.load(Ordering::Relaxed) {
            return;
        }
        let self_id = self.device_id.load(Ordering::Relaxed);
        let policy = self.policy_for(peer.id);
        // Auto 下允许"直连资源缺失→中继兜底"；策略档不允许。
        let relay_fallback = policy == PathPolicy::Auto;
        let path = match policy {
            PathPolicy::Auto => peer.path(),
            PathPolicy::RelayUdp => PathKind::RelayUdp,
            PathPolicy::RelayTcp => PathKind::RelayTcp,
            PathPolicy::DirectAny => match peer.path() {
                PathKind::DirectUdp | PathKind::DirectTcp => peer.path(),
                _ => {
                    // 无既有直连：优先可用 TCP 连接，其次 UDP 端点；全无丢帧。
                    let conn = peer.tcp_conn.lock().unwrap().clone();
                    if conn.as_ref().is_some_and(|c| !c.is_closed()) {
                        PathKind::DirectTcp
                    } else if peer.direct_endpoint.lock().unwrap().is_some() {
                        PathKind::DirectUdp
                    } else {
                        // No direct resource: drop rather than leak via relay.
                        self.note_policy_drop(peer, "directAny-no-resource");
                        return;
                    }
                }
            },
            PathPolicy::DirectUdp => PathKind::DirectUdp,
            PathPolicy::DirectTcp => PathKind::DirectTcp,
        };
        match path {
            PathKind::DirectUdp => {
                // 学习到的端点带本地绑定：直连数据经学习到它的 socket 发送
                //（保持 NAT 映射一致）；无端点时用观测端点兜底（primary）。
                let learned = peer.direct_endpoint.lock().unwrap().is_some();
                if learned {
                    let (ep, local) = peer.direct_endpoint.lock().unwrap().unwrap();
                    self.udp.send_direct_from(local, ep, frame);
                    peer.add_tx(frame.len());
                } else {
                    let ep = peer.endpoints.lock().unwrap().first().copied();
                    match ep {
                        Some(ep) => self.udp.send_direct(ep, frame),
                        None if relay_fallback => self.udp.send_relay(self_id, peer.id, frame),
                        None => self.note_policy_drop(peer, "directUdp-no-endpoint"),
                    }
                    peer.add_tx(frame.len());
                }
            }
            PathKind::DirectTcp => {
                let conn = peer.tcp_conn.lock().unwrap().clone();
                match conn {
                    Some(conn) if !conn.is_closed() => {
                        if conn.send(frame) {
                            peer.add_tx(frame.len());
                        } else {
                            // 发送失败计入丢帧（曾静默——连接写端已死等探测重建）。
                            self.note_policy_drop(peer, "directTcp-send-failed");
                        }
                    }
                    _ if relay_fallback => {
                        self.udp.send_relay(self_id, peer.id, frame);
                        peer.add_tx(frame.len());
                    }
                    _ => self.note_policy_drop(peer, "directTcp-no-conn"),
                }
            }
            PathKind::RelayTcp => {
                // 经单消费者 FIFO 发送（保序；ensure_connected 的 10s 连接
                // 超时在队列任务里消化，不阻塞事件循环）。
                peer.add_tx(frame.len());
                let _ = self.relay_tcp_tx.send(RelayTcpOut {
                    peer: Arc::clone(peer),
                    frame: frame.to_vec(),
                    fallback: relay_fallback,
                    policy,
                });
            }
            PathKind::RelayUdp => {
                self.udp.send_relay(self_id, peer.id, frame);
                peer.add_tx(frame.len());
            }
        }
        let _ = net_id;
    }

    /// 每 peer 60s 一条的节流诊断日志（TX_DROP / 探测跳过共用锚点）——
    /// 策略档资源缺失是"静默丢帧"型故障，不落日志则无从诊断。
    fn throttled_diag(&self, peer: &Arc<PeerSession>, msg: &str) {
        let now = unix_ms();
        let last = peer.last_diag_log_ms.load(Ordering::Relaxed);
        if now - last > 60_000
            && peer
                .last_diag_log_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            (self.log)(&format!("peer={} {msg}", peer.name()));
        }
    }

    /// 策略档丢帧（pin 无中继回退）：计数 + 节流日志。
    fn note_policy_drop(&self, peer: &Arc<PeerSession>, reason: &str) {
        note_drop_detached(&self.log.clone(), peer, self.policy_for(peer.id), reason);
    }

    /// Reply on the arrival path — the PONG invariant that makes direct
    /// path upgrades work (the reply must leave through the same socket /
    /// NAT mapping the request used).
    fn reply_on_arrival(&self, peer: &Arc<PeerSession>, arrival: &Arrival, frame: &[u8]) {
        match arrival {
            Arrival::DirectUdp(ep, local) => self.udp.send_direct_from(*local, *ep, frame),
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
            let policy = self.policy_for(peer.id);
            policy_allows(policy, PathKind::DirectTcp)
                && matches!(*peer.current_path.lock().unwrap(), PathKind::RelayUdp | PathKind::RelayTcp)
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
                if let Arrival::DirectUdp(from, local) = &arrival {
                    // 策略允许即记录直连端点（pin 档下 path 已被 apply 置为
                    // DirectUdp，不能以 path 判断是否已建立——端点才是资源）。
                    let policy = self.policy_for(peer.id);
                    if policy_allows(policy, PathKind::DirectUdp) {
                        let was_missing = peer.direct_endpoint.lock().unwrap().is_none();
                        *peer.direct_endpoint.lock().unwrap() = Some((*from, *local));
                        if peer.path() != PathKind::DirectUdp {
                            *peer.current_path.lock().unwrap() = PathKind::DirectUdp;
                            (self.log)(&format!(
                                "PATH_UP peer={} net={} type=DirectUdp ep={}",
                                peer.name(),
                                self.network_name(&net_id),
                                from
                            ));
                        } else if was_missing {
                            (self.log)(&format!(
                                "PATH_UP peer={} net={} type=DirectUdp(pinned) ep={}",
                                peer.name(),
                                self.network_name(&net_id),
                                from
                            ));
                        }
                    }
                }
            }
            FRAME_DATA => (self.data_sink)(&payload),
            FRAME_FLOW => {
                // 经 FlowManager 串行队列保序处理（曾每帧 spawn，处理顺序
                // 不保——DATA/CLOSE 乱序会静默截断流）。
                self.flows.enqueue(net_id, peer.id, &payload);
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

/// 启动期生效值：托管配置预拉的解析结果（mode/listen）。
pub struct EffectiveListen {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
    /// 原始 URL 列表（托管值或文件默认，用于运行时 diff）。
    pub raw: Vec<String>,
}

/// 生效监听：托管 listen 全量替换文件默认；逐条解析 URL，按协议分组
/// （保持列表顺序，primary=首个）。
pub fn effective_listen_addrs(settings: &DeviceSettings) -> anyhow::Result<EffectiveListen> {
    let raw: Vec<String> = effective_listen_raw(settings);
    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for item in &raw {
        let (proto, addr) =
            skiff_core::models::parse_listen_url(item).map_err(|e| anyhow::anyhow!(e))?;
        match proto {
            skiff_core::models::ListenProto::Udp => udp.push(addr),
            skiff_core::models::ListenProto::Tcp => tcp.push(addr),
        }
    }
    if udp.is_empty() {
        anyhow::bail!("监听列表中没有任何 UDP 地址");
    }
    Ok(EffectiveListen { udp, tcp, raw })
}

/// 生效运行模式：托管 mode 覆盖文件默认（枚举化后由 serde+编译器保证
/// 合法值穷举，无需手动解析——字符串时期曾两路径语义相反，AGENTS #21）。
pub fn effective_mode_of(settings: &DeviceSettings) -> ClientMode {
    settings.mode.unwrap_or(ClientMode::Proxy)
}

impl NodeEngine {
    pub async fn start(
        config_path: PathBuf,
        cfg: NodeConfig,
        data_sink: DataSink,
        log: LogFn,
    ) -> anyhow::Result<Arc<NodeEngine>> {
        cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
        // 监听/模式的生效值依赖托管配置：lib.rs 已预拉的场景由
        // start_with_settings 直传；此处自拉一次（测试 harness 直调路径）。
        let control0 = ControlClient::new(
            &cfg.server,
            cfg.identity.device_token.expose(),
            cfg.identity.server_cert_pin.as_deref(),
        );
        let settings = bootstrap_settings(&control0, &config_path, &log).await;
        Self::start_with_settings(config_path, cfg, data_sink, settings, log).await
    }

    pub async fn start_with_settings(
        config_path: PathBuf,
        cfg: NodeConfig,
        data_sink: DataSink,
        settings: DeviceSettings,
        log: LogFn,
    ) -> anyhow::Result<Arc<NodeEngine>> {
        cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
        let effective_mode = effective_mode_of(&settings);
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
        let control = Arc::new(ControlClient::new(&server_url, cfg.identity.device_token.expose(), cfg.identity.server_cert_pin.as_deref()));
        if control.insecure_http {
            (log)("警告：控制面使用明文 http://（服务器 --no-tls 模式？）");
        }
        let effective_listen = effective_listen_addrs(&settings)?;
        let udp = UdpMesh::bind(&effective_listen.udp, events_tx.clone(), Arc::clone(&log)).await?;
        if udp
            .used_fallback_port
            .load(Ordering::Relaxed)
        {
            (log)(&format!("UDP 通配端口被占用，已部分回退随机端口（primary={}）", udp.local_port));
        }

        let relay_key = skiff_core::protocol::relay_udp::relay_key_from_token(cfg.identity.device_token.expose());
        let relay_tcp = RelayTcpClient::new(device_id, &relay_key);

        let (flow_out_tx, mut flow_out_rx) = mpsc::unbounded_channel::<(NetId, u64, Vec<u8>)>();
        let networks: NetworksMap = Arc::new(DashMap::new());
        // chunk_hint 需要 shared，而 flows 又是 shared 的字段——OnceLock 打破
        // 构造环：shared 构造完成后立刻填充；hint 的实际调用都发生在运行期。
        let shared_cell: Arc<std::sync::OnceLock<Arc<EngineShared>>> =
            Arc::new(std::sync::OnceLock::new());
        let hint_cell = Arc::clone(&shared_cell);
        let flows = FlowManager::new(
            flow_out_tx,
            Arc::clone(&networks),
            log.clone(),
            Arc::new(move |net, dev| {
                hint_cell
                    .get()
                    .map(|s| s.flow_chunk_for(net, dev))
                    .unwrap_or(skiff_core::consts::FLOW_CHUNK_UDP)
            }),
        );
        let (relay_tcp_tx, mut relay_tcp_rx) = mpsc::unbounded_channel::<RelayTcpOut>();

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
            relay_tcp_tx,
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
            heartbeat_secs: AtomicU32::new(skiff_core::consts::HEARTBEAT_SLOW_SECS),
            hb_rate_baseline: Mutex::new(None),
            hb_err_last_log_ms: AtomicI64::new(0),
            hb_err_count: AtomicU64::new(0),
            path_policy: Mutex::new(PathPolicy::Auto),
            peer_policies: DashMap::new(),
            runtime_socks: Mutex::new(None),
            runtime_forwards: Mutex::new(Vec::new()),
            runtime_mtu: AtomicU32::new(skiff_core::consts::DEFAULT_MTU),
            runtime_mode: Mutex::new(effective_mode),
            runtime_listen: Mutex::new(effective_listen.raw.clone()),
            tcp_listen_port: AtomicU16::new(0),
            tcp_listen_ports: Mutex::new(Vec::new()),
            stop_reason: Mutex::new(None),
            roster: Mutex::new(std::collections::HashSet::new()),
            stopped_tx: stopped_tx.clone(),
            stopped_rx,
        });
        let _ = shared_cell.set(Arc::clone(&shared)); // chunk_hint 生效（见上方构造注释）

        // FetchConfigOrFail：服务端权威名单 → 逐网络配置（无限重试）。
        let configs = fetch_configs_or_fail(&shared).await;
        let Some(first_cfg) = configs.first().cloned() else {
            anyhow::bail!("配置中没有网络");
        };
        // TUN 限单网络（服务端名单口径；服务端强制 join 已预检，兜底）。
        if effective_mode == ClientMode::Tun && configs.len() > 1 {
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

        // 直连 TCP 监听（多地址）：通配绑定失败跳过（容错）；指定 IP
        // 绑定失败为致命错误（显式意图，走配置回滚）。
        let mut tcp_listeners = Vec::new();
        let mut tcp_ports = Vec::new();
        for addr in &effective_listen.tcp {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => {
                    let port = l.local_addr()?.port();
                    if tcp_listeners.is_empty() {
                        shared.tcp_listen_port.store(port, Ordering::Relaxed);
                    }
                    tcp_ports.push(port);
                    tcp_listeners.push(l);
                }
                Err(e) if addr.ip().is_unspecified() => {
                    (log)(&format!("TCP 通配端口 {addr} 绑定失败，已跳过（{e}）"));
                }
                Err(e) => {
                    anyhow::bail!("TCP 监听绑定失败 {addr}: {e}");
                }
            }
        }
        *shared.tcp_listen_ports.lock().unwrap() = tcp_ports;

        refresh_peers(&shared).await;

        // 应用运行态（settings 已在绑定前预拉）。SOCKS/forwarders/MTU 以
        // 生效值在此确定——行为配置不落文件，重启时重新拉取。
        let _: bool = apply_runtime_settings(&shared, &settings, true);
        // 启动成功即应答：写 applied revision 并立即心跳上报（管理页的
        // 下发闭环靠它确认成功；不再等 WS 首连才追平）。
        shared
            .applied_settings_revision
            .store(settings.revision.max(0) as u64, Ordering::Relaxed);
        heartbeat_tick(&shared).await;
        let effective_socks = match settings.socks_listen.as_deref() {
            // 托管空串 = 显式禁用；未托管沿用默认开启。
            Some("") => None,
            Some(addr) => Some(addr.to_string()),
            None => Some("127.0.0.1:1080".to_string()),
        };
        let effective_forwards = settings.forwards.clone().unwrap_or_default();
        *shared.runtime_socks.lock().unwrap() = effective_socks.clone();
        *shared.runtime_forwards.lock().unwrap() = effective_forwards.clone();
        shared.runtime_mtu.store(settings.mtu.unwrap_or(skiff_core::consts::DEFAULT_MTU), Ordering::Relaxed);

        // Proxy-mode listeners: SOCKS5 + forwarders.
        if effective_mode == ClientMode::Proxy {
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

        // Inbound direct TCP accept loops（每地址一个监听）。
        for listener in tcp_listeners {
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

        // RelayTcp 出站 FIFO 消费者：严格按入队顺序发送（保序），失败按
        // 策略回落/计数——连接建立（最长 10s）只阻塞本队列，不阻塞事件
        // 循环（期间帧在队列中缓冲而非丢失）。
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                while let Some(out) = relay_tcp_rx.recv().await {
                    let ok = shared2
                        .relay_tcp
                        .send(out.peer.id, &out.frame, &shared2.events)
                        .await;
                    if !ok {
                        if out.fallback {
                            let self_id = shared2.device_id.load(Ordering::Relaxed);
                            shared2.udp.send_relay(self_id, out.peer.id, &out.frame);
                        } else {
                            note_drop_detached(
                                &shared2.log.clone(),
                                &out.peer,
                                out.policy,
                                "relayTcp-send-failed",
                            );
                        }
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
                                // WS 建立即重发中继注册：服务端重启会丢全部
                                // 内存注册表，若只等心跳的每 2 tick（慢档
                                // 30s），期间探测目标退化为对端私网地址
                                //（公网无效）——连接建立是"服务端已就绪"
                                // 的最可靠信号。
                                s.udp.send_register();
                                s.relay_tcp.keepalive().await;
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

        // Heartbeat loop (adaptive interval; every 2nd tick re-registers with
        // the relays). 间隔由服务端心跳响应建议（管理页被查看时快档），
        // 睡前读取当前值——响应后更新的值下一轮生效，收敛 ≤ 一个周期。
        {
            let shared2 = Arc::clone(&shared);
            tasks.push(tokio::spawn(async move {
                let mut tick: u64 = 0;
                loop {
                    let secs = shared2
                        .heartbeat_secs
                        .load(Ordering::Relaxed)
                        .clamp(
                            skiff_core::consts::HEARTBEAT_MIN_SECS,
                            skiff_core::consts::HEARTBEAT_MAX_SECS,
                        );
                    tokio::time::sleep(Duration::from_secs(secs as u64)).await;
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
            // 启动时清掉残留的 stop.flag：上次进程被硬杀（如 Windows 控制台
            // Ctrl+C 会同时送达 worker 子进程令其默认终止，来不及删 master
            // 随后写入的标志）会留下陈旧文件，本次启动 1s 内即被误停。
            // stop.flag 语义是"停止运行中的引擎"，不是"禁止启动"。
            let _ = std::fs::remove_file(shared.data_dir().join("stop.flag"));
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
/// 公开包装：lib.rs 启动链路预拉托管配置用。
pub async fn bootstrap_settings_pub(
    control: &ControlClient,
    config_path: &std::path::Path,
    log: &LogFn,
) -> DeviceSettings {
    bootstrap_settings(control, config_path, log).await
}

async fn bootstrap_settings(
    control: &ControlClient,
    _config_path: &std::path::Path,
    log: &LogFn,
) -> DeviceSettings {
    // 配置全托管：直接拉取（服务器不可达时节点无法工作，无限重试）。
    // 遗留收编（adopt）已随 NodeConfig 终态瘦身移除——未上线无兼容负担。
    loop {
        if let Some(s) = control.get_settings().await {
            return s;
        }
        (log)("cannot fetch settings; retrying in 3s");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 把托管配置应用到运行态。路径策略（全局+对端覆盖）与 exposes 热生效；
/// 重启类字段（mtu / socks / forwards）不落文件——与启动时实际生效值
/// 比对，有差异即置 restart_pending，重启时按拉取值重建。
fn apply_runtime_settings(shared: &Arc<EngineShared>, settings: &DeviceSettings, startup: bool) -> bool {
    // 路径策略：写全局与覆盖表，按各 peer 的生效策略同步 current_path
    //（pin 档写入对应值使 status/心跳/管理页真实；Auto 下清掉 pin-only
    // 的 RelayTcp 残留，状态机回到 RelayUdp 基线）。策略只被托管字段
    // 驱动：PUT 全量记录，pathPolicy/peerPolicies 缺省即回 Auto/无覆盖。
    let global = settings.path_policy.unwrap_or_default();
    {
        *shared.path_policy.lock().unwrap() = global;
        shared.peer_policies.clear();
        for pp in settings.peer_policies.iter().flatten() {
            match pp.device_id.parse::<u64>() {
                Ok(id) => {
                    shared.peer_policies.insert(id, pp.policy);
                }
                Err(_) => {
                    (shared.log)(&format!("peerPolicies 含无效设备 id，已跳过：{}", pp.device_id));
                }
            }
        }
        let mut any_relay_tcp = global == PathPolicy::RelayTcp;
        let entries: Vec<Arc<PeerSession>> = shared.peers.iter().map(|e| Arc::clone(e.value())).collect();
        for peer in &entries {
            let eff = shared.policy_for(peer.id);
            any_relay_tcp |= eff == PathPolicy::RelayTcp;
            let mut path = peer.current_path.lock().unwrap();
            match eff {
                PathPolicy::Auto => {
                    if *path == PathKind::RelayTcp {
                        *path = PathKind::RelayUdp;
                    }
                }
                PathPolicy::RelayUdp => *path = PathKind::RelayUdp,
                PathPolicy::RelayTcp => *path = PathKind::RelayTcp,
                PathPolicy::DirectAny => {} // 保持现状（状态机/对端拉动继续）
                PathPolicy::DirectUdp => *path = PathKind::DirectUdp,
                PathPolicy::DirectTcp => *path = PathKind::DirectTcp,
            }
        }
        if any_relay_tcp {
            // 预热 TCP 中继连接：RelayTcpClient 是懒建连，提前连上消除
            // pin 切换后的首包丢失（send 与建连竞态会返回 false）。
            let relay = Arc::clone(&shared.relay_tcp);
            let events = shared.events.clone();
            tokio::spawn(async move {
                relay.ensure_connected(&events).await;
            });
        }
    }
    if let Some(list) = &settings.exposes {
        for ne in list {
            // 热应用：对新入站连接立即生效（已建立的旧 flow 不受影响）。
            if shared.networks.contains_key(&ne.network_id) {
                shared.flows.set_exposes(ne.network_id, ne.rules.clone());
            }
        }
    }
    if startup {
        // 启动基准：生效模式与监听地址（重启类 diff 的比对基准）。
        *shared.runtime_listen.lock().unwrap() =
            crate::engine::effective_listen_raw(settings);
    }
    let mut restart_needed = false;
    if !startup {
        let mut pending = shared.restart_pending.load(Ordering::Relaxed);
        if let Some(v) = settings.mtu
            && v != shared.runtime_mtu.load(Ordering::Relaxed)
        {
            pending = true;
            restart_needed = true;
        }
        if let Some(v) = settings.socks_listen.as_deref() {
            let desired = if v.is_empty() { None } else { Some(v.to_string()) };
            if *shared.runtime_socks.lock().unwrap() != desired {
                pending = true;
                restart_needed = true;
                }
        }
        if let Some(v) = &settings.forwards
            && &*shared.runtime_forwards.lock().unwrap() != v
        {
            pending = true;
            restart_needed = true;
        }
        // mode / listen：与生效基准不同即需重启应用（TUN 权限、端口占用等
        // 失败由 worker 启动失败上报 → 服务端回滚闭环处理）。
        if let Some(desired) = settings.mode
            && *shared.runtime_mode.lock().unwrap() != desired
        {
            pending = true;
            restart_needed = true;
        }
        if let Some(v) = settings.listen.as_ref()
            && *shared.runtime_listen.lock().unwrap() != *v
        {
            pending = true;
            restart_needed = true;
        }
        shared.restart_pending.store(pending, Ordering::Relaxed);
    }
    restart_needed
}

/// 生效监听原始 URL 列表（托管全量替换文件默认；空列表视为未托管走默认）。
pub fn effective_listen_raw(settings: &DeviceSettings) -> Vec<String> {
    match settings.listen.as_ref() {
        Some(list) if !list.is_empty() => list.clone(),
        // 未下发 = 编译期默认（NodeConfig.listen 已裁剪，服务端为唯一来源）。
        _ => skiff_core::models::default_listen(),
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
    let restart_needed = apply_runtime_settings(shared, &settings, false);
    if restart_needed {
        // 重启类变更（mode/listen/mtu/socks/forwards）**不在此应答**：此刻
        // 新值尚未真正生效，提前上报 applied 会让服务端把未验证的配置
        // 固化为回滚锚点（last_good），失败回滚将回到坏配置自身、形成
        // 失败循环。应答由重启后的新 worker 启动成功时给出；启动失败则
        // worker 上报 fail，服务端回滚到真正的上一版成功配置。
        (shared.log)("托管配置含重启类变更，自动重启引擎应用……");
        request_stop(shared, StopReason::Restart);
        return;
    }
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

/// 心跳速率差分（纯函数，便于单测）：对端累计 (tx,rx) 与基线差分除以
/// 实际间隔。无基线（首个窗口）/间隔 <1s → 两侧缺省；单侧计数回退仅
/// 该侧缺省（防御，正常单调递增不会触发）。口径为密文整帧字节（含
/// 探测帧与加密开销），展示为链路层吞吐。
fn rate_bps(
    prev: Option<(u64, u64)>,
    cur: (u64, u64),
    dt: Duration,
) -> (Option<u64>, Option<u64>) {
    fn one(prev: u64, cur: u64, dt_ms: u128) -> Option<u64> {
        if cur < prev {
            return None;
        }
        Some(((cur - prev) as u128 * 1000 / dt_ms) as u64)
    }
    let Some(prev) = prev else {
        return (None, None);
    };
    if dt < Duration::from_secs(1) {
        return (None, None);
    }
    let dt_ms = dt.as_millis().max(1);
    (one(prev.0, cur.0, dt_ms), one(prev.1, cur.1, dt_ms))
}

/// 帧缺口率差分（纯函数，便于单测）：窗口内 Δlost / (Δseen + Δlost)，
/// 万分比 0..=10000（即 100.00%）。无基线（首窗）/ 窗口内无任何帧
/// （无样本，不代表 0 丢包）/ 计数回退（防御）→ 缺省。
fn loss_permille(prev: Option<(u64, u64)>, cur: (u64, u64)) -> Option<u16> {
    let (p_seen, p_lost) = prev?;
    let (c_seen, c_lost) = cur;
    if c_seen < p_seen || c_lost < p_lost {
        return None;
    }
    let d_seen = c_seen - p_seen;
    let d_lost = c_lost - p_lost;
    let total = (d_seen + d_lost) as u128;
    if total == 0 {
        return None;
    }
    Some((d_lost as u128 * 10_000 / total) as u16)
}

/// 单次心跳（pub 供集成测试直接触发：速率差分/间隔建议的全链路断言）。
pub async fn heartbeat_tick(shared: &Arc<EngineShared>) {
    // Only report peers we have actually interacted with (rtt recorded):
    // a never-answered peer would report its initial RelayUdp state, which
    // misleads the topology view into drawing phantom relay edges.
    //（current_path 在策略应用时已同步为真实生效路径，直接上报裸枚举串。）
    // 速率 = 相邻两次心跳间对端累计字节的差分 ÷ 实际间隔；窗口随自适应
    // 间隔伸缩（被查看时 5s，平时 15s）。
    let now = std::time::Instant::now();
    let paths: Vec<PeerPathReport> = {
        let mut baseline = shared.hb_rate_baseline.lock().unwrap();
        let (dt, prev_map) = match baseline.as_ref() {
            Some((at, map)) => (Some(now - *at), map.clone()),
            None => (None, HashMap::new()),
        };
        let mut next_map: HbRateMap = HashMap::new();
        let paths: Vec<PeerPathReport> = shared
            .peers
            .iter()
            .filter_map(|p| {
                let rtt = p.value().rtt_ms.load(Ordering::Relaxed);
                if rtt < 0 {
                    return None;
                }
                let dev = p.key().1;
                let sess = p.value();
                // codec 统计读取是短临界区（拷贝两个 u64），不与任何锁重叠。
                let (rx_seen, rx_lost) = sess.codec.lock().unwrap().stats();
                let cur = HbCounters {
                    tx_bytes: sess.tx_bytes.load(Ordering::Relaxed),
                    rx_bytes: sess.rx_bytes.load(Ordering::Relaxed),
                    rx_seen,
                    rx_lost,
                };
                let (tx_bps, rx_bps) = match dt {
                    Some(dt) => rate_bps(prev_map.get(&dev).map(|c| (c.tx_bytes, c.rx_bytes)), (cur.tx_bytes, cur.rx_bytes), dt),
                    None => (None, None),
                };
                let rx_loss = loss_permille(
                    prev_map.get(&dev).map(|c| (c.rx_seen, c.rx_lost)),
                    (cur.rx_seen, cur.rx_lost),
                );
                next_map.insert(dev, cur);
                let path = sess.path().as_str().to_string();
                Some(PeerPathReport {
                    device_id: dev.to_string(),
                    path,
                    rtt_ms: Some(rtt),
                    tx_bps,
                    rx_bps,
                    rx_loss,
                })
            })
            .collect();
        // 整体替换基线：对端消失（rtt<0 不上报）随之清理，回来后首窗无速率。
        *baseline = Some((now, next_map));
        paths
    };
    let mode_val = *shared.runtime_mode.lock().unwrap();
    let tcp_port = shared.tcp_listen_port.load(Ordering::Relaxed);
    let req = HeartbeatRequest {
        local_addrs: crate::local_ipv4_addrs(),
        listen_udp_port: Some(shared.udp.local_port),
        listen_tcp_port: (tcp_port > 0).then_some(tcp_port),
        paths: Some(paths),
        settings_revision: Some(shared.applied_settings_revision.load(Ordering::Relaxed) as i64),
        restart_pending: Some(shared.restart_pending.load(Ordering::Relaxed)),
        mode: Some(mode_val),
        proto_version: Some(skiff_core::consts::PROTOCOL_VERSION),
        node_version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    match shared.control.heartbeat(&req).await {
        Ok(resp) => {
            if let Some(ep) = resp.observed_udp_endpoint {
                *shared.observed_endpoint.lock().unwrap() = Some(ep);
            }
            // 应用服务端的间隔建议（声明式，每次心跳重发）；仅档位变化
            // 时记一条日志，避免每拍刷屏。
            let want = resp
                .heartbeat_secs
                .clamp(
                    skiff_core::consts::HEARTBEAT_MIN_SECS,
                    skiff_core::consts::HEARTBEAT_MAX_SECS,
                );
            let was = shared.heartbeat_secs.swap(want, Ordering::Relaxed);
            if was != want {
                (shared.log)(&format!(
                    "心跳间隔 {was}s → {want}s（服务端建议，管理页查看时快档）"
                ));
            }
            // 失败后恢复：一次性补报（期间失败数在节流条目里留痕）。
            let fails = shared.hb_err_count.swap(0, Ordering::Relaxed);
            if fails > 0 {
                (shared.log)(&format!(
                    "HEARTBEAT_RECOVERED fails={fails}（链路恢复）"
                ));
            }
        }
        Err(e) => {
            // 差链路下心跳失败可能每拍一条（曾刷屏）：60s 节流一条并携带
            // 期间累计数，恢复时 HEARTBEAT_RECOVERED 补报闭合。
            let fails = shared.hb_err_count.fetch_add(1, Ordering::Relaxed) + 1;
            let now = unix_ms();
            let last = shared.hb_err_last_log_ms.load(Ordering::Relaxed);
            if now - last > 60_000
                && shared
                    .hb_err_last_log_ms
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                (shared.log)(&format!(
                    "HEARTBEAT_ERR uptime_s={} fails={fails} err={e}",
                    (now - shared.started_ms) / 1000
                ));
            }
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

    // 探测按生效策略裁剪：Relay* 不直连探测；directTcp 只探 TCP；
    // directUdp 只探 UDP（含邻近端口预测）；Auto/DirectAny 双探测。
    let policy = shared.policy_for(peer.id);
    if matches!(policy, PathPolicy::RelayUdp | PathPolicy::RelayTcp) {
        return;
    }
    let path = peer.path();
    let now = unix_ms();
    // 探测需求按"资源是否就绪"判断，而非 path：策略应用会把 path 置为
    // pin 值，若以 path 判断"已建立"将永远不再探测（directUdp pin 下
    // direct_endpoint 永远缺失的死锁即源于此）。
    let want_udp = match policy {
        PathPolicy::Auto | PathPolicy::DirectAny => path != PathKind::DirectUdp,
        PathPolicy::DirectUdp => peer.direct_endpoint.lock().unwrap().is_none(),
        _ => false,
    };
    let want_tcp = match policy {
        PathPolicy::Auto | PathPolicy::DirectAny => path != PathKind::DirectUdp,
        PathPolicy::DirectTcp => peer
            .tcp_conn
            .lock()
            .unwrap()
            .as_ref()
            .is_none_or(|c| c.is_closed()),
        _ => false,
    };
    if want_udp {
        // Direct UDP probes: known endpoints (up to 4) + neighbour-port
        // prediction around the relay-observed endpoint (symmetric NATs
        // allocate ports sequentially).
        let endpoints = peer.endpoints.lock().unwrap().clone();
        for ep in endpoints.iter().take(4) {
            shared.udp.send_direct_all(*ep, &ping);
        }
        if let Some(observed) = endpoints.first() {
            for d in 1u16..=4 {
                if let Some(p) = observed.port().checked_add(d) {
                    shared.udp.send_direct_all(SocketAddr::new(observed.ip(), p), &ping);
                }
                if observed.port() > d + 1024 {
                    shared.udp.send_direct_all(SocketAddr::new(observed.ip(), observed.port() - d), &ping);
                }
            }
        }
    }
    if want_tcp {
        let endpoints = peer.endpoints.lock().unwrap().clone();
        try_direct_tcp_probe(shared, &peer, &endpoints).await;
    }
    if matches!(path, PathKind::DirectUdp | PathKind::DirectTcp) {
        // 直连升级只在收到 PONG 时发生（升级前必已写入 last_pong_ms），
        // 因此直连路径下 last 恒 > 0；last==0 表示从未直连成功。
        // 降级仅 Auto 允许（策略档保持 pin，靠丢帧+探测自愈）。
        // DirectTcp 半开连接（NAT 静默丢映射：写内核缓冲不报错、读永不
        // 返回）此前无任何降级路径，黑洞流量直到 TCP 重传超时（~15min）
        // 且 conn 存在即跳过重探——同用 PONG 超时判定，30s 内回退中继。
        let last = peer.last_pong_ms.load(Ordering::Relaxed);
        if direct_path_dead(now, last) && policy == PathPolicy::Auto {
            match path {
                PathKind::DirectUdp => *peer.direct_endpoint.lock().unwrap() = None,
                PathKind::DirectTcp => *peer.tcp_conn.lock().unwrap() = None, // drop 关 socket
                _ => unreachable!(),
            }
            *peer.current_path.lock().unwrap() = PathKind::RelayUdp;
            (shared.log)(&format!(
                "PATH_DOWN peer={} net={} from={} to=RelayUdp reason=timeout",
                peer.name(),
                shared.network_name(&net_id),
                path.as_str()
            ));
        }
    }
}

/// 直连死亡判定（DirectUdp/DirectTcp 共用）：曾有 PONG（last > 0）且
/// 超过 MISS_LIMIT × PING_INTERVAL 未应答。纯函数供单测（30s 阈值语义
/// 由常量算出，勿内联重算散落多处）。
fn direct_path_dead(now_ms: i64, last_pong_ms: i64) -> bool {
    let dead_after = (skiff_core::consts::PEER_PING_INTERVAL
        * skiff_core::consts::PEER_PING_MISS_LIMIT)
        .as_millis() as i64;
    last_pong_ms > 0 && now_ms - last_pong_ms > dead_after
}

/// 策略档丢帧计数 + 每 peer 60s 节流日志（脱离 &EngineShared 的任务上下
/// 文用：只持 Arc 字段克隆，如 RelayTcp 发送任务）。
fn note_drop_detached(log: &LogFn, peer: &Arc<PeerSession>, policy: PathPolicy, reason: &str) {
    let total = peer.tx_dropped.fetch_add(1, Ordering::Relaxed) + 1;
    let now = unix_ms();
    let last = peer.last_diag_log_ms.load(Ordering::Relaxed);
    if now - last > 60_000
        && peer
            .last_diag_log_ms
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        log(&format!(
            "peer={} TX_DROP policy={policy:?} reason={reason} total={total}（pin 档无中继回退，等待探测重建直连资源）",
            peer.name()
        ));
    }
}

async fn try_direct_tcp_probe(shared: &Arc<EngineShared>, peer: &Arc<PeerSession>, endpoints: &[SocketAddr]) {
    // 对端心跳公布的 TCP 监听端口；未公布 = 对端无 TCP 监听（端口被占
    // 禁用 / 托管 listen 无 tcp:// 条目），directTcp 无法建立——必须留痕。
    let Some(tcp_port) = *peer.tcp_listen_port.lock().unwrap() else {
        shared.throttled_diag(peer, "TCP_PROBE_SKIP reason=peer-no-tcp-port（对端未公布 TCP 监听）");
        return;
    };
    if peer.tcp_conn.lock().unwrap().is_some() {
        return;
    }
    // 多端点逐个尝试（对端公布的 UDP 端点 IP + 其 TCP 监听端口）：观测
    // 端点[0] 在 NAT 后是公网映射，同局域网/服务器异网时几乎必败；LAN
    // 地址排在 [1..]。此前只连 endpoints[0]，直连 TCP 在这些场景永远
    // 建不起来且无任何日志——正是"pin directTcp 后 ping 全超时"的根因。
    let targets: Vec<SocketAddr> = endpoints
        .iter()
        .take(4)
        .map(|e| SocketAddr::new(e.ip(), tcp_port))
        .collect();
    if targets.is_empty() {
        shared.throttled_diag(peer, "TCP_PROBE_SKIP reason=no-endpoints");
        return;
    }
    let now = unix_ms();
    if now < peer.tcp_cooldown_until_ms.load(Ordering::Relaxed) {
        return;
    }
    peer.tcp_cooldown_until_ms.store(now + 60_000, Ordering::Relaxed);
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
        for target in targets {
            // Silent on connect failure: the cooldown throttles retries.
            if let Ok(conn) = PeerTcpConnection::connect(target, Duration::from_secs(3), tx.clone()).await {
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
                return;
            }
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
                .map(|(e, _local)| e.to_string())
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
        (cfg.server.clone(), shared.runtime_mode.lock().unwrap().as_str().to_string())
    };
    let forwards = shared
        .runtime_forwards
        .lock()
        .unwrap()
        .iter()
        .map(|f| format!("{} {}->{}", f.proto.as_str(), f.listen, f.dest))
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
            .map(|(e, _local)| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with_mode(mode: Option<ClientMode>) -> DeviceSettings {
        DeviceSettings {
            mode,
            ..DeviceSettings::default()
        }
    }

    /// 托管 "proxy" 必须覆盖文件 tun（曾落入 `_` 分支沿用文件值——
    /// 见 AGENTS.md #21：合法值穷举，双向变更都要测）。
    #[test]
    fn managed_proxy_overrides_file_tun() {
        assert_eq!(
            effective_mode_of(&settings_with_mode(Some(ClientMode::Proxy))),
            ClientMode::Proxy
        );
    }

    #[test]
    fn managed_tun_overrides_file_proxy() {
        assert_eq!(
            effective_mode_of(&settings_with_mode(Some(ClientMode::Tun))),
            ClientMode::Tun
        );
    }

    /// 未托管（None）= 编译期默认 Proxy（NodeConfig 已无 mode 字段，
    /// 服务端为唯一来源，缺省即默认值）。
    #[test]
    fn unmanaged_mode_falls_back_to_default() {
        assert_eq!(
            effective_mode_of(&settings_with_mode(None)),
            ClientMode::Proxy
        );
    }

    /// 心跳速率差分：窗口数学与三重守护（无基线/窗口过短/计数回退）。
    #[test]
    fn rate_bps_math_and_guards() {
        use std::time::Duration;
        let dt5 = Duration::from_secs(5);
        // 无基线（首个窗口）→ 两侧缺省。
        assert_eq!(rate_bps(None, (100, 200), dt5), (None, None));
        // 5s 窗口 500B/1000B → 100/200 B/s；零增量侧为 Some(0)。
        assert_eq!(
            rate_bps(Some((1000, 2000)), (1500, 3000), dt5),
            (Some(100), Some(200))
        );
        assert_eq!(
            rate_bps(Some((100, 100)), (100, 100), dt5),
            (Some(0), Some(0))
        );
        // 窗口 <1s（相邻心跳贴得过近）→ 缺省，不除以近零时长。
        assert_eq!(
            rate_bps(Some((0, 0)), (10, 10), Duration::from_millis(999)),
            (None, None)
        );
        // 单侧计数回退：仅该侧缺省，另一侧照常计算。
        assert_eq!(
            rate_bps(Some((100, 100)), (50, 200), dt5),
            (None, Some(20))
        );
    }

    /// 帧缺口率差分：窗口数学与守护（无基线/无样本/计数回退）。
    #[test]
    fn loss_permille_math_and_guards() {
        // 无基线（首个窗口）→ 缺省。
        assert_eq!(loss_permille(None, (100, 5)), None);
        // 窗口内无帧：无样本 ≠ 0 丢包，缺省。
        assert_eq!(loss_permille(Some((100, 5)), (100, 5)), None);
        // 100 收 0 丢 → 0；100 收 1 丢 → 1%（万分比 100）。
        assert_eq!(loss_permille(Some((0, 0)), (100, 0)), Some(0));
        // 101 帧丢 1 → 10000/101 = 99（整除向下取整）。
        assert_eq!(loss_permille(Some((0, 0)), (100, 1)), Some(99));
        // 25% 丢包边界：300 收 100 丢 → 2500。
        assert_eq!(loss_permille(Some((0, 0)), (300, 100)), Some(2500));
        // 全丢：0 收 50 丢 → 10000（100.00%）。
        assert_eq!(loss_permille(Some((0, 0)), (0, 50)), Some(10_000));
        // 计数回退（防御，正常单调递增）→ 缺省。
        assert_eq!(loss_permille(Some((100, 5)), (90, 5)), None);
        assert_eq!(loss_permille(Some((100, 5)), (100, 3)), None);
    }

    /// 直连死亡判定（DirectUdp/DirectTcp 共用）：从未 PONG 不判死；
    /// MISS_LIMIT×PING_INTERVAL（30s）为阈值边界。
    #[test]
    fn direct_path_dead_threshold() {
        let now = 1_000_000i64;
        assert!(!direct_path_dead(now, 0), "从未收到 PONG（从未直连成功）不判死");
        assert!(!direct_path_dead(now, now - 30_000), "恰在 30s 阈值上仍未死");
        assert!(direct_path_dead(now, now - 30_001), "超过 30s 无 PONG 判死");
        assert!(direct_path_dead(now, now - 15 * 60_000), "半开 15min 必死");
    }
}
