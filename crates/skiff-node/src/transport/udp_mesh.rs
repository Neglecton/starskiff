//! UdpMesh: a set of UDP sockets serving both the relay (REGISTER/RELAY and
//! relayed frames) and direct peer traffic. 支持多地址监听（绑定指定网卡/
//! IPv6，每协议由 DeviceSettings.listen / NodeConfig.listen 描述，本模块
//! 只管 UDP 条目）。
//!
//! 绑定失败语义：通配地址（0.0.0.0/[::]）失败沿用容错——非 0 端口回退
//! 随机端口（同机多节点与并行测试依赖），端口 0 失败直接 Err；**指定 IP
//! 绑定失败为致命错误**（显式意图，由上层走配置回滚）。
//!
//! 发送选路：中继注册/RELAY 与默认发送走 primary（首个 socket）；PONG
//! 沿到达路径回复（携带收到 PING 的那个 socket 的本地绑定地址）；DirectUdp
//! 数据帧经学习到该端点的 socket 发送，保持 NAT 映射一致。
//!
//! 入站分类（AGENTS.md #20）：判据是**来源地址**（from == relay_addr），
//! 不是包格式——中继转发的是剥壳后的内层 wire 帧（0x0A），parse 中继
//! 协议必然失败；若按"能否 parse 成中继协议"分流，中继流量会被全部
//! 误判为直连（PONG 裸发中继被丢、RTT 永测不到）。classify 为纯函数，
//! 分支语义由单测锁定。

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use skiff_core::consts::UDP_BUFFER_SIZE;
use skiff_core::logging::LogFn;
use skiff_core::protocol::relay_udp;
use skiff_core::logging::unix_ms;
use tokio::net::UdpSocket;

use crate::engine::EngineEvent;

pub struct UdpMesh {
    /// 与 writer 一一对应的本地绑定地址（发送选路用；socket 本体由
    /// 各 writer/reader 任务持有）。
    binds: Vec<SocketAddr>,
    /// 与 sockets 一一对应的 writer 通道（FIFO 保序——每包 tokio::spawn
    /// 在 multi_thread runtime 下不保序，FLOW DATA/CLOSE 乱序会静默截断
    /// 流；参照 peer_tcp.rs 的单 writer 模式）。
    writers: Vec<tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>>,
    pub local_port: u16,
    pub used_fallback_port: AtomicBool,
    /// send_to 失败计数（曾 `let _ =` 静默——超限帧/网络错误的唯一痕迹）。
    pub send_errors: Arc<AtomicU64>,
    /// 读循环与发送侧共享的中继地址（读循环闭包在 bind 时创建、
    /// configure_relay 写入，故必须经 Arc 共享同一 cell）。
    relay_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// REGISTER 凭据。每次发送生成新 nonce——服务端记忆已用 nonce 防重放，
    /// 缓存整个报文会导致重注册被拒。
    register_creds: Mutex<Option<(u64, [u8; 32])>>,
}

impl UdpMesh {
    /// 按地址列表绑定（去重保序）。至少要有一个成功绑定的 socket。
    pub async fn bind(
        addrs: &[SocketAddr],
        events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
        log: LogFn,
    ) -> anyhow::Result<Arc<UdpMesh>> {
        if addrs.is_empty() {
            anyhow::bail!("UDP 监听地址列表为空");
        }
        let relay_cell = Arc::new(Mutex::new(None::<SocketAddr>));
        let send_errors = Arc::new(AtomicU64::new(0));
        let mut sockets: Vec<Arc<UdpSocket>> = Vec::new();
        let mut binds: Vec<SocketAddr> = Vec::new();
        let mut writers: Vec<tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>> = Vec::new();
        let mut used_fallback = false;
        let spawn_socket = |s: Arc<UdpSocket>,
                            events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
                            relay_cell: Arc<Mutex<Option<SocketAddr>>>,
                            log: LogFn,
                            send_errors: Arc<AtomicU64>|
         -> tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)> {
            spawn_reader(Arc::clone(&s), events, relay_cell);
            spawn_writer(s, log, send_errors)
        };
        let bind_one = |want: SocketAddr| -> anyhow::Result<UdpSocket> {
            // 经 socket2 扩内核缓冲（32KiB 级密封帧突发防内核静默丢弃，
            // 见 platform::udp_socket_buffered）。绑定错误语义与
            // UdpSocket::bind 一致（调用方据此走容错/致命分支）。
            let std_sock = skiff_core::platform::udp_socket_buffered(want)
                .map_err(|e| anyhow::anyhow!("UDP 监听绑定失败 {want}: {e}"))?;
            UdpSocket::from_std(std_sock).map_err(|e| anyhow::anyhow!("UDP 监听绑定失败 {want}: {e}"))
        };
        for want in addrs {
            // 同一地址只绑一次（调用方可能给出重复项）。
            if binds.contains(want) {
                continue;
            }
            let primary_empty = sockets.is_empty();
            match bind_one(*want) {
                Ok(s) => {
                    let local = s.local_addr()?;
                    let s = Arc::new(s);
                    let tx = spawn_socket(
                        Arc::clone(&s),
                        events.clone(),
                        Arc::clone(&relay_cell),
                        log.clone(),
                        Arc::clone(&send_errors),
                    );
                    sockets.push(s);
                    binds.push(local);
                    writers.push(tx);
                }
                Err(e) => {
                    let wildcard = want.ip().is_unspecified();
                    if wildcard && want.port() != 0 {
                        // 通配 + 固定端口：回退随机端口（同机多节点容错）。
                        let s = bind_one(SocketAddr::new(want.ip(), 0))?;
                        let local = s.local_addr()?;
                        let s = Arc::new(s);
                        let tx = spawn_socket(
                            Arc::clone(&s),
                            events.clone(),
                            Arc::clone(&relay_cell),
                            log.clone(),
                            Arc::clone(&send_errors),
                        );
                        sockets.push(s);
                        binds.push(local);
                        writers.push(tx);
                        used_fallback = true;
                    } else if wildcard && want.port() == 0 && !primary_empty {
                        // 端口 0 通配失败且已有 socket：跳过（无需回退目标）。
                        continue;
                    } else {
                        // 指定 IP 失败 / 首个通配端口 0 失败：致命（bind_one
                        // 的错误信息已含地址与原因）。
                        anyhow::bail!("{e}");
                    }
                }
            }
        }
        if sockets.is_empty() {
            anyhow::bail!("UDP 监听全部绑定失败");
        }
        let local_port = sockets[0].local_addr()?.port();
        Ok(Arc::new(UdpMesh {
            binds,
            writers,
            local_port,
            used_fallback_port: AtomicBool::new(used_fallback),
            send_errors,
            relay_addr: relay_cell,
            register_creds: Mutex::new(None),
        }))
    }

    fn primary_tx(&self) -> &tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)> {
        &self.writers[0]
    }

    /// 与本地绑定地址匹配的 writer（找不到回退 primary）。
    fn writer_for(&self, local: SocketAddr) -> &tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)> {
        self.binds
            .iter()
            .position(|b| *b == local)
            .map(|i| &self.writers[i])
            .unwrap_or(&self.writers[0])
    }

    /// 全部本地绑定地址（探测从所有 socket 喷射）。
    pub fn local_binds(&self) -> &[SocketAddr] {
        &self.binds
    }

    pub fn configure_relay(&self, relay_addr: SocketAddr, device_id: u64, relay_key: &[u8; 32]) {
        *self.register_creds.lock().unwrap() = Some((device_id, *relay_key));
        *self.relay_addr.lock().unwrap() = Some(relay_addr);
    }

    /// (Re)send the REGISTER; a no-op before configure_relay. 每次发送用
    /// 新 nonce（服务端拒绝重放已用 nonce 的 REGISTER）。
    pub fn send_register(&self) {
        let Some((device_id, key)) = *self.register_creds.lock().unwrap() else {
            return;
        };
        let Some(relay) = *self.relay_addr.lock().unwrap() else {
            return;
        };
        let pkt = relay_udp::build_register(device_id, &key).to_vec();
        let _ = self.primary_tx().send((relay, pkt));
    }

    pub fn send_relay(&self, src_id: u64, dst_id: u64, frame: &[u8]) {
        let Some(relay) = *self.relay_addr.lock().unwrap() else {
            return;
        };
        let pkt = relay_udp::build_relay(src_id, dst_id, frame);
        let _ = self.primary_tx().send((relay, pkt));
    }

    /// 默认直发（primary socket）。
    pub fn send_direct(&self, endpoint: SocketAddr, frame: &[u8]) {
        let _ = self.primary_tx().send((endpoint, frame.to_vec()));
    }

    /// 经指定本地绑定的 socket 直发（PONG 沿到达路径 / 直连数据保持
    /// NAT 映射一致；未知绑定回退 primary）。
    pub fn send_direct_from(&self, local: SocketAddr, endpoint: SocketAddr, frame: &[u8]) {
        let _ = self.writer_for(local).send((endpoint, frame.to_vec()));
    }

    /// 从每个 socket 各直发一次（探测 PING 喷射：对端可沿任一路径回 PONG）。
    pub fn send_direct_all(&self, endpoint: SocketAddr, frame: &[u8]) {
        for tx in &self.writers {
            let _ = tx.send((endpoint, frame.to_vec()));
        }
    }
}

/// 单 socket 常驻 writer：严格按入队顺序 send_to（保序），失败计数 +
/// 60s 节流日志（消灭曾经的 `let _ =` 静默——超限帧/网络错误唯一痕迹）。
fn spawn_writer(
    socket: Arc<UdpSocket>,
    log: LogFn,
    errors: Arc<AtomicU64>,
) -> tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    tokio::spawn(async move {
        let mut last_log_ms: i64 = 0;
        while let Some((dst, pkt)) = rx.recv().await {
            if let Err(e) = socket.send_to(&pkt, dst).await {
                let total = errors.fetch_add(1, Ordering::Relaxed) + 1;
                let now = unix_ms();
                if now - last_log_ms > 60_000 {
                    last_log_ms = now;
                    log(&format!(
                        "UDP_SEND_ERR dst={dst} len={} err={e} total={total}（帧超 UDP 数据报上限或本机网络错误）",
                        pkt.len()
                    ));
                }
            }
        }
    });
    tx
}

/// 单 socket 读循环：收包按 classify 分流后上抛事件。
fn spawn_reader(
    reader: Arc<UdpSocket>,
    events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    relay_cell: Arc<Mutex<Option<SocketAddr>>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        loop {
            match reader.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    let relay = *relay_cell.lock().unwrap();
                    handle(from, local_bind_of(&reader), &buf[..len], &events, relay);
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        }
    });
}

/// 读循环回调：中继控制包在此消化（ACK/ERROR），中继转发帧与对端直发
/// wire 帧作为 Frame 事件上抛（RelayUdp / DirectUdp 到达，携带来源地址
/// 与收包 socket 的本地绑定地址）。
fn handle(
    from: SocketAddr,
    local_bind: SocketAddr,
    packet: &[u8],
    events: &tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    relay: Option<SocketAddr>,
) {
    match classify(from, relay, packet) {
        UdpInbound::ObservedEndpoint(ep) => {
            let _ = events.send(EngineEvent::ObservedEndpoint(ep));
        }
        UdpInbound::RelayFrame(frame) => {
            let _ = events.send(EngineEvent::Frame {
                arrival: crate::engine::Arrival::relay_udp(),
                packet: frame,
            });
        }
        UdpInbound::Direct(frame) => {
            let _ = events.send(EngineEvent::Frame {
                arrival: crate::engine::Arrival::direct_udp(from, local_bind),
                packet: frame,
            });
        }
        UdpInbound::Ignore => {}
    }
}

/// 入站单包分类（纯函数，分支语义由单测锁定）。判据 = 来源地址是否为
/// 中继地址（见模块注释），包格式只用于区分中继控制类型。
#[derive(Debug)]
enum UdpInbound {
    /// 中继 REGISTER ACK：观测端点回存（仅信任中继来源——任意来源的
    /// 0x0B ACK 可伪造 ObservedEndpoint、污染探测目标）。
    ObservedEndpoint(String),
    /// 中继转发的帧（剥壳内层 wire 帧，或 RELAY 壳内层——后者真实
    /// 服务器不发送，防御性保留）。
    RelayFrame(Vec<u8>),
    /// 对端直发的 wire 帧（或无法解析的噪声，交上层 codec 丢弃）。
    Direct(Vec<u8>),
    /// 丢弃：中继 ERROR / 非中继来源的 0x0B（伪造或噪声）。
    Ignore,
}

fn classify(from: SocketAddr, relay: Option<SocketAddr>, packet: &[u8]) -> UdpInbound {
    let from_relay = relay == Some(from);
    match (from_relay, relay_udp::parse(packet)) {
        (true, Some(RelayPacket::Ack { ip, port })) => {
            // observed endpoint 回存（服务端视角的公网映射）。
            let ep = if ip.contains(':') && !ip.starts_with('[') {
                format!("[{ip}]:{port}")
            } else {
                format!("{ip}:{port}")
            };
            UdpInbound::ObservedEndpoint(ep)
        }
        (true, Some(RelayPacket::Relay { frame, .. })) => UdpInbound::RelayFrame(frame.to_vec()),
        (true, Some(RelayPacket::Error { .. })) | (true, Some(RelayPacket::Register { .. })) => {
            UdpInbound::Ignore
        }
        // 中继转发的内层 wire 帧：parse 中继协议必然失败，这正是中继
        // 数据面的到达形态——必须分类为 RelayUdp（PONG 沿中继回程的
        // 前提），绝不能落入直连分支。
        (true, None) => UdpInbound::RelayFrame(packet.to_vec()),
        (false, Some(_)) => UdpInbound::Ignore,
        (false, None) => UdpInbound::Direct(packet.to_vec()),
    }
}

use skiff_core::protocol::relay_udp::RelayPacket;

/// 读循环里拿不到 UdpMesh 的 binds 表——把 local_bind 的查询改为通过
/// local_addr()：socket 的本地地址即绑定地址（随机回退后也是真实绑定）。
fn local_bind_of(socket: &UdpSocket) -> SocketAddr {
    socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// 中继转发的内层 wire 帧（0x0A 头）：来自中继地址 → RelayFrame。
    #[test]
    fn relayed_wire_frame_from_relay_is_relay() {
        let relay = addr("203.0.113.1:24931");
        let frame = [0x0Au8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 7, 7, 7];
        assert!(relay_udp::parse(&frame).is_none(), "前提：内层帧不是中继协议");
        match classify(relay, Some(relay), &frame) {
            UdpInbound::RelayFrame(f) => assert_eq!(f, frame),
            other => panic!("中继地址来的 wire 帧必须是 RelayFrame: {other:?}"),
        }
    }

    /// 同样的 wire 帧来自陌生地址 → Direct（对端直发）。
    #[test]
    fn wire_frame_from_stranger_is_direct() {
        let frame = [0x0Au8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
        match classify(addr("10.0.0.2:5000"), Some(addr("203.0.113.1:24931")), &frame) {
            UdpInbound::Direct(f) => assert_eq!(f, frame),
            other => panic!("陌生地址来的 wire 帧必须是 Direct: {other:?}"),
        }
    }

    /// ACK 只信任中继来源：中继来的 ACK → 观测端点（IPv6 加方括号）。
    #[test]
    fn ack_from_relay_is_observed_endpoint() {
        let relay = addr("203.0.113.1:24931");
        let pkt = relay_udp::build_ack_packet("2001:db8::1", 41234);
        match classify(relay, Some(relay), &pkt) {
            UdpInbound::ObservedEndpoint(ep) => assert_eq!(ep, "[2001:db8::1]:41234"),
            other => panic!("中继 ACK 必须是 ObservedEndpoint: {other:?}"),
        }
        let pkt = relay_udp::build_ack_packet("198.51.100.9", 24933);
        match classify(relay, Some(relay), &pkt) {
            UdpInbound::ObservedEndpoint(ep) => assert_eq!(ep, "198.51.100.9:24933"),
            other => panic!("中继 ACK 必须是 ObservedEndpoint: {other:?}"),
        }
    }

    /// 伪造的 ACK（非中继来源）→ 丢弃。
    #[test]
    fn ack_from_stranger_is_ignored() {
        let pkt = relay_udp::build_ack_packet("6.6.6.6", 6666);
        assert!(matches!(
            classify(addr("10.0.0.2:5000"), Some(addr("203.0.113.1:24931")), &pkt),
            UdpInbound::Ignore
        ));
    }

    /// RELAY 壳来自中继（真实服务器不发送，防御性）→ 取内层帧。
    #[test]
    fn relay_shell_from_relay_unwraps_inner_frame() {
        let relay = addr("203.0.113.1:24931");
        let pkt = relay_udp::build_relay(7, 8, b"inner");
        match classify(relay, Some(relay), &pkt) {
            UdpInbound::RelayFrame(f) => assert_eq!(f, b"inner".to_vec()),
            other => panic!("RELAY 壳必须是 RelayFrame: {other:?}"),
        }
    }

    /// 中继 ERROR / REGISTER 出现在中继地址上 → 丢弃。
    #[test]
    fn error_from_relay_is_ignored() {
        let relay = addr("203.0.113.1:24931");
        let pkt = relay_udp::build_error_packet("unknown device or bad auth");
        assert!(matches!(classify(relay, Some(relay), &pkt), UdpInbound::Ignore));
    }

    /// 中继未配置（None）时：wire 帧按直连处理（与配置前现状一致，
    /// 未注册中继前不会有中继流量到达）。
    #[test]
    fn unconfigured_relay_defaults_to_direct() {
        let frame = [0x0Au8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 9];
        assert!(matches!(
            classify(addr("10.0.0.2:5000"), None, &frame),
            UdpInbound::Direct(_)
        ));
    }
}
