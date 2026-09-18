//! FLOW sub-protocol engine: user-space stream multiplexing (TCP flows +
//! UDP datagrams) over sealed wire frames. Flow ids are chosen by the
//! initiator and shared by both sides; replies travel on the same id.
//! Every flow belongs to one network — the self ip used in UDP reply
//! addresses and the exposes looked up for inbound connections are
//! resolved in that network, and the CLOSE frame must be sealed with the
//! owning network's key (keys are derived per network).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rand_core::{OsRng, RngCore};
use skiff_core::logging::LogFn;
use skiff_core::models::{ExposeRule, NetId};
use skiff_core::protocol::flow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

use crate::engine::NetworksMap;

/// Outbound flow frames: (network, peer device id, FLOW plaintext payload).
/// The engine seals and routes them on the peer's current path.
pub type FlowOut = mpsc::UnboundedSender<(NetId, u64, Vec<u8>)>;

enum FlowKind {
    /// Initiated TCP flow, waiting for OPENED_OK, then delivering DATA.
    OutTcp {
        open_reply: Option<oneshot::Sender<Result<(), String>>>,
        data_tx: mpsc::UnboundedSender<Vec<u8>>,
    },
    /// Accepted TCP flow pumping a local socket.
    InTcp {
        writer: mpsc::UnboundedSender<Vec<u8>>,
    },
    /// UDP flow (either direction); inbound datagrams delivered to the handle.
    Udp {
        outbound: bool,
        datagram_tx: mpsc::Sender<(String, Vec<u8>)>,
    },
}

/// 每条 flow 固定属于一个 (网络, 对端)。密钥按 networkId 派生，CLOSE 帧
/// 必须用所属网络的密钥密封；close_peer 也按网络精确匹配，避免同一设备
/// 在其他网络的流被误杀。
struct FlowCtx {
    net_id: NetId,
    peer: u64,
    kind: FlowKind,
}

pub struct FlowManager {
    flows: DashMap<u32, FlowCtx>,
    /// Responder-side local connects in flight (idempotency guard: the
    /// initiator re-sends OPEN every 700ms until answered, so a duplicate
    /// OPEN while the local service is still connecting is the norm).
    connecting: DashMap<u32, ()>,
    /// Responder-side local UDP sockets keyed by (network, flow, exposed port).
    udp_locals: DashMap<(NetId, u32, u16), Arc<UdpSocket>>,
    flow_out: FlowOut,
    /// 收端串行队列：帧按到达顺序单任务处理（曾每帧 spawn——multi_thread
    /// 下处理顺序不保，DATA/CLOSE 乱序会静默截断流）。
    inbox: mpsc::UnboundedSender<(NetId, u64, Vec<u8>)>,
    /// Per-network exposes (network -> rules), shared view of engine state.
    exposes: DashMap<NetId, Vec<ExposeRule>>,
    networks: NetworksMap,
    log: LogFn,
}

/// Send/control half of an initiated UDP flow (cheap to clone).
#[derive(Clone)]
pub struct UdpFlowSender {
    pub flow_id: u32,
    pub net_id: NetId,
    pub peer: u64,
    mgr: std::sync::Weak<FlowManager>,
}

impl UdpFlowSender {
    /// Send a datagram to `dst` ("ip:port" of the virtual target).
    pub fn send(&self, dst: &str, data: &[u8]) {
        if let Some(mgr) = self.mgr.upgrade() {
            let payload = flow::build_datagram(dst, data);
            mgr.send_frame(self.net_id, self.peer, self.flow_id, flow::FLAG_DATAGRAM, &payload);
        }
    }

    pub fn close(&self) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.close_flow(self.flow_id, true);
        }
    }
}

/// Handle over an initiated UDP flow; split into sender + receiver halves.
pub struct UdpFlowHandle {
    pub sender: UdpFlowSender,
    pub rx: mpsc::Receiver<(String, Vec<u8>)>,
}

/// Handle over an initiated TCP flow. Interior mutability keeps the read
/// half usable through `Arc<FlowStream>` from pumping loops.
pub struct FlowStream {
    pub flow_id: u32,
    pub net_id: NetId,
    pub peer: u64,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    mgr: std::sync::Weak<FlowManager>,
}

impl FlowStream {
    /// Read the next inbound chunk (None = flow closed).
    pub async fn read(&self) -> Option<Vec<u8>> {
        self.rx.lock().await.recv().await
    }

    /// Write one chunk as a DATA frame.
    pub fn write(&self, chunk: &[u8]) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.send_frame(self.net_id, self.peer, self.flow_id, flow::FLAG_DATA, chunk);
        }
    }

    pub fn close(&self) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.close_flow(self.flow_id, true);
        }
    }
}

impl FlowManager {
    pub fn new(flow_out: FlowOut, networks: NetworksMap, log: LogFn) -> Arc<FlowManager> {
        let (inbox_tx, mut inbox_rx) = mpsc::unbounded_channel::<(NetId, u64, Vec<u8>)>();
        let mgr = Arc::new(FlowManager {
            flows: DashMap::new(),
            connecting: DashMap::new(),
            udp_locals: DashMap::new(),
            flow_out,
            inbox: inbox_tx,
            exposes: DashMap::new(),
            networks,
            log,
        });
        // 串行消费者：按入队顺序逐帧处理（保序）。
        let consumer = Arc::clone(&mgr);
        tokio::spawn(async move {
            while let Some((net_id, peer, payload)) = inbox_rx.recv().await {
                consumer.on_frame(net_id, peer, &payload).await;
            }
        });
        mgr
    }

    /// 引擎侧入队（收端保序入口）。
    pub fn enqueue(&self, net_id: NetId, peer: u64, payload: &[u8]) {
        let _ = self.inbox.send((net_id, peer, payload.to_vec()));
    }

    /// Replace the per-network expose rules (engine refreshes from config).
    pub fn set_exposes(&self, net_id: NetId, rules: Vec<ExposeRule>) {
        self.exposes.insert(net_id, rules);
    }

    fn self_ip_of(&self, net_id: &NetId) -> Option<Ipv4Addr> {
        self.networks.get(net_id).and_then(|c| c.value().self_ip)
    }

    fn new_flow_id(&self) -> Option<u32> {
        for _ in 0..16 {
            let id = OsRng.next_u32();
            if id != 0 && !self.flows.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    fn send_frame(&self, net_id: NetId, peer: u64, flow_id: u32, flags: u8, payload: &[u8]) {
        // 统一出站守卫：载荷超 UDP 数据报安全上限的帧密封后必然 send
        // 失败（数据报不可拆分），在此丢弃并留痕——曾静默黑洞。
        if payload.len() > skiff_core::consts::FLOW_MAX_DATAGRAM {
            (self.log)(&format!(
                "FLOW_DROP frame flow={flow_id} flags={flags} payload={} 超 UDP 数据报上限，已丢弃",
                payload.len()
            ));
            return;
        }
        let _ = self.flow_out.send((net_id, peer, flow::encode(flow_id, flags, payload)));
    }

    /// CLOSE 帧用 flow 所属网络的密钥密封（密钥以 networkId 为派生盐），
    /// 因此从 ctx 取 net_id/peer，不依赖调用方传参。
    fn close_flow(&self, flow_id: u32, notify_peer: bool) {
        if let Some((_, ctx)) = self.flows.remove(&flow_id) {
            if notify_peer {
                self.send_frame(ctx.net_id, ctx.peer, flow_id, flow::FLAG_CLOSE, b"");
            }
            self.udp_locals.retain(|k, _| k.1 != flow_id);
        }
    }

    /// Open a TCP flow to a peer's exposed service; waits up to `timeout`.
    pub async fn open_tcp(self: &Arc<Self>, net_id: NetId, peer: u64, dest: &str, timeout: Duration) -> Option<FlowStream> {
        let flow_id = self.new_flow_id()?;
        // 无界：应用侧消费慢时先缓冲（try_send 的 Full 曾被当作流失败
        // 立即拆除——任何突发回波都会瞬间杀死流，CONNECT 后即 EOF）。
        let (data_tx, data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (open_tx, open_rx) = oneshot::channel::<Result<(), String>>();
        self.flows.insert(
            flow_id,
            FlowCtx { net_id, peer, kind: FlowKind::OutTcp { open_reply: Some(open_tx), data_tx } },
        );
        // Re-send the OPEN until answered: the first UDP-carried OPEN may be
        // lost (or the peer's relay registration may lag presence).
        {
            let mgr = Arc::clone(self);
            let dest = dest.to_string();
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + timeout;
                while tokio::time::Instant::now() < deadline {
                    mgr.send_frame(net_id, peer, flow_id, flow::FLAG_OPEN, &flow::build_open(flow::PROTO_TCP, &dest));
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    match mgr.flows.get(&flow_id) {
                        // 成功应答后 entry 保留收发数据，open_reply 已被取走
                        // = 已应答，停止重发；entry 消失 = 已关闭/失败。
                        None => return,
                        Some(ctx) if matches!(&ctx.value().kind, FlowKind::OutTcp { open_reply: None, .. }) => return,
                        _ => {}
                    }
                }
            });
        }
        match tokio::time::timeout(timeout, open_rx).await {
            Ok(Ok(Ok(()))) => Some(FlowStream {
                flow_id,
                net_id,
                peer,
                rx: tokio::sync::Mutex::new(data_rx),
                mgr: Arc::downgrade(self),
            }),
            _ => {
                self.close_flow(flow_id, true);
                None
            }
        }
    }

    /// Open a UDP flow; fire-and-forget (no OPENED_OK wait).
    pub fn open_udp(self: &Arc<Self>, net_id: NetId, peer: u64, default_dest: &str) -> Option<UdpFlowHandle> {
        let flow_id = self.new_flow_id()?;
        let (tx, rx) = mpsc::channel::<(String, Vec<u8>)>(64);
        self.flows.insert(flow_id, FlowCtx { net_id, peer, kind: FlowKind::Udp { outbound: true, datagram_tx: tx } });
        self.send_frame(net_id, peer, flow_id, flow::FLAG_OPEN, &flow::build_open(flow::PROTO_UDP, default_dest));
        (self.log)(&format!("opening udp flow {flow_id} to peer {peer} {default_dest}"));
        Some(UdpFlowHandle {
            sender: UdpFlowSender { flow_id, net_id, peer, mgr: Arc::downgrade(self) },
            rx,
        })
    }

    /// Entry point for decrypted FLOW frames.
    pub async fn on_frame(self: &Arc<Self>, net_id: NetId, peer: u64, payload: &[u8]) {
        let Some(msg) = flow::decode(payload) else { return };
        match msg.flags {
            flow::FLAG_OPEN => self.handle_open(net_id, peer, msg.flow_id, msg.payload).await,
            flow::FLAG_OPENED_OK | flow::FLAG_OPENED_FAIL => {
                if let Some(mut ctx) = self.flows.get_mut(&msg.flow_id)
                    && let FlowKind::OutTcp { open_reply, .. } = &mut ctx.value_mut().kind
                        && let Some(tx) = open_reply.take() {
                            let result = if msg.flags == flow::FLAG_OPENED_OK {
                                Ok(())
                            } else {
                                Err(String::from_utf8_lossy(msg.payload).into_owned())
                            };
                            let _ = tx.send(result);
                        }
            }
            flow::FLAG_CLOSE => self.close_flow(msg.flow_id, false),
            flow::FLAG_DATA => {
                // OutTcp: deliver to the stream; InTcp: to the local writer.
                // 两路通道均无界：背压时缓冲而非拆流。kill 判定与 close_flow
                // 之间必须先 drop DashMap 引用（同 key 重叠会死锁，AGENTS #5）。
                let kill = match self.flows.get(&msg.flow_id) {
                    Some(entry) => match &entry.value().kind {
                        FlowKind::OutTcp { data_tx, .. } => {
                            let _ = data_tx.send(msg.payload.to_vec());
                            false
                        }
                        FlowKind::InTcp { writer, .. } => {
                            let _ = writer.send(msg.payload.to_vec());
                            false
                        }
                        FlowKind::Udp { .. } => true,
                    },
                    None => false,
                };
                if kill {
                    self.close_flow(msg.flow_id, true);
                }
            }
            flow::FLAG_DATAGRAM => self.handle_datagram(net_id, peer, msg.flow_id, msg.payload).await,
            _ => {}
        }
    }

    async fn handle_open(self: &Arc<Self>, net_id: NetId, peer: u64, flow_id: u32, payload: &[u8]) {
        let Some(info) = flow::parse_open(payload) else { return };
        let dest_port = info.addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
        match info.proto {
            flow::PROTO_TCP => {
                let Some(port) = dest_port else { return };
                // 幂等：flow 已建立（InTcp）→ 补发 OPENED_OK；其余形态（本端
                // 自己发起的同 id flow，随机 id 碰撞）→ 静默忽略。发起方每
                // 700ms 重发 OPEN，重复 OPEN 是常态：绝不能再次连接本地服务
                // ——重复 insert 会覆盖旧流，旧 reader 退出时的 close_flow 会
                // 误拆新流。
                if let Some(entry) = self.flows.get(&flow_id) {
                    let established = matches!(&entry.value().kind, FlowKind::InTcp { .. });
                    drop(entry);
                    if established {
                        self.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_OK, b"");
                    }
                    return;
                }
                let exposes = self.exposes.get(&net_id).map(|e| e.value().clone()).unwrap_or_default();
                let Some(expose) = exposes.iter().find(|e| e.proto == skiff_core::models::ProtoKind::Tcp && e.port == port) else {
                    let reason = format!("no tcp service on port {port}");
                    self.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_FAIL, &flow::build_opened_fail(&reason));
                    return;
                };
                let dest = expose.dest.clone();
                // In-flight guard: a duplicate OPEN arriving while the local
                // service is still connecting must not spawn a second connect.
                if self.connecting.insert(flow_id, ()).is_some() {
                    return;
                }
                let mgr = Arc::clone(self);
                tokio::spawn(async move {
                    let connect = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&dest)).await;
                    match connect {
                        Ok(Ok(stream)) => {
                            let (mut rd, wr) = stream.into_split();
                            let (writer_tx, writer_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                            // 先登记再清 in-flight 标记：两者之间到达的重复
                            // OPEN 会看到 InTcp 并补发 OPENED_OK，无副作用。
                            mgr.flows.insert(
                                flow_id,
                                FlowCtx { net_id, peer, kind: FlowKind::InTcp { writer: writer_tx } },
                            );
                            let _ = mgr.connecting.remove(&flow_id);
                            mgr.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_OK, b"");
                            tokio::spawn(local_writer_loop(wr, writer_rx));
                            // 分块上限 FLOW_CHUNK：读到多少发多少，保证
                            // 密封后不超 UDP 数据报上限（曾为 64KiB——
                            // 密封后 65592 > 65507，UDP 路径必失败且静默）。
                            let mut buf = vec![0u8; skiff_core::consts::FLOW_CHUNK];
                            loop {
                                match rd.read(&mut buf).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => {
                                        let _ = mgr
                                            .flow_out
                                            .send((net_id, peer, flow::encode(flow_id, flow::FLAG_DATA, &buf[..n])));
                                    }
                                }
                            }
                            mgr.close_flow(flow_id, true);
                        }
                        _ => {
                            let _ = mgr.connecting.remove(&flow_id);
                            let payload = flow::build_opened_fail("local service unreachable");
                            mgr.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_FAIL, &payload);
                        }
                    }
                });
            }
            flow::PROTO_UDP => {
                // Accept immediately; datagrams route per-packet by port.
                // 幂等：重复 OPEN 只补发 OPENED_OK，不替换已有 Udp ctx。
                if self.flows.get(&flow_id).is_some() {
                    self.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_OK, b"");
                    return;
                }
                let (datagram_tx, _discard_rx) = mpsc::channel::<(String, Vec<u8>)>(1);
                self.flows.insert(flow_id, FlowCtx { net_id, peer, kind: FlowKind::Udp { outbound: false, datagram_tx } });
                self.send_frame(net_id, peer, flow_id, flow::FLAG_OPENED_OK, b"");
            }
            _ => {}
        }
    }

    async fn handle_datagram(self: &Arc<Self>, net_id: NetId, peer: u64, flow_id: u32, payload: &[u8]) {
        let Some(info) = flow::parse_datagram(payload) else { return };
        // Initiator side: deliver to the handle (direction matters — the
        // responder also keeps a Udp ctx for the same flow id).
        let mut handled = false;
        if let Some(entry) = self.flows.get(&flow_id)
            && let FlowKind::Udp { outbound: true, datagram_tx, .. } = &entry.value().kind {
                handled = datagram_tx.try_send((info.addr.to_string(), info.data.to_vec())).is_ok();
            }
        if handled {
            return;
        }
        // Responder side: route to the exposed UDP service in this network.
        let Some(dst_port) = info.addr.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) else { return };
        let exposes = self.exposes.get(&net_id).map(|e| e.value().clone()).unwrap_or_default();
        let Some(expose) = exposes.iter().find(|e| e.proto == skiff_core::models::ProtoKind::Udp && e.port == dst_port) else { return };
        let Some(self_ip) = self.self_ip_of(&net_id) else { return };
        let dest: SocketAddr = expose.dest.parse().unwrap_or_else(|_| {
            format!("127.0.0.1:{}", expose.port).parse().expect("fallback udp dest parses")
        });
        let reply_addr = format!("{}:{}", self_ip, dst_port);

        let key = (net_id, flow_id, dst_port);
        let sock = match self.udp_locals.get(&key) {
            Some(s) => Arc::clone(s.value()),
            None => {
                let Ok(raw) = UdpSocket::bind(("127.0.0.1", 0)).await else { return };
                let sock = Arc::new(raw);
                self.udp_locals.insert(key, Arc::clone(&sock));
                // Reply loop for this (network, flow, port): local answers
                // go back as DATAGRAM frames carrying the local virtual
                // address of THIS network.
                let mgr = Arc::clone(self);
                let sock_clone = Arc::clone(&sock);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    while let Ok(Ok((n, _))) =
                        tokio::time::timeout(Duration::from_secs(300), sock_clone.recv_from(&mut buf)).await
                    {
                        // 走 send_frame 统一超限守卫（超大数据报丢弃留痕）。
                        mgr.send_frame(net_id, peer, flow_id, flow::FLAG_DATAGRAM, &flow::build_datagram(&reply_addr, &buf[..n]));
                    }
                    // 5 min idle or socket error ends this port's reply loop.
                    mgr.udp_locals.remove(&(net_id, flow_id, dst_port));
                });
                sock
            }
        };
        let _ = sock.send_to(info.data, dest).await;
    }

    /// Close all flows of a peer that left a network. 按网络精确匹配：同一
    /// 设备可能同时参加多个网络，跨网关闭会误杀其他网络的流。
    pub fn close_peer(&self, net_id: NetId, peer: u64) {
        let ids: Vec<u32> = self
            .flows
            .iter()
            .filter(|e| e.value().net_id == net_id && e.value().peer == peer)
            .map(|e| *e.key())
            .collect();
        for id in ids {
            self.close_flow(id, true);
        }
    }
}

async fn local_writer_loop(mut wr: tokio::net::tcp::OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(chunk) = rx.recv().await {
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
    }
    let _ = wr.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::NetworkCtx;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type FlowOutRx = mpsc::UnboundedReceiver<(NetId, u64, Vec<u8>)>;

    fn mk_mgr() -> (Arc<FlowManager>, FlowOutRx) {
        let (tx, rx) = mpsc::unbounded_channel();
        let networks: NetworksMap = Arc::new(DashMap::new());
        networks.insert(
            NetId([3; 16]),
            NetworkCtx { name: "t".into(), cidr: None, self_ip: None, ip_map: Default::default() },
        );
        (FlowManager::new(tx, networks, Arc::new(|_| {})), rx)
    }

    /// 等待 flow_out 上出现指定 (flowId, flags) 的帧。
    async fn recv_flag(
        rx: &mut mpsc::UnboundedReceiver<(NetId, u64, Vec<u8>)>,
        flow_id: u32,
        want: u8,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let Ok(Some((_n, _p, payload))) =
                tokio::time::timeout(Duration::from_millis(500), rx.recv()).await
            else {
                continue;
            };
            if let Some(msg) = flow::decode(&payload)
                && msg.flow_id == flow_id
                && msg.flags == want
            {
                return true;
            }
        }
        false
    }

    /// close_peer 只关指定网络的 flow：同一 peer 在另一网络的流不受影响。
    /// （FlowManager::new 会 spawn 收端串行消费者，需在 tokio 上下文构造。）
    #[tokio::test]
    async fn close_peer_is_scoped_to_network() {
        let (mgr, _rx) = mk_mgr();
        let net_a = NetId([1; 16]);
        let net_b = NetId([2; 16]);
        let flow_a = mgr.open_udp(net_a, 42, "10.0.0.2:53").unwrap();
        let flow_b = mgr.open_udp(net_b, 42, "10.1.0.2:53").unwrap();

        mgr.close_peer(net_a, 42);

        assert!(mgr.flows.get(&flow_a.sender.flow_id).is_none());
        assert!(mgr.flows.get(&flow_b.sender.flow_id).is_some());
    }

    /// 重复 OPEN（连接进行中 + 已建立后）都不得重复连接本地服务。
    #[tokio::test]
    async fn duplicate_tcp_open_is_idempotent() {
        let (mgr, mut rx) = mk_mgr();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let net = NetId([3; 16]);
        mgr.set_exposes(
            net,
            vec![ExposeRule { port, proto: skiff_core::models::ProtoKind::Tcp, dest: format!("127.0.0.1:{port}") }],
        );
        let accepted = Arc::new(AtomicUsize::new(0));
        let acc = Arc::clone(&accepted);
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                acc.fetch_add(1, Ordering::Relaxed);
                drop(s);
            }
        });

        let open = flow::encode(
            777,
            flow::FLAG_OPEN,
            &flow::build_open(flow::PROTO_TCP, &format!("10.3.0.5:{port}")),
        );
        mgr.on_frame(net, 42, &open).await; // 首次 OPEN：开始连接本地服务
        mgr.on_frame(net, 42, &open).await; // 本地服务连接中的重复 OPEN
        assert!(recv_flag(&mut rx, 777, flow::FLAG_OPENED_OK).await, "首次应答缺失");
        mgr.on_frame(net, 42, &open).await; // 已建立后的重复 OPEN
        assert!(recv_flag(&mut rx, 777, flow::FLAG_OPENED_OK).await, "重复 OPEN 未补发应答");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepted.load(Ordering::Relaxed), 1, "重复 OPEN 导致了多余的本地连接");
    }
}
