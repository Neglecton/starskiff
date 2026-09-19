//! TCP relay (port 24932): length-prefixed relay control channel. First
//! frame must be an HMAC-authenticated REGISTER within 15s; a device id may
//! hold one connection (new ones kick old ones); idle connections are closed
//! after 120s without any inbound frame (nodes keepalive every 2 heartbeat
//! ticks). `Send` frames are forwarded to the target's connection as
//! `Frame` frames with the destination id stripped (sender identity lives in
//! the inner wire frame).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use skiff_core::protocol::relay_tcp::{
    self, CMD_TCP_FRAME, CMD_TCP_KEEPALIVE_RESP, FrameReassembler, RelayTcpMsg,
};
use skiff_core::protocol::relay_udp::{self, CMD_ACK, CMD_ERROR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::presence::Presence;

const REGISTER_TIMEOUT: Duration = Duration::from_secs(15);
/// 每连接写队列深度上限（帧）：128 帧 × ≤512KiB 为最坏内存上界，慢接
/// 收方溢出即丢弃计数（背压防护，见 handle_connection 注释）。
const RELAY_TCP_QUEUE_FRAMES: usize = 128;
/// 连接空闲回收：节点每 2 心跳 tick（慢档 30s、快档 10s）发一次
/// KEEPALIVE，120s = 慢档 4 个周期仍无任何入帧即回收——死链不再占用
/// 连接槽位 12h（半开连接此前一直挂到节点侧 TCP 重传超时）。
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// 全局并发连接上限（pre-auth 即拦截连接洪泛；正常规模每设备 1 连接）。
const MAX_CONNS_TOTAL: i64 = 1024;
/// 单 IP 并发上限（CGNAT 后多节点共享公网 IP，留足余量）。
const MAX_CONNS_PER_IP: u32 = 64;
/// pre-auth 首帧（REGISTER）长度上限：真实 ~60B，4KB 已极宽松——认证
/// 通过前按 512KB 上限预分配读缓冲是纯资源耗尽面。
const PREAUTH_MAX_FRAME: usize = 4 * 1024;

struct ConnHandle {
    tx: mpsc::Sender<Vec<u8>>,
}

pub struct TcpRelay {
    connections: DashMap<u64, ConnHandle>,
    presence: Presence,
    lookup_key: Arc<dyn Fn(u64) -> Option<[u8; 32]> + Send + Sync>,
    /// REGISTER 防重放（与 UDP 中继共享同一份 nonce 记忆）。
    register_guard: crate::relay::register_guard::RegisterGuard,
    forwarded_bytes: AtomicU64,
    forwarded_packets: AtomicU64,
    dropped_packets: AtomicU64,
    /// 并发连接准入（pre-auth 资源耗尽防护）：全局计数 + per-IP 表。
    conn_total: std::sync::atomic::AtomicI64,
    conn_per_ip: DashMap<std::net::IpAddr, u32>,
    last_reject_log_ms: std::sync::atomic::AtomicI64,
}

/// 并发准入守卫：drop 时释放全局与 per-IP 计数。
struct ConnAdmission {
    relay: Arc<TcpRelay>,
    ip: std::net::IpAddr,
}

impl Drop for ConnAdmission {
    fn drop(&mut self) {
        self.relay.conn_total.fetch_sub(1, Ordering::Relaxed);
        if let Some(mut e) = self.relay.conn_per_ip.get_mut(&self.ip) {
            *e -= 1;
            let zeroed = *e == 0;
            drop(e); // 同 key 引用不重叠（AGENTS #5）
            if zeroed {
                self.relay.conn_per_ip.remove(&self.ip);
            }
        }
    }
}

impl TcpRelay {
    pub fn new(
        presence: Presence,
        lookup_key: Arc<dyn Fn(u64) -> Option<[u8; 32]> + Send + Sync>,
        register_guard: crate::relay::register_guard::RegisterGuard,
    ) -> Arc<TcpRelay> {
        Arc::new(TcpRelay {
            connections: DashMap::new(),
            presence,
            lookup_key,
            register_guard,
            forwarded_bytes: AtomicU64::new(0),
            forwarded_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            conn_total: std::sync::atomic::AtomicI64::new(0),
            conn_per_ip: DashMap::new(),
            last_reject_log_ms: std::sync::atomic::AtomicI64::new(0),
        })
    }

    /// 并发准入：超限返回 None（60s 节流日志——洪泛时打日志本身会放大）。
    fn admit(self: &Arc<Self>, ip: std::net::IpAddr, now_ms: i64) -> Option<ConnAdmission> {
        if self.conn_total.load(Ordering::Relaxed) >= MAX_CONNS_TOTAL {
            self.reject_log(now_ms, "total");
            return None;
        }
        let mut entry = self.conn_per_ip.entry(ip).or_insert(0);
        if *entry >= MAX_CONNS_PER_IP {
            drop(entry);
            self.reject_log(now_ms, "per-ip");
            return None;
        }
        *entry += 1;
        drop(entry);
        self.conn_total.fetch_add(1, Ordering::Relaxed);
        Some(ConnAdmission {
            relay: Arc::clone(self),
            ip,
        })
    }

    fn reject_log(&self, now_ms: i64, kind: &str) {
        let last = self.last_reject_log_ms.load(Ordering::Relaxed);
        if now_ms - last > 60_000
            && self
                .last_reject_log_ms
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            eprintln!("TCP_RELAY_REJECT kind={kind}（并发连接超限，疑似连接洪泛）");
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let relay = Arc::clone(&self);
                    tokio::spawn(async move {
                        let _ = stream.set_nodelay(true);
                        relay.handle_connection(stream, peer).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }

    async fn handle_connection(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        // 并发准入（pre-auth）：连接洪泛在分配任何任务/队列之前被拒。
        let _admission = match self.admit(peer.ip(), skiff_core::logging::unix_ms()) {
            Some(g) => g,
            None => return, // 超限直接断开（reject_log 已节流记录）
        };
        let (mut read_half, mut write_half) = stream.into_split();
        // Pre-auth：读首帧 REGISTER 并认证——此阶段零任务/零队列分配，
        // 帧长上限 4KB（认证前不替未知客户端预分配大缓冲）。
        let auth = self.authenticate(&mut read_half).await;
        let device_id = match auth {
            Ok(id) => id,
            Err(msg) => {
                // 错误帧直写 socket（一次性），无需队列。
                let inner = relay_tcp::encode_cmd(CMD_ERROR, msg.as_bytes());
                let mut framed = Vec::with_capacity(inner.len() + 4);
                relay_tcp::write_length_prefixed(&mut framed, &inner);
                let _ = tokio::time::timeout(
                    Duration::from_secs(2),
                    async {
                        write_half.write_all(&framed).await?;
                        write_half.flush().await
                    },
                )
                .await;
                return;
            }
        };
        // Post-auth：才有资格分配写队列与任务。
        // 有界写队列（背压防护）：合法设备可向慢接收方灌帧，无界队列
        // 会按入速-排空速累积直至内存耗尽。溢出丢弃并计数——加密帧丢失
        // 由上层重传/超时处理，与 UDP 中继的丢弃语义一致。
        let (writer_tx, writer_rx) = mpsc::channel::<Vec<u8>>(RELAY_TCP_QUEUE_FRAMES);
        let writer = tokio::spawn(writer_loop(write_half, writer_rx));

        let result = self
            .relay_session(device_id, read_half, writer_tx.clone(), peer)
            .await;
        if let Err(msg) = &result {
            // Mirror the C# error text contract.
            let inner = relay_tcp::encode_cmd(CMD_ERROR, msg.as_bytes());
            let _ = writer_tx.try_send(length_prefix(&inner));
        }
        // Kick self from the table only if we still own the entry.
        if let Ok(id) = &result
            && let Some(entry) = self.connections.get(id)
            && entry.tx.same_channel(&writer_tx)
        {
            drop(entry);
            self.connections.remove(id);
        }
        drop(writer_tx); // stops the writer loop, closing the socket
        let _ = writer.await;
    }

    /// 读首帧 REGISTER 并完成 HMAC + nonce 认证；成功返回 device_id。
    /// kick-old/登记/ACK 挪到 post-auth（需要写队列）。
    async fn authenticate(&self, read: &mut OwnedReadHalf) -> Result<u64, String> {
        // First frame: REGISTER with the 56-byte body, within 15s.
        let first = read_frame(read, REGISTER_TIMEOUT, PREAUTH_MAX_FRAME)
            .await
            .map_err(|_| "register timeout".to_string())?;
        let RelayTcpMsg::Register { body } = relay_tcp::parse(&first).ok_or("bad register")? else {
            return Err("expected register".into());
        };
        // Recover device id from the body before HMAC verification.
        if body.len() != 56 {
            return Err("bad register body length".into());
        }
        let device_id = u64::from_le_bytes(body[..8].try_into().unwrap());
        let Some(key) = (self.lookup_key)(device_id) else {
            return Err("unknown device or bad auth".into());
        };
        if !skiff_core::protocol::relay_udp::verify_register_body(body, device_id, &key) {
            return Err("unknown device or bad auth".into());
        }
        // 防重放：重放的 REGISTER 会踢掉该设备当前在线的连接（新踢旧），
        // 攻击者截获一次合法 REGISTER 即可无限打断服务，必须拒绝。
        let Some(nonce) = relay_udp::register_body_nonce(body) else {
            return Err("bad register body length".into());
        };
        if !self.register_guard.admit(device_id, &nonce) {
            return Err("replayed register".into());
        }
        Ok(device_id)
    }

    /// Post-auth 主循环：登记连接（新踢旧）→ ACK → 转发/保活循环。
    async fn relay_session(
        self: &Arc<Self>,
        device_id: u64,
        mut read: OwnedReadHalf,
        writer_tx: mpsc::Sender<Vec<u8>>,
        peer: SocketAddr,
    ) -> Result<u64, String> {
        // Same device reconnecting kicks the old connection.
        if let Some((_, old)) = self.connections.remove(&device_id) {
            let _ = old.tx.try_send(Vec::new()); // empty write signals close-ish; rely on drop
        }
        self.connections.insert(
            device_id,
            ConnHandle {
                tx: writer_tx.clone(),
            },
        );
        self.presence.touch_relay_tcp(device_id);

        let ack_inner = relay_tcp::encode_cmd(
            CMD_ACK,
            &relay_udp::build_ack_payload(&peer.ip().to_string(), peer.port()),
        );
        if writer_tx.try_send(length_prefix(&ack_inner)).is_err() {
            return Ok(device_id);
        }

        let mut reassembler = FrameReassembler::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = tokio::time::timeout(IDLE_TIMEOUT, read.read(&mut chunk))
                .await
                .map_err(|_| "idle timeout".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Ok(device_id); // peer closed
            }
            let frames = match reassembler.feed(&chunk[..n]) {
                Ok(f) => f,
                // 超限帧：流边界已不可信，只能断开。
                Err(_) => return Err("frame too large".into()),
            };
            for frame in frames {
                self.presence.touch_relay_tcp(device_id);
                match relay_tcp::parse(&frame) {
                    Some(RelayTcpMsg::Keepalive) => {
                        let resp = relay_tcp::encode_cmd(CMD_TCP_KEEPALIVE_RESP, b"");
                        if writer_tx.try_send(length_prefix(&resp)).is_err() {
                            return Ok(device_id);
                        }
                    }
                    Some(RelayTcpMsg::Send { dst, frame }) => {
                        // DashMap 引用先 drop 再计丢弃（统一收尾，避免重叠）。
                        let sent = match self.connections.get(&dst) {
                            Some(target) => {
                                let inner = relay_tcp::encode_cmd(CMD_TCP_FRAME, frame);
                                let ok = target.tx.try_send(length_prefix(&inner)).is_ok();
                                drop(target);
                                ok
                            }
                            None => false,
                        };
                        if sent {
                            self.forwarded_packets.fetch_add(1, Ordering::Relaxed);
                            self.forwarded_bytes
                                .fetch_add(frame.len() as u64, Ordering::Relaxed);
                        } else {
                            // 目标离线或写队列满（慢接收方）：丢弃计数。
                            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => return Err("unexpected command".into()),
                }
            }
        }
    }

    pub fn unregister(&self, device_id: u64) {
        self.connections.remove(&device_id);
    }

    pub fn active(&self) -> usize {
        self.connections.len()
    }

    pub fn forwarded_packets(&self) -> u64 {
        self.forwarded_packets.load(Ordering::Relaxed)
    }

    pub fn forwarded_bytes(&self) -> u64 {
        self.forwarded_bytes.load(Ordering::Relaxed)
    }
}

fn length_prefix(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + inner.len());
    relay_tcp::write_length_prefixed(&mut out, inner);
    out
}

async fn writer_loop(mut write: OwnedWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(msg) = rx.recv().await {
        // Empty payload is the kick signal from a replacing connection.
        if msg.is_empty() {
            break;
        }
        if write.write_all(&msg).await.is_err() {
            break;
        }
        if write.flush().await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// Read one complete length-prefixed frame.
async fn read_frame(
    read: &mut OwnedReadHalf,
    timeout: Duration,
    max_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    tokio::time::timeout(timeout, read.read_exact(&mut header)).await??;
    let len = u32::from_le_bytes(header) as usize;
    if len > max_len {
        return Err(std::io::Error::other("frame too large"));
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout(timeout, read.read_exact(&mut body)).await??;
    Ok(body)
}
