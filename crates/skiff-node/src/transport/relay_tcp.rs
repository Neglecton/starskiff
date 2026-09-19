//! RelayTcpClient: lazy persistent TCP connection to the relay. Sends
//! trigger a connection on demand; keepalives only fire while connected.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use skiff_core::protocol::relay_tcp::{
    self, CMD_TCP_KEEPALIVE, CMD_TCP_KEEPALIVE_RESP, CMD_TCP_SEND, RelayTcpMsg,
};
use skiff_core::protocol::relay_udp::CMD_REGISTER;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::engine::EngineEvent;

pub struct RelayTcpClient {
    /// REGISTER 凭据：每次连接生成新 nonce（服务端记忆已用 nonce 防重放，
    /// 缓存整个 REGISTER body 会导致重连被拒）。
    device_id: u64,
    relay_key: [u8; 32],
    addr: Mutex<Option<SocketAddr>>,
    writer: AsyncMutex<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    connecting: AtomicBool,
}

impl RelayTcpClient {
    pub fn new(device_id: u64, relay_key: &[u8; 32]) -> Arc<RelayTcpClient> {
        Arc::new(RelayTcpClient {
            device_id,
            relay_key: *relay_key,
            addr: Mutex::new(None),
            writer: AsyncMutex::new(None),
            connecting: AtomicBool::new(false),
        })
    }

    pub fn configure(self: &Arc<Self>, addr: SocketAddr) {
        *self.addr.lock().unwrap() = Some(addr);
    }

    pub fn is_connected(&self) -> bool {
        self.writer.try_lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Connect if not connected (idempotent, single-flight).
    pub async fn ensure_connected(self: Arc<Self>, events: &mpsc::UnboundedSender<EngineEvent>) {
        {
            let guard = self.writer.lock().await;
            if guard.is_some() {
                return;
            }
        }
        if self.connecting.swap(true, Ordering::Relaxed) {
            return;
        }
        let Some(addr) = *self.addr.lock().unwrap() else {
            self.connecting.store(false, Ordering::Relaxed);
            return;
        };
        let result: std::io::Result<mpsc::UnboundedSender<Vec<u8>>> = async {
            let stream =
                tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await??;
            let _ = stream.set_nodelay(true);
            let (read, mut write) = stream.into_split();
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            // REGISTER body = the UDP REGISTER packet minus its 3-byte
            // header; fresh nonce per connection (server rejects replays).
            let udp_pkt = skiff_core::protocol::relay_udp::build_register(self.device_id, &self.relay_key);
            let mut reg = relay_tcp::encode_cmd(CMD_REGISTER, &udp_pkt[3..]);
            let mut framed = Vec::new();
            relay_tcp::write_length_prefixed(&mut framed, &reg);
            reg.clear();
            write.write_all(&framed).await?;
            write.flush().await?;
            tokio::spawn(writer_loop(write, rx));
            tokio::spawn(read_loop(read, Arc::clone(&self), events.clone()));
            Ok(tx)
        }
        .await;
        self.connecting.store(false, Ordering::Relaxed);
        if let Ok(tx) = result {
            *self.writer.lock().await = Some(tx);
        }
    }

    /// Send a frame to a peer through the relay; connects lazily. A send
    /// racing the handshake returns false and the caller retries later.
    pub async fn send(
        self: &Arc<Self>,
        dst_id: u64,
        frame: &[u8],
        events: &mpsc::UnboundedSender<EngineEvent>,
    ) -> bool {
        if !self.is_connected() {
            self.clone().ensure_connected(events).await;
        }
        let guard = self.writer.lock().await;
        let Some(tx) = guard.as_ref() else {
            return false;
        };
        let inner = relay_tcp::encode_cmd(CMD_TCP_SEND, &relay_tcp::build_send_body(dst_id, frame));
        let mut framed = Vec::new();
        relay_tcp::write_length_prefixed(&mut framed, &inner);
        tx.send(framed).is_ok()
    }

    pub async fn keepalive(self: &Arc<Self>) {
        let guard = self.writer.lock().await;
        if let Some(tx) = guard.as_ref() {
            let inner = relay_tcp::encode_cmd(CMD_TCP_KEEPALIVE, b"");
            let mut framed = Vec::new();
            relay_tcp::write_length_prefixed(&mut framed, &inner);
            let _ = tx.send(framed);
        }
    }
}

async fn writer_loop(
    mut write: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(msg) = rx.recv().await {
        if write.write_all(&msg).await.is_err() || write.flush().await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

async fn read_loop(
    mut read: tokio::net::tcp::OwnedReadHalf,
    client: Arc<RelayTcpClient>,
    events: mpsc::UnboundedSender<EngineEvent>,
) {
    const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
    let mut reassembler = relay_tcp::FrameReassembler::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // 半开检测：keepalive 每 2 心跳 tick（慢档 30s）必有一轮 RESP，
        // 90s（3 个周期）无任何入帧视为死链——写 keepalive 进内核缓冲
        // "成功"但对端已不可达的半开连接只有读超时能暴露。断开后由
        // 下次 send/keepalive 懒重连。
        let read_res = tokio::time::timeout(IDLE_TIMEOUT, read.read(&mut buf)).await;
        let n = match read_res {
            Err(_) => break, // idle timeout：半开/死链
            Ok(v) => v,
        };
        match n {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let frames = match reassembler.feed(&buf[..n]) {
                    Ok(f) => f,
                    // 超限帧：流边界已不可信，断开由后续 send 重新连接。
                    Err(_) => return,
                };
                for frame in frames {
                    match relay_tcp::parse(&frame) {
                        Some(RelayTcpMsg::Frame { frame }) => {
                            let _ = events.send(EngineEvent::Frame {
                                arrival: crate::engine::Arrival::relay_tcp(),
                                packet: frame.to_vec(),
                            });
                        }
                        Some(RelayTcpMsg::Keepalive) => {
                            if let Some(tx) =
                                client.writer.lock().await.as_ref().map(|tx| tx.clone())
                            {
                                let inner = relay_tcp::encode_cmd(CMD_TCP_KEEPALIVE_RESP, b"");
                                let mut framed = Vec::new();
                                relay_tcp::write_length_prefixed(&mut framed, &inner);
                                let _ = tx.send(framed);
                            }
                        }
                        // REGISTER 的 ACK：忽略即可继续读（曾落入 `_ => return`
                        // 导致读循环首包即退出——发送正常、接收永久失效的
                        // 僵尸连接，RelayTcp 从未被路由所以一直没暴露）。
                        Some(RelayTcpMsg::Ack { .. }) => {}
                        Some(RelayTcpMsg::Error { body }) => {
                            let _ = events.send(EngineEvent::Log(format!(
                                "中继 TCP 错误: {}",
                                String::from_utf8_lossy(body)
                            )));
                            return;
                        }
                        _ => return, // unexpected command: drop the connection
                    }
                }
            }
        }
    }
    // Socket gone: clear the writer slot so a future send reconnects.
    *client.writer.lock().await = None;
}
