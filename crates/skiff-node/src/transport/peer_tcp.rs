//! Direct peer TCP tunnel: `[len u32 LE][wire frame]` with no inner header
//! — the first frame's senderId identifies the peer.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use skiff_core::protocol::relay_tcp::{FrameReassembler, LENGTH_HEADER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use crate::engine::EngineEvent;

pub struct PeerTcpConnection {
    /// Resolved from the first frame's senderId; 0 = not yet known.
    pub peer_id: AtomicU64,
    writer: mpsc::UnboundedSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

impl PeerTcpConnection {
    /// Outbound connect with a timeout; on success a read loop is spawned
    /// feeding the engine.
    pub async fn connect(
        endpoint: SocketAddr,
        timeout: std::time::Duration,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> anyhow::Result<Arc<PeerTcpConnection>> {
        let stream = tokio::time::timeout(timeout, TcpStream::connect(endpoint)).await??;
        Ok(Self::wrap(stream, events))
    }

    /// Inbound wrap: spawns the read loop; `peer_id` resolves from the first
    /// frame (the frame itself is still delivered as normal traffic).
    pub fn wrap(
        stream: TcpStream,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> Arc<PeerTcpConnection> {
        let _ = stream.set_nodelay(true);
        let (read, write) = stream.into_split();
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        tokio::spawn(writer_loop(write, rx));
        let closed = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(PeerTcpConnection {
            peer_id: AtomicU64::new(0),
            writer: tx,
            closed: Arc::clone(&closed),
        });
        tokio::spawn(read_loop(read, Arc::clone(&conn), events, closed));
        conn
    }

    pub fn send(&self, frame: &[u8]) -> bool {
        if self.closed.load(Ordering::Relaxed) {
            return false;
        }
        let mut framed = Vec::with_capacity(LENGTH_HEADER + frame.len());
        skiff_core::protocol::relay_tcp::write_length_prefixed(&mut framed, frame);
        self.writer.send(framed).is_ok()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

async fn writer_loop(mut write: OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Vec<u8>>) {
    while let Some(msg) = rx.recv().await {
        if write.write_all(&msg).await.is_err() || write.flush().await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

async fn read_loop(
    mut read: OwnedReadHalf,
    conn: Arc<PeerTcpConnection>,
    events: mpsc::UnboundedSender<EngineEvent>,
    closed: Arc<AtomicBool>,
) {
    let mut reassembler = FrameReassembler::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match read.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let frames = match reassembler.feed(&buf[..n]) {
                    Ok(f) => f,
                    // 超限帧：流边界已不可信，保留连接只会形成数据黑洞。
                    Err(_) => break,
                };
                for frame in frames {
                    if conn.peer_id.load(Ordering::Relaxed) == 0
                        && let Some(raw) = skiff_core::protocol::wire::RawFrame::try_parse(&frame)
                    {
                        conn.peer_id.store(raw.sender_id, Ordering::Relaxed);
                    }
                    let _ = events.send(EngineEvent::Frame {
                        arrival: crate::engine::Arrival::direct_tcp(Arc::clone(&conn)),
                        packet: frame,
                    });
                }
            }
        }
    }
    closed.store(true, Ordering::Relaxed);
}
