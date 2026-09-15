//! Port forwarders: local TCP listeners and UDP sockets bridging to remote
//! exposed services over FLOW. UDP flows idle for 5 minutes are collected
//! every 30s.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use skiff_core::logging::unix_ms;
use skiff_core::models::ForwardRule;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::engine::EngineShared;

const PUMP_BUF: usize = 32 * 1024;
const UDP_IDLE_MS: i64 = 5 * 60 * 1000;
const UDP_SWEEP: Duration = Duration::from_secs(30);

pub async fn spawn_all(
    rules: &[ForwardRule],
    shared: Arc<EngineShared>,
) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for rule in rules {
        let listen: SocketAddr = rule.listen.parse()?;
        let dest: SocketAddr = rule.dest.parse()?;
        let port = match rule.proto.as_str() {
            "udp" => spawn_udp(rule, listen, dest, Arc::clone(&shared)).await?,
            _ => spawn_tcp(listen, dest, Arc::clone(&shared)).await?,
        };
        ports.push(port);
    }
    Ok(ports)
}

async fn spawn_tcp(
    listen: SocketAddr,
    dest: SocketAddr,
    shared: Arc<EngineShared>,
) -> anyhow::Result<u16> {
    let listener = TcpListener::bind(listen).await?;
    let port = listener.local_addr()?.port();
    (shared.log)(&format!("TCP 转发 {listen} -> {dest}"));
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let shared = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let _ = pump_tcp(stream, shared, dest).await;
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
    Ok(port)
}

async fn pump_tcp(
    stream: tokio::net::TcpStream,
    shared: Arc<EngineShared>,
    dest: SocketAddr,
) -> anyhow::Result<()> {
    let IpAddr::V4(v4) = dest.ip() else {
        anyhow::bail!("目标 {} 不是 IPv4", dest)
    };
    let Some((net_id, peer)) = shared.peer_by_ip(v4) else {
        anyhow::bail!("目标 {} 不在网内", dest);
    };
    let dest_text = dest.to_string();
    let Some(flow) = shared
        .flows
        .open_tcp(net_id, peer.id, &dest_text, Duration::from_secs(8))
        .await
    else {
        anyhow::bail!("无法建立到 {} 的流", dest_text);
    };
    let flow = Arc::new(flow);
    let (mut rd, mut wr) = stream.into_split();
    let writer = {
        let flow = Arc::clone(&flow);
        tokio::spawn(async move {
            let mut buf = vec![0u8; PUMP_BUF];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => flow.write(&buf[..n]),
                }
            }
            flow.close();
        })
    };
    while let Some(chunk) = flow.read().await {
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
    }
    writer.abort();
    Ok(())
}

struct UdpFlowEntry {
    sender: crate::flow::UdpFlowSender,
    last_seen_ms: std::sync::atomic::AtomicI64,
}

async fn spawn_udp(
    rule: &ForwardRule,
    listen: SocketAddr,
    dest: SocketAddr,
    shared: Arc<EngineShared>,
) -> anyhow::Result<u16> {
    let sock = Arc::new(UdpSocket::bind(listen).await?);
    let port = sock.local_addr()?.port();
    (shared.log)(&format!("UDP 转发 {listen} -> {dest}"));
    // One flow per client endpoint.
    let flows: Arc<DashMap<SocketAddr, Arc<UdpFlowEntry>>> = Arc::new(DashMap::new());

    // Client -> mesh.
    {
        let sock = Arc::clone(&sock);
        let flows = Arc::clone(&flows);
        let shared = Arc::clone(&shared);
        let rule_listen = rule.listen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, client)) = sock.recv_from(&mut buf).await {
                let entry = match flows.get(&client) {
                    Some(e) => Arc::clone(e.value()),
                    None => {
                        let std::net::IpAddr::V4(dest_v4) = dest.ip() else {
                            continue;
                        };
                        let Some((net_id, peer)) = shared.peer_by_ip(dest_v4) else {
                            continue;
                        };
                        let Some(handle) = shared.flows.open_udp(net_id, peer.id, &dest.to_string()) else {
                            continue;
                        };
                        let entry = Arc::new(UdpFlowEntry {
                            sender: handle.sender,
                            last_seen_ms: std::sync::atomic::AtomicI64::new(0),
                        });
                        // Reply loop for this client.
                        let sock = Arc::clone(&sock);
                        let mut rx = handle.rx;
                        tokio::spawn(async move {
                            while let Some((_addr, data)) = rx.recv().await {
                                if sock.send_to(&data, client).await.is_err() {
                                    break;
                                }
                            }
                        });
                        flows.insert(client, Arc::clone(&entry));
                        entry
                    }
                };
                entry
                    .last_seen_ms
                    .store(unix_ms(), std::sync::atomic::Ordering::Relaxed);
                entry.sender.send(&dest.to_string(), &buf[..n]);
            }
            let _ = rule_listen;
        });
    }

    // Idle sweeper.
    {
        let flows = Arc::clone(&flows);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(UDP_SWEEP).await;
                let now = unix_ms();
                flows.retain(|_, e| {
                    let fresh = now - e.last_seen_ms.load(std::sync::atomic::Ordering::Relaxed)
                        < UDP_IDLE_MS;
                    if !fresh {
                        e.sender.close();
                    }
                    fresh
                });
            }
        });
    }
    Ok(port)
}
