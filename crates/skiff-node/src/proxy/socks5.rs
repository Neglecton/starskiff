//! Minimal SOCKS5 server: CONNECT to virtual-network targets and UDP
//! ASSOCIATE. No-auth only; targets must live inside the mesh.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use skiff_core::models::NetId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::engine::EngineShared;
use crate::flow::UdpFlowSender;

const PUMP_BUF: usize = skiff_core::consts::FLOW_CHUNK;

pub async fn spawn(listen: &str, shared: Arc<EngineShared>) -> anyhow::Result<u16> {
    let listener = TcpListener::bind(parse_listen(listen)?).await?;
    let port = listener.local_addr()?.port();
    let log = shared.log.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let shared = Arc::clone(&shared);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, shared).await {
                            let _ = e;
                        }
                    });
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    });
    (log)(&format!("SOCKS5 监听 127.0.0.1:{port}"));
    Ok(port)
}

fn parse_listen(listen: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(a) = listen.parse::<SocketAddr>() {
        return Ok(a);
    }
    // "0" or bare port means an ephemeral port on loopback.
    if let Ok(port) = listen.parse::<u16>() {
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    anyhow::bail!("无效的 SOCKS 监听地址 {listen}")
}

async fn handle_client(mut stream: TcpStream, shared: Arc<EngineShared>) -> anyhow::Result<()> {
    // Greeting: [VER=5 NMETHODS METHODS...]
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 {
        anyhow::bail!("not socks5");
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?; // no-auth

    // Request: [VER CMD RSV ATYP ADDR... PORT...]
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    let atyp = req[3];
    let target_ip: Ipv4Addr = match atyp {
        1 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            a.into()
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            stream.read_exact(&mut name).await?;
            let name = String::from_utf8_lossy(&name).to_string();
            // Local resolution, IPv4 only.
            use std::net::ToSocketAddrs;
            let mut ip = None;
            if let Ok(addrs) = (name.as_str(), 80).to_socket_addrs() {
                for a in addrs {
                    if let std::net::IpAddr::V4(v4) = a.ip() {
                        ip = Some(v4);
                        break;
                    }
                }
            }
            ip.ok_or_else(|| anyhow::anyhow!("domain resolve failed"))?
        }
        4 => anyhow::bail!("IPv6 targets unsupported"),
        _ => anyhow::bail!("bad atyp"),
    };
    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let target_port = u16::from_be_bytes(port_bytes);

    match req[1] {
        1 => handle_connect(stream, shared, target_ip, target_port).await,
        3 => handle_udp_associate(stream, shared, target_ip, target_port).await,
        cmd => {
            let _ = stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await; // command not supported
            anyhow::bail!("unsupported cmd {cmd}")
        }
    }
}

async fn reply(stream: &mut TcpStream, code: u8, ip: Ipv4Addr, port: u16) -> std::io::Result<()> {
    let ip = ip.octets();
    stream
        .write_all(&[
            5,
            code,
            0,
            1,
            ip[0],
            ip[1],
            ip[2],
            ip[3],
            (port >> 8) as u8,
            port as u8,
        ])
        .await
}

async fn handle_connect(
    mut stream: TcpStream,
    shared: Arc<EngineShared>,
    ip: Ipv4Addr,
    port: u16,
) -> anyhow::Result<()> {
    let Some((net_id, peer)) = shared.peer_by_ip(ip) else {
        reply(&mut stream, 4, Ipv4Addr::LOCALHOST, 0).await?; // host unreachable
        anyhow::bail!("target outside virtual network");
    };
    let dest = format!("{ip}:{port}");
    let Some(flow) = shared
        .flows
        .open_tcp(net_id, peer.id, &dest, Duration::from_secs(8))
        .await
    else {
        reply(&mut stream, 5, Ipv4Addr::LOCALHOST, 0).await?; // connection refused
        anyhow::bail!("flow open failed");
    };
    reply(&mut stream, 0, ip, port).await?;

    // Pump both directions until either side closes.
    let flow = Arc::new(flow);
    let (mut tcp_rd, mut tcp_wr) = stream.into_split();
    let writer = {
        let flow = Arc::clone(&flow);
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut buf = vec![0u8; PUMP_BUF];
            loop {
                // 分块按对端当前出口路径动态选择（UDP 路径不分片）。
                let chunk = shared.flow_chunk_for(flow.net_id, flow.peer).min(buf.len());
                match tcp_rd.read(&mut buf[..chunk]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => flow.write(&buf[..n]),
                }
            }
            flow.close();
        })
    };
    while let Some(chunk) = flow.read().await {
        if tcp_wr.write_all(&chunk).await.is_err() {
            break;
        }
        let _ = tcp_wr.flush().await;
    }
    writer.abort();
    Ok(())
}

async fn handle_udp_associate(
    mut stream: TcpStream,
    shared: Arc<EngineShared>,
    ip: Ipv4Addr,
    port: u16,
) -> anyhow::Result<()> {
    let _ = ip; // 目的地以每个数据报的 SOCKS 头为准
    let local = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let local_port = local.local_addr()?.port();
    reply(&mut stream, 0, Ipv4Addr::LOCALHOST, local_port).await?;
    let _ = stream.flush().await;

    // 逐包路由：每个数据报按目的虚拟 IP 解析 (网络, 对端)，按 (net, peer)
    // 懒建并复用 UDP flow。旧实现把会话固定到 associate 时随机挑中的单一
    // flow——多网络节点上 0.0.0.0 关联后，其他网络的目的 IP 会随错网 flow
    // 送出，对端按端口匹配到错误网络的 expose 造成跨网串扰。
    type FlowMap = std::sync::Mutex<HashMap<(NetId, u64), UdpFlowSender>>;
    let flows: Arc<FlowMap> = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let (merge_tx, mut merge_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();

    // Client -> mesh: parse the SOCKS UDP header on each datagram. The
    // client's first sender address is where replies go.
    let client_sock = Arc::new(local);
    let client_ep: Arc<std::sync::Mutex<Option<SocketAddr>>> =
        Arc::new(std::sync::Mutex::new(None));
    let pump = {
        let sock = Arc::clone(&client_sock);
        let client_ep = Arc::clone(&client_ep);
        let flows = Arc::clone(&flows);
        let merge_tx = merge_tx.clone();
        async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if client_ep.lock().unwrap().is_none() {
                    *client_ep.lock().unwrap() = Some(from);
                }
                let Some((dst_ip, dst_port, payload)) = parse_socks_udp_header(&buf[..n]) else {
                    continue;
                };
                // 只发往目的虚拟 IP 所属网络的对应 peer；解析不到（非 mesh
                // 流量或未知 IP）直接丢弃。
                let Some((net_id, peer)) = shared.peer_by_ip(dst_ip) else {
                    continue;
                };
                let sender = {
                    let mut map = flows.lock().unwrap();
                    if let Some(s) = map.get(&(net_id, peer.id)) {
                        s.clone()
                    } else {
                        // 该 (net, peer) 的首个数据报：建立 UDP flow，并把其
                        // 接收端合并进本会话的回包流。
                        let default_dest = format!("{}:{port}", peer.virtual_ip());
                        match shared.flows.open_udp(net_id, peer.id, &default_dest) {
                            Some(h) => {
                                let tx = merge_tx.clone();
                                let mut rx = h.rx;
                                tokio::spawn(async move {
                                    while let Some(item) = rx.recv().await {
                                        let _ = tx.send(item);
                                    }
                                });
                                map.insert((net_id, peer.id), h.sender.clone());
                                h.sender
                            }
                            None => continue,
                        }
                    }
                };
                sender.send(&format!("{dst_ip}:{dst_port}"), payload);
            }
        }
    };
    let pump = tokio::spawn(pump);

    // Mesh -> client: wrap datagrams in a SOCKS UDP header.
    let writer = tokio::spawn(async move {
        let sock = Arc::clone(&client_sock);
        let client_ep = Arc::clone(&client_ep);
        while let Some((addr, data)) = merge_rx.recv().await {
            let Ok(target) = addr.parse::<SocketAddr>() else {
                continue;
            };
            let ip = match target.ip() {
                std::net::IpAddr::V4(v4) => v4.octets(),
                _ => continue,
            };
            let port = target.port();
            let mut out = vec![
                0u8,
                0u8,
                0u8,
                1,
                ip[0],
                ip[1],
                ip[2],
                ip[3],
                (port >> 8) as u8,
                port as u8,
            ];
            out.extend_from_slice(&data);
            let ep = { *client_ep.lock().unwrap() };
            if let Some(ep) = ep {
                let _ = sock.send_to(&out, ep).await;
            }
        }
    });

    // Keep the TCP control connection open: session lives while it does.
    let mut discard = [0u8; 64];
    loop {
        match stream.read(&mut discard).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    pump.abort();
    writer.abort();
    // 会话结束：关闭本会话建立的全部 UDP flow。
    for (_, s) in flows.lock().unwrap().drain() {
        s.close();
    }
    Ok(())
}

/// SOCKS UDP request header: [RSV RSV FRAG ATYP ADDR PORT payload].
/// Returns (target ip, target port, payload).
fn parse_socks_udp_header(packet: &[u8]) -> Option<(Ipv4Addr, u16, &[u8])> {
    if packet.len() < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
        return None;
    }
    match packet[3] {
        1 => {
            let ip: [u8; 4] = packet[4..8].try_into().ok()?;
            let port = u16::from_be_bytes([packet[8], packet[9]]);
            Some((ip.into(), port, &packet[10..]))
        }
        3 => {
            let len = packet[4] as usize;
            if packet.len() < 5 + len + 2 {
                return None;
            }
            let _domain = &packet[5..5 + len];
            let _port = u16::from_be_bytes([packet[5 + len], packet[6 + len]]);
            // Domain targets in datagrams are not resolved here (mesh-only).
            None::<(Ipv4Addr, u16, &[u8])>
        }
        _ => None,
    }
}
