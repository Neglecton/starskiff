//! UdpMesh: a single UDP socket serving both the relay (REGISTER/RELAY and
//! relayed frames) and direct peer traffic. Port binding falls back to a
//! random port when the configured port is taken — never a hard error
//! (multi-node hosts and parallel tests rely on this).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use skiff_core::consts::UDP_BUFFER_SIZE;
use skiff_core::protocol::relay_udp;
use tokio::net::UdpSocket;

use crate::engine::EngineEvent;

pub struct UdpMesh {
    socket: Arc<UdpSocket>,
    pub local_port: u16,
    pub used_fallback_port: AtomicBool,
    relay_addr: Mutex<Option<SocketAddr>>,
    /// REGISTER 凭据。每次发送生成新 nonce——服务端记忆已用 nonce 防重放，
    /// 缓存整个报文会导致重注册被拒。
    register_creds: Mutex<Option<(u64, [u8; 32])>>,
}

impl UdpMesh {
    pub async fn bind(
        listen_port: u16,
        events: tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    ) -> anyhow::Result<Arc<UdpMesh>> {
        let (socket, fallback) = match UdpSocket::bind(("0.0.0.0", listen_port)).await {
            Ok(s) => (s, false),
            Err(_) if listen_port != 0 => {
                // Occupied: fall back to a random port.
                (UdpSocket::bind(("0.0.0.0", 0)).await?, true)
            }
            Err(e) => return Err(e.into()),
        };
        let socket = Arc::new(socket);
        let local_port = socket.local_addr()?.port();
        let mesh = Arc::new(UdpMesh {
            socket: Arc::clone(&socket),
            local_port,
            used_fallback_port: AtomicBool::new(fallback),
            relay_addr: Mutex::new(None),
            register_creds: Mutex::new(None),
        });
        let reader = Arc::clone(&mesh);
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_BUFFER_SIZE];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, from)) => reader.handle(from, &buf[..len], &events),
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
                }
            }
        });
        Ok(mesh)
    }

    fn handle(
        &self,
        from: SocketAddr,
        packet: &[u8],
        events: &tokio::sync::mpsc::UnboundedSender<EngineEvent>,
    ) {
        let is_relay = *self.relay_addr.lock().unwrap() == Some(from);
        if is_relay {
            if packet.first() == Some(&relay_udp::RELAY_MAGIC) {
                match relay_udp::parse(packet) {
                    Some(relay_udp::RelayPacket::Ack { ip, port }) => {
                        let ep = format!("{ip}:{port}");
                        let _ = events.send(EngineEvent::ObservedEndpoint(ep));
                    }
                    Some(relay_udp::RelayPacket::Error { msg }) => {
                        let _ = events.send(EngineEvent::Log(format!("中继注册被拒绝: {msg}")));
                    }
                    _ => {}
                }
            } else {
                // A wire frame forwarded by the relay.
                let _ = events.send(EngineEvent::Frame {
                    arrival: crate::engine::Arrival::relay_udp(),
                    packet: packet.to_vec(),
                });
            }
        } else {
            let _ = events.send(EngineEvent::Frame {
                arrival: crate::engine::Arrival::direct_udp(from),
                packet: packet.to_vec(),
            });
        }
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
        let socket = Arc::clone(&self.socket);
        tokio::spawn(async move {
            let _ = socket.send_to(&pkt, relay).await;
        });
    }

    pub fn send_relay(&self, src_id: u64, dst_id: u64, frame: &[u8]) {
        let Some(relay) = *self.relay_addr.lock().unwrap() else {
            return;
        };
        let pkt = relay_udp::build_relay(src_id, dst_id, frame);
        let socket = Arc::clone(&self.socket);
        tokio::spawn(async move {
            let _ = socket.send_to(&pkt, relay).await;
        });
    }

    pub fn send_direct(&self, endpoint: SocketAddr, frame: &[u8]) {
        let socket = Arc::clone(&self.socket);
        let frame = frame.to_vec();
        tokio::spawn(async move {
            let _ = socket.send_to(&frame, endpoint).await;
        });
    }

    pub fn observed_sender(&self) -> Option<SocketAddr> {
        *self.relay_addr.lock().unwrap()
    }

    pub fn bound_socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    pub fn fallback_used(&self) -> bool {
        self.used_fallback_port.load(Ordering::Relaxed)
    }
}
