//! Server application: HTTP API + WebSocket realtime + relay wiring.
//! Library-exposed so tests can run a real server in-process.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::Message;
use axum::extract::{ConnectInfo, Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde_json::json;
use sha2::Digest as _;
use skiff_core::crypto::tokens::{sha256_hex, split_token, with_fingerprint};
use skiff_core::ipam::Cidr;
use skiff_core::logging::{LogFn, unix_ms};
use skiff_core::models::*;
use skiff_core::platform::rss_kib;

use crate::assets::AdminAssets;
use crate::events_hub::{Hub, HubMessage};
use crate::presence::{Presence, PresenceStore};
use crate::relay::tcp_relay::TcpRelay;
use crate::relay::udp_relay::UdpRelay;
use crate::repo::{DeviceRow, EnrollResult, NetworkRow, Repo, RepoError};

pub struct ServerOptions {
    pub db_path: PathBuf,
    pub api_port: u16,
    pub relay_udp_port: u16,
    pub relay_tcp_port: u16,
    pub no_tls: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub log: LogFn,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            db_path: PathBuf::from("starskiff.sqlite"),
            api_port: skiff_core::consts::DEFAULT_API_PORT,
            relay_udp_port: skiff_core::consts::DEFAULT_RELAY_UDP_PORT,
            relay_tcp_port: skiff_core::consts::DEFAULT_RELAY_TCP_PORT,
            no_tls: false,
            cert_file: None,
            key_file: None,
            log: skiff_core::logging::console_logger(),
        }
    }
}

pub struct AppState {
    pub repo: Repo,
    pub presence: Presence,
    pub hub: Hub,
    pub udp_relay: Arc<UdpRelay>,
    pub tcp_relay: Arc<TcpRelay>,
    pub admin_token: String,
    pub api_port: u16,
    pub relay_udp_port: u16,
    pub relay_tcp_port: u16,
    pub started_ms: i64,
    pub log: LogFn,
    pub cert_fingerprint: Option<String>,
    /// 最近一次管理端轮询 /admin/devices 的时间（unix ms）——"有人在看
    /// 管理页"的判定依据：心跳据此建议节点把间隔切到快档（拓扑/速率
    /// 展示更跟手），超时无人查看回落常态档。内存态，重启即回到常态档。
    pub last_admin_observe_ms: AtomicU64,
}

pub type SharedState = Arc<AppState>;

pub struct RunningServer {
    pub api_port: u16,
    pub relay_udp_port: u16,
    pub relay_tcp_port: u16,
    pub base_url: String,
    pub cert_fingerprint: Option<String>,
    pub admin_token: String,
    /// 共享状态（repo/hub/presence/中继句柄），供集成测试断言内部计数。
    pub state: std::sync::Arc<AppState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl RunningServer {
    /// Abort all background tasks (listeners stop accepting).
    pub fn shutdown(self) {
        for t in self.tasks {
            t.abort();
        }
    }
}

pub async fn start(opts: ServerOptions) -> anyhow::Result<RunningServer> {
    let repo = Repo::open(&opts.db_path)?;
    let admin_token = repo.get_or_create_admin_token()?;

    let cert = if opts.no_tls {
        None
    } else {
        Some(crate::tls::load_or_generate(
            &repo,
            opts.cert_file.as_deref(),
            opts.key_file.as_deref(),
        )?)
    };
    let fingerprint = cert.as_ref().map(|c| c.fingerprint.clone());

    let (presence, online_rx) = PresenceStore::new();
    let hub = crate::events_hub::EventsHub::new();

    let repo_for_keys = repo.clone();
    let lookup_key = Arc::new(move |id: u64| -> Option<[u8; 32]> {
        repo_for_keys.get_device(id).ok().flatten().and_then(|d| {
            hex::decode(&d.relay_key)
                .ok()
                .and_then(|k| k.try_into().ok())
        })
    });
    // REGISTER 防重放的 nonce 记忆由两个中继共享。
    let register_guard = crate::relay::register_guard::RegisterGuard::new();
    let udp_relay = UdpRelay::new(presence.clone(), lookup_key.clone(), register_guard.clone());
    let tcp_relay = TcpRelay::new(presence.clone(), lookup_key, register_guard);

    // Bind sockets first so port-0 resolution is real. UDP 经 socket2 扩
    // 内核缓冲（32KiB 级中继帧突发防内核静默丢弃——曾表现为 bulk 传输
    // 无痕停摆且零计数）。
    let udp_socket = tokio::net::UdpSocket::from_std(
        skiff_core::platform::udp_socket_buffered(std::net::SocketAddr::from((
            [0, 0, 0, 0],
            opts.relay_udp_port,
        )))?,
    )?;
    let relay_udp_port = udp_socket.local_addr()?.port();
    let tcp_listener = tokio::net::TcpListener::bind(("0.0.0.0", opts.relay_tcp_port)).await?;
    let relay_tcp_port = tcp_listener.local_addr()?.port();

    let state = Arc::new(AppState {
        repo,
        presence,
        hub: hub.clone(),
        udp_relay: udp_relay.clone(),
        tcp_relay: tcp_relay.clone(),
        admin_token,
        api_port: opts.api_port,
        relay_udp_port,
        relay_tcp_port,
        started_ms: unix_ms(),
        log: opts.log.clone(),
        cert_fingerprint: fingerprint.clone(),
        last_admin_observe_ms: AtomicU64::new(0),
    });

    // Presence -> WS broadcast sidecar.
    {
        let presence = state.presence.clone();
        let hub = state.hub.clone();
        let repo = state.repo.clone();
        crate::presence::spawn_online_broadcaster(online_rx, presence, hub, move |device_id| {
            repo.memberships_of_device(device_id)
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.network_id)
                .collect()
        });
    }

    // Relays.
    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(UdpRelay::serve(udp_relay, udp_socket)));
    tasks.push(tokio::spawn(TcpRelay::serve(tcp_relay, tcp_listener)));

    // HTTP(S).
    let app = router(state.clone());
    let http_listener = tokio::net::TcpListener::bind(("0.0.0.0", opts.api_port)).await?;
    let api_port = http_listener.local_addr()?.port();

    if let Some(cert) = cert {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cert.tls_config));
        let listener = TlsListener::new(http_listener, acceptor).await?;
        tasks.push(tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<ConnAddr>(),
            )
            .await;
        }));
    } else {
        let listener = PlainListener {
            inner: http_listener,
        };
        tasks.push(tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<ConnAddr>(),
            )
            .await;
        }));
    }

    // STATS loop: every 5 minutes.
    {
        let state = state.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(300)).await;
                let stats = state.udp_relay.stats();
                let devices = state.repo.list_devices().map(|v| v.len()).unwrap_or(0);
                let online = state.repo.list_devices().map(|v| {
                    v.iter().filter(|d| state.presence.is_online(d.id)).count()
                }).unwrap_or(0);
                let line = format!(
                    "STATS uptime_s={} relay_fwd_bytes={} relay_fwd_pkts={} relay_drops={} relay_registers={} relay_active={} devices_total={} devices_online={} mem={}KB",
                    (unix_ms() - state.started_ms) / 1000,
                    stats.forwarded_bytes,
                    stats.forwarded_packets,
                    stats.dropped_packets,
                    stats.registers,
                    stats.active,
                    devices,
                    online,
                    rss_kib(),
                );
                (state.log)(&line);
            }
        }));
    }

    let scheme = if opts.no_tls { "http" } else { "https" };
    Ok(RunningServer {
        api_port,
        relay_udp_port,
        relay_tcp_port,
        base_url: format!("{scheme}://127.0.0.1:{api_port}"),
        cert_fingerprint: fingerprint,
        admin_token: state.admin_token.clone(),
        state,
        tasks,
    })
}

// ---------------------------------------------------------------------------
// TLS listener bridging async handshakes into axum's sync Listener trait
// ---------------------------------------------------------------------------

struct TlsListener {
    rx: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    local: SocketAddr,
}

impl TlsListener {
    async fn new(
        listener: tokio::net::TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> anyhow::Result<TlsListener> {
        let local = listener.local_addr()?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let _ = tx.send((tls, addr)).await;
                    }
                });
            }
        });
        Ok(TlsListener { rx, local })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = ConnAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some((io, addr)) => (io, ConnAddr(addr)),
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(ConnAddr(self.local))
    }
}

/// Plain TCP listener exposing the same Addr type so handlers can use one
/// ConnectInfo extractor for both TLS and non-TLS serving.
struct PlainListener {
    inner: tokio::net::TcpListener,
}

impl axum::serve::Listener for PlainListener {
    type Io = tokio::net::TcpStream;
    type Addr = ConnAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.inner.accept().await {
            Ok((io, addr)) => (io, ConnAddr(addr)),
            Err(_) => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr().map(ConnAddr)
    }
}

/// Peer address for ConnectInfo extraction (works for both listeners).
#[derive(Debug, Clone, Copy)]
pub struct ConnAddr(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for ConnAddr
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        *target.remote_addr()
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, PlainListener>>
    for ConnAddr
{
    fn connect_info(target: axum::serve::IncomingStream<'_, PlainListener>) -> Self {
        *target.remote_addr()
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn router(state: SharedState) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::temporary("/admin/") }))
        .route("/api/enroll", post(enroll))
        .route("/api/config", get(get_config))
        .route("/api/peers", get(get_peers))
        .route("/api/settings", get(get_device_settings))
        .route("/api/settings/fail", post(report_settings_fail))
        .route("/api/memberships", get(list_memberships))
        .route("/api/heartbeat", post(heartbeat))
        .route("/api/join", post(join_network))
        .route("/api/leave", post(leave_network))
        .route("/api/events", get(ws_events))
        .route("/admin/summary", get(admin_summary))
        .route(
            "/admin/networks",
            get(admin_list_networks).post(admin_create_network),
        )
        .route("/admin/networks/{id}", delete(admin_delete_network))
        .route(
            "/admin/tokens",
            get(admin_list_tokens).post(admin_create_token),
        )
        .route("/admin/tokens/{token}", delete(admin_revoke_token))
        .route("/admin/devices", get(admin_list_devices))
        .route("/admin/devices/{id}", delete(admin_delete_device))
        .route(
            "/admin/devices/{id}/settings",
            put(admin_put_device_settings).get(admin_get_device_settings),
        )
        .route("/admin/devices/{id}/restart", post(admin_device_restart))
        .route("/admin/devices/{id}/reconnect", post(admin_device_reconnect))
        .route("/admin/devices/{id}/networks", post(admin_device_join_network))
        .route(
            "/admin/devices/{id}/networks/{nid}",
            delete(admin_device_leave_network),
        )
        .route("/admin/networks/{nid}/devices/{did}/ip", post(admin_set_ip))
        .route("/admin", get(|| async { Redirect::temporary("/admin/") }))
        .route("/admin/", get(admin_index))
        .route("/admin/{*path}", get(admin_static))
        .with_state(state)
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

fn extract_token(req: &Request<Body>) -> Option<String> {
    if let Some(auth) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(bearer) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
    {
        return Some(bearer.trim().to_string());
    }
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                return Some(urldecode(token));
            }
        }
    }
    None
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex_pair = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok());
                if let Some(v) = hex_pair.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl AppState {
    fn auth_device(&self, req: &Request<Body>) -> Option<DeviceRow> {
        let token = extract_token(req)?;
        let hash = sha256_hex(&token);
        self.repo.find_device_by_token_hash(&hash).ok().flatten()
    }

    fn auth_admin(&self, req: &Request<Body>) -> bool {
        let Some(provided) = req
            .headers()
            .get("X-Admin-Token")
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        let (bare, _) = split_token(provided);
        bare == self.admin_token
    }

    /// Resolve the network for a device: ?network=<hex id or name>, else the
    /// first membership.
    fn resolve_network(
        &self,
        device: &DeviceRow,
        network_param: Option<&str>,
    ) -> Option<NetworkRow> {
        let memberships = self.repo.memberships_of_device(device.id).ok()?;
        let pick = match network_param {
            Some(n) => memberships.into_iter().find(|m| {
                m.network_id.to_hex() == n
                    || self
                        .repo
                        .get_network(m.network_id)
                        .ok()
                        .flatten()
                        .is_some_and(|nw| nw.name.eq_ignore_ascii_case(n))
            })?,
            None => memberships.into_iter().next()?,
        };
        self.repo.get_network(pick.network_id).ok().flatten()
    }
}

// ---------------------------------------------------------------------------
// Node-facing handlers
// ---------------------------------------------------------------------------

async fn enroll(State(state): State<SharedState>, Json(req): Json<EnrollRequest>) -> Response {
    let name = req.name.trim();
    if name.is_empty() || req.name.chars().count() > 64 {
        return err(StatusCode::BAD_REQUEST, "设备名长度必须在 1..64 之间");
    }
    for (label, key) in [
        ("signPubkey", &req.sign_pubkey),
        ("dhPubkey", &req.dh_pubkey),
    ] {
        if hex::decode(key).map(|b| b.len() != 32).unwrap_or(true) {
            return err(
                StatusCode::BAD_REQUEST,
                format!("{label} 必须是 32 字节的 hex 字符串"),
            );
        }
    }
    match state.repo.enroll(
        &req.token,
        name,
        &req.sign_pubkey,
        &req.dh_pubkey,
        req.requested_ip.as_deref(),
    ) {
        Ok(EnrollResult {
            device_id,
            device_token,
            network,
            ip,
        }) => {
            state.hub.broadcast_network(
                &network.id,
                WsEvent {
                    event_type: ws_events::PEERS_CHANGED.to_string(),
                    network_id: Some(network.id),
                    device_id: Some(device_id),
                    message: None,
                },
            );
            Json(EnrollResponse {
                device_id,
                device_token,
                network_id: network.id,
                network_name: network.name,
                cidr: network.cidr,
                ip,
                mtu: skiff_core::consts::DEFAULT_MTU,
            })
            .into_response()
        }
        Err(RepoError::Conflict(msg)) => err(StatusCode::BAD_REQUEST, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_config(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    req: Request<Body>,
) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(net) = state.resolve_network(&device, params.get("network").map(|s| s.as_str()))
    else {
        return err(
            StatusCode::NOT_FOUND,
            "Device is not enrolled in any network.",
        );
    };
    let membership = state.repo.membership_of(net.id, device.id).ok().flatten();
    let Some(m) = membership else {
        return err(
            StatusCode::NOT_FOUND,
            "Device is not enrolled in any network.",
        );
    };
    Json(ConfigResponse {
        device_id: device.id,
        name: device.name,
        network_id: net.id,
        network_name: net.name,
        cidr: net.cidr,
        ip: m.ip,
        mtu: skiff_core::consts::DEFAULT_MTU,
        relay_udp_port: state.relay_udp_port,
        relay_tcp_port: state.relay_tcp_port,
    })
    .into_response()
}

async fn get_peers(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    req: Request<Body>,
) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(net) = state.resolve_network(&device, params.get("network").map(|s| s.as_str()))
    else {
        return err(
            StatusCode::NOT_FOUND,
            "Device is not enrolled in any network.",
        );
    };
    let members = state
        .repo
        .memberships_of_network(net.id)
        .unwrap_or_default();
    let mut peers = Vec::with_capacity(members.len().saturating_sub(1));
    for m in members {
        if m.device_id == device.id {
            continue;
        }
        let Some(d) = state.repo.get_device(m.device_id).ok().flatten() else {
            continue;
        };
        let rec = state.presence.record(m.device_id);
        // udpEndpoints[0] is the relay-observed endpoint by contract.
        let mut udp_endpoints = Vec::new();
        if let Some(observed) = rec.as_ref().and_then(|r| r.observed_udp_endpoint.clone()) {
            udp_endpoints.push(observed);
        }
        if let Some(r) = &rec
            && let Some(port) = r.udp_port
        {
            for addr in &r.local_addrs {
                udp_endpoints.push(format!("{addr}:{port}"));
            }
        }
        peers.push(PeerInfo {
            device_id: d.id,
            name: d.name,
            network_id: net.id,
            ip: m.ip,
            sign_pubkey: d.pubkey_sign,
            dh_pubkey: d.pubkey_dh,
            udp_endpoints,
            tcp_listen_port: rec.as_ref().and_then(|r| r.tcp_port),
            online: state.presence.is_online(d.id),
        });
    }
    Json(peers).into_response()
}

async fn heartbeat(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let hb: HeartbeatRequest = match serde_json::from_slice(&body) {
        Ok(hb) => hb,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid heartbeat body"),
    };
    state.presence.touch_heartbeat(device.id, &hb);
    let _ = state.repo.touch_device(device.id);
    // 下发成功应答：节点上报的 appliedRevision 追平当前 revision 时，
    // 把该版内容固化为回滚锚点（last_good）并清除错误记录。条件写带
    // revision 守卫（repo 层单条原子 UPDATE）：与并发管理员 PUT 交错时
    // 未验证的新版本不会被固化（AGENTS.md #22）。
    if let Some(applied) = hb.settings_revision {
        let _ = state.repo.mark_settings_applied(device.id, applied);
    }
    // 自适应心跳间隔：近期有管理端轮询 /admin/devices（有人在看管理页）
    // → 建议快档，否则常态档。PRESENCE_TIMEOUT 是固定常量、与心跳频率
    // 无关，快档不会收紧在线判定。建议随每次心跳响应重发（声明式），
    // 观察结束/服务端重启后节点在一个周期内自然回落。
    let last_observe = state.last_admin_observe_ms.load(Ordering::Relaxed) as i64;
    let since_observe = unix_ms() - last_observe;
    let observed = (0..=skiff_core::consts::ADMIN_OBSERVER_TTL_MS).contains(&since_observe);
    let heartbeat_secs = if observed {
        skiff_core::consts::HEARTBEAT_FAST_SECS
    } else {
        skiff_core::consts::HEARTBEAT_SLOW_SECS
    };
    Json(HeartbeatResponse {
        observed_udp_endpoint: state.presence.observed_endpoint(device.id),
        heartbeat_secs,
    })
    .into_response()
}

/// GET /api/settings — 节点自拉自己的托管配置（WS 推送只是加速，最终
/// 一致靠这里 + 节点侧 revision 幂等）。
async fn get_device_settings(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match state.repo.get_device_settings(device.id) {
        Ok(settings) => Json(settings).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// POST /api/settings/fail —— worker 启动失败上报：revision 匹配当前版
/// 则自动回滚到 last_good（无则清空托管）并递增 revision，向节点重推
/// settings_changed；过期/重复上报被忽略（幂等）。
async fn report_settings_fail(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let body = axum::body::to_bytes(req.into_body(), 8 * 1024)
        .await
        .unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    let (Some(revision), Some(error)) = (payload["revision"].as_i64(), payload["error"].as_str())
    else {
        return err(StatusCode::BAD_REQUEST, "revision/error 缺失");
    };
    match state.repo.report_settings_fail(device.id, revision, error) {
        Ok(Some(rolled)) => {
            (state.log)(&format!(
                "SETTINGS_FAIL device={}({}) failed_rev={revision} rolled_back_to_rev={} error={error}",
                device.name, device.id, rolled.revision
            ));
            state.hub.send_to_device(
                device.id,
                WsEvent {
                    event_type: ws_events::SETTINGS_CHANGED.to_string(),
                    network_id: None,
                    device_id: Some(device.id),
                    message: Some(rolled.revision.to_string()),
                },
            );
            (StatusCode::OK, Json(json!({ "rolledBackTo": rolled.revision }))).into_response()
        }
        Ok(None) => (StatusCode::OK, Json(json!({ "rolledBackTo": null }))).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// GET /api/memberships — 节点启动名单（服务端权威的网络成员关系；
/// 节点文件的 networks[] 仅作缓存）。
async fn list_memberships(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let out: Vec<MembershipInfo> = state
        .repo
        .memberships_of_device(device.id)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|m| {
            let net = state.repo.get_network(m.network_id).ok().flatten()?;
            Some(MembershipInfo {
                network_id: m.network_id,
                network_name: net.name,
                cidr: net.cidr,
                ip: m.ip,
            })
        })
        .collect();
    Json(out).into_response()
}

/// POST /admin/devices/{id}/networks — 管理员强制设备加入网络。
async fn admin_device_join_network(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    if state.repo.get_device(device_id).ok().flatten().is_none() {
        return err(StatusCode::NOT_FOUND, "设备不存在");
    }
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<AdminJoinNetworkRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    let Some(net_id) = resolve_network_id(&state, &payload.network) else {
        return err(StatusCode::NOT_FOUND, "网络不存在");
    };
    // TUN 单网络守卫：权威判定在 admin_join_network 的事务内（预检读在
    // 事务外，两个并发 join 都读到 1 个成员时会让 TUN 设备进 2 个网络）。
    // 这里仅取 mode 标志传入；presence 缺失时回退读托管 settings 的 mode。
    let mode = state
        .presence
        .record(device_id)
        .and_then(|r| r.mode)
        .or_else(|| {
            state
                .repo
                .get_device_settings(device_id)
                .ok()
                .and_then(|s| s.mode)
        });
    let tun_required = mode == Some(skiff_core::models::ClientMode::Tun);
    match state.repo.admin_join_network(device_id, net_id, payload.requested_ip.as_deref(), tun_required) {
        Ok(join) => {
            (state.log)(&format!(
                "ADMIN_JOIN device={device_id} network={}({}) ip={} already={}",
                join.network.name, join.network.id, join.ip, join.already_member
            ));
            state.hub.send_to_device(
                device_id,
                WsEvent {
                    event_type: ws_events::NETWORKS_CHANGED.to_string(),
                    network_id: Some(net_id),
                    device_id: Some(device_id),
                    message: None,
                },
            );
            state.hub.broadcast_network(
                &net_id,
                WsEvent {
                    event_type: ws_events::PEERS_CHANGED.to_string(),
                    network_id: Some(net_id),
                    device_id: Some(device_id),
                    message: None,
                },
            );
            Json(JoinResponse {
                network_id: join.network.id,
                network_name: join.network.name,
                cidr: join.network.cidr,
                ip: join.ip,
            })
            .into_response()
        }
        Err(RepoError::Conflict(msg)) => err(StatusCode::CONFLICT, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// DELETE /admin/devices/{id}/networks/{nid} — 管理员强制设备退出网络。
async fn admin_device_leave_network(
    State(state): State<SharedState>,
    Path((id, nid)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    let Some(net_id) = NetId::from_hex(&nid) else {
        return err(StatusCode::BAD_REQUEST, "无效的网络 ID");
    };
    match state.repo.admin_remove_membership(device_id, net_id) {
        Ok(net) => {
            (state.log)(&format!("ADMIN_LEAVE device={device_id} network={}({})", net.name, net.id));
            state.hub.unregister(device_id, net.id);
            for event_type in [ws_events::PEERS_CHANGED, ws_events::DEVICE_OFFLINE] {
                state.hub.broadcast_network(
                    &net.id,
                    WsEvent {
                        event_type: event_type.to_string(),
                        network_id: Some(net.id),
                        device_id: Some(device_id),
                        message: None,
                    },
                );
            }
            state.hub.send_to_device(
                device_id,
                WsEvent {
                    event_type: ws_events::NETWORKS_CHANGED.to_string(),
                    network_id: Some(net.id),
                    device_id: Some(device_id),
                    message: None,
                },
            );
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(RepoError::Conflict(msg)) => err(StatusCode::CONFLICT, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// 网络名或 32-hex id → NetId。
fn resolve_network_id(state: &SharedState, name_or_id: &str) -> Option<NetId> {
    if let Some(id) = NetId::from_hex(name_or_id) {
        return Some(id);
    }
    state
        .repo
        .list_networks()
        .ok()?
        .into_iter()
        .find(|n| n.name.eq_ignore_ascii_case(name_or_id))
        .map(|n| n.id)
}

async fn admin_get_device_settings(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    match state.repo.get_device_settings(device_id) {
        Ok(settings) => Json(settings).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// PUT /admin/devices/{id}/settings — 保存托管配置并定向通知节点。
/// 请求体即 DeviceSettings（revision 字段忽略；字段缺省 = 改为未托管）。
async fn admin_put_device_settings(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    if state.repo.get_device(device_id).ok().flatten().is_none() {
        return err(StatusCode::NOT_FOUND, "设备不存在");
    }
    let body = axum::body::to_bytes(req.into_body(), 256 * 1024)
        .await
        .unwrap_or_default();
    let Ok(mut payload) = serde_json::from_slice::<DeviceSettings>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    payload.revision = 0; // 服务端权威，忽略请求中的值
    if let Err(msg) = payload.validate() {
        return err(StatusCode::BAD_REQUEST, msg);
    }
    // TUN 预检：TUN 限单网络，设备当前多网络成员时直接拒绝（节点侧
    // 启动兜底会失败回滚，这里提前给出明确错误）。
    if payload.mode == Some(skiff_core::models::ClientMode::Tun) {
        let nets = state.repo.memberships_of_device(device_id).unwrap_or_default().len();
        if nets > 1 {
            return err(
                StatusCode::CONFLICT,
                format!("TUN 模式仅支持单网络，该设备当前有 {nets} 个网络成员"),
            );
        }
    }
    // 对端覆盖的 deviceId 必须是已注册设备（防手滑写错 id；字符串形式，
    // 解析失败同样拒绝）。
    if let Some(list) = &payload.peer_policies {
        for pp in list {
            let Ok(id) = pp.device_id.parse::<u64>() else {
                return err(StatusCode::BAD_REQUEST, format!("对端设备 id 无效：{}", pp.device_id));
            };
            if state.repo.get_device(id).ok().flatten().is_none() {
                return err(StatusCode::BAD_REQUEST, format!("对端设备 {} 不存在", pp.device_id));
            }
        }
    }
    let stored = match state.repo.set_device_settings(device_id, &payload) {
        Ok(s) => s,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (state.log)(&format!(
        "SETTINGS_PUT device={device_id} revision={} managed={:?}",
        stored.revision,
        if stored.is_empty() { "none" } else { "partial" }
    ));
    // 定向通知（at-most-once；节点 WS 重连/CONNECTED 时会自拉兜底）。
    state.hub.send_to_device(
        device_id,
        WsEvent {
            event_type: ws_events::SETTINGS_CHANGED.to_string(),
            network_id: None,
            device_id: Some(device_id),
            message: Some(stored.revision.to_string()),
        },
    );
    Json(stored).into_response()
}

/// POST /admin/devices/{id}/restart — 请求节点重启引擎（worker 优雅退出，
/// 由 master/worker 宿主拉起；旧版节点忽略该事件）。
async fn admin_device_restart(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    if state.repo.get_device(device_id).ok().flatten().is_none() {
        return err(StatusCode::NOT_FOUND, "设备不存在");
    }
    (state.log)(&format!("RESTART_REQUEST device={device_id}"));
    state.hub.send_to_device(
        device_id,
        WsEvent {
            event_type: ws_events::RESTART_REQUESTED.to_string(),
            network_id: None,
            device_id: Some(device_id),
            message: None,
        },
    );
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

/// POST /admin/devices/{id}/reconnect — 请求节点轻量重连（重发中继注册 +
/// 刷新 peers，不重启引擎）。
async fn admin_device_reconnect(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    if state.repo.get_device(device_id).ok().flatten().is_none() {
        return err(StatusCode::NOT_FOUND, "设备不存在");
    }
    (state.log)(&format!("RECONNECT_REQUEST device={device_id}"));
    state.hub.send_to_device(
        device_id,
        WsEvent {
            event_type: ws_events::RECONNECT_REQUESTED.to_string(),
            network_id: None,
            device_id: Some(device_id),
            message: None,
        },
    );
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

async fn join_network(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024).await.unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<JoinRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    match state.repo.join_network(device.id, &payload.token, payload.requested_ip.as_deref()) {
        Ok(join) => {
            state.hub.broadcast_network(
                &join.network.id,
                WsEvent {
                    event_type: ws_events::PEERS_CHANGED.to_string(),
                    network_id: Some(join.network.id),
                    device_id: Some(device.id),
                    message: None,
                },
            );
            if join.already_member {
                (state.log)(&format!(
                    "JOIN idempotent device={}({}) network={}({}) ip={}",
                    device.name, device.id, join.network.name, join.network.id, join.ip
                ));
            }
            Json(JoinResponse {
                network_id: join.network.id,
                network_name: join.network.name,
                cidr: join.network.cidr,
                ip: join.ip,
            })
            .into_response()
        }
        Err(RepoError::Conflict(msg)) => err(StatusCode::BAD_REQUEST, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn leave_network(State(state): State<SharedState>, req: Request<Body>) -> Response {
    let Some(device) = state.auth_device(&req) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024).await.unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<LeaveRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    match state.repo.leave_network(device.id, &payload.network) {
        Ok(net) => {
            state.hub.unregister(device.id, net.id);
            for event_type in [ws_events::PEERS_CHANGED, ws_events::DEVICE_OFFLINE] {
                state.hub.broadcast_network(
                    &net.id,
                    WsEvent {
                        event_type: event_type.to_string(),
                        network_id: Some(net.id),
                        device_id: Some(device.id),
                        message: None,
                    },
                );
            }
            (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
        }
        Err(RepoError::Conflict(msg)) => err(StatusCode::BAD_REQUEST, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn ws_events(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    ConnectInfo(peer): ConnectInfo<ConnAddr>,
    ws: WebSocketUpgrade,
    req: Request<Body>,
) -> Response {
    let token = params.get("token").cloned().or_else(|| extract_token(&req));
    let Some(token) = token else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let hash = sha256_hex(&token);
    let Some(device) = state.repo.find_device_by_token_hash(&hash).ok().flatten() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(net) = state.resolve_network(&device, params.get("network").map(|s| s.as_str()))
    else {
        return err(
            StatusCode::NOT_FOUND,
            "Device is not enrolled in any network.",
        );
    };
    ws.on_upgrade(move |socket| async move {
        (state.log)(&format!(
            "WS_CONNECT device={}({}) ep={}",
            device.name,
            device.id,
            peer.0.ip()
        ));
        state.presence.ws_connected(device.id);
        let mut incoming = socket;
        let (mut events, events_tx) = state.hub.register(device.id, net.id);
        loop {
            tokio::select! {
                msg = incoming.recv() => {
                    match msg {
                        None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                        Some(Ok(_)) => {} // discard client messages
                    }
                }
                evt = events.recv() => {
                    match evt {
                        Some(HubMessage::Ws(evt)) => {
                            let payload = serde_json::to_string(&evt).unwrap_or_default();
                            if incoming.send(Message::Text(payload.into())).await.is_err() {
                                break;
                            }
                        }
                        Some(HubMessage::Close) | None => {
                            let _ = incoming.send(Message::Close(None)).await;
                            break;
                        }
                    }
                }
            }
        }
        // 仅当仍是当前注册时注销：快重连的新连接已顶掉同 key 旧条目，
        // 旧任务收尾按 key 无条件注销会误杀新连接（闪断链）。
        state.hub.unregister_if_current(device.id, net.id, &events_tx);
        state.presence.ws_disconnected(device.id);
        (state.log)(&format!(
            "WS_DISCONNECT device={}({})",
            device.name, device.id
        ));
    })
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

async fn admin_summary(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let networks = state.repo.list_networks().map(|v| v.len()).unwrap_or(0);
    let devices = state.repo.list_devices().unwrap_or_default();
    let online = devices
        .iter()
        .filter(|d| state.presence.is_online(d.id))
        .count();
    Json(SummaryResponse {
        networks,
        devices: devices.len(),
        online,
        relay_udp_port: state.relay_udp_port,
        relay_tcp_port: state.relay_tcp_port,
    })
    .into_response()
}

fn network_to_admin(net: &NetworkRow, device_count: usize) -> AdminNetwork {
    AdminNetwork {
        id: net.id,
        name: net.name.clone(),
        cidr: net.cidr.clone(),
        created_at: net.created_at,
        device_count,
    }
}

async fn admin_list_networks(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let nets = state.repo.list_networks().unwrap_or_default();
    let all_members = state.repo.all_memberships().unwrap_or_default();
    let out: Vec<AdminNetwork> = nets
        .iter()
        .map(|n| {
            network_to_admin(
                n,
                all_members.iter().filter(|m| m.network_id == n.id).count(),
            )
        })
        .collect();
    Json(out).into_response()
}

async fn admin_create_network(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<CreateNetworkRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    if payload.name.is_empty()
        || payload.name.len() > 32
        || !payload
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return err(
            StatusCode::BAD_REQUEST,
            "网络名必须是 1-32 位字母/数字/下划线/连字符",
        );
    }
    let cidr = match Cidr::parse(&payload.cidr) {
        Ok(c) if c.prefix <= 30 => c,
        Ok(_) => return err(StatusCode::BAD_REQUEST, "前缀长度过大（最大 /30）"),
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if state
        .repo
        .get_network_by_name(&payload.name)
        .ok()
        .flatten()
        .is_some()
    {
        return err(StatusCode::CONFLICT, "同名网络已存在");
    }
    match state.repo.create_network(&payload.name, &cidr.to_string()) {
        Ok(net) => Json(network_to_admin(&net, 0)).into_response(),
        // 与上方前置查重一致：竞态撞 UNIQUE 也返回 409。
        Err(RepoError::Conflict(msg)) => err(StatusCode::CONFLICT, msg),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn admin_delete_network(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Some(net_id) = NetId::from_hex(&id) else {
        return err(StatusCode::BAD_REQUEST, "无效的网络 ID");
    };
    // 删除前收集成员（删除后 memberships 级联消失）：删网必须给存量
    // 成员节点收敛信号——节点对账（reconcile_roster）只由 NETWORKS_CHANGED
    // 推送或 WS 重连触发，5s 轮询遇 404 直接早退不清理，零信号意味着
    // 死网络的 peers/探测/中继转发无限期续命（安全边界落空）。
    let members: Vec<u64> = state
        .repo
        .memberships_of_network(net_id)
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.device_id)
        .collect();
    match state.repo.delete_network(net_id) {
        Ok(true) => {
            (state.log)(&format!("ADMIN_NET_DELETE network={net_id} members={}", members.len()));
            for event_type in [ws_events::PEERS_CHANGED, ws_events::DEVICE_OFFLINE] {
                state.hub.broadcast_network(
                    &net_id,
                    WsEvent {
                        event_type: event_type.to_string(),
                        network_id: Some(net_id),
                        device_id: None,
                        message: None,
                    },
                );
            }
            // 逐成员推 NETWORKS_CHANGED（多网络节点任一 WS 收到即对账）
            // 并注销其在死网络上的 hub 条目（关闭该 WS）。
            for device_id in members {
                state.hub.send_to_device(
                    device_id,
                    WsEvent {
                        event_type: ws_events::NETWORKS_CHANGED.to_string(),
                        network_id: Some(net_id),
                        device_id: Some(device_id),
                        message: None,
                    },
                );
                state.hub.unregister(device_id, net_id);
            }
            (StatusCode::OK, "OK").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "网络不存在"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn admin_list_tokens(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let tokens = state.repo.list_tokens().unwrap_or_default();
    let fp = state.cert_fingerprint.clone();
    let out: Vec<AdminToken> = tokens
        .into_iter()
        .map(|t| {
            let network_name = state
                .repo
                .get_network(t.network_id)
                .ok()
                .flatten()
                .map(|n| n.name)
                .unwrap_or_default();
            let token = match &fp {
                Some(fp) => with_fingerprint(&t.token, fp),
                None => t.token.clone(),
            };
            AdminToken {
                token,
                network_id: t.network_id,
                network_name,
                uses_left: t.uses_left,
                expires_at: t.expires_at,
                requested_ip: t.requested_ip,
            }
        })
        .collect();
    Json(out).into_response()
}

async fn admin_create_token(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<CreateTokenRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    let net = match NetId::from_hex(&payload.network)
        .and_then(|id| state.repo.get_network(id).ok().flatten())
        .or_else(|| {
            state
                .repo
                .get_network_by_name(&payload.network)
                .ok()
                .flatten()
        }) {
        Some(n) => n,
        None => return err(StatusCode::BAD_REQUEST, "网络不存在"),
    };
    if !(1..=1000).contains(&payload.uses) {
        return err(StatusCode::BAD_REQUEST, "uses 必须在 1..=1000");
    }
    if !(1..=8760).contains(&payload.expires_in_hours) {
        return err(StatusCode::BAD_REQUEST, "expiresInHours 必须在 1..=8760");
    }
    if let Some(ip) = &payload.requested_ip
        && ip.parse::<std::net::Ipv4Addr>().is_err()
    {
        return err(StatusCode::BAD_REQUEST, "requestedIp 不是合法的 IPv4 地址");
    }
    match state.repo.create_token(
        net.id,
        payload.uses,
        payload.expires_in_hours * 3_600_000,
        payload.requested_ip.as_deref(),
    ) {
        Ok(t) => {
            let token = match &state.cert_fingerprint {
                Some(fp) => with_fingerprint(&t.token, fp),
                None => t.token.clone(),
            };
            Json(AdminToken {
                token,
                network_id: t.network_id,
                network_name: net.name,
                uses_left: t.uses_left,
                expires_at: t.expires_at,
                requested_ip: t.requested_ip,
            })
            .into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn admin_revoke_token(
    State(state): State<SharedState>,
    Path(token): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    match state.repo.delete_token(&token) {
        Ok(true) => (StatusCode::OK, "OK").into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "令牌不存在"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn admin_list_devices(State(state): State<SharedState>, req: Request<Body>) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    // "有人在看管理页"信号：拓扑页自动刷新每 5s 轮询本端点，命中即让
    // 心跳建议切快档（见 heartbeat handler）。需管理员令牌，只有授权
    // 查看者能触发。
    state
        .last_admin_observe_ms
        .store(unix_ms() as u64, Ordering::Relaxed);
    let devices = state.repo.list_devices().unwrap_or_default();
    let all_members = state.repo.all_memberships().unwrap_or_default();
    let out: Vec<AdminDevice> = devices
        .into_iter()
        .map(|d| {
            let networks: Vec<AdminDeviceMembership> = all_members
                .iter()
                .filter(|m| m.device_id == d.id)
                .map(|m| AdminDeviceMembership {
                    network_id: m.network_id,
                    network_name: state
                        .repo
                        .get_network(m.network_id)
                        .ok()
                        .flatten()
                        .map(|n| n.name)
                        .unwrap_or_default(),
                    ip: m.ip.clone(),
                })
                .collect();
            let record = state.presence.record(d.id);
            let paths = record.as_ref().map(|r| r.paths.clone()).filter(|p| !p.is_empty());
            let applied_revision = record.as_ref().and_then(|r| r.applied_settings_revision);
            let restart_pending = record.as_ref().map(|r| r.restart_pending);
            // 期望 revision 与下发失败状态：从未保存过托管配置的设备不显示。
            let (settings, settings_error, settings_error_revision) =
                state.repo.get_device_settings_full(d.id).unwrap_or_default();
            let settings_revision = (settings.revision > 0).then_some(settings.revision);
            AdminDevice {
                id: d.id.to_string(),
                name: d.name,
                created_at: d.created_at,
                last_seen: d.last_seen,
                online: state.presence.is_online(d.id),
                networks,
                paths,
                settings_revision,
                applied_revision,
                restart_pending,
                settings_error,
                settings_error_revision,
            }
        })
        .collect();
    Json(out).into_response()
}

async fn admin_delete_device(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let Ok(device_id) = id.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    let networks: Vec<NetId> = state
        .repo
        .memberships_of_device(device_id)
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.network_id)
        .collect();
    match state.repo.delete_device(device_id) {
        Ok(true) => {
            state.udp_relay.unregister(device_id);
            state.tcp_relay.unregister(device_id);
            state.presence.remove(device_id);
            state.hub.unregister_device(device_id);
            for net in networks {
                for event_type in [ws_events::PEERS_CHANGED, ws_events::DEVICE_OFFLINE] {
                    state.hub.broadcast_network(
                        &net,
                        WsEvent {
                            event_type: event_type.to_string(),
                            network_id: Some(net),
                            device_id: Some(device_id),
                            message: None,
                        },
                    );
                }
            }
            (StatusCode::OK, "OK").into_response()
        }
        Ok(false) => err(StatusCode::NOT_FOUND, "设备不存在"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn admin_set_ip(
    State(state): State<SharedState>,
    Path((nid, did)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    if !state.auth_admin(&req) {
        return err(StatusCode::UNAUTHORIZED, "鉴权失败：请检查管理员令牌");
    }
    let body = axum::body::to_bytes(req.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    let Ok(payload) = serde_json::from_slice::<SetIpRequest>(&body) else {
        return err(StatusCode::BAD_REQUEST, "invalid body");
    };
    let Some(net_id) = NetId::from_hex(&nid) else {
        return err(StatusCode::BAD_REQUEST, "无效的网络 ID");
    };
    let Ok(device_id) = did.parse::<u64>() else {
        return err(StatusCode::BAD_REQUEST, "无效的设备 ID");
    };
    let Some(net) = state.repo.get_network(net_id).ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "网络不存在");
    };
    let Some(_) = state.repo.membership_of(net_id, device_id).ok().flatten() else {
        return err(StatusCode::NOT_FOUND, "设备不属于该网络");
    };
    let cidr = match Cidr::parse(&net.cidr) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    // 校验+写入单事务（并发抢注由 UNIQUE 约束兜底并映射为 409）。
    if let Err(e) = state.repo.set_membership_ip_atomic(net_id, device_id, &payload.ip, &cidr) {
        return match e {
            RepoError::Conflict(msg) => err(StatusCode::CONFLICT, msg),
            other => err(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        };
    }
    state.hub.send_to_device(
        device_id,
        WsEvent {
            event_type: ws_events::CONFIG_CHANGED.to_string(),
            network_id: Some(net_id),
            device_id: Some(device_id),
            message: Some(payload.ip.clone()),
        },
    );
    state.hub.broadcast_network(
        &net_id,
        WsEvent {
            event_type: ws_events::PEERS_CHANGED.to_string(),
            network_id: Some(net_id),
            device_id: Some(device_id),
            message: None,
        },
    );
    (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
}

// ---------------------------------------------------------------------------
// Static admin console
// ---------------------------------------------------------------------------

fn asset_response(path: &str) -> Response {
    match AdminAssets::get(path) {
        Some(asset) => {
            let mut h = sha2::Sha256::new();
            h.update(&asset.data);
            let etag = hex::encode(&h.finalize()[..8]);
            let mime = match path.rsplit('.').next() {
                Some("html") => "text/html; charset=utf-8",
                Some("js") => "application/javascript; charset=utf-8",
                Some("css") => "text/css; charset=utf-8",
                Some("svg") => "image/svg+xml",
                Some("png") => "image/png",
                Some("ico") => "image/x-icon",
                Some("woff2") => "font/woff2",
                Some("woff") => "font/woff",
                Some("ttf") => "font/ttf",
                Some("json") => "application/json; charset=utf-8",
                Some("map") => "application/json; charset=utf-8",
                Some("txt") => "text/plain; charset=utf-8",
                _ => "application/octet-stream",
            };
            let mut resp = Response::new(Body::from(asset.data.into_owned()));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
            if let Ok(v) = HeaderValue::from_str(&etag) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            // Vite emits content-hashed names under assets/: cache forever.
            // The shell document must always revalidate to pick up new builds.
            let cache = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            if let Ok(v) = HeaderValue::from_str(cache) {
                resp.headers_mut().insert(header::CACHE_CONTROL, v);
            }
            resp
        }
        None => err(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn admin_index() -> Response {
    asset_response("index.html")
}

async fn admin_static(Path(path): Path<String>) -> Response {
    asset_response(&path)
}
