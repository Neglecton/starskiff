//! Control-plane client: REST (config/peers/heartbeat/enroll) plus the
//! /api/events WebSocket with 3s reconnect backoff.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use skiff_core::models::{
    ConfigResponse, DeviceSettings, EnrollRequest, EnrollResponse, HeartbeatRequest,
    HeartbeatResponse, MembershipInfo, PeerInfo, PeerPathReport, WsEvent,
};
use tokio::sync::mpsc;

use crate::tls_verifier::{TrustState, client_config};

pub struct ControlClient {
    server: String,
    device_token: String,
    http: reqwest::Client,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    pub tofu_fingerprint: Arc<Mutex<Option<String>>>,
    /// 与 verifier 共享的 pin（Tier 3 TOFU 首连后由 verifier 写入）。
    pub server_cert_pin: Arc<Mutex<Option<String>>>,
    pub insecure_http: bool,
}

impl ControlClient {
    pub fn new(server: &str, device_token: &str, cert_pin: Option<&str>) -> ControlClient {
        let server = server.trim_end_matches('/').to_string();
        let insecure_http = server.starts_with("http://");
        let tofu = Arc::new(Mutex::new(None));
        let pin = Arc::new(Mutex::new(cert_pin.map(String::from)));
        let (http, tls_config) = if server.starts_with("https://") {
            let trust = TrustState {
                pin: pin.clone(),
                tofu_fingerprint: tofu.clone(),
            };
            let cfg = Arc::new(client_config(trust));
            let client = reqwest::Client::builder()
                .use_preconfigured_tls(rustls::ClientConfig::clone(&cfg))
                .timeout(Duration::from_secs(15))
                .build()
                .expect("reqwest client builds");
            (client, Some(cfg))
        } else {
            (
                reqwest::Client::builder()
                    .timeout(Duration::from_secs(15))
                    .build()
                    .expect("reqwest client builds"),
                None,
            )
        };
        ControlClient {
            server,
            device_token: device_token.to_string(),
            http,
            tls_config,
            tofu_fingerprint: tofu,
            server_cert_pin: pin,
            insecure_http,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.server, path)
    }

    pub async fn get_config(&self, network: &str) -> Option<ConfigResponse> {
        let url = self.url(&format!("/api/config?network={}", urlencode(network)));
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.device_token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    pub async fn get_peers(&self, network: &str) -> Option<Vec<PeerInfo>> {
        let url = self.url(&format!("/api/peers?network={}", urlencode(network)));
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.device_token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    /// 拉取本设备的托管配置（服务端权威；revision 驱动幂等应用）。
    pub async fn get_settings(&self) -> Option<DeviceSettings> {
        let resp = self
            .http
            .get(self.url("/api/settings"))
            .bearer_auth(&self.device_token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    /// worker 启动失败上报：服务端收到后自动回滚到上一版成功配置
    ///（revision 不匹配当前版时忽略——过期/重复上报天然幂等）。
    pub async fn report_settings_fail(&self, revision: i64, error: &str) {
        let _ = self
            .http
            .post(self.url("/api/settings/fail"))
            .bearer_auth(&self.device_token)
            .json(&serde_json::json!({ "revision": revision, "error": error }))
            .send()
            .await;
    }

    /// 把遗留本地配置值收编为服务端托管（仅填充未托管字段；返回合并
    /// 后的最新配置）。
    pub async fn get_memberships(&self) -> Option<Vec<MembershipInfo>> {
        let resp = self
            .http
            .get(self.url("/api/memberships"))
            .bearer_auth(&self.device_token)
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        resp.json().await.ok()
    }

    /// 失败时 Err 携带状态码与服务端错误文本（如协议版本不匹配的诊断）。
    pub async fn heartbeat(
        &self,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, String> {
        let url = self.url("/api/heartbeat");
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.device_token)
            .json(req)
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            return Err(body["error"]
                .as_str()
                .map(|e| format!("HTTP {status}: {e}"))
                .unwrap_or_else(|| format!("HTTP {status}")));
        }
        resp.json().await.map_err(|e| format!("响应格式无效: {e}"))
    }

    pub async fn join(&self, token: &str, requested_ip: Option<&str>) -> Result<skiff_core::models::JoinResponse, String> {
        let url = self.url("/api/join");
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.device_token)
            .json(&serde_json::json!({
                "token": token,
                "requestedIp": requested_ip,
                "protoVersion": skiff_core::consts::PROTOCOL_VERSION,
            }))
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            return Err(body["error"].as_str().unwrap_or("加入网络失败").to_string());
        }
        serde_json::from_value(body).map_err(|e| format!("响应格式无效: {e}"))
    }

    pub async fn leave(&self, network: &str) -> Result<(), String> {
        let url = self.url("/api/leave");
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.device_token)
            .json(&serde_json::json!({ "network": network }))
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
            return Err(body["error"].as_str().unwrap_or("退出网络失败").to_string());
        }
        Ok(())
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, String> {
        let url = self.url("/api/enroll");
        let resp = self
            .http
            .post(url)
            .json(req)
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        if !status.is_success() {
            return Err(body["error"].as_str().unwrap_or("注册失败").to_string());
        }
        serde_json::from_value(body).map_err(|e| format!("响应格式无效: {e}"))
    }

    /// Spawn the /api/events WebSocket loop for one network. Events (plus a
    /// locally synthesized "connected") are delivered on the channel; the
    /// loop reconnects every 3s on failure until the engine stops
    ///（stopped 通道置 true 时退出——避免引擎停止后僵尸循环把新引擎的
    /// 同键 socket 顶掉，hub 按 (device, network) 单连接注册）。
    pub fn spawn_event_loop(
        self: &Arc<Self>,
        network: &str,
        tx: mpsc::UnboundedSender<WsEvent>,
        stopped: tokio::sync::watch::Receiver<bool>,
    ) {
        let client = Arc::clone(self);
        let network = network.to_string();
        tokio::spawn(async move {
            // 重连退避：连续失败 3s ×1.5 递增、封顶 30s（服务端长时间
            // 宕机时避免固定 3s 高频重试）；连接曾建立（干净关闭）即重置。
            let mut backoff = Duration::from_secs(3);
            while !*stopped.borrow() {
                if client.run_ws_once(&network, &tx).await.is_ok() {
                    backoff = Duration::from_secs(1);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff.mul_f32(1.5)).min(Duration::from_secs(30));
                }
            }
        });
    }

    async fn run_ws_once(&self, network: &str, tx: &mpsc::UnboundedSender<WsEvent>) -> anyhow::Result<()> {
        let ws_url = self.url(&format!(
            "/api/events?network={}&token={}",
            urlencode(network),
            urlencode(&self.device_token)
        ));
        let ws_url = if self.server.starts_with("https://") {
            ws_url.replacen("https://", "wss://", 1)
        } else {
            ws_url.replacen("http://", "ws://", 1)
        };
        // 从 URL 生成合规握手请求：IntoClientRequest 会补齐
        // sec-websocket-key/version/upgrade/connection 头——手工用
        // Request::builder 构造的请求缺这些头，握手必被服务端拒绝
        // （曾因此整个事件订阅静默失效，只剩 5s 轮询兜底）。
        // 令牌已在 query string 中，无需额外头。
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let request = ws_url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow::anyhow!("ws request: {e}"))?;
        let connector = match &self.tls_config {
            Some(cfg) => tokio_tungstenite::Connector::Rustls(cfg.clone()),
            None => tokio_tungstenite::Connector::Plain,
        };
        match tokio_tungstenite::connect_async_tls_with_config(request, None, false, Some(connector)).await {
            Ok((ws, _resp)) => {
                let _ = tx.send(WsEvent {
                    event_type: skiff_core::models::ws_events::CONNECTED.to_string(),
                    network_id: None,
                    device_id: None,
                    message: None,
                });
                Self::pump_ws(ws, tx.clone()).await
            }
            Err(e) => {
                // 服务端明确拒绝（如设备已不属任何网络 → 404）：推送必然
                // 收不到，发合成 NETWORKS_CHANGED 触发对账——否则零成员
                // 设备永远连不上 WS，roster 永不收敛、死网络无限期残留
                //（曾为删网后节点僵尸的根因）。仅限 HTTP 应答型拒绝，
                // 网络不可达不触发（避免故障期高频拉取）。
                if matches!(
                    e,
                    tokio_tungstenite::tungstenite::Error::Http(_)
                ) {
                    let _ = tx.send(WsEvent {
                        event_type: skiff_core::models::ws_events::NETWORKS_CHANGED.to_string(),
                        network_id: None,
                        device_id: None,
                        message: None,
                    });
                }
                Err(anyhow::anyhow!("ws connect: {e}"))
            }
        }
    }

    async fn pump_ws(
        mut ws: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tx: mpsc::UnboundedSender<WsEvent>,
    ) -> anyhow::Result<()> {
        use futures_util::SinkExt as _;
        use futures_util::StreamExt;
        // 半开检测：周期发 Ping（写路径同时 flush 库自动排队的服务端
        // Pong），60s 无任何入帧（含 Pong）视为链路已死，主动断开重连
        // ——否则 NAT 静默丢映射时事件通道黑洞，只剩 5s 轮询兜底。
        let mut last_rx = std::time::Instant::now();
        let mut ping = tokio::time::interval(Duration::from_secs(25));
        ping.tick().await; // 首个 tick 立即完成，跳过
        loop {
            tokio::select! {
                msg = ws.next() => {
                    match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                            last_rx = std::time::Instant::now();
                            if let Ok(evt) = serde_json::from_str::<WsEvent>(&text)
                                && tx.send(evt).is_err()
                            {
                                return Ok(()); // engine dropped the channel
                            }
                        }
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                            return Ok(());
                        }
                        Some(Ok(_)) => last_rx = std::time::Instant::now(), // Ping/Pong 等
                        Some(Err(_)) => return Ok(()),
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > Duration::from_secs(60) {
                        return Ok(()); // 半开：60s 无任何入帧，重连
                    }
                    if ws
                        .send(tokio_tungstenite::tungstenite::Message::Ping(Vec::new().into()))
                        .await
                        .is_err()
                    {
                        return Ok(());
                    }
                }
            }
        }
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Helper for heartbeat payload assembly.
pub fn paths_report(reports: Vec<PeerPathReport>) -> HeartbeatRequest {
    HeartbeatRequest {
        local_addrs: Vec::new(),
        listen_udp_port: None,
        listen_tcp_port: None,
        paths: Some(reports),
        settings_revision: None,
        restart_pending: None,
        mode: None,
        proto_version: None,
        node_version: None,
    }
}
