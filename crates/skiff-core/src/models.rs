//! API DTOs, node state and config models shared by server and node.
//!
//! JSON conventions: camelCase field names, `null` fields omitted on write.
//! Timestamps are Unix milliseconds; device ids are random u64.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::secret::Secret;

use crate::consts::DEFAULT_MTU;

/// 16-byte opaque network identifier. Serialized as 32 lowercase hex chars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetId(pub [u8; 16]);

impl NetId {
    pub fn random() -> NetId {
        let mut b = [0u8; 16];
        OsRng.fill_bytes(&mut b);
        NetId(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<NetId> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 16 {
            return None;
        }
        Some(NetId(bytes.try_into().unwrap()))
    }
}

impl std::fmt::Display for NetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for NetId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for NetId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<NetId, D::Error> {
        let s = String::deserialize(deserializer)?;
        NetId::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid network id hex"))
    }
}

// ---------------------------------------------------------------------------
// Node-facing API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    /// Enroll token, may carry a `.<64hex>` cert-fingerprint suffix.
    pub token: String,
    pub name: String,
    pub sign_pubkey: String,
    pub dh_pubkey: String,
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub device_id: u64,
    pub device_token: String,
    pub network_id: NetId,
    pub network_name: String,
    pub cidr: String,
    pub ip: String,
    pub mtu: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub device_id: u64,
    pub name: String,
    pub network_id: NetId,
    pub network_name: String,
    pub cidr: String,
    pub ip: String,
    pub mtu: u32,
    pub relay_udp_port: u16,
    pub relay_tcp_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub device_id: u64,
    pub name: String,
    pub network_id: NetId,
    pub ip: String,
    pub sign_pubkey: String,
    pub dh_pubkey: String,
    /// udpEndpoints[0] must be the relay-observed endpoint: peers rely on
    /// that position for neighbour-port prediction.
    pub udp_endpoints: Vec<String>,
    pub tcp_listen_port: Option<u16>,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerPathReport {
    pub device_id: u64,
    pub path: String,
    /// One-way observation by the reporting node (>= 0); absent when the
    /// peer never answered a probe (or an older node that doesn't report it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub local_addrs: Vec<String>,
    pub listen_udp_port: Option<u16>,
    pub listen_tcp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<PeerPathReport>>,
    /// 已应用的 settings revision（旧节点不上报，服务端显示未知）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings_revision: Option<i64>,
    /// 有重启类托管配置（socks/forwards/mtu）已写入文件但尚未重启生效。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_pending: Option<bool>,
    /// 节点运行模式（"tun"/"proxy"）——服务端据此预防性拒绝会让 TUN
    /// 节点超过单网络限制的强制 join。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_udp_endpoint: Option<String>,
}

/// WebSocket event pushed to nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WsEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<NetId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub mod ws_events {
    pub const PEERS_CHANGED: &str = "peers_changed";
    pub const DEVICE_ONLINE: &str = "device_online";
    pub const DEVICE_OFFLINE: &str = "device_offline";
    pub const CONFIG_CHANGED: &str = "config_changed";
    /// 服务端权威的设备行为配置有新版本，节点自拉 /api/settings 应用。
    pub const SETTINGS_CHANGED: &str = "settings_changed";
    /// 管理员请求节点重启引擎（worker 优雅退出，由 master 拉起）。
    pub const RESTART_REQUESTED: &str = "restart_requested";
    /// 管理员请求节点轻量重连（重发中继注册 + 刷新 peers，不重启）。
    pub const RECONNECT_REQUESTED: &str = "reconnect_requested";
    /// 管理员变更了设备的网络成员关系（强制 join/leave），节点重拉名单。
    pub const NETWORKS_CHANGED: &str = "networks_changed";
    /// Locally synthesized by the client when the WS connects.
    pub const CONNECTED: &str = "connected";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error: String,
}

// ---------------------------------------------------------------------------
// Admin API
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SummaryResponse {
    pub networks: usize,
    pub devices: usize,
    pub online: usize,
    pub relay_udp_port: u16,
    pub relay_tcp_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminNetwork {
    pub id: NetId,
    pub name: String,
    pub cidr: String,
    pub created_at: i64,
    pub device_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNetworkRequest {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminToken {
    /// Full token including the `.<64hex>` fingerprint suffix.
    pub token: String,
    pub network_id: NetId,
    pub network_name: String,
    pub uses_left: i64,
    pub expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTokenRequest {
    /// Network name or 32-hex network id.
    pub network: String,
    pub uses: i64,
    pub expires_in_hours: i64,
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDeviceMembership {
    pub network_id: NetId,
    pub network_name: String,
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminDevice {
    pub id: u64,
    pub name: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub online: bool,
    pub networks: Vec<AdminDeviceMembership>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<PeerPathReport>>,
    /// 服务端期望的 settings revision（从未保存过则无）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_revision: Option<i64>,
    /// 节点心跳上报的已应用 revision（旧节点不上报则无）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_revision: Option<i64>,
    /// 节点上报的重启待生效标志。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_pending: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetIpRequest {
    pub ip: String,
}

/// POST /api/join — an already-enrolled device joins another network using
/// an enroll token (device-token authenticated).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    /// Enroll token for the target network (may carry a cert fingerprint suffix).
    pub token: String,
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinResponse {
    pub network_id: NetId,
    pub network_name: String,
    pub cidr: String,
    pub ip: String,
}

/// POST /api/leave — remove one's own membership in a network.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaveRequest {
    /// Network name or 32-hex id.
    pub network: String,
}

/// GET /api/memberships 条目——服务端权威的设备网络名单（节点启动名单
/// 的唯一来源；节点文件 networks[] 仅作展示缓存）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipInfo {
    pub network_id: NetId,
    pub network_name: String,
    pub cidr: String,
    pub ip: String,
}

/// POST /admin/devices/{id}/networks — 管理员强制设备加入网络。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminJoinNetworkRequest {
    /// 网络名或 32-hex id。
    pub network: String,
    pub requested_ip: Option<String>,
}

/// 单网络的 exposes 托管条目（DeviceSettings.exposes 的元素）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkExposes {
    pub network_id: NetId,
    #[serde(default)]
    pub rules: Vec<ExposeRule>,
}

/// 服务端权威的设备行为配置（device_settings 表，JSON 存储）。
///
/// Option 字段是"逐字段渐进迁移"的载具：`Some(v)` = 该项由服务端托管、
/// 节点以 v 覆盖本地值；`None` = 未托管，节点沿用本地配置。socks_listen
/// 的托管值为 `"ip:port"` 或空串（空串 = 禁用 SOCKS）。force 开关与
/// exposes 热生效；mtu/socks/forwards 写入文件后重启引擎生效。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSettings {
    /// 单调递增；节点只应用大于已应用值的 revision（多网络节点 WS 重复
    /// 投递的幂等去重依据）。PUT 时忽略请求中的该字段。
    #[serde(default)]
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_relay: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_direct: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwards: Option<Vec<ForwardRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposes: Option<Vec<NetworkExposes>>,
}

impl DeviceSettings {
    /// 托管子集的格式校验（节点在持久化前还会做整体 validate 兜底）。
    pub fn validate(&self) -> Result<(), String> {
        if self.force_relay == Some(true) && self.force_direct == Some(true) {
            return Err("forceRelay 与 forceDirect 不能同时开启".into());
        }
        if let Some(mtu) = self.mtu
            && !(576..=65500).contains(&mtu)
        {
            return Err("mtu 必须在 576–65500 之间".into());
        }
        if let Some(socks) = &self.socks_listen
            && !socks.is_empty()
            && socks.parse::<std::net::SocketAddr>().is_err()
        {
            return Err(format!("socksListen 不是合法的 ip:port（{socks}）"));
        }
        if let Some(forwards) = &self.forwards {
            if forwards.len() > 64 {
                return Err("forwards 最多 64 条".into());
            }
            for (i, f) in forwards.iter().enumerate() {
                if f.proto != "tcp" && f.proto != "udp" {
                    return Err(format!("forwards[{i}].proto 必须是 tcp 或 udp"));
                }
                if f.listen.parse::<std::net::SocketAddr>().is_err() {
                    return Err(format!("forwards[{i}].listen 不是合法的 ip:port（{}）", f.listen));
                }
                if parse_virtual_dest(&f.dest).is_none() {
                    return Err(format!("forwards[{i}].dest 不是合法的 ip:port（{}）", f.dest));
                }
            }
        }
        if let Some(list) = &self.exposes {
            if list.len() > 32 {
                return Err("exposes 最多覆盖 32 个网络".into());
            }
            for (i, ne) in list.iter().enumerate() {
                if ne.rules.len() > 64 {
                    return Err(format!("exposes[{i}] 规则过多（最多 64 条）"));
                }
                for (j, r) in ne.rules.iter().enumerate() {
                    if r.proto != "tcp" && r.proto != "udp" {
                        return Err(format!("exposes[{i}].rules[{j}].proto 必须是 tcp 或 udp"));
                    }
                    if r.port == 0 {
                        return Err(format!("exposes[{i}].rules[{j}].port 无效"));
                    }
                    if r.dest.parse::<std::net::SocketAddr>().is_err() {
                        return Err(format!(
                            "exposes[{i}].rules[{j}].dest 不是合法的 ip:port（{}）",
                            r.dest
                        ));
                    }
                }
            }
            for i in 0..list.len() {
                for j in (i + 1)..list.len() {
                    if list[i].network_id == list[j].network_id {
                        return Err("exposes 中存在重复的 networkId".into());
                    }
                }
            }
        }
        Ok(())
    }

    /// 是否有任何托管字段（全 None = 未管理，等同无记录）。
    pub fn is_empty(&self) -> bool {
        self.force_relay.is_none()
            && self.force_direct.is_none()
            && self.mtu.is_none()
            && self.socks_listen.is_none()
            && self.forwards.is_none()
            && self.exposes.is_none()
    }
}

/// 转发目标是虚拟 IP:port（比 SocketAddr 宽松：允许解析失败仅要求
/// "host:port" 形态——虚拟 IP 一定可解析，但保持错误信息友好）。
fn parse_virtual_dest(dest: &str) -> Option<(String, u16)> {
    let (host, port) = dest.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host.to_string(), port))
}

// ---------------------------------------------------------------------------
// Node-local files
// ---------------------------------------------------------------------------

/// Device identity — the sensitive half of the node configuration.
/// Private keys and the device token are field-sealed (`Secret`); public
/// keys and ids stay plain so the file remains inspectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub device_id: u64,
    pub name: String,
    pub device_token: Secret,
    pub sign_public_key: String,
    pub sign_private_key: Secret,
    pub dh_public_key: String,
    pub dh_private_key: Secret,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_pin: Option<String>,
}

/// starskiff.json —— 瘦节点配置：连接信息 + 本机部署参数 + 身份。
/// 一切网络行为配置（成员关系/exposes/socks/forwards/force 开关/托管
/// mtu）均由服务端权威下发（GET /api/memberships + GET /api/settings），
/// 启动时拉取应用，不在文件持久化；遗留文件中的旧字段在加载时忽略、
/// 首次启动自动收编为服务端托管值。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_mode")]
    pub mode: ClientMode,
    /// 本机参数语义：TUN 设备的默认 MTU（服务端托管值可覆盖，重启生效）。
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default)]
    pub data_dir: String,
    #[serde(default = "default_listen_port")]
    pub listen_udp_port: u16,
    #[serde(default = "default_listen_port")]
    pub listen_tcp_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub identity: Identity,
}

impl NodeConfig {
    /// Load and validate a config file.
    pub fn load(path: &std::path::Path) -> Result<NodeConfig, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取 {}: {e}", path.display()))?;
        let cfg: NodeConfig =
            serde_json::from_str(&text).map_err(|e| format!("配置格式无效: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate required fields. Returns a user-facing error message on
    /// failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.server.trim().is_empty() {
            return Err("配置缺少 server".into());
        }
        Ok(())
    }
}

fn default_mtu() -> u32 {
    DEFAULT_MTU
}

fn default_listen_port() -> u16 {
    crate::consts::DEFAULT_LISTEN_PORT
}

fn default_mode() -> ClientMode {
    ClientMode::Proxy
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMode {
    #[serde(rename = "tun")]
    Tun,
    #[serde(rename = "proxy")]
    Proxy,
}

impl ClientMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientMode::Tun => "tun",
            ClientMode::Proxy => "proxy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardRule {
    /// Local "ip:port" to listen on.
    pub listen: String,
    #[serde(default = "default_proto")]
    pub proto: String,
    /// Remote "virtual-ip:port".
    pub dest: String,
}

fn default_proto() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExposeRule {
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
    /// Local "ip:port" of the real service.
    pub dest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub network: String,
    pub ip: String,
    pub cidr: String,
}

/// status.json — written periodically while the engine runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerStatus {
    pub network: String,
    pub name: String,
    pub ip: String,
    pub online: bool,
    pub path: String,
    pub endpoint: String,
    pub rtt_ms: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub running: bool,
    pub pid: u32,
    pub started_at: i64,
    pub uptime_sec: i64,
    pub server: String,
    #[serde(default)]
    pub networks: Vec<NetworkStatus>,
    pub mode: String,
    pub udp_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socks: Option<String>,
    #[serde(default)]
    pub forwards: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_id_hex_round_trip() {
        let id = NetId::random();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(NetId::from_hex(&hex).unwrap(), id);
        assert!(NetId::from_hex("zz").is_none());
    }

    #[test]
    fn enroll_request_camel_case() {
        let json = r#"{
            "token": "skk_abc",
            "name": "node-a",
            "signPubkey": "aa",
            "dhPubkey": "bb",
            "requestedIp": "10.0.0.5"
        }"#;
        let req: EnrollRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.requested_ip.as_deref(), Some("10.0.0.5"));

        let minimal = r#"{"token":"t","name":"n","signPubkey":"s","dhPubkey":"d"}"#;
        let req: EnrollRequest = serde_json::from_str(minimal).unwrap();
        assert!(req.requested_ip.is_none());
    }

    #[test]
    fn ws_event_null_fields_omitted() {
        let evt = WsEvent {
            event_type: "peers_changed".into(),
            network_id: Some(NetId::random()),
            device_id: None,
            message: None,
        };
        let s = serde_json::to_string(&evt).unwrap();
        assert!(s.contains("\"networkId\""));
        assert!(!s.contains("\"deviceId\""));
        assert!(!s.contains("\"message\""));
        assert!(s.contains("\"type\":\"peers_changed\""));
    }

    #[test]
    fn device_settings_camel_case_and_defaults() {
        let json = r#"{
            "revision": 3,
            "forceRelay": true,
            "socksListen": "",
            "exposes": [{"networkId": "0102030405060708090a0b0c0d0e0f10",
                          "rules": [{"port": 8080, "proto": "tcp", "dest": "127.0.0.1:9090"}]}]
        }"#;
        let s: DeviceSettings = serde_json::from_str(json).unwrap();
        assert_eq!(s.revision, 3);
        assert_eq!(s.force_relay, Some(true));
        assert_eq!(s.socks_listen.as_deref(), Some(""));
        assert_eq!(s.exposes.as_ref().unwrap()[0].rules.len(), 1);
        assert!(s.validate().is_ok());
        assert!(!s.is_empty());

        // 未托管字段缺省（None），序列化时省略。
        let minimal: DeviceSettings = serde_json::from_str(r#"{"revision":0}"#).unwrap();
        assert!(minimal.is_empty());
        let out = serde_json::to_string(&minimal).unwrap();
        assert!(!out.contains("forceRelay"));
        assert!(!out.contains("exposes"));

        // 校验规则。
        let bad: DeviceSettings = serde_json::from_str(r#"{"forceRelay":true,"forceDirect":true}"#).unwrap();
        assert!(bad.validate().is_err());
        let bad: DeviceSettings =
            serde_json::from_str(r#"{"socksListen":"not-an-addr"}"#).unwrap();
        assert!(bad.validate().is_err());
        let bad: DeviceSettings =
            serde_json::from_str(r#"{"forwards":[{"listen":"1.2.3.4:x","proto":"tcp","dest":"10.0.0.2:80"}]}"#)
                .unwrap();
        assert!(bad.validate().is_err());
        let bad: DeviceSettings = serde_json::from_str(
            r#"{"exposes":[{"networkId":"0102030405060708090a0b0c0d0e0f10","rules":[{"port":80,"proto":"sctp","dest":"127.0.0.1:80"}]}]}"#,
        )
        .unwrap();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn node_config_defaults_validation_and_secret_form() {
        let cfg: NodeConfig = serde_json::from_str(
            r#"{"server":"http://127.0.0.1:24930","identity":{"deviceId":7,"name":"n","deviceToken":"skd_t","signPublicKey":"aa","signPrivateKey":"bb","dhPublicKey":"cc","dhPrivateKey":"dd"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.mode, ClientMode::Proxy);
        assert_eq!(cfg.listen_udp_port, 24933);
        assert_eq!(cfg.mtu, 1300);
        assert!(cfg.validate().is_ok());

        // 遗留字段（networks/socks/forwards/force）在加载时被忽略——
        // 行为配置由服务端下发，首次启动自动收编。
        let legacy: NodeConfig = serde_json::from_str(
            r#"{"server":"http://x","forceRelay":true,"socksListen":"127.0.0.1:1080","networks":[{"network":"n1"}],"identity":{"deviceId":1,"name":"n","deviceToken":"t","signPublicKey":"a","signPrivateKey":"b","dhPublicKey":"c","dhPrivateKey":"d"}}"#,
        )
        .unwrap();
        assert!(legacy.validate().is_ok());
        let saved = serde_json::to_string(&legacy).unwrap();
        assert!(!saved.contains("networks"));
        assert!(!saved.contains("forceRelay"));

        let bad: NodeConfig = serde_json::from_str(
            r#"{"server":"","identity":{"deviceId":1,"name":"n","deviceToken":"t","signPublicKey":"a","signPrivateKey":"b","dhPublicKey":"c","dhPrivateKey":"d"}}"#,
        )
        .unwrap();
        assert!(bad.validate().is_err());

        // Full JSON round trip keeps the identity secrets working.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: NodeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.identity.device_token.expose(), "skd_t");
        assert_eq!(back.identity.dh_private_key.expose(), "dd");
    }

    #[test]
    fn peer_path_report_rtt_compat() {
        // Legacy JSON without rttMs parses to None.
        let legacy: PeerPathReport = serde_json::from_str(
            r#"{"deviceId":7,"path":"DirectUdp"}"#,
        )
        .unwrap();
        assert_eq!(legacy.device_id, 7);
        assert!(legacy.rtt_ms.is_none());
        // New form round-trips and omits None on write.
        let full: PeerPathReport = serde_json::from_str(
            r#"{"deviceId":8,"path":"RelayUdp","rttMs":23}"#,
        )
        .unwrap();
        assert_eq!(full.rtt_ms, Some(23));
        let json = serde_json::to_string(&full).unwrap();
        assert!(json.contains("\"rttMs\":23"));
        let none_json = serde_json::to_string(&legacy).unwrap();
        assert!(!none_json.contains("rttMs"));
    }

    #[test]
    fn heartbeat_request_accepts_minimal_payload() {
        let req: HeartbeatRequest = serde_json::from_str(r#"{"localAddrs":[]}"#).unwrap();
        assert!(req.paths.is_none());
        assert!(req.listen_udp_port.is_none());
    }
}
