//! Global protocol and deployment constants.

use std::time::Duration;

/// Control-plane API port (HTTPS + WebSocket).
pub const DEFAULT_API_PORT: u16 = 24930;
/// Data-plane UDP relay port.
pub const DEFAULT_RELAY_UDP_PORT: u16 = 24931;
/// Data-plane TCP relay port.
pub const DEFAULT_RELAY_TCP_PORT: u16 = 24932;
/// Node P2P listen port (UDP and TCP share the same number).
pub const DEFAULT_LISTEN_PORT: u16 = 24933;

pub const DEFAULT_MTU: u32 = 1300;

/// Presence: a peer is online if seen (WS connected or refreshed) within this window.
pub const PRESENCE_TIMEOUT: Duration = Duration::from_secs(45);
/// 心跳间隔（常态档）。自适应：服务端在心跳响应里下发当期间隔——
/// 管理页正被查看（轮询 /admin/devices）时建议快档，无人查看回落常态档。
pub const HEARTBEAT_SLOW_SECS: u32 = 15;
/// 心跳间隔（被查看时的快档）：拓扑/速率展示更跟手，速率差分窗口随之变 5s。
pub const HEARTBEAT_FAST_SECS: u32 = 5;
/// 节点对服务端建议间隔的钳制下限（防异常值把节点打成高频轮询）。
pub const HEARTBEAT_MIN_SECS: u32 = 5;
/// 节点对服务端建议间隔的钳制上限。
pub const HEARTBEAT_MAX_SECS: u32 = 60;
/// 服务端"正在被查看"判定窗口：管理页 5s 轮询一次，超过 12s 未命中视为无人查看。
pub const ADMIN_OBSERVER_TTL_MS: i64 = 12_000;
/// Target re-registration cadence for the UDP relay.
pub const RELAY_REGISTER_INTERVAL: Duration = Duration::from_secs(25);
/// Path keep-alive ping interval.
pub const PEER_PING_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive missed pings before a direct path is considered dead.
pub const PEER_PING_MISS_LIMIT: u32 = 3;
/// Direct-path probe cadence.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// Timeout for a single direct probe round.
pub const DIRECT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Token prefixes: skd_ device, ska_ admin, skk_ enroll.
pub const DEVICE_TOKEN_PREFIX: &str = "skd_";
pub const ADMIN_TOKEN_PREFIX: &str = "ska_";
pub const ENROLL_TOKEN_PREFIX: &str = "skk_";
/// Random bytes in a token body (base64url, no padding).
pub const TOKEN_RANDOM_BYTES: usize = 24;

/// UDP receive buffer: must hold any datagram (max UDP payload 65507).
pub const UDP_BUFFER_SIZE: usize = 65535;
/// Upper bound for a length-prefixed TCP payload.
pub const TCP_MAX_PAYLOAD: usize = 512 * 1024;
/// TCP flow 数据分块上限。字节账：块 + flow 头 5 + wire 密封 51（含 AEAD
/// tag）必须 ≤ IPv4 UDP 数据报上限 65507——更大的块在 UDP 路径（直连或
/// 中继）send_to 必然失败。分块依赖 IP 分片（1500 MTU 下 ~23 片，丢失
/// 放大）是已知权衡；应用层不做重组/重传（见 AGENTS.md 功能边界）。
pub const FLOW_CHUNK: usize = 32 * 1024;
/// UDP flow 数据报载荷上限：65507 − flow 头 5 − wire 密封 51 − 中继壳 19
/// = 65432，取整留余量。数据报语义不可拆分，超限丢弃并记日志。
pub const FLOW_MAX_DATAGRAM: usize = 65_400;

#[cfg(test)]
mod tests {
    use super::*;

    /// FLOW_CHUNK 字节账（P1 黑洞守护）：数据块 + flow 头 + wire 密封
    /// （明文头 + AEAD tag）+ 中继壳必须 ≤ IPv4 UDP 数据报上限 65507——
    /// 曾用 64KiB 读块，密封后 65592 在所有 UDP 路径 send_to 必失败且
    /// 静默（本单测直接引用各层头常量算总账，改任一头布局即自暴露）。
    #[test]
    fn flow_chunk_fits_max_udp_datagram() {
        let aead_tag = 16; // ChaCha20-Poly1305
        let wire_overhead = crate::protocol::wire::FIXED_HEADER + aead_tag;
        let relay_overhead = crate::protocol::relay_udp::build_relay(1, 2, b"").len();
        let total = FLOW_CHUNK + crate::protocol::flow::FLOW_HEADER + wire_overhead + relay_overhead;
        assert!(
            total <= 65507,
            "FLOW_CHUNK 密封后超 IPv4 UDP 数据报上限：{total} > 65507（中继 UDP 路径必失败）"
        );
        assert!(
            FLOW_MAX_DATAGRAM + crate::protocol::flow::FLOW_HEADER + wire_overhead + relay_overhead <= 65507,
            "FLOW_MAX_DATAGRAM 密封后超上限"
        );
    }
}
