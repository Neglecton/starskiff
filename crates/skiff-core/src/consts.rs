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
/// Path keep-alive ping interval. 注意：探测循环实际节奏是
/// PATH_PROBE_INTERVAL（5s，每轮顺带保活 PING）；本常量用于计算直连
/// 死亡阈值（PEER_PING_MISS_LIMIT × 本值 = 30s 无 PONG 判死）。
pub const PEER_PING_INTERVAL: Duration = Duration::from_secs(10);
/// Consecutive missed pings before a direct path is considered dead.
pub const PEER_PING_MISS_LIMIT: u32 = 3;
/// Direct-path probe cadence.
pub const PATH_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Token prefixes: skd_ device, ska_ admin, skk_ enroll.
pub const DEVICE_TOKEN_PREFIX: &str = "skd_";
pub const ADMIN_TOKEN_PREFIX: &str = "ska_";
pub const ENROLL_TOKEN_PREFIX: &str = "skk_";
/// Random bytes in a token body (base64url, no padding).
pub const TOKEN_RANDOM_BYTES: usize = 24;

/// 节点协议代次（enroll/join/heartbeat 的 protoVersion）。公网异版混布
/// 时服务端据此给出明确错误而非静默丢弃；演进线格式（wire/relay/flow）
/// 时递增此值并在服务端校验处维护兼容区间。未上线单版本期"不等即拒绝"。
pub const PROTOCOL_VERSION: u32 = 1;

/// UDP receive buffer: must hold any datagram (max UDP payload 65507).
pub const UDP_BUFFER_SIZE: usize = 65535;
/// Upper bound for a length-prefixed TCP payload.
pub const TCP_MAX_PAYLOAD: usize = 512 * 1024;
/// TCP flow 数据分块上限（directTcp/relayTcp 路径）：TCP 流无 IP 分片
/// 问题，大块摊薄帧头与系统调用开销。字节账：块 + flow 头 9 + wire
/// 密封 51（含 AEAD tag）≤ TCP 帧上限 512KiB——远小，恒安全。
pub const FLOW_CHUNK: usize = 32 * 1024;
/// UDP 路径（directUdp/relayUdp）的 flow 分块。
///
/// 字节账：块 + 密封 51 + 中继壳 19 + flow 头 9 必须 ≤ IPv4 不分片上限
/// （1500 MTU − 28 头 = 1472），故取 1200。32KiB 分块分 ~23 片，公网
/// 1% 丢包下块丢失率 ≈21%（丢一作废且无重传）；1200B 单帧不分片后块
/// 丢失率即线路丢包率，配 seq 跳号断流（上层 TCP 重连自愈）。
pub const FLOW_CHUNK_UDP: usize = 1200;
/// UDP flow 数据报载荷上限：65507 − flow 头 5 − wire 密封 51 − 中继壳 19
/// = 65432，取整留余量。数据报语义不可拆分，超限丢弃并记日志。
pub const FLOW_MAX_DATAGRAM: usize = 65_400;

#[cfg(test)]
mod tests {
    use super::*;

    /// FLOW_CHUNK（TCP 路径）字节账（P1 黑洞守护）：数据块 + flow 头 +
    /// wire 密封（明文头 + AEAD tag）+ 中继壳必须 ≤ IPv4 UDP 数据报上限
    /// 65507——曾用 64KiB 读块，密封后 65592 在所有 UDP 路径 send_to 必
    /// 失败且静默（本单测直接引用各层头常量算总账，改任一头布局即自暴露）。
    #[test]
    fn flow_chunk_fits_max_udp_datagram() {
        let aead_tag = 16; // ChaCha20-Poly1305
        let wire_overhead = crate::protocol::wire::FIXED_HEADER + aead_tag;
        let relay_overhead = crate::protocol::relay_udp::build_relay(1, 2, b"").len();
        let flow_header = crate::protocol::flow::FLOW_HEADER;
        let total = FLOW_CHUNK + flow_header + wire_overhead + relay_overhead;
        assert!(
            total <= 65507,
            "FLOW_CHUNK 密封后超 IPv4 UDP 数据报上限：{total} > 65507（中继 UDP 路径必失败）"
        );
        assert!(
            FLOW_MAX_DATAGRAM + flow_header + wire_overhead + relay_overhead <= 65507,
            "FLOW_MAX_DATAGRAM 密封后超上限"
        );
    }

    /// FLOW_CHUNK_UDP 不分片账：1500 MTU − IP/UDP 头 28 = 1472 为不分片
    /// 上限；UDP 路径分块密封后必须落在其内（任一分片丢失整块作废，
    /// 公网丢包下 23 片的丢失放大是吞吐坍塌根因）。
    #[test]
    fn flow_chunk_udp_never_fragments() {
        let aead_tag = 16;
        let wire_overhead = crate::protocol::wire::FIXED_HEADER + aead_tag;
        let relay_overhead = crate::protocol::relay_udp::build_relay(1, 2, b"").len();
        let total =
            FLOW_CHUNK_UDP + crate::protocol::flow::FLOW_HEADER + wire_overhead + relay_overhead;
        assert!(
            total <= 1472,
            "FLOW_CHUNK_UDP 密封后超不分片上限：{total} > 1472（1500 MTU 下仍会分片）"
        );
    }
}
