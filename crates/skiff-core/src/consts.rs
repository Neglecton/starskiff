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
