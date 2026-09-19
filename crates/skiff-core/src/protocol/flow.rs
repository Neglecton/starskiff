//! FLOW sub-protocol: user-space stream multiplexing over wire frames.
//!
//! Plaintext layout of a type=4 frame payload:
//! `[flowId u32 LE][seq u32 LE][flags u8][payload]`
//!
//! | flags    | payload                                          |
//! |----------|--------------------------------------------------|
//! | OPEN(1)  | `[proto u8: 1=TCP 2=UDP][addrLen u8]["ip:port"]` |
//! | OPENED_OK(2)   | empty                                      |
//! | OPENED_FAIL(3) | `[reasonLen u8][reason utf-8 <= 200]`      |
//! | CLOSE(4) | empty                                            |
//! | DATA(5)  | TCP byte chunk                                   |
//! | DATAGRAM(6) | `[addrLen u8]["ip:port"][udp payload]`       |
//!
//! The flow id is chosen randomly by the initiator and shared by both sides;
//! reply frames travel back on the same id.
//!
//! seq 仅对 DATA 有意义（发送方按流内字节块顺序递增，u32 自然回绕）；
//! 其他 flags 恒 0。接收方对 DATA 做**跳号即断流**校验：UDP 路径无
//! 应用层重传，丢块或乱序留下的缺口无法恢复，与其静默损坏流（内层
//! TCP 缺段且永不补齐），不如立即 CLOSE 让上层重连自愈。DATAGRAM 是
//! 独立数据报语义，不参与序号。

use crate::endec::{read_u32_le, write_u32_le};

pub const FLOW_HEADER: usize = 9;
pub const FLOW_HEADER_OFFSET: usize = 0;

pub const FLAG_OPEN: u8 = 1;
pub const FLAG_OPENED_OK: u8 = 2;
pub const FLAG_OPENED_FAIL: u8 = 3;
pub const FLAG_CLOSE: u8 = 4;
pub const FLAG_DATA: u8 = 5;
pub const FLAG_DATAGRAM: u8 = 6;

pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

pub const REASON_MAX: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowMsg<'a> {
    pub flow_id: u32,
    /// DATA 块的流内序号（0,1,2…，发送方递增）；其他 flags 恒 0。
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

pub fn encode(flow_id: u32, seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FLOW_HEADER + payload.len());
    write_u32_le(&mut out, flow_id);
    write_u32_le(&mut out, seq);
    out.push(flags);
    out.extend_from_slice(payload);
    out
}

pub fn decode(buf: &[u8]) -> Option<FlowMsg<'_>> {
    if buf.len() < FLOW_HEADER {
        return None;
    }
    let flags = buf[8];
    if !(FLAG_OPEN..=FLAG_DATAGRAM).contains(&flags) {
        return None;
    }
    Some(FlowMsg {
        flow_id: read_u32_le(buf),
        seq: read_u32_le(&buf[4..]),
        flags,
        payload: &buf[9..],
    })
}

/// OPEN payload: `[proto u8][addrLen u8]["ip:port"]`.
pub fn build_open(proto: u8, addr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + addr.len());
    out.push(proto);
    out.push(addr.len() as u8);
    out.extend_from_slice(addr.as_bytes());
    out
}

pub struct OpenInfo<'a> {
    pub proto: u8,
    pub addr: &'a str,
}

pub fn parse_open(payload: &[u8]) -> Option<OpenInfo<'_>> {
    if payload.len() < 3 {
        return None;
    }
    let proto = payload[0];
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    let addr_len = payload[1] as usize;
    if payload.len() != 2 + addr_len {
        return None;
    }
    let addr = std::str::from_utf8(&payload[2..]).ok()?;
    if !addr.contains(':') {
        return None;
    }
    Some(OpenInfo { proto, addr })
}

pub fn build_opened_fail(reason: &str) -> Vec<u8> {
    let bytes = reason.as_bytes();
    let len = bytes.len().min(REASON_MAX);
    let mut out = Vec::with_capacity(1 + len);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
    out
}

/// DATAGRAM payload: `[addrLen u8]["ip:port"][datagram]`.
pub fn build_datagram(addr: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + addr.len() + data.len());
    out.push(addr.len() as u8);
    out.extend_from_slice(addr.as_bytes());
    out.extend_from_slice(data);
    out
}

pub struct DatagramInfo<'a> {
    pub addr: &'a str,
    pub data: &'a [u8],
}

pub fn parse_datagram(payload: &[u8]) -> Option<DatagramInfo<'_>> {
    let addr_len = *payload.first()? as usize;
    if payload.len() < 1 + addr_len {
        return None;
    }
    let addr = std::str::from_utf8(&payload[1..1 + addr_len]).ok()?;
    if !addr.contains(':') {
        return None;
    }
    Some(DatagramInfo {
        addr,
        data: &payload[1 + addr_len..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let msg = encode(0x11223344, 7, FLAG_DATA, b"chunk");
        let decoded = decode(&msg).unwrap();
        assert_eq!(decoded.flow_id, 0x11223344);
        assert_eq!(decoded.seq, 7);
        assert_eq!(decoded.flags, FLAG_DATA);
        assert_eq!(decoded.payload, b"chunk");
        // 非 DATA 帧的 seq 不参与语义（恒 0 习惯写法）。
        let open = encode(5, 0, FLAG_OPEN, b"");
        let decoded = decode(&open).unwrap();
        assert_eq!(decoded.seq, 0);
    }

    #[test]
    fn rejects_bad_frames() {
        assert!(decode(&[0u8; 8]).is_none()); // too short
        assert!(decode(&encode(1, 0, 0, b"")).is_none()); // flag 0
        assert!(decode(&encode(1, 0, 7, b"")).is_none()); // flag 7
    }

    #[test]
    fn open_payload() {
        let payload = build_open(PROTO_TCP, "10.10.0.5:8080");
        let info = parse_open(&payload).unwrap();
        assert_eq!(info.proto, PROTO_TCP);
        assert_eq!(info.addr, "10.10.0.5:8080");
        assert!(parse_open(&[PROTO_TCP, 5, b'1', b'0']).is_none()); // addrLen mismatch
    }

    #[test]
    fn datagram_payload() {
        let payload = build_datagram("10.10.0.9:53", b"query");
        let info = parse_datagram(&payload).unwrap();
        assert_eq!(info.addr, "10.10.0.9:53");
        assert_eq!(info.data, b"query");
    }

    #[test]
    fn fail_reason_truncated() {
        let reason = "x".repeat(300);
        let payload = build_opened_fail(&reason);
        assert_eq!(payload.len(), 1 + REASON_MAX);
    }
}
