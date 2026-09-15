//! TCP framing: length prefix + relay control channel (magic 0x0B).
//!
//! Direct peer TCP carries raw wire frames (`[len u32 LE][wire frame]`);
//! relay TCP carries `[len u32 LE][magic 0x0B][version 1][cmd][data]`.
//!
//! Commands: REGISTER(1, data = the 56-byte UDP REGISTER body without the
//! 3-byte header), ACK(3), ERROR(4), SEND(5, client→server `[dstId u64][wire
//! frame]`), FRAME(6, server→client `[wire frame]`), KEEPALIVE(7)/RESP(8).

use crate::consts::TCP_MAX_PAYLOAD;
use crate::endec::{read_u32_le, read_u64_le, write_u32_le, write_u64_le};

use super::relay_udp::{CMD_ACK, CMD_ERROR, CMD_REGISTER, RELAY_MAGIC, RELAY_VERSION};

pub const CMD_TCP_SEND: u8 = 5;
pub const CMD_TCP_FRAME: u8 = 6;
pub const CMD_TCP_KEEPALIVE: u8 = 7;
pub const CMD_TCP_KEEPALIVE_RESP: u8 = 8;

pub const LENGTH_HEADER: usize = 4;

/// Wrap `inner` (already including its own 0x0B header for relay frames)
/// into a length-prefixed TCP message.
pub fn write_length_prefixed(out: &mut Vec<u8>, inner: &[u8]) {
    write_u32_le(out, inner.len() as u32);
    out.extend_from_slice(inner);
}

/// Build the relay-TCP inner payload `[0x0B][1][cmd][data]`.
pub fn encode_cmd(cmd: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + data.len());
    out.push(RELAY_MAGIC);
    out.push(RELAY_VERSION);
    out.push(cmd);
    out.extend_from_slice(data);
    out
}

/// SEND body: `[dstId u64 LE][wire frame]`.
pub fn build_send_body(dst_id: u64, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + frame.len());
    write_u64_le(&mut out, dst_id);
    out.extend_from_slice(frame);
    out
}

pub fn parse_send_body(body: &[u8]) -> Option<(u64, &[u8])> {
    if body.len() < 8 {
        return None;
    }
    Some((read_u64_le(body), &body[8..]))
}

/// Parsed relay-TCP command.
#[derive(Debug)]
pub enum RelayTcpMsg<'a> {
    Register { body: &'a [u8] },
    Ack { body: &'a [u8] },
    Error { body: &'a [u8] },
    Send { dst: u64, frame: &'a [u8] },
    Frame { frame: &'a [u8] },
    Keepalive,
    KeepaliveResp,
}

pub fn parse(inner: &[u8]) -> Option<RelayTcpMsg<'_>> {
    if inner.len() < 3 || inner[0] != RELAY_MAGIC || inner[1] != RELAY_VERSION {
        return None;
    }
    let data = &inner[3..];
    match inner[2] {
        CMD_REGISTER => Some(RelayTcpMsg::Register { body: data }),
        CMD_ACK => Some(RelayTcpMsg::Ack { body: data }),
        CMD_ERROR => Some(RelayTcpMsg::Error { body: data }),
        CMD_TCP_SEND => {
            let (dst, frame) = parse_send_body(data)?;
            Some(RelayTcpMsg::Send { dst, frame })
        }
        CMD_TCP_FRAME => Some(RelayTcpMsg::Frame { frame: data }),
        CMD_TCP_KEEPALIVE => Some(RelayTcpMsg::Keepalive),
        CMD_TCP_KEEPALIVE_RESP => Some(RelayTcpMsg::KeepaliveResp),
        _ => None,
    }
}

/// Incremental length-prefixed frame reassembly for a byte stream.
#[derive(Default)]
pub struct FrameReassembler {
    buf: Vec<u8>,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed stream bytes; returns completed inner payloads in order.
    /// 超限帧（> 512 KiB）返回 Err：只清缓冲无法重新对齐流边界（该帧的
    /// 后续字节会被误当作新帧解析），调用方必须断开连接。
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
        self.buf.extend_from_slice(chunk);
        let mut frames = Vec::new();
        loop {
            if self.buf.len() < LENGTH_HEADER {
                break;
            }
            let len = read_u32_le(&self.buf) as usize;
            if len > TCP_MAX_PAYLOAD {
                self.buf.clear();
                return Err("frame too large");
            }
            if self.buf.len() < LENGTH_HEADER + len {
                break;
            }
            let frame: Vec<u8> = self.buf[LENGTH_HEADER..LENGTH_HEADER + len].to_vec();
            self.buf.drain(..LENGTH_HEADER + len);
            frames.push(frame);
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_round_trip() {
        let frame = [0x0Au8, 1, 9, 9];
        let inner = encode_cmd(CMD_TCP_SEND, &build_send_body(77, &frame));
        match parse(&inner).unwrap() {
            RelayTcpMsg::Send { dst, frame: f } => {
                assert_eq!(dst, 77);
                assert_eq!(f, frame);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn keepalive_and_register() {
        assert!(matches!(
            parse(&encode_cmd(CMD_TCP_KEEPALIVE, b"")).unwrap(),
            RelayTcpMsg::Keepalive
        ));
        let body = [2u8; 56];
        match parse(&encode_cmd(CMD_REGISTER, &body)).unwrap() {
            RelayTcpMsg::Register { body: b } => assert_eq!(b.len(), 56),
            _ => panic!(),
        }
    }

    #[test]
    fn reject_foreign_magic() {
        assert!(parse(&[0x0A, 1, CMD_TCP_KEEPALIVE]).is_none());
        assert!(parse(&[0x0B, 2, CMD_TCP_KEEPALIVE]).is_none()); // version
    }

    #[test]
    fn reassembler_handles_chunking_and_oversize() {
        let mut r = FrameReassembler::new();
        let mut stream = Vec::new();
        let small = vec![1u8; 10];
        let big = vec![2u8; 70_000]; // crosses the 64 KB path
        write_length_prefixed(&mut stream, &small);
        write_length_prefixed(&mut stream, &big);

        // Feed one byte at a time to exercise partial buffering.
        let mut got = Vec::new();
        for b in &stream {
            got.extend(r.feed(std::slice::from_ref(b)).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], small);
        assert_eq!(got[1], big);

        // 超限帧返回 Err：流边界已不可信，调用方必须断开连接。
        let mut huge = Vec::new();
        write_length_prefixed(&mut huge, &vec![0u8; TCP_MAX_PAYLOAD + 1]);
        assert!(r.feed(&huge).is_err());
        assert!(r.buf.is_empty());
    }
}
