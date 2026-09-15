//! UDP relay control protocol (magic 0x0B).
//!
//! ```text
//! [magic u8 = 0x0B][version u8 = 1][cmd u8][...]
//! REGISTER(1): [deviceId u64 LE][nonce 16B][HMAC-SHA256(relayKey, domain||header||deviceId||nonce) 32B]  (59B total)
//! RELAY(2):    [srcId u64][dstId u64][inner wire frame ...]   (>= 19B, forwarded verbatim)
//! ACK(3):      [ipLen u8][ip ascii][port u16 LE]              (reply to REGISTER)
//! ERROR(4):    [msgLen u8][msg utf-8]                          (truncated to 200 bytes)
//! ```
//!
//! relayKey = SHA-256 of the device token string. The HMAC message is the
//! domain separator followed by the first 11 bytes of the packet, so the MAC
//! covers magic+version+cmd+deviceId+nonce. Comparison is constant-time.

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::endec::{read_u16_le, read_u64_le, write_u16_le, write_u64_le};

pub const RELAY_MAGIC: u8 = 0x0B;
pub const RELAY_VERSION: u8 = 1;

pub const CMD_REGISTER: u8 = 1;
pub const CMD_RELAY: u8 = 2;
pub const CMD_ACK: u8 = 3;
pub const CMD_ERROR: u8 = 4;

pub const REGISTER_DOMAIN: &[u8] = b"starskiff-relay-register";
/// deviceId(8) + nonce(16) + mac(32) — the REGISTER body without the 3-byte header.
pub const REGISTER_BODY_SIZE: usize = 8 + 16 + 32;
pub const REGISTER_PACKET_SIZE: usize = 3 + REGISTER_BODY_SIZE;
pub const ERROR_MSG_MAX: usize = 200;

/// HMAC over the domain separator + everything before the MAC itself
/// (magic + version + cmd + deviceId + nonce = 27 bytes).
fn register_mac(key: &[u8; 32], mac_input: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(REGISTER_DOMAIN);
    mac.update(mac_input);
    mac.finalize().into_bytes().into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build the 59-byte REGISTER packet for the UDP path.
pub fn build_register(device_id: u64, relay_key: &[u8; 32]) -> [u8; REGISTER_PACKET_SIZE] {
    let mut body = Vec::with_capacity(REGISTER_BODY_SIZE);
    write_u64_le(&mut body, device_id);
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    body.extend_from_slice(&nonce);

    let mut mac_input = vec![RELAY_MAGIC, RELAY_VERSION, CMD_REGISTER];
    mac_input.extend_from_slice(&body);
    let mac = register_mac(relay_key, &mac_input);
    body.extend_from_slice(&mac);

    let mut out = [0u8; REGISTER_PACKET_SIZE];
    out[0] = RELAY_MAGIC;
    out[1] = RELAY_VERSION;
    out[2] = CMD_REGISTER;
    out[3..].copy_from_slice(&body);
    out
}

/// Verify a full UDP REGISTER packet (header included).
pub fn verify_register(packet: &[u8], key: &[u8; 32]) -> bool {
    if packet.len() != REGISTER_PACKET_SIZE
        || packet[0] != RELAY_MAGIC
        || packet[1] != RELAY_VERSION
        || packet[2] != CMD_REGISTER
    {
        return false;
    }
    let expected = register_mac(key, &packet[..27]);
    let provided: [u8; 32] = packet[27..59].try_into().unwrap();
    ct_eq(&expected, &provided)
}

/// Verify the TCP variant: the body is the 56 bytes following the 3-byte
/// header; the MAC domain still covers the reconstructed `[0x0B,1,1]` header.
pub fn verify_register_body(body: &[u8], device_id: u64, key: &[u8; 32]) -> bool {
    if body.len() != REGISTER_BODY_SIZE {
        return false;
    }
    let mut mac_input = Vec::with_capacity(27);
    mac_input.extend_from_slice(&[RELAY_MAGIC, RELAY_VERSION, CMD_REGISTER]);
    write_u64_le(&mut mac_input, device_id);
    mac_input.extend_from_slice(&body[8..24]); // nonce
    let expected = register_mac(key, &mac_input);
    let provided: [u8; 32] = body[24..].try_into().unwrap();
    ct_eq(&expected, &provided)
}

/// Extract the 16-byte nonce from a full UDP REGISTER packet (MAC-covered;
/// the server remembers used nonces to reject replays).
pub fn register_nonce(packet: &[u8]) -> Option<[u8; 16]> {
    if packet.len() != REGISTER_PACKET_SIZE {
        return None;
    }
    packet[11..27].try_into().ok()
}

/// Extract the nonce from the 56-byte TCP REGISTER body.
pub fn register_body_nonce(body: &[u8]) -> Option<[u8; 16]> {
    if body.len() != REGISTER_BODY_SIZE {
        return None;
    }
    body[8..24].try_into().ok()
}

/// RELAY packet: the inner wire frame is forwarded verbatim.
pub fn build_relay(src_id: u64, dst_id: u64, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 16 + frame.len());
    out.push(RELAY_MAGIC);
    out.push(RELAY_VERSION);
    out.push(CMD_RELAY);
    write_u64_le(&mut out, src_id);
    write_u64_le(&mut out, dst_id);
    out.extend_from_slice(frame);
    out
}

/// ACK payload without the 3-byte header (also used as the TCP Ack body):
/// `[ipLen u8][ip ascii][port u16 LE]`.
pub fn build_ack_payload(ip: &str, port: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + ip.len());
    out.push(ip.len() as u8);
    out.extend_from_slice(ip.as_bytes());
    write_u16_le(&mut out, port);
    out
}

pub fn build_ack_packet(ip: &str, port: u16) -> Vec<u8> {
    let mut out = vec![RELAY_MAGIC, RELAY_VERSION, CMD_ACK];
    out.extend_from_slice(&build_ack_payload(ip, port));
    out
}

pub fn build_error_packet(msg: &str) -> Vec<u8> {
    let bytes = msg.as_bytes();
    let len = bytes.len().min(ERROR_MSG_MAX);
    let mut out = vec![RELAY_MAGIC, RELAY_VERSION, CMD_ERROR, len as u8];
    out.extend_from_slice(&bytes[..len]);
    out
}

/// Parsed control packet variants (REGISTER / RELAY / ACK / ERROR).
#[derive(Debug)]
pub enum RelayPacket<'a> {
    Register { device_id: u64 },
    Relay { src: u64, dst: u64, frame: &'a [u8] },
    Ack { ip: String, port: u16 },
    Error { msg: String },
}

pub fn parse(packet: &[u8]) -> Option<RelayPacket<'_>> {
    if packet.len() < 4 || packet[0] != RELAY_MAGIC || packet[1] != RELAY_VERSION {
        return None;
    }
    match packet[2] {
        CMD_REGISTER => {
            if packet.len() != REGISTER_PACKET_SIZE {
                return None;
            }
            Some(RelayPacket::Register {
                device_id: read_u64_le(&packet[3..]),
            })
        }
        CMD_RELAY => {
            if packet.len() < 19 {
                return None;
            }
            Some(RelayPacket::Relay {
                src: read_u64_le(&packet[3..]),
                dst: read_u64_le(&packet[11..]),
                frame: &packet[19..],
            })
        }
        CMD_ACK => {
            let ip_len = packet[3] as usize;
            if packet.len() < 4 + ip_len + 2 {
                return None;
            }
            let ip = std::str::from_utf8(&packet[4..4 + ip_len])
                .ok()?
                .to_string();
            let port = read_u16_le(&packet[4 + ip_len..]);
            Some(RelayPacket::Ack { ip, port })
        }
        CMD_ERROR => {
            let msg_len = packet[3] as usize;
            if packet.len() < 4 + msg_len {
                return None;
            }
            let msg = String::from_utf8_lossy(&packet[4..4 + msg_len]).into_owned();
            Some(RelayPacket::Error { msg })
        }
        _ => None,
    }
}

/// SHA-256 relay key derived from the device token string (raw digest bytes).
pub fn relay_key_from_token(device_token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(device_token.as_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trip_and_auth() {
        let key = relay_key_from_token("skd_test-token");
        let pkt = build_register(41, &key);
        assert_eq!(pkt.len(), 59);
        assert!(verify_register(&pkt, &key));
        let bad = relay_key_from_token("skd_other");
        assert!(!verify_register(&pkt, &bad));
        // Single-bit flip breaks the MAC.
        let mut tampered = pkt;
        tampered[5] ^= 1;
        assert!(!verify_register(&tampered, &key));
        // Parse extracts the device id.
        match parse(&pkt).unwrap() {
            RelayPacket::Register { device_id } => assert_eq!(device_id, 41),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn register_body_tcp_variant() {
        let key = relay_key_from_token("skd_x");
        let pkt = build_register(77, &key);
        let body = &pkt[3..];
        assert_eq!(body.len(), REGISTER_BODY_SIZE);
        assert!(verify_register_body(body, 77, &key));
        assert!(!verify_register_body(body, 78, &key)); // device id covered by MAC
    }

    #[test]
    fn nonce_extraction() {
        let key = relay_key_from_token("skd_n");
        let pkt = build_register(5, &key);
        let body = &pkt[3..];
        assert_eq!(register_nonce(&pkt).unwrap(), register_body_nonce(body).unwrap());
        assert!(register_nonce(&pkt[..40]).is_none());
        assert!(register_body_nonce(&body[..40]).is_none());
    }

    #[test]
    fn relay_round_trip() {
        let inner = [0x0Au8, 1, 2, 3, 4];
        let pkt = build_relay(41, 42, &inner);
        match parse(&pkt).unwrap() {
            RelayPacket::Relay { src, dst, frame } => {
                assert_eq!(src, 41);
                assert_eq!(dst, 42);
                assert_eq!(frame, inner);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn ack_round_trip() {
        let pkt = build_ack_packet("203.0.113.7", 51820);
        match parse(&pkt).unwrap() {
            RelayPacket::Ack { ip, port } => {
                assert_eq!(ip, "203.0.113.7");
                assert_eq!(port, 51820);
            }
            _ => panic!("wrong variant"),
        }
        // Payload variant matches the TCP Ack body layout.
        assert_eq!(build_ack_payload("1.2.3.4", 99), {
            let mut v = vec![7];
            v.extend_from_slice(b"1.2.3.4");
            v.extend_from_slice(&99u16.to_le_bytes());
            v
        });
    }

    #[test]
    fn error_round_trip_and_truncation() {
        let short = build_error_packet("boom");
        match parse(&short).unwrap() {
            RelayPacket::Error { msg } => assert_eq!(msg, "boom"),
            _ => panic!(),
        }
        let long = build_error_packet(&"x".repeat(300));
        assert_eq!(long.len(), 4 + 200);
    }
}
