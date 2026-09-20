//! Encrypted wire frame (magic 0x0A) and its AEAD codec.
//!
//! ```text
//! [magic u8 = 0x0A][version u8 = 2][senderId u64 LE][type u8][nonce 24B][ciphertext || tag 16B]
//! ```
//!
//! - type: 1 = PING, 2 = PONG, 3 = DATA (raw IPv4 packet), 4 = FLOW (user-space streams)
//! - nonce = 16B per-process random bootNonce || 8B LE send counter (starts at 1)
//! - AEAD: XChaCha20-Poly1305 with the 11-byte clear header (magic, version,
//!   senderId, type) as AAD — the header is readable by relays but not
//!   forgeable: flipping any header bit fails authentication. Without this a
//!   captured frame's type could be rewritten (e.g. PING→PONG) to hijack the
//!   direct path (version 2; version 1 frames are silently dropped)
//! - replay: 128-bit sliding window over the counter per boot nonce; the last
//!   few generations of boot nonces keep their watermarks, so replaying a
//!   frame from an earlier generation cannot reset the window (flip attack)
//!
//! The magic byte must stay inside 0x04..=0x13 to stay clear of STUN (0x00-0x03),
//! DTLS/TLS (0x14-0x19), IKE (0x21+), QUIC (0x40-0xFF) and ASCII protocols.

use std::collections::VecDeque;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

use crate::crypto::replay::ReplayWindow;
use crate::crypto::session_keys::SessionKeys;
use crate::endec::{read_u64_le, write_u64_le};

pub const WIRE_MAGIC: u8 = 0x0A;
pub const WIRE_VERSION: u8 = 2;
pub const BOOT_NONCE_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
/// magic + version + senderId + type + nonce.
pub const FIXED_HEADER: usize = 1 + 1 + 8 + 1 + NONCE_SIZE;
/// 进入 AEAD 认证的明文头长度（magic + version + senderId + type）。
pub const AAD_HEADER: usize = 11;
/// 每个 codec 保留的 bootNonce 代数（每代一个重放窗口水位）。对端重启
/// 换新 nonce 开新代；只有最新代接受帧，旧代仅用于识别并拒绝重放。
/// 超过代数后被淘汰的 nonce 会再次被当作新代——需要攻击者持有超过
/// 这么多次对端重启之前的抓包，现实中不可行；代数只需覆盖合理次数的
/// 重启。
pub const BOOT_NONCE_GENERATIONS: usize = 32;

pub const FRAME_PING: u8 = 1;
pub const FRAME_PONG: u8 = 2;
pub const FRAME_DATA: u8 = 3;
pub const FRAME_FLOW: u8 = 4;

pub fn frame_type_is_valid(t: u8) -> bool {
    (FRAME_PING..=FRAME_FLOW).contains(&t)
}

/// Header fields borrowed from a raw (still encrypted) packet.
#[derive(Debug, Clone, Copy)]
pub struct RawFrame<'a> {
    pub sender_id: u64,
    pub frame_type: u8,
    /// 24-byte nonce = bootNonce(16) || counter LE(8).
    pub nonce: &'a [u8; NONCE_SIZE],
    /// Ciphertext including the trailing 16-byte tag.
    pub ciphertext: &'a [u8],
}

impl RawFrame<'_> {
    pub fn counter(&self) -> u64 {
        read_u64_le(&self.nonce[BOOT_NONCE_SIZE..])
    }

    /// Length-, magic-, version- and type-checked parse.
    pub fn try_parse(packet: &[u8]) -> Option<RawFrame<'_>> {
        if packet.len() < FIXED_HEADER + TAG_SIZE {
            return None;
        }
        if packet[0] != WIRE_MAGIC || packet[1] != WIRE_VERSION {
            return None;
        }
        let frame_type = packet[10];
        if !frame_type_is_valid(frame_type) {
            return None;
        }
        let sender_id = read_u64_le(&packet[2..]);
        let nonce: &[u8; NONCE_SIZE] = packet[11..FIXED_HEADER].try_into().ok()?;
        Some(RawFrame {
            sender_id,
            frame_type,
            nonce,
            ciphertext: &packet[FIXED_HEADER..],
        })
    }
}

struct CodecState {
    /// 最近 N 代 (bootNonce, 重放窗口)。当前代在队尾；旧代保留水位，
    /// 对端短暂消失后 peer 会话重建也不会丢窗口。
    generations: VecDeque<([u8; BOOT_NONCE_SIZE], ReplayWindow)>,
    /// 已淘汰代的接收统计累计（帧数/缺口数），stats() 聚合时并入——
    /// 丢包率差分窗口不应因代淘汰（对端多次重启）而丢失历史样本。
    retired_seen: u64,
    retired_lost: u64,
}

/// Per-peer, per-direction AEAD codec. Clone-safe: cloning shares no state.
pub struct PacketCodec {
    keys: SessionKeys,
    boot_nonce: [u8; BOOT_NONCE_SIZE],
    send_counter: u64,
    state: Mutex<CodecState>,
}

impl PacketCodec {
    pub fn new(keys: SessionKeys) -> PacketCodec {
        let mut boot_nonce = [0u8; BOOT_NONCE_SIZE];
        OsRng.fill_bytes(&mut boot_nonce);
        PacketCodec {
            keys,
            boot_nonce,
            send_counter: 0,
            state: Mutex::new(CodecState {
                generations: VecDeque::new(),
                retired_seen: 0,
                retired_lost: 0,
            }),
        }
    }

    pub fn seal(&mut self, sender_id: u64, frame_type: u8, payload: &[u8]) -> Vec<u8> {
        self.send_counter += 1; // first sealed frame uses counter = 1
        let mut out = Vec::with_capacity(FIXED_HEADER + payload.len() + TAG_SIZE);
        out.push(WIRE_MAGIC);
        out.push(WIRE_VERSION);
        write_u64_le(&mut out, sender_id);
        out.push(frame_type);
        out.extend_from_slice(&self.boot_nonce);
        write_u64_le(&mut out, self.send_counter);
        let nonce = XNonce::from_slice(&out[11..FIXED_HEADER]);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.keys.send_key));
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: payload,
                    // 明文头纳入 AAD：头部对中继可见但不可篡改。
                    aad: &out[..AAD_HEADER],
                },
            )
            .expect("XChaCha20-Poly1305 encryption never fails");
        out.extend_from_slice(&sealed);
        out
    }

    /// Decrypt + replay-check a raw packet. `None` on any malformed,
    /// replayed or unauthenticated input (callers drop silently).
    ///
    /// Invariant: the AEAD decryption runs BEFORE any replay-window state is
    /// touched. A failed decryption (wrong key, forgery) must leave zero
    /// side effects — the engine tries multiple per-network codecs for the
    /// same sender and relies on this being side-effect free. Replayed
    /// frames decrypt fine and are then rejected by the window.
    pub fn try_open(&self, packet: &[u8]) -> Option<(u64, u8, Vec<u8>)> {
        let frame = RawFrame::try_parse(packet)?;
        let peer_boot: [u8; BOOT_NONCE_SIZE] = frame.nonce[..BOOT_NONCE_SIZE].try_into().ok()?;
        let counter = frame.counter();

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.keys.recv_key));
        let nonce = XNonce::from_slice(frame.nonce);
        let plain = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: frame.ciphertext,
                    aad: &packet[..AAD_HEADER],
                },
            )
            .ok()?;

        let mut state = self.state.lock().unwrap();
        // 按 bootNonce 找对应代；未见过的 nonce 视为对端重启（或首包），
        // 开新代并保留旧代水位。
        let is_current = match state.generations.iter().position(|(nb, _)| *nb == peer_boot) {
            Some(i) => i + 1 == state.generations.len(),
            None => {
                state.generations.push_back((peer_boot, ReplayWindow::new()));
                if state.generations.len() > BOOT_NONCE_GENERATIONS
                    && let Some((_, retired)) = state.generations.pop_front()
                {
                    let (seen, lost) = retired.stats();
                    state.retired_seen += seen;
                    state.retired_lost += lost;
                }
                true
            }
        };
        // 旧代帧一律拒绝：已被更新的代超越，只可能是重放或重启前的迟到
        // 帧（内容先于对端重启，丢弃无碍上层——TCP 流会重传、UDP 本就
        // 允许丢）。这同时封死“重放旧代帧翻转窗口”与跨重启延迟注入。
        if !is_current {
            return None;
        }
        let window = &mut state.generations.back_mut().unwrap().1;
        if !window.check_and_set(counter) {
            return None; // 当前代内重放
        }
        Some((frame.sender_id, frame.frame_type, plain))
    }

    /// 累计接收统计 (帧数, 永久缺口帧数)，跨代持续——心跳差分即得
    /// 本方向帧缺口率（丢包率）。只读原子安全：不触碰密钥状态。
    pub fn stats(&self) -> (u64, u64) {
        let state = self.state.lock().unwrap();
        let (mut seen, mut lost) = (state.retired_seen, state.retired_lost);
        for (_, w) in &state.generations {
            let (s, l) = w.stats();
            seen += s;
            lost += l;
        }
        (seen, lost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionKeys;
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn codec_pair() -> (PacketCodec, PacketCodec) {
        let a = StaticSecret::random_from_rng(OsRng);
        let b = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a);
        let b_pub = PublicKey::from(&b);
        let net = [42u8; 16];
        let ka =
            SessionKeys::derive(&a.to_bytes(), &a_pub.to_bytes(), &b_pub.to_bytes(), &net).unwrap();
        let kb =
            SessionKeys::derive(&b.to_bytes(), &b_pub.to_bytes(), &a_pub.to_bytes(), &net).unwrap();
        (PacketCodec::new(ka), PacketCodec::new(kb))
    }

    #[test]
    fn seal_open_round_trip() {
        let (mut a, b) = codec_pair();
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let sealed = a.seal(0xAABB, FRAME_DATA, &payload);
        let (sender, ty, plain) = b.try_open(&sealed).unwrap();
        assert_eq!(sender, 0xAABB);
        assert_eq!(ty, FRAME_DATA);
        assert_eq!(plain, payload);
    }

    #[test]
    fn counter_starts_at_one() {
        let (mut a, b) = codec_pair();
        let sealed = a.seal(1, FRAME_PING, &[0u8; 8]);
        let f = RawFrame::try_parse(&sealed).unwrap();
        assert_eq!(f.counter(), 1);
        assert!(b.try_open(&sealed).is_some());
    }

    #[test]
    fn replay_rejected() {
        let (mut a, b) = codec_pair();
        let sealed = a.seal(7, FRAME_DATA, b"hello");
        assert!(b.try_open(&sealed).is_some());
        assert!(b.try_open(&sealed).is_none());
    }

    #[test]
    fn wrong_key_rejected() {
        let (mut a, _) = codec_pair();
        let (_, other) = codec_pair();
        let sealed = a.seal(7, FRAME_DATA, b"hello");
        assert!(other.try_open(&sealed).is_none());
    }

    #[test]
    fn tampered_packet_rejected() {
        let (mut a, b) = codec_pair();
        let mut sealed = a.seal(7, FRAME_DATA, b"hello");
        let n = sealed.len();
        sealed[n - 1] ^= 1;
        assert!(b.try_open(&sealed).is_none());
    }

    #[test]
    fn reorder_within_window_accepted() {
        let (mut a, b) = codec_pair();
        let f1 = a.seal(1, FRAME_PING, &[1; 8]);
        let f2 = a.seal(1, FRAME_PING, &[2; 8]);
        let f3 = a.seal(1, FRAME_PING, &[3; 8]);
        assert!(b.try_open(&f3).is_some());
        assert!(b.try_open(&f1).is_some());
        assert!(b.try_open(&f2).is_some());
        assert!(b.try_open(&f2).is_none()); // duplicate
    }

    #[test]
    fn boot_nonce_change_resets_window() {
        // Two codecs sharing b's key material but with different boot nonces.
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a_secret);
        let b_pub = PublicKey::from(&b_secret);
        let net = [3u8; 16];
        let ka = SessionKeys::derive(
            &a_secret.to_bytes(),
            &a_pub.to_bytes(),
            &b_pub.to_bytes(),
            &net,
        )
        .unwrap();
        let kb = SessionKeys::derive(
            &b_secret.to_bytes(),
            &b_pub.to_bytes(),
            &a_pub.to_bytes(),
            &net,
        )
        .unwrap();

        let ka_restart = ka.clone();
        let mut a = PacketCodec::new(ka);
        let b = PacketCodec::new(kb);
        for i in 0..200u64 {
            let _ = b.try_open(&a.seal(9, FRAME_DATA, &i.to_le_bytes()));
        }
        // Peer restart: fresh codec (same keys, new boot nonce) reuses low
        // counters; the new generation gets a fresh window so those frames
        // are accepted.
        let mut a_restarted = PacketCodec::new(ka_restart);
        let early = a_restarted.seal(9, FRAME_DATA, b"early"); // counter 1
        assert!(b.try_open(&early).is_some());
    }

    #[test]
    fn old_generation_frame_not_replayable_after_restart() {
        // 翻转攻击：持有两个 bootNonce 时代的抓包，对端重启后重放旧代帧。
        // 多代水位保证旧代帧被拒，且与新代帧交替到达也无法重置窗口。
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a_secret);
        let b_pub = PublicKey::from(&b_secret);
        let net = [5u8; 16];
        let ka = SessionKeys::derive(
            &a_secret.to_bytes(),
            &a_pub.to_bytes(),
            &b_pub.to_bytes(),
            &net,
        )
        .unwrap();
        let kb = SessionKeys::derive(
            &b_secret.to_bytes(),
            &b_pub.to_bytes(),
            &a_pub.to_bytes(),
            &net,
        )
        .unwrap();

        let ka_restart = ka.clone();
        let mut a_old = PacketCodec::new(ka);
        let b = PacketCodec::new(kb);
        let old1 = a_old.seal(9, FRAME_DATA, b"old-1");
        let old2 = a_old.seal(9, FRAME_DATA, b"old-2");
        assert!(b.try_open(&old1).is_some());

        // 对端重启，新代流量到来。
        let mut a_new = PacketCodec::new(ka_restart);
        let fresh1 = a_new.seal(9, FRAME_DATA, b"new-1");
        assert!(b.try_open(&fresh1).is_some());

        // 旧代帧重放必须被拒（旧代窗口保留水位）。
        assert!(b.try_open(&old1).is_none());
        // 旧代里未接收过的 counter 也被拒：该代已被超越，不接受新帧。
        assert!(b.try_open(&old2).is_none());

        // 新旧交替也不能翻转。
        let fresh2 = a_new.seal(9, FRAME_DATA, b"new-2");
        assert!(b.try_open(&fresh2).is_some());
        assert!(b.try_open(&old2).is_none());
    }

    #[test]
    fn header_tamper_rejected() {
        // 明文头纳入 AAD：篡改 type/senderId 任一位认证失败——防止
        // DATA↔FLOW↔PONG 类型混淆与 PONG 伪造路径劫持。
        let (mut a, b) = codec_pair();
        let mut sealed = a.seal(7, FRAME_PING, &[0u8; 8]);
        sealed[10] = FRAME_PONG; // type: PING -> PONG
        assert!(b.try_open(&sealed).is_none());

        let mut sealed2 = a.seal(7, FRAME_PING, &[0u8; 8]);
        sealed2[2] ^= 1; // senderId 最低位
        assert!(b.try_open(&sealed2).is_none());

        let mut sealed3 = a.seal(7, FRAME_PING, &[0u8; 8]);
        sealed3[0] ^= 1; // magic
        assert!(RawFrame::try_parse(&sealed3).is_none());
        assert!(b.try_open(&sealed3).is_none());
    }

    #[test]
    fn version_one_frame_rejected() {
        // 版本 2 起帧头进入 AAD，与版本 1 帧不互通：静默丢弃。
        let (mut a, b) = codec_pair();
        let mut sealed = a.seal(7, FRAME_DATA, b"hello");
        sealed[1] = 1;
        assert!(RawFrame::try_parse(&sealed).is_none());
        assert!(b.try_open(&sealed).is_none());
    }

    #[test]
    fn wrong_key_probe_leaves_no_trace() {
        // Multi-network engines try several codecs for the same sender; a
        // failed decryption must not consume replay-window state.
        let (mut a, b) = codec_pair();
        let sealed = a.seal(7, FRAME_DATA, b"hello");
        let (_, other) = codec_pair();

        // Probe with the wrong codec first (must fail silently)...
        assert!(other.try_open(&sealed).is_none());
        // ...then the right codec must still accept counter=1.
        assert!(b.try_open(&sealed).is_some());
        // And the replay protection on the correct codec is intact.
        assert!(b.try_open(&sealed).is_none());
    }

    #[test]
    fn garbage_rejected() {
        let (_, b) = codec_pair();
        assert!(b.try_open(&[]).is_none());
        assert!(b.try_open(&[0u8; 34]).is_none());
        let mut bad_magic = [0u8; 60];
        bad_magic[0] = WIRE_MAGIC;
        bad_magic[1] = WIRE_VERSION;
        bad_magic[10] = 99; // invalid type
        assert!(b.try_open(&bad_magic).is_none());
        let mut bad_ver = [0u8; 60];
        bad_ver[0] = WIRE_MAGIC;
        bad_ver[1] = WIRE_VERSION + 1;
        assert!(b.try_open(&bad_ver).is_none());
    }

    #[test]
    fn gap_stats_reflect_dropped_frames() {
        // 帧流丢中间一帧（counter 跳号）计入缺口；迟到补位撤回。
        let (mut a, b) = codec_pair();
        let f1 = a.seal(7, FRAME_DATA, b"1");
        let f2 = a.seal(7, FRAME_DATA, b"2");
        let f3 = a.seal(7, FRAME_DATA, b"3");
        assert!(b.try_open(&f1).is_some());
        assert!(b.try_open(&f3).is_some()); // f2 "丢失"
        assert_eq!(b.stats(), (2, 1));
        assert!(b.try_open(&f2).is_some()); // 迟到补位
        assert_eq!(b.stats(), (3, 0));
    }

    #[test]
    fn generation_switch_not_counted_as_gap() {
        // 对端重启换 bootNonce：新代首包成为新水位，不得计成大跳缺口。
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a_secret);
        let b_pub = PublicKey::from(&b_secret);
        let net = [7u8; 16];
        let ka = SessionKeys::derive(&a_secret.to_bytes(), &a_pub.to_bytes(), &b_pub.to_bytes(), &net)
            .unwrap();
        let kb = SessionKeys::derive(&b_secret.to_bytes(), &b_pub.to_bytes(), &a_pub.to_bytes(), &net)
            .unwrap();

        let ka_restart = ka.clone();
        let mut a1 = PacketCodec::new(ka);
        let b = PacketCodec::new(kb);
        for i in 1..=3u64 {
            assert!(b.try_open(&a1.seal(7, FRAME_DATA, &i.to_le_bytes())).is_some());
        }
        let mut a2 = PacketCodec::new(ka_restart); // 新代 counter 从 1 重新开始
        for i in 1..=2u64 {
            assert!(b.try_open(&a2.seal(7, FRAME_DATA, &i.to_le_bytes())).is_some());
        }
        assert_eq!(b.stats(), (5, 0));
    }

    #[test]
    fn stats_survive_generation_eviction() {
        // 旧代（含缺口）被代数上限淘汰后，统计并入 retired，差分口径不丢历史。
        let a_secret = StaticSecret::random_from_rng(OsRng);
        let b_secret = StaticSecret::random_from_rng(OsRng);
        let a_pub = PublicKey::from(&a_secret);
        let b_pub = PublicKey::from(&b_secret);
        let net = [9u8; 16];
        let ka = SessionKeys::derive(&a_secret.to_bytes(), &a_pub.to_bytes(), &b_pub.to_bytes(), &net)
            .unwrap();
        let kb = SessionKeys::derive(&b_secret.to_bytes(), &b_pub.to_bytes(), &a_pub.to_bytes(), &net)
            .unwrap();

        let mut a0 = PacketCodec::new(ka.clone());
        let b = PacketCodec::new(kb);
        let f1 = a0.seal(7, FRAME_DATA, b"1");
        a0.seal(7, FRAME_DATA, b"2"); // f2 不发送：制造缺口
        let f3 = a0.seal(7, FRAME_DATA, b"3");
        assert!(b.try_open(&f1).is_some());
        assert!(b.try_open(&f3).is_some()); // 缺口 1
        assert_eq!(b.stats(), (2, 1));

        // 超过 BOOT_NONCE_GENERATIONS 次重启，把首代淘汰出窗口。
        for _ in 0..BOOT_NONCE_GENERATIONS {
            let mut a = PacketCodec::new(ka.clone());
            assert!(b.try_open(&a.seal(7, FRAME_DATA, b"x")).is_some());
        }
        // 首代 (2,1) + 32 个新代各 1 帧。
        assert_eq!(b.stats(), (2 + BOOT_NONCE_GENERATIONS as u64, 1));
    }

    #[test]
    fn magic_range_assertion() {
        // Discrimination design: both magics live in 0x04..=0x13 and differ.
        assert!((0x04..=0x13).contains(&WIRE_MAGIC));
        assert!((0x04..=0x13).contains(&super::super::relay_udp::RELAY_MAGIC));
        assert_ne!(WIRE_MAGIC, super::super::relay_udp::RELAY_MAGIC);
    }
}
