//! 128-bit sliding replay window over the packet counter.
//!
//! Semantics (must stay in lockstep with the wire codec):
//! - first packet: accepted, becomes the window high-water mark;
//! - newer counter: shift the bitmap (clear it entirely on jumps >= 128), accept;
//! - older counter within 128 of the high-water mark: reject if seen, accept and mark otherwise;
//! - older than 128 behind the high-water mark: reject.
//!
//! Additionally tracks (seen_total, lost_total) per generation: the receive-side
//! frame gap estimate used for the admin-facing loss metric. Gaps are charged
//! when the window advances and refunded when a late packet fills the hole.

pub const WINDOW_BITS: u32 = 128;

#[derive(Debug, Default)]
pub struct ReplayWindow {
    bitmap: u128,
    highest: u64,
    initialized: bool,
    /// 本代成功接收的帧数（含迟到补位帧）——链路质量统计的样本数。
    seen_total: u64,
    /// 本代帧流永久缺口估计：窗口推进时按 delta-1 累计，迟到帧补位时扣回。
    /// lost/(seen+lost) 即"该方向帧流中永久丢失的比例"（近似丢包率）。
    lost_total: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.bitmap = 0;
        self.highest = 0;
        self.initialized = false;
        self.seen_total = 0;
        self.lost_total = 0;
    }

    /// (已接收帧数, 永久缺口帧数) —— 供心跳差分计算丢包率。
    pub fn stats(&self) -> (u64, u64) {
        (self.seen_total, self.lost_total)
    }

    pub fn check_and_set(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1;
            self.seen_total += 1;
            return true;
        }
        if seq > self.highest {
            let delta = seq - self.highest;
            // 推进即视为缺口：这些 counter 此刻尚未到达；迟到补位路径会扣回。
            self.lost_total = self.lost_total.saturating_add(delta - 1);
            if delta >= WINDOW_BITS as u64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << delta) | 1;
            }
            self.highest = seq;
            self.seen_total += 1;
            return true;
        }
        let offset = self.highest - seq;
        if offset >= WINDOW_BITS as u64 {
            return false;
        }
        let bit = 1u128 << offset;
        if self.bitmap & bit != 0 {
            return false; // replay
        }
        self.bitmap |= bit;
        // 迟到帧补上推进时预记的缺口位，撤回一次缺口计数。
        self.lost_total = self.lost_total.saturating_sub(1);
        self.seen_total += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        assert!(!w.check_and_set(1000));
    }

    #[test]
    fn in_order_and_duplicates() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(2));
        assert!(w.check_and_set(3));
        assert!(!w.check_and_set(2));
        assert!(!w.check_and_set(3));
    }

    #[test]
    fn reorder_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(3));
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(2));
        assert!(!w.check_and_set(1));
    }

    #[test]
    fn jump_beyond_window_clears() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        assert!(!w.check_and_set(800)); // 200 behind: far past rejected
        assert!(w.check_and_set(1500)); // big jump accepted, window cleared
        assert!(w.check_and_set(1495)); // near-past of new mark accepted
    }

    #[test]
    fn reset_forgets_everything() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(5));
        w.reset();
        assert!(w.check_and_set(5));
        assert_eq!(w.stats(), (1, 0));
    }

    #[test]
    fn continuous_stream_has_zero_gap() {
        let mut w = ReplayWindow::new();
        for seq in 1..=100 {
            assert!(w.check_and_set(seq));
        }
        assert_eq!(w.stats(), (100, 0));
    }

    #[test]
    fn skipped_counter_charged_as_gap() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(2));
        assert!(w.check_and_set(4)); // 3 丢失
        assert_eq!(w.stats(), (3, 1));
    }

    #[test]
    fn late_fill_refunds_gap() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1));
        assert!(w.check_and_set(3)); // 2 预记缺口
        assert_eq!(w.stats(), (2, 1));
        assert!(w.check_and_set(2)); // 迟到补位，撤回
        assert_eq!(w.stats(), (3, 0));
    }

    #[test]
    fn replay_and_far_past_do_not_distort_stats() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        assert!(w.check_and_set(1001));
        assert!(!w.check_and_set(1001)); // 重放
        assert!(!w.check_and_set(700)); // 超窗迟到（缺口已在推进时计入）
        assert_eq!(w.stats(), (2, 0));
    }

    #[test]
    fn big_jump_accumulates_permanent_gap() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_set(1000));
        assert!(w.check_and_set(1500)); // 跳号 500，499 帧缺口永不可补
        assert_eq!(w.stats(), (2, 499));
        assert!(w.check_and_set(1495)); // 新水位近侧迟到帧补回 1
        assert_eq!(w.stats(), (3, 498));
    }
}
