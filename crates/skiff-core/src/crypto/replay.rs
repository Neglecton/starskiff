//! 128-bit sliding replay window over the packet counter.
//!
//! Semantics (must stay in lockstep with the wire codec):
//! - first packet: accepted, becomes the window high-water mark;
//! - newer counter: shift the bitmap (clear it entirely on jumps >= 128), accept;
//! - older counter within 128 of the high-water mark: reject if seen, accept and mark otherwise;
//! - older than 128 behind the high-water mark: reject.

pub const WINDOW_BITS: u32 = 128;

#[derive(Debug, Default)]
pub struct ReplayWindow {
    bitmap: u128,
    highest: u64,
    initialized: bool,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.bitmap = 0;
        self.highest = 0;
        self.initialized = false;
    }

    pub fn check_and_set(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest {
            let delta = seq - self.highest;
            if delta >= WINDOW_BITS as u64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << delta) | 1;
            }
            self.highest = seq;
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
    }
}
