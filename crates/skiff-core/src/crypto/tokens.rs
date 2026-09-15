//! Token formats and the fingerprint suffix scheme.
//!
//! Tokens are `<prefix> + base64url(24 random bytes)` without padding. Enroll
//! and admin tokens may carry a `.<64 hex>` suffix pinning the server
//! certificate SHA-256 fingerprint — the token itself is then the
//! out-of-band trust channel for first contact.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::consts::{
    ADMIN_TOKEN_PREFIX, DEVICE_TOKEN_PREFIX, ENROLL_TOKEN_PREFIX, TOKEN_RANDOM_BYTES,
};

/// Random token with the given prefix (skd_/ska_/skk_).
pub fn make_token(prefix: &str) -> String {
    let mut raw = [0u8; TOKEN_RANDOM_BYTES];
    OsRng.fill_bytes(&mut raw);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(raw))
}

pub fn make_device_token() -> String {
    make_token(DEVICE_TOKEN_PREFIX)
}

pub fn make_admin_token() -> String {
    make_token(ADMIN_TOKEN_PREFIX)
}

pub fn make_enroll_token() -> String {
    make_token(ENROLL_TOKEN_PREFIX)
}

/// Lowercase hex of SHA-256 over the UTF-8 bytes of `s`.
pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

pub fn with_fingerprint(bare: &str, fingerprint: &str) -> String {
    format!("{bare}.{fingerprint}")
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Split `tbk-style` token into (bare, fingerprint). The suffix counts only
/// when it is exactly 64 hex characters after the last '.'.
pub fn split_token(token: &str) -> (String, Option<String>) {
    match token.rfind('.') {
        Some(pos) => {
            let (bare, suffix) = token.split_at(pos);
            let suffix = &suffix[1..];
            if is_hex64(suffix) {
                (bare.to_string(), Some(suffix.to_string()))
            } else {
                (token.to_string(), None)
            }
        }
        None => (token.to_string(), None),
    }
}

/// Compare a certificate fingerprint against a pin, case-insensitively.
pub fn matches_pin(actual_hex: &str, pin: &str) -> bool {
    actual_hex.eq_ignore_ascii_case(pin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape() {
        let t = make_enroll_token();
        assert!(t.starts_with("skk_"));
        assert_eq!(t.len(), "skk_".len() + 32); // 24 bytes -> 32 base64 chars
        assert!(!t.contains('=') && !t.contains('+') && !t.contains('/'));
    }

    #[test]
    fn split_behaviour() {
        let fp = "ab".repeat(32);
        let (bare, got) = split_token(&format!("skk_abc.{fp}"));
        assert_eq!(bare, "skk_abc");
        assert_eq!(got.as_deref(), Some(fp.as_str()));

        // Non-hex or wrong-length suffixes are not fingerprints.
        let (bare, got) = split_token("skk_abc.xyz");
        assert_eq!(bare, "skk_abc.xyz");
        assert!(got.is_none());
        let (bare, got) = split_token(&format!("skk_abc.{}", "a".repeat(63)));
        assert!(got.is_none());
        assert_eq!(bare, format!("skk_abc.{}", "a".repeat(63)));
        // Uppercase hex still counts.
        let (_bare, got) = split_token(&format!("skk_abc.{}", "AB".repeat(32)));
        assert_eq!(got.as_deref(), Some("AB".repeat(32).as_str()));
        // Multiple dots: split at the last one.
        let (bare, got) = split_token(&format!("skk_a.b.{fp}"));
        assert_eq!(bare, "skk_a.b");
        assert!(got.is_some());
    }

    #[test]
    fn pin_compare_case_insensitive() {
        assert!(matches_pin("abcdef", "ABCDEF"));
        assert!(!matches_pin("abcdef", "abcdeg"));
    }
}
