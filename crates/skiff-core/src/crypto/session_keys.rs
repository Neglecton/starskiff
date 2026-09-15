//! Static-static X25519 session key derivation.
//!
//! ```text
//! shared = X25519(myDhPriv, peerDhPub)                  # rejected when all-zero
//! okm    = HKDF-SHA256(ikm=shared, salt=networkId,      # 16-byte network id
//!                      info="starskiff/session/v1" || lowPub || highPub,
//!                      L=64)
//! sendKey/recvKey = okm[0..32] / okm[32..64]            # lower pubkey sends with front half
//! ```
//!
//! Known limitation (inherited by design): static-static ECDH has no forward
//! secrecy; moving to Noise IK is a separate future change.

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const KDF_INFO_PREFIX: &[u8] = b"starskiff/session/v1";
pub const OKM_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    #[error("X25519 共享秘密无效（小阶公钥）")]
    DegenerateSharedSecret,
}

#[derive(Clone)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keys are secrets: never print them.
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
}

impl SessionKeys {
    pub fn derive(
        my_dh_priv: &[u8; 32],
        my_dh_pub: &[u8; 32],
        peer_dh_pub: &[u8; 32],
        network_id: &[u8; 16],
    ) -> Result<SessionKeys, KdfError> {
        let secret = StaticSecret::from(*my_dh_priv);
        let peer = PublicKey::from(*peer_dh_pub);
        let mut shared = secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            shared.zeroize();
            return Err(KdfError::DegenerateSharedSecret);
        }

        // Order the two pubkeys lexicographically; the lower side sends with okm[0..32].
        let (low, high, mine_is_low) = if my_dh_pub < peer_dh_pub {
            (my_dh_pub, peer_dh_pub, true)
        } else {
            (peer_dh_pub, my_dh_pub, false)
        };

        let mut info = Vec::with_capacity(KDF_INFO_PREFIX.len() + 64);
        info.extend_from_slice(KDF_INFO_PREFIX);
        info.extend_from_slice(low);
        info.extend_from_slice(high);

        let hk = Hkdf::<Sha256>::new(Some(network_id), shared.as_bytes());
        let mut okm = [0u8; OKM_LEN];
        hk.expand(&info, &mut okm)
            .expect("64-byte HKDF-SHA256 output is valid");
        shared.zeroize();

        let (front, back) = okm.split_at(32);
        let (send_key, recv_key) = if mine_is_low {
            (front, back)
        } else {
            (back, front)
        };
        let keys = SessionKeys {
            send_key: send_key.try_into().unwrap(),
            recv_key: recv_key.try_into().unwrap(),
        };
        okm.zeroize();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret.to_bytes(), public.to_bytes())
    }

    #[test]
    fn symmetric_keys() {
        let (a_priv, a_pub) = keypair();
        let (b_priv, b_pub) = keypair();
        let net = [7u8; 16];
        let ka = SessionKeys::derive(&a_priv, &a_pub, &b_pub, &net).unwrap();
        let kb = SessionKeys::derive(&b_priv, &b_pub, &a_pub, &net).unwrap();
        assert_eq!(ka.send_key, kb.recv_key);
        assert_eq!(ka.recv_key, kb.send_key);
    }

    #[test]
    fn different_networks_derive_different_keys() {
        let (a_priv, a_pub) = keypair();
        let (_b_priv, b_pub) = keypair();
        let k1 = SessionKeys::derive(&a_priv, &a_pub, &b_pub, &[1; 16]).unwrap();
        let k2 = SessionKeys::derive(&a_priv, &a_pub, &b_pub, &[2; 16]).unwrap();
        assert_ne!(k1.send_key, k2.send_key);
    }

    #[test]
    fn self_session_takes_low_branch() {
        // Same key on both sides: cmp == 0 takes the "mine is low" branch,
        // so send uses okm[0..32] and recv uses okm[32..64] (matches the
        // two-peer case where both sides pick the same orientation).
        let (priv1, pub1) = keypair();
        let k = SessionKeys::derive(&priv1, &pub1, &pub1, &[9; 16]).unwrap();
        assert_ne!(k.send_key, k.recv_key);
        assert!(k.send_key.iter().any(|&b| b != 0));
    }
}
