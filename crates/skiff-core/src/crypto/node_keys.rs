//! Long-term node identity keys: Ed25519 (reserved for future signing use)
//! plus the X25519 static pair used for session key agreement.
//! Stored in node.json as lowercase hex.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct NodeKeys {
    /// Ed25519 seed (32 bytes; the expanded 64-byte form is derived on use).
    pub sign_secret: [u8; 32],
    pub sign_public: [u8; 32],
    pub dh_secret: [u8; 32],
    pub dh_public: [u8; 32],
}

impl NodeKeys {
    pub fn generate() -> NodeKeys {
        let signing = SigningKey::generate(&mut OsRng);
        let dh_secret = StaticSecret::random_from_rng(OsRng);
        let dh_public = PublicKey::from(&dh_secret);
        NodeKeys {
            sign_secret: signing.to_bytes(),
            sign_public: signing.verifying_key().to_bytes(),
            dh_secret: dh_secret.to_bytes(),
            dh_public: dh_public.to_bytes(),
        }
    }

    pub fn sign_public_hex(&self) -> String {
        hex::encode(self.sign_public)
    }

    pub fn dh_public_hex(&self) -> String {
        hex::encode(self.dh_public)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_hex_round_trip() {
        let k = NodeKeys::generate();
        assert_eq!(k.sign_public.len(), 32);
        assert_eq!(k.sign_secret.len(), 32);
        assert_eq!(k.dh_public.len(), 32);
        assert_eq!(k.dh_secret.len(), 32);
        assert_eq!(hex::decode(k.sign_public_hex()).unwrap(), k.sign_public);
        assert_eq!(hex::decode(k.dh_public_hex()).unwrap(), k.dh_public);
        // Seed expands to the matching public key.
        let signing = SigningKey::from_bytes(&k.sign_secret);
        assert_eq!(signing.verifying_key().to_bytes(), k.sign_public);
    }

    #[test]
    fn dh_pair_is_valid() {
        let k = NodeKeys::generate();
        let secret = StaticSecret::from(k.dh_secret);
        assert_eq!(PublicKey::from(&secret).to_bytes(), k.dh_public);
    }
}
