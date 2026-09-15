//! Field-level at-rest sealing for sensitive values inside the otherwise
//! plain-text node configuration file.
//!
//! On Windows the value serializes as `"sealed:<base64(SKF1…DPAPI blob)>"`
//! (LocalMachine scope — the Windows service running as LocalSystem must
//! open files written by the enrolling user). On other platforms the value
//! serializes as plain text (no DPAPI); protect the file with permissions.
//! Deserialization accepts both forms, so files stay portable across
//! re-encryption and platforms.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::secretbox;

const PREFIX: &str = "sealed:";

#[derive(Debug, Clone, Default)]
pub struct Secret(pub String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Secret {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg(windows)]
fn encode(value: &str) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let blob = secretbox::seal(value.as_bytes()).map_err(|e| e.to_string())?;
    Ok(format!("{PREFIX}{}", STANDARD.encode(blob)))
}

fn decode(text: &str) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let Some(b64) = text.strip_prefix(PREFIX) else {
        return Ok(text.to_string()); // legacy/plain form
    };
    let blob = STANDARD.decode(b64).map_err(|e| format!("sealed 字段 base64 无效: {e}"))?;
    // The prefix promises a SKF1 blob; anything else is corruption, not a
    // plain-text passthrough.
    if blob.len() <= 4 || &blob[..4] != b"SKF1" {
        return Err("sealed 字段不是有效的 SKF1 密封块".into());
    }
    let plain = secretbox::unseal(&blob).map_err(|e| e.to_string())?;
    String::from_utf8(plain).map_err(|e| format!("sealed 字段不是 UTF-8: {e}"))
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[cfg(windows)]
        {
            // Never fall back to plain text on failure — a save must not leak.
            match encode(&self.0) {
                Ok(text) => serializer.serialize_str(&text),
                Err(e) => Err(serde::ser::Error::custom(format!("字段密封失败: {e}"))),
            }
        }
        #[cfg(not(windows))]
        {
            serializer.serialize_str(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text)
            .map(Secret)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn round_trip_via_json() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Holder {
            token: Secret,
        }
        let h = Holder { token: Secret::new("skd_secret-value") };
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("sealed:"), "serialized form is sealed: {json}");
        assert!(!json.contains("skd_secret-value"), "plaintext must not leak");
        let back: Holder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token.expose(), "skd_secret-value");
    }

    #[test]
    fn plain_form_accepted() {
        let h: Secret = serde_json::from_str(r#""skd_plain""#).unwrap();
        assert_eq!(h.expose(), "skd_plain");
    }

    #[test]
    fn tampered_sealed_rejected() {
        let json = r#""sealed:QUFBQQ==""#; // garbage blob
        assert!(serde_json::from_str::<Secret>(json).is_err());
    }
}
