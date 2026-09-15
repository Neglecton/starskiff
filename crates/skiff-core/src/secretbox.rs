//! Local at-rest sealing for node identity files.
//!
//! Layout: `"SKF1"` (4 bytes) || DPAPI blob (LocalMachine scope, entropy
//! `"starskiff.NodeState.v1"`). LocalMachine — not CurrentUser — because the
//! Windows service runs as LocalSystem and must open files written by the
//! enrolling user. Non-Windows platforms store plaintext by design and refuse
//! to open sealed blobs; identity files are not portable across OSes.

#[derive(Debug, thiserror::Error)]
pub enum SecretBoxError {
    #[error("无法加密身份文件（DPAPI Protect 失败）")]
    EncryptFailed,
    #[error("无法解密身份文件（DPAPI 密钥或熵不匹配）：请在本机重新 enroll")]
    DecryptFailed,
    #[error("此平台不支持打开密封的身份文件（文件由 Windows 机器加密）")]
    UnsupportedPlatform,
    #[error("身份文件损坏")]
    Corrupt,
}

#[cfg(windows)]
mod imp {
    use super::*;

    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CryptProtectData, CryptUnprotectData,
    };
    use windows::core::PCWSTR;

    const MAGIC: &[u8; 4] = b"SKF1";
    const ENTROPY: &[u8] = b"starskiff.NodeState.v1";

    fn blob_from(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: bytes.len() as u32,
            pbData: bytes.as_ptr() as *mut u8,
        }
    }

    unsafe fn take_blob(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        unsafe {
            let out = std::slice::from_raw_parts(blob.pbData, blob.cbData as usize).to_vec();
            let _ = LocalFree(Some(HLOCAL(blob.pbData as *mut _)));
            out
        }
    }

    pub fn seal(plain: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
        unsafe {
            let entropy = blob_from(ENTROPY);
            let mut out = std::mem::zeroed::<CRYPT_INTEGER_BLOB>();
            let ok = CryptProtectData(
                &blob_from(plain),
                PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            );
            if ok.is_err() {
                return Err(SecretBoxError::EncryptFailed);
            }
            let mut result = MAGIC.to_vec();
            result.extend_from_slice(&take_blob(out));
            Ok(result)
        }
    }

    pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
        if !is_sealed(blob) {
            return Ok(blob.to_vec());
        }
        let sealed = &blob[4..];
        unsafe {
            let entropy = blob_from(ENTROPY);
            let mut out = std::mem::zeroed::<CRYPT_INTEGER_BLOB>();
            let ok = CryptUnprotectData(
                &blob_from(sealed),
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            );
            if ok.is_err() {
                return Err(SecretBoxError::DecryptFailed);
            }
            Ok(take_blob(out))
        }
    }

    pub fn is_sealed(blob: &[u8]) -> bool {
        blob.len() > 4 && &blob[..4] == MAGIC
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn seal(plain: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
        Ok(plain.to_vec())
    }

    pub fn unseal(blob: &[u8]) -> Result<Vec<u8>, SecretBoxError> {
        if is_sealed(blob) {
            Err(SecretBoxError::UnsupportedPlatform)
        } else {
            Ok(blob.to_vec())
        }
    }

    pub fn is_sealed(_blob: &[u8]) -> bool {
        false
    }
}

pub use imp::{is_sealed, seal, unseal};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn round_trip_and_tamper() {
        let plain = b"{\"secret\":\"skd_token_value\"}";
        let sealed = seal(plain).unwrap();
        assert!(is_sealed(&sealed));
        assert!(!sealed.windows(plain.len()).any(|w| w == plain));
        assert_eq!(unseal(&sealed).unwrap(), plain);

        let mut tampered = sealed.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 1;
        assert!(unseal(&tampered).is_err());

        // Plaintext passthrough (legacy files).
        assert_eq!(unseal(plain).unwrap(), plain);
    }

    #[test]
    #[cfg(not(windows))]
    fn passthrough_and_refuse_sealed() {
        let plain = b"plain-bytes";
        assert_eq!(seal(plain).unwrap(), plain);
        assert_eq!(unseal(plain).unwrap(), plain);
        let mut sealed = b"SKF1".to_vec();
        sealed.extend_from_slice(b"dpapi-blob");
        assert!(matches!(
            unseal(&sealed),
            Err(SecretBoxError::UnsupportedPlatform)
        ));
    }
}
