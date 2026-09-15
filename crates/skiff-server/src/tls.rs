//! Server TLS: self-signed ECDSA P-256 certificate (rcgen/ring), persisted
//! as PEM in the settings table. The SHA-256 fingerprint of the certificate
//! DER is the identity anchor embedded in enroll tokens.

use std::path::Path;
use std::sync::Arc;

use sha2::Digest;

use crate::repo::Repo;

pub const CERT_CN: &str = "starskiff-server";
const SETTING_KEY: &str = "tls_pem";

pub struct ServerCert {
    pub tls_config: rustls::ServerConfig,
    pub fingerprint: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("证书文件读取失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("证书格式无效：{0}")]
    Parse(String),
    #[error("证书生成失败：{0}")]
    Generate(String),
}

/// SHA-256 of the certificate DER, lowercase hex.
pub fn fingerprint_of_cert_der(der: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(der);
    hex::encode(h.finalize())
}

fn build_server_config(cert_pem: &str, key_pem: &str) -> Result<rustls::ServerConfig, CertError> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<_, _>>()
            .map_err(|e| CertError::Parse(format!("certificate: {e}")))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| CertError::Parse(format!("private key: {e}")))?
        .ok_or_else(|| CertError::Parse("private key missing".into()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| CertError::Parse(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| CertError::Parse(e.to_string()))
}

/// Resolution order: explicit PEM files, then the
/// persisted `tls_pem` setting, then generate-and-persist.
pub fn load_or_generate(
    repo: &Repo,
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
) -> Result<ServerCert, CertError> {
    let (cert_pem, key_pem, persist) = if let (Some(cf), Some(kf)) = (cert_file, key_file) {
        (
            std::fs::read_to_string(cf)?,
            std::fs::read_to_string(kf)?,
            false,
        )
    } else if let Some(stored) = repo
        .get_setting(SETTING_KEY)
        .map_err(|e| CertError::Parse(e.to_string()))?
    {
        // Stored as one blob: certificate PEM followed by private key PEM.
        let (cert, key) = split_pem_bundle(&stored)
            .ok_or_else(|| CertError::Parse("stored tls_pef corrupt".into()))?;
        (cert, key, false)
    } else {
        let (cert, key) = generate_self_signed()?;
        (cert, key, true)
    };

    let config = build_server_config(&cert_pem, &key_pem)?;
    let der = pem_certificate_der(&cert_pem)?;
    let fingerprint = fingerprint_of_cert_der(&der);
    if persist {
        // Best-effort persistence: regenerated next start on failure.
        let _ = repo.set_setting(SETTING_KEY, &format!("{cert_pem}{key_pem}"));
    }
    Ok(ServerCert {
        tls_config: config,
        fingerprint,
    })
}

fn split_pem_bundle(blob: &str) -> Option<(String, String)> {
    let cert_end = blob.find("-----END CERTIFICATE-----")?;
    let key_begin = blob[cert_end + 1..].find("-----BEGIN")? + cert_end + 1;
    let cert = blob[..cert_end + "-----END CERTIFICATE-----".len()].to_string() + "\n";
    let key = blob[key_begin..].to_string();
    Some((cert, key))
}

/// First certificate block decoded to DER (for fingerprinting).
fn pem_certificate_der(cert_pem: &str) -> Result<Vec<u8>, CertError> {
    rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .transpose()
        .map_err(|e| CertError::Parse(e.to_string()))?
        .map(|c| c.to_vec())
        .ok_or_else(|| CertError::Parse("no certificate in PEM".into()))
}

fn generate_self_signed() -> Result<(String, String), CertError> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| CertError::Generate(e.to_string()))?;
    let mut params = rcgen::CertificateParams::new(vec![CERT_CN.to_string()])
        .map_err(|e| CertError::Generate(e.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CERT_CN);
    let not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    let not_after = not_before + time::Duration::days(3650);
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| CertError::Generate(e.to_string()))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}
