//! Three-tier server certificate trust (shared by HTTP and WSS):
//! 1. pin present → strict fingerprint comparison;
//! 2. no pin + public CA chain validates (Mozilla roots) → trust, do not pin
//!    (CDN scenario, cert rotation survives);
//! 3. no pin + self-signed → TOFU: trust this once and report the
//!    fingerprint so the caller can persist it into node.json.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::Digest;

#[derive(Debug, Clone)]
pub struct TrustState {
    /// Expected fingerprint (64 lowercase hex), when known. 共享可写：
    /// Tier 3 TOFU 首连固化后，同进程后续握手立即落入 Tier 1 严格比对。
    pub pin: Arc<Mutex<Option<String>>>,
    /// Set when tier-3 TOFU accepted a new fingerprint.
    pub tofu_fingerprint: Arc<Mutex<Option<String>>>,
}

fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    let mut h = sha2::Sha256::new();
    h.update(cert.as_ref());
    hex::encode(h.finalize())
}

fn default_provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

fn ca_verifier() -> Arc<rustls::client::WebPkiServerVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("webpki verifier builds")
}

#[derive(Debug)]
pub struct TrustVerifier {
    pub state: TrustState,
}

impl ServerCertVerifier for TrustVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = fingerprint_of(end_entity);
        // Tier 1: strict pin comparison.
        let pinned = self.state.pin.lock().unwrap().clone();
        if let Some(pin) = pinned {
            if actual.eq_ignore_ascii_case(&pin) {
                return Ok(ServerCertVerified::assertion());
            }
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                    std::io::Error::other(format!(
                        "服务器证书指纹不匹配（期望 {}… 实际 {}…）；服务器已迁移或被劫持，请用新令牌重新 enroll",
                        &pin[..12.min(pin.len())],
                        &actual[..12.min(actual.len())]
                    )),
                ))),
            ));
        }
        // Tier 2: public CA chain (CDN / reverse proxy) — trust without pinning.
        if ca_verifier()
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
            .is_ok()
        {
            return Ok(ServerCertVerified::assertion());
        }
        // Tier 3: TOFU — 首连接受，立即固化内存 pin（同进程后续握手走
        // Tier 1 严格比对：MITM 每次换自签证书不再都能通过），并上报指纹
        // 供引擎持久化到 node.json。
        {
            let mut pin = self.state.pin.lock().unwrap();
            if pin.is_none() {
                *pin = Some(actual.clone());
            }
        }
        if let Ok(mut slot) = self.state.tofu_fingerprint.lock() {
            *slot = Some(actual);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a rustls client config with the three-tier verifier.
pub fn client_config(state: TrustState) -> rustls::ClientConfig {
    let verifier = TrustVerifier { state };
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}
