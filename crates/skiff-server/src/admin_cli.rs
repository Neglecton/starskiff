//! `starskiff-server admin` — REST client for the admin API, with the same
//! certificate-pin trust rules as the node client (pin from the token suffix
//! when present; TOFU warning otherwise).

use anyhow::{Context, anyhow};
use skiff_core::crypto::tokens::split_token;

pub struct AdminCli {
    pub server: String,
    pub token: String,
    http: reqwest::Client,
}

impl AdminCli {
    /// Build a client. For https servers whose token carries a fingerprint
    /// suffix, only that certificate is accepted; otherwise a TOFU warning
    /// is printed and any certificate is accepted.
    pub fn new(server: &str, token: &str) -> anyhow::Result<AdminCli> {
        let server = server.trim_end_matches('/').to_string();
        let (bare, fingerprint) = split_token(token);
        let http = if server.starts_with("https://") {
            match fingerprint {
                Some(fp) => {
                    let expected = fp.to_ascii_lowercase();
                    let pin = expected.clone();
                    let verifier = PinOnlyVerifier { pin };
                    let tls = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
                        .with_no_client_auth();
                    reqwest::Client::builder()
                        .use_preconfigured_tls(tls)
                        .build()?
                }
                None => {
                    eprintln!("警告：管理令牌未带证书指纹（TOFU 模式，接受任意证书）");
                    let tls = rustls::ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAllVerifier))
                        .with_no_client_auth();
                    reqwest::Client::builder()
                        .use_preconfigured_tls(tls)
                        .build()?
                }
            }
        } else {
            reqwest::Client::new()
        };
        Ok(AdminCli {
            server,
            token: bare,
            http,
        })
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<reqwest::Response> {
        let url = format!("{}{}", self.server, path);
        let mut req = self
            .http
            .request(method, &url)
            .header("X-Admin-Token", &self.token);
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("Request failed: {e}（服务器 {} 在运行吗？）", self.server))?;
        Ok(resp)
    }

    async fn expect_ok(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> anyhow::Result<String> {
        let resp = self.request(method, path, body).await?;
        let status = resp.status();
        if status.is_success() {
            return Ok("OK".to_string());
        }
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("HTTP {status}: {text}")
    }

    async fn get_json(&self, path: &str) -> anyhow::Result<serde_json::Value> {
        let resp = self.request(reqwest::Method::GET, path, None).await?;
        let status = resp.status();
        let value = resp
            .json::<serde_json::Value>()
            .await
            .context("响应不是合法 JSON")?;
        if !status.is_success() {
            anyhow::bail!("HTTP {status}: {value}");
        }
        Ok(value)
    }

    async fn post_json(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .request(reqwest::Method::POST, path, Some(body))
            .await?;
        let status = resp.status();
        let value = resp
            .json::<serde_json::Value>()
            .await
            .context("响应不是合法 JSON")?;
        if !status.is_success() {
            anyhow::bail!("HTTP {status}: {value}");
        }
        Ok(value)
    }

    // network ----------------------------------------------------------------

    pub async fn network_list(&self) -> anyhow::Result<()> {
        let v = self.get_json("/admin/networks").await?;
        println!("{v:#}");
        Ok(())
    }

    pub async fn network_create(&self, name: &str, cidr: &str) -> anyhow::Result<()> {
        let v = self
            .post_json(
                "/admin/networks",
                serde_json::json!({ "name": name, "cidr": cidr }),
            )
            .await?;
        println!("{v:#}");
        Ok(())
    }

    pub async fn network_remove(&self, name_or_id: &str) -> anyhow::Result<()> {
        // Resolve names to ids first (delete expects the id).
        let id = if name_or_id.len() == 32 && name_or_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            name_or_id.to_string()
        } else {
            let v = self.get_json("/admin/networks").await?;
            v.as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|n| n["name"].as_str() == Some(name_or_id))
                        .and_then(|n| n["id"].as_str().map(String::from))
                })
                .ok_or_else(|| anyhow!("网络 {name_or_id} 不存在"))?
        };
        println!(
            "{}",
            self.expect_ok(
                reqwest::Method::DELETE,
                &format!("/admin/networks/{id}"),
                None
            )
            .await?
        );
        Ok(())
    }

    // token ------------------------------------------------------------------

    pub async fn token_list(&self) -> anyhow::Result<()> {
        let v = self.get_json("/admin/tokens").await?;
        println!("{v:#}");
        Ok(())
    }

    pub async fn token_create(
        &self,
        network: &str,
        uses: i64,
        hours: i64,
        ip: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut body =
            serde_json::json!({ "network": network, "uses": uses, "expiresInHours": hours });
        if let Some(ip) = ip {
            body["requestedIp"] = serde_json::Value::String(ip.to_string());
        }
        let v = self.post_json("/admin/tokens", body).await?;
        println!("{v:#}");
        Ok(())
    }

    pub async fn token_revoke(&self, token: &str) -> anyhow::Result<()> {
        println!(
            "{}",
            self.expect_ok(
                reqwest::Method::DELETE,
                &format!("/admin/tokens/{}", token),
                None
            )
            .await?
        );
        Ok(())
    }

    // device -----------------------------------------------------------------

    pub async fn device_list(&self) -> anyhow::Result<()> {
        let v = self.get_json("/admin/devices").await?;
        println!("{v:#}");
        Ok(())
    }

    pub async fn device_remove(&self, id: u64) -> anyhow::Result<()> {
        println!(
            "{}",
            self.expect_ok(
                reqwest::Method::DELETE,
                &format!("/admin/devices/{id}"),
                None
            )
            .await?
        );
        Ok(())
    }

    pub async fn device_set_ip(&self, device: &str, network: &str, ip: &str) -> anyhow::Result<()> {
        let net_id = if network.len() == 32 && network.bytes().all(|b| b.is_ascii_hexdigit()) {
            network.to_string()
        } else {
            let v = self.get_json("/admin/networks").await?;
            v.as_array()
                .and_then(|arr| {
                    arr.iter()
                        .find(|n| n["name"].as_str() == Some(network))
                        .and_then(|n| n["id"].as_str().map(String::from))
                })
                .ok_or_else(|| anyhow!("网络 {network} 不存在"))?
        };
        let path = format!("/admin/networks/{net_id}/devices/{device}/ip");
        let resp = self
            .request(
                reqwest::Method::POST,
                &path,
                Some(serde_json::json!({ "ip": ip })),
            )
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {status}: {text}");
        }
        println!("OK");
        Ok(())
    }

    pub async fn device_settings_get(&self, device: u64) -> anyhow::Result<()> {
        let v = self.get_json(&format!("/admin/devices/{device}/settings")).await?;
        println!("{v:#}");
        Ok(())
    }

    /// 设置托管配置。json 为 DeviceSettings 形态的 JSON 字符串
    /// （字段缺省 = 该项改为未托管）。
    pub async fn device_settings_set(&self, device: u64, json: &str) -> anyhow::Result<()> {
        let value: serde_json::Value =
            serde_json::from_str(json).context("settings JSON 解析失败")?;
        let resp = self
            .request(
                reqwest::Method::PUT,
                &format!("/admin/devices/{device}/settings"),
                Some(value),
            )
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("HTTP {status}: {text}");
        }
        println!("{text}");
        Ok(())
    }

    pub async fn device_restart(&self, id: u64) -> anyhow::Result<()> {
        println!(
            "{}",
            self.expect_ok(reqwest::Method::POST, &format!("/admin/devices/{id}/restart"), None)
                .await?
        );
        Ok(())
    }

    /// 网络名 → 32-hex id（已是 hex 则原样返回）。
    async fn resolve_network_id(&self, network: &str) -> anyhow::Result<String> {
        if network.len() == 32 && network.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(network.to_ascii_lowercase());
        }
        let v = self.get_json("/admin/networks").await?;
        v.as_array()
            .and_then(|arr| {
                arr.iter()
                    .find(|n| n["name"].as_str() == Some(network))
                    .and_then(|n| n["id"].as_str().map(String::from))
            })
            .ok_or_else(|| anyhow!("网络 {network} 不存在"))
    }

    pub async fn device_network_add(
        &self,
        device: u64,
        network: &str,
        ip: Option<&str>,
    ) -> anyhow::Result<()> {
        let net_id = self.resolve_network_id(network).await?;
        let body = serde_json::json!({ "network": net_id, "requestedIp": ip });
        let resp = self
            .request(
                reqwest::Method::POST,
                &format!("/admin/devices/{device}/networks"),
                Some(body),
            )
            .await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("HTTP {status}: {text}");
        }
        println!("{text}");
        Ok(())
    }

    pub async fn device_network_remove(&self, device: u64, network: &str) -> anyhow::Result<()> {
        let net_id = self.resolve_network_id(network).await?;
        println!(
            "{}",
            self.expect_ok(
                reqwest::Method::DELETE,
                &format!("/admin/devices/{device}/networks/{net_id}"),
                None
            )
            .await?
        );
        Ok(())
    }

    pub async fn device_reconnect(&self, id: u64) -> anyhow::Result<()> {
        println!(
            "{}",
            self.expect_ok(reqwest::Method::POST, &format!("/admin/devices/{id}/reconnect"), None)
                .await?
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TLS verifiers
// ---------------------------------------------------------------------------

/// Signature-scheme helpers shared by the custom verifiers: delegate to the
/// standard webpki verifier (no roots) so scheme handling stays correct.
fn default_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()))
}

fn verify_signature(
    message: &[u8],
    cert: &rustls::pki_types::CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    let algs = &default_provider().signature_verification_algorithms;
    rustls::crypto::verify_tls12_signature(message, cert, dss, algs)
        .or_else(|_| rustls::crypto::verify_tls13_signature(message, cert, dss, algs))
}

#[derive(Debug)]
struct PinOnlyVerifier {
    pin: String,
}

impl rustls::client::danger::ServerCertVerifier for PinOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(end_entity.as_ref());
        let actual = hex::encode(h.finalize());
        if actual.eq_ignore_ascii_case(&self.pin) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let msg = std::sync::Arc::new(std::io::Error::other(format!(
                "证书指纹不匹配（期望 {}… 实际 {}…）",
                &self.pin[..12.min(self.pin.len())],
                &actual[..12.min(actual.len())]
            )));
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(msg)),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
struct AcceptAllVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
