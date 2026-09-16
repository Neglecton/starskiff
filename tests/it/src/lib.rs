//! In-process test harness: a real server (random ports, NoTls) plus node
//! engines. Tests run in parallel, each with its own temp directory.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use skiff_core::crypto::NodeKeys;
use skiff_core::logging::LogFn;
use skiff_core::models::{Identity, NodeConfig};
use skiff_node::engine::NodeEngine;
use skiff_server::app::{ServerOptions, start};

pub struct TestHarness {
    pub server: skiff_server::app::RunningServer,
    pub admin: reqwest::Client,
    pub admin_token: String,
    pub network: String,
    pub token: String,
    pub dir: PathBuf,
    pub quiet_log: LogFn,
}

impl TestHarness {
    pub async fn create() -> TestHarness {
        Self::create_with("testnet", "10.99.0.0/24").await
    }

    pub async fn create_with(network: &str, cidr: &str) -> TestHarness {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "skiff-it-{}-{}-{}",
            std::process::id(),
            skiff_core::logging::unix_ms(),
            seq
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let running = start(ServerOptions {
            db_path: dir.join("test.sqlite"),
            api_port: 0,
            relay_udp_port: 0,
            relay_tcp_port: 0,
            no_tls: true,
            cert_file: None,
            key_file: None,
            log: std::sync::Arc::new(|_| {}),
        })
        .await
        .expect("server starts");

        let base = format!("http://127.0.0.1:{}", running.api_port);
        let admin_token = running.admin_token.clone();
        let admin = reqwest::Client::new();
        admin
            .post(format!("{base}/admin/networks"))
            .header("X-Admin-Token", &admin_token)
            .json(&serde_json::json!({ "name": network, "cidr": cidr }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let resp: serde_json::Value = admin
            .post(format!("{base}/admin/tokens"))
            .header("X-Admin-Token", &admin_token)
            .json(&serde_json::json!({ "network": network, "uses": 100, "expiresInHours": 24 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = resp["token"].as_str().unwrap().to_string();

        TestHarness {
            server: running,
            admin,
            admin_token,
            network: network.to_string(),
            token,
            dir,
            quiet_log: if std::env::var("SKIFF_IT_LOG").is_ok() {
                std::sync::Arc::new(|line: &str| eprintln!("[skiff] {line}"))
            } else {
                std::sync::Arc::new(|_| {})
            },
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.server.api_port)
    }

    /// Enroll a fresh node identity (writes starskiff.json, returns the path).
    pub async fn enroll_node(&self, name: &str, ip: Option<&str>) -> std::path::PathBuf {
        let keys = NodeKeys::generate();
        let mut body = serde_json::json!({
            "token": self.token,
            "name": name,
            "signPubkey": keys.sign_public_hex(),
            "dhPubkey": keys.dh_public_hex(),
        });
        if let Some(ip) = ip {
            body["requestedIp"] = serde_json::Value::String(ip.to_string());
        }
        let resp: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/api/enroll", self.base_url()))
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let data_dir = self.dir.join(name);
        std::fs::create_dir_all(&data_dir).unwrap();
        // 瘦配置：网络成员与行为配置由服务端权威下发，文件不落。
        let cfg = NodeConfig {
            server: self.base_url(),
            mode: skiff_core::models::ClientMode::Proxy,
            mtu: resp["mtu"].as_u64().unwrap_or(1300) as u32,
            data_dir: data_dir.to_string_lossy().into_owned(),
            listen: vec!["udp://0.0.0.0:0".to_string()],
            log_file: None,
            identity: Identity {
                device_id: resp["deviceId"].as_u64().unwrap(),
                name: name.to_string(),
                device_token: skiff_core::secret::Secret::new(resp["deviceToken"].as_str().unwrap()),
                sign_public_key: keys.sign_public_hex(),
                sign_private_key: skiff_core::secret::Secret::new(hex::encode(keys.sign_secret)),
                dh_public_key: keys.dh_public_hex(),
                dh_private_key: skiff_core::secret::Secret::new(hex::encode(keys.dh_secret)),
                server_cert_pin: None,
            },
        };
        let path = data_dir.join("starskiff.json");
        skiff_node::node_config::save(&path, &cfg).unwrap();
        path
    }

    /// 设备 id（读本地身份文件）。
    pub fn device_id_of(&self, config_path: &std::path::Path) -> u64 {
        skiff_node::node_config::load(config_path).unwrap().identity.device_id
    }

    /// 设备首个网络的虚拟 IP（服务端视角，/admin/devices）。
    pub async fn virtual_ip_of(&self, config_path: &std::path::Path) -> String {
        let id = self.device_id_of(config_path);
        let devs: serde_json::Value = self
            .admin
            .get(format!("{}/admin/devices", self.base_url()))
            .header("X-Admin-Token", &self.admin_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        devs.as_array()
            .unwrap()
            .iter()
            .find(|d| d["id"].as_str() == Some(&id.to_string()))
            .unwrap()["networks"][0]["ip"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// 按名查网络 id（/admin/networks）。
    pub async fn network_id_by_name(&self, name: &str) -> skiff_core::models::NetId {
        let nets: serde_json::Value = self
            .admin
            .get(format!("{}/admin/networks", self.base_url()))
            .header("X-Admin-Token", &self.admin_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let hex = nets
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"].as_str() == Some(name))
            .unwrap()["id"]
            .as_str()
            .unwrap();
        skiff_core::models::NetId::from_hex(hex).unwrap()
    }

    /// 管理端写入设备托管配置（DeviceSettings；返回含 revision 的落库值）。
    pub async fn set_settings(
        &self,
        config_path: &std::path::Path,
        body: serde_json::Value,
    ) -> serde_json::Value {
        let id = self.device_id_of(config_path);
        self.admin
            .put(format!("{}/admin/devices/{id}/settings", self.base_url()))
            .header("X-Admin-Token", &self.admin_token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    /// 以指定注册令牌直接注册一个新设备身份并写瘦配置（用于把设备注册
    /// 进非默认网络）。
    pub async fn enroll_into(&self, token: &str, name: &str) -> std::path::PathBuf {
        let keys = NodeKeys::generate();
        let resp: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/api/enroll", self.base_url()))
            .json(&serde_json::json!({
                "token": token,
                "name": name,
                "signPubkey": keys.sign_public_hex(),
                "dhPubkey": keys.dh_public_hex(),
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if resp.get("error").is_some() {
            panic!("enroll_into 失败: {resp}");
        }
        let data_dir = self.dir.join(name);
        std::fs::create_dir_all(&data_dir).unwrap();
        let cfg = NodeConfig {
            server: self.base_url(),
            mode: skiff_core::models::ClientMode::Proxy,
            mtu: resp["mtu"].as_u64().unwrap_or(1300) as u32,
            data_dir: data_dir.to_string_lossy().into_owned(),
            listen: vec!["udp://0.0.0.0:0".to_string()],
            log_file: None,
            identity: Identity {
                device_id: resp["deviceId"].as_u64().unwrap(),
                name: name.to_string(),
                device_token: skiff_core::secret::Secret::new(resp["deviceToken"].as_str().unwrap()),
                sign_public_key: keys.sign_public_hex(),
                sign_private_key: skiff_core::secret::Secret::new(hex::encode(keys.sign_secret)),
                dh_public_key: keys.dh_public_hex(),
                dh_private_key: skiff_core::secret::Secret::new(hex::encode(keys.dh_secret)),
                server_cert_pin: None,
            },
        };
        let path = data_dir.join("starskiff.json");
        skiff_node::node_config::save(&path, &cfg).unwrap();
        path
    }

    /// Start a node engine from an existing config file (proxy mode).
    pub async fn start_engine(
        &self,
        config_path: &std::path::Path,
        tune: impl FnOnce(&mut NodeConfig),
    ) -> std::sync::Arc<NodeEngine> {
        let mut cfg = skiff_node::node_config::load(config_path).unwrap();
        tune(&mut cfg);
        skiff_node::node_config::save(config_path, &cfg).unwrap();
        NodeEngine::start(config_path.to_path_buf(), cfg, Box::new(|_| {}), self.quiet_log.clone())
            .await
            .expect("engine starts")
    }

    /// Join an existing node to another network via /api/join.
    pub async fn join_node(&self, config_path: &std::path::Path, token: &str) -> Result<serde_json::Value, String> {
        let cfg = skiff_node::node_config::load(config_path).unwrap();
        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(format!("{}/api/join", self.base_url()))
            .bearer_auth(cfg.identity.device_token.expose())
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if resp.get("error").is_some() {
            return Err(resp["error"].as_str().unwrap_or("?").to_string());
        }
        Ok(resp)
    }

    /// Create an enroll token for a network (admin).
    pub async fn token_for(&self, network: &str) -> String {
        let resp: serde_json::Value = self
            .admin
            .post(format!("{}/admin/tokens", self.base_url()))
            .header("X-Admin-Token", &self.admin_token)
            .json(&serde_json::json!({ "network": network, "uses": 100, "expiresInHours": 24 }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        resp["token"].as_str().unwrap().to_string()
    }

    /// Create a second network on the shared server.
    pub async fn create_network(&self, name: &str, cidr: &str) {
        self.admin
            .post(format!("{}/admin/networks", self.base_url()))
            .header("X-Admin-Token", &self.admin_token)
            .json(&serde_json::json!({ "name": name, "cidr": cidr }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
    }

    /// Load the config back from an enroll_node result.
    pub fn node_cfg(&self, path: &std::path::Path) -> NodeConfig {
        skiff_node::node_config::load(path).unwrap()
    }

    /// Poll until the condition holds (15s / 200ms cadence by default).
    pub async fn until(&self, cond: impl FnMut() -> bool) {
        self.until_with_timeout(cond, Duration::from_secs(15)).await;
    }

    pub async fn until_with_timeout(&self, mut cond: impl FnMut() -> bool, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        panic!("condition not met within {timeout:?}");
    }
}
