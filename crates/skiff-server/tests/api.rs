//! In-process server integration tests: real HTTP + WebSocket + UDP relay
//! on random ports, temp directories, NoTls (TLS is covered by unit tests
//! for cert handling; loopback TLS can be intercepted by host VPN layers).

use std::net::SocketAddr;
use std::time::Duration;

use skiff_core::crypto::NodeKeys;
use skiff_core::models::{ConfigResponse, EnrollResponse};
use skiff_core::protocol::relay_udp;
use skiff_server::app::{ServerOptions, start};

struct TestServer {
    #[allow(dead_code)]
    running: skiff_server::app::RunningServer,
    admin_token: String,
    base_url: String,
    relay_udp: SocketAddr,
    client: reqwest::Client,
}

async fn spawn_server() -> TestServer {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "skiff-srv-it-{}-{}-{}",
        std::process::id(),
        skiff_core::logging::unix_ms(),
        seq
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = ServerOptions {
        db_path: dir.join("test.sqlite"),
        api_port: 0,
        relay_udp_port: 0,
        relay_tcp_port: 0,
        no_tls: true,
        cert_file: None,
        key_file: None,
        log: std::sync::Arc::new(|_| {}),
    };
    let running = start(opts).await.expect("server starts");
    let base_url = format!("http://127.0.0.1:{}", running.api_port);
    let relay_udp: SocketAddr = format!("127.0.0.1:{}", running.relay_udp_port)
        .parse()
        .unwrap();
    let admin_token = running.admin_token.clone();
    TestServer {
        running,
        admin_token,
        base_url,
        relay_udp,
        client: reqwest::Client::new(),
    }
}

async fn create_network(srv: &TestServer, name: &str, cidr: &str) {
    let resp = srv
        .client
        .post(format!("{}/admin/networks", srv.base_url))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "name": name, "cidr": cidr }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "create network");
}

async fn create_token(srv: &TestServer, network: &str) -> String {
    let resp = srv
        .client
        .post(format!("{}/admin/tokens", srv.base_url))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "network": network, "uses": 100, "expiresInHours": 24 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    v["token"].as_str().unwrap().to_string()
}

async fn enroll(
    srv: &TestServer,
    token: &str,
    name: &str,
    ip: Option<&str>,
) -> Result<EnrollResponse, String> {
    let keys = NodeKeys::generate();
    let mut body = serde_json::json!({
        "token": token,
        "name": name,
        "signPubkey": keys.sign_public_hex(),
        "dhPubkey": keys.dh_public_hex(),
    });
    if let Some(ip) = ip {
        body["requestedIp"] = serde_json::Value::String(ip.to_string());
    }
    let resp = srv
        .client
        .post(format!("{}/api/enroll", srv.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    if !resp.status().is_success() {
        let v: serde_json::Value = resp.json().await.unwrap();
        return Err(v["error"].as_str().unwrap_or("?").to_string());
    }
    Ok(resp.json().await.unwrap())
}

#[tokio::test]
async fn enroll_config_peers_flow() {
    let srv = spawn_server().await;
    create_network(&srv, "corp", "10.99.0.0/24").await;
    let token = create_token(&srv, "corp").await;

    let a = enroll(&srv, &token, "node-a", None).await.unwrap();
    let b = enroll(&srv, &token, "node-b", None).await.unwrap();
    let c = enroll(&srv, &token, "node-c", Some("10.99.0.200"))
        .await
        .unwrap();
    assert_eq!(a.ip, "10.99.0.1");
    assert_eq!(b.ip, "10.99.0.2");
    assert_eq!(c.ip, "10.99.0.200");
    assert_ne!(a.device_token, b.device_token);

    // Duplicate manual IP rejected.
    let err = enroll(&srv, &token, "node-d", Some("10.99.0.1"))
        .await
        .unwrap_err();
    assert!(err.contains("占用"), "got: {err}");

    // Bad token rejected.
    let err = enroll(&srv, "skk_nope", "node-e", None).await.unwrap_err();
    assert!(err.contains("不存在"));

    // config
    let resp = srv
        .client
        .get(format!("{}/api/config", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cfg: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cfg["ip"], "10.99.0.1");
    assert_eq!(cfg["networkName"], "corp");
    assert_eq!(cfg["relayUdpPort"], srv.relay_udp.port());
    // config requires auth
    let resp = srv
        .client
        .get(format!("{}/api/config", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // peers (no relay registration yet: empty endpoints, offline)
    let resp = srv
        .client
        .get(format!("{}/api/peers", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let peers: Vec<serde_json::Value> = resp.json().await.unwrap();
    assert_eq!(peers.len(), 2);
    for p in &peers {
        assert_eq!(p["online"], false);
        assert!(p["udpEndpoints"].as_array().unwrap().is_empty());
    }
}

#[tokio::test]
async fn udp_relay_register_ack_and_forward() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.50.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();
    let b = enroll(&srv, &token, "b", None).await.unwrap();

    // Raw UDP REGISTER for both devices (mirrors the node's UdpMesh).
    let sock_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key_a = relay_udp::relay_key_from_token(&a.device_token);
    let key_b = relay_udp::relay_key_from_token(&b.device_token);
    sock_a
        .send_to(
            &relay_udp::build_register(a.device_id, &key_a),
            srv.relay_udp,
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_a.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    match relay_udp::parse(&buf[..n]).unwrap() {
        relay_udp::RelayPacket::Ack { ip, port } => {
            assert!(!ip.is_empty());
            assert!(port > 0);
        }
        other => panic!("expected ACK, got {other:?}"),
    }
    // Bad auth rejected with ERROR.
    let bad = relay_key_from("skd_wrong");
    sock_b
        .send_to(&relay_udp::build_register(b.device_id, &bad), srv.relay_udp)
        .await
        .unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    match relay_udp::parse(&buf[..n]).unwrap() {
        relay_udp::RelayPacket::Error { msg } => assert!(msg.contains("auth")),
        other => panic!("expected ERROR, got {other:?}"),
    }
    // Register b properly, then relay a frame a -> b.
    sock_b
        .send_to(
            &relay_udp::build_register(b.device_id, &key_b),
            srv.relay_udp,
        )
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let inner = [0x0Au8, 1, 2, 3, 4, 5];
    sock_a
        .send_to(
            &relay_udp::build_relay(a.device_id, b.device_id, &inner),
            srv.relay_udp,
        )
        .await
        .unwrap();
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), sock_b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(from, srv.relay_udp);
    assert_eq!(&buf[..n], &inner, "inner frame forwarded verbatim");

    // Spoofed source (b's id from a's socket) must be dropped.
    sock_a
        .send_to(
            &relay_udp::build_relay(b.device_id, a.device_id, &inner),
            srv.relay_udp,
        )
        .await
        .unwrap();
    let outcome =
        tokio::time::timeout(Duration::from_millis(300), sock_a.recv_from(&mut buf)).await;
    match outcome {
        Err(_) => {} // nothing came back to a — good (frame was for a though...)
        Ok(Ok((n, _))) => panic!("unexpected packet to a: {:?}", &buf[..n]),
        Ok(Err(e)) => panic!("recv error: {e}"),
    }

    // Heartbeat now returns the observed endpoint (from relay registration).
    let resp = srv
        .client
        .post(format!("{}/api/heartbeat", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "localAddrs": ["192.168.1.5"], "listenUdpPort": 24933 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let hb: serde_json::Value = resp.json().await.unwrap();
    let observed = hb["observedUdpEndpoint"].as_str().unwrap();
    let observed_port: u16 = observed.rsplit(':').next().unwrap().parse().unwrap();
    assert_eq!(observed_port, sock_a.local_addr().unwrap().port());
}

fn relay_key_from(token: &str) -> [u8; 32] {
    relay_udp::relay_key_from_token(token)
}

#[tokio::test]
async fn tcp_relay_register_and_forward() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.51.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();
    let b = enroll(&srv, &token, "b", None).await.unwrap();

    // Register a TCP relay connection for both devices.
    let mut conn_a = tokio::net::TcpStream::connect(("127.0.0.1", srv.running.relay_tcp_port))
        .await
        .unwrap();
    let mut conn_b = tokio::net::TcpStream::connect(("127.0.0.1", srv.running.relay_tcp_port))
        .await
        .unwrap();
    use skiff_core::protocol::relay_tcp::{self, RelayTcpMsg};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let register_a = {
        let udp_pkt = relay_udp::build_register(
            a.device_id,
            &relay_udp::relay_key_from_token(&a.device_token),
        );
        let mut msg = relay_tcp::encode_cmd(relay_udp::CMD_REGISTER, &udp_pkt[3..]);
        let mut framed = Vec::new();
        relay_tcp::write_length_prefixed(&mut framed, &msg);
        msg.clear();
        framed
    };
    conn_a.write_all(&register_a).await.unwrap();
    let mut re = skiff_core::protocol::relay_tcp::FrameReassembler::new();
    let mut buf = vec![0u8; 4096];
    let n = conn_a.read(&mut buf).await.unwrap();
    let frames = re.feed(&buf[..n]).unwrap();
    assert!(matches!(
        relay_tcp::parse(frames.first().unwrap()).unwrap(),
        RelayTcpMsg::Ack { .. }
    ));

    let register_b = {
        let udp_pkt = relay_udp::build_register(
            b.device_id,
            &relay_udp::relay_key_from_token(&b.device_token),
        );
        let msg = relay_tcp::encode_cmd(relay_udp::CMD_REGISTER, &udp_pkt[3..]);
        let mut framed = Vec::new();
        relay_tcp::write_length_prefixed(&mut framed, &msg);
        framed
    };
    conn_b.write_all(&register_b).await.unwrap();
    let n = conn_b.read(&mut buf).await.unwrap();
    let frames = re.feed(&buf[..n]).unwrap();
    assert!(matches!(
        relay_tcp::parse(frames.first().unwrap()).unwrap(),
        RelayTcpMsg::Ack { .. }
    ));

    // a sends to b via Send; b receives a Frame.
    let inner = [0x0Au8, 1, 9, 9];
    let mut send_msg = relay_tcp::encode_cmd(5, &relay_tcp::build_send_body(b.device_id, &inner));
    let mut framed = Vec::new();
    relay_tcp::write_length_prefixed(&mut framed, &send_msg);
    send_msg.clear();
    conn_a.write_all(&framed).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), conn_b.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let frames = re.feed(&buf[..n]).unwrap();
    match relay_tcp::parse(frames.first().unwrap()).unwrap() {
        RelayTcpMsg::Frame { frame } => assert_eq!(frame, inner),
        other => panic!("expected Frame, got {other:?}"),
    }
}

#[tokio::test]
async fn relay_register_replay_rejected() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.53.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();

    // UDP: 同一 REGISTER 报文首次 ACK，重放静默丢弃。
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let pkt = relay_udp::build_register(a.device_id, &relay_key_from(&a.device_token));
    sock.send_to(&pkt, srv.relay_udp).await.unwrap();
    let mut buf = [0u8; 128];
    let _ = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("first register acked")
        .unwrap();
    assert_eq!(buf[2], relay_udp::CMD_ACK);
    sock.send_to(&pkt, srv.relay_udp).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .is_err(),
        "replayed register must be silently dropped"
    );

    // TCP: 新连接重放同一 REGISTER 帧（nonce 已被 UDP 路径用掉，两个中继
    // 共享 nonce 记忆）收到 ERROR 后断开。
    use skiff_core::protocol::relay_tcp::{self, RelayTcpMsg};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let register_frame = {
        let mut msg = relay_tcp::encode_cmd(relay_udp::CMD_REGISTER, &pkt[3..]);
        let mut framed = Vec::new();
        relay_tcp::write_length_prefixed(&mut framed, &msg);
        msg.clear();
        framed
    };
    let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", srv.running.relay_tcp_port))
        .await
        .unwrap();
    conn.write_all(&register_frame).await.unwrap();
    let mut re = relay_tcp::FrameReassembler::new();
    let mut rbuf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut rbuf))
        .await
        .unwrap()
        .unwrap();
    let frames = re.feed(&rbuf[..n]).unwrap();
    match relay_tcp::parse(frames.first().unwrap()).unwrap() {
        RelayTcpMsg::Error { body } => {
            assert!(String::from_utf8_lossy(body).contains("replay"))
        }
        other => panic!("expected error, got {other:?}"),
    }
}

/// 轮询等设备在管理面显示在线（= WS 已注册入 hub）——替代固定 sleep
/// （CI 慢机上 300ms 不够即 flaky；presence 的 online 在无引擎心跳的
/// API 测试里只由 WS 驱动）。
async fn wait_ws_online(srv: &TestServer, device_id: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        let resp = srv
            .client
            .get(format!("{}/admin/devices", srv.base_url))
            .header("X-Admin-Token", &srv.admin_token)
            .send()
            .await
            .unwrap();
        let devs: serde_json::Value = resp.json().await.unwrap();
        let hit = devs.as_array().is_some_and(|list| {
            list.iter().any(|d| {
                d["id"].as_str() == Some(&device_id.to_string()) && d["online"] == serde_json::json!(true)
            })
        });
        if hit {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("device {device_id} 未在 10s 内上线（WS 注册超时）");
}

#[tokio::test]

async fn admin_set_ip_pushes_config_changed_over_ws() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.52.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();
    let b = enroll(&srv, &token, "b", None).await.unwrap();

    // Connect a WS events socket as device a.
    use futures_util::{SinkExt, StreamExt};
    let (ws, _) = tokio_tungstenite::connect_async(format!(
        "{}/api/events?network=net&token={}",
        srv.base_url.replace("http", "ws"),
        a.device_token
    ))
    .await
    .unwrap();
    let (mut write, mut read) = ws.split();

    // 等 WS 服务端注册完成（在线可见）再触发事件，替代固定 sleep。
    wait_ws_online(&srv, a.device_id).await;
    let network_id_hex = a.network_id.to_hex();
    let resp = srv
        .client
        .post(format!(
            "{}/admin/networks/{network_id_hex}/devices/{}/ip",
            srv.base_url, b.device_id
        ))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "ip": "10.52.0.77" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The WS must deliver peers_changed (and config_changed to b, not a).
    let mut saw_peers_changed = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && !saw_peers_changed {
        let msg = tokio::time::timeout_at(deadline, read.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            if v["type"] == "peers_changed" {
                saw_peers_changed = true;
            }
        }
    }
    assert!(saw_peers_changed, "peers_changed event received over WS");
    write.close().await.ok();
}

#[tokio::test]
async fn admin_settings_roundtrip_and_ws_push() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.54.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();
    let put = |body: serde_json::Value| {
        srv.client
            .put(format!("{}/admin/devices/{}/settings", srv.base_url, a.device_id))
            .header("X-Admin-Token", &srv.admin_token)
            .json(&body)
            .send()
    };

    // 校验失败：非法策略档位（serde 拒绝）/ 对端覆盖重复。
    let resp = put(serde_json::json!({ "pathPolicy": "carrierPigeon" })).await.unwrap();
    assert_eq!(resp.status(), 400);
    let resp = put(serde_json::json!({ "pathPolicy": "auto" })).await.unwrap();
    assert_eq!(resp.status(), 200, "auto 合法");
    let resp = put(serde_json::json!({
        "peerPolicies": [{"deviceId": a.device_id, "policy": "relayUdp"},
                          {"deviceId": a.device_id, "policy": "relayTcp"}]
    }))
    .await
    .unwrap();
    assert_eq!(resp.status(), 400, "重复对端拒绝");

    // WS 连接（settings_changed 经 send_to_device 定向推给设备）。
    use futures_util::{SinkExt, StreamExt};
    let (ws, _) = tokio_tungstenite::connect_async(format!(
        "{}/api/events?network=net&token={}",
        srv.base_url.replace("http", "ws"),
        a.device_token
    ))
    .await
    .unwrap();
    let (mut write, mut read) = ws.split();
    wait_ws_online(&srv, a.device_id).await;

    // 保存合法配置 → revision（含对端覆盖回读）。
    let resp = put(serde_json::json!({
        "pathPolicy": "relayUdp",
        "peerPolicies": [{"deviceId": a.device_id, "policy": "directTcp"}]
    }))
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v["revision"].as_i64().unwrap() >= 1);
    assert_eq!(v["pathPolicy"], "relayUdp");
    assert_eq!(v["peerPolicies"][0]["policy"], "directTcp");
    let main_rev = v["revision"].as_i64().unwrap();

    let mut saw_settings = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline && !saw_settings {
        let msg = tokio::time::timeout_at(deadline, read.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            if v["type"] == "settings_changed" {
                saw_settings = true;
                assert_eq!(
                    v["message"].as_str().and_then(|m| m.parse::<i64>().ok()),
                    Some(main_rev),
                    "message carries the new revision"
                );
            }
        }
    }
    assert!(saw_settings, "settings_changed pushed over WS");
    write.close().await.ok();

    // 节点侧自拉与管理侧读取一致。
    let v: serde_json::Value = srv
        .client
        .get(format!("{}/api/settings", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["revision"], main_rev);
    assert_eq!(v["pathPolicy"], "relayUdp");
    assert_eq!(v["peerPolicies"].as_array().unwrap().len(), 1);
    let v: serde_json::Value = srv
        .client
        .get(format!(
            "{}/admin/devices/{}/settings",
            srv.base_url, a.device_id
        ))
        .header("X-Admin-Token", &srv.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["revision"], main_rev);

    // 全量替换：socksListen 空串=禁用；未包含的 pathPolicy/peerPolicies 回到未托管。
    let resp = put(serde_json::json!({ "socksListen": "" })).await.unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["revision"], main_rev + 1, "socks PUT 响应: {v}");
    assert!(v.get("pathPolicy").is_none());
    assert!(v.get("peerPolicies").is_none());

    // 心跳上报 revision/pending 后设备列表可见（管理页收敛状态）。
    let resp = srv
        .client
        .post(format!("{}/api/heartbeat", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "settingsRevision": main_rev + 1, "restartPending": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let devs: serde_json::Value = srv
        .client
        .get(format!("{}/admin/devices", srv.base_url))
        .header("X-Admin-Token", &srv.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let me = devs
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"].as_str() == Some(&a.device_id.to_string()))
        .unwrap();
    assert_eq!(me["settingsRevision"], main_rev + 1);
    assert_eq!(me["appliedRevision"], main_rev + 1);
    assert_eq!(me["restartPending"], true);

    // 鉴权：无 admin 令牌 PUT/POST 指令端点均 401。
    let resp = srv
        .client
        .put(format!("{}/admin/devices/{}/settings", srv.base_url, a.device_id))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let resp = srv
        .client
        .post(format!("{}/admin/devices/{}/restart", srv.base_url, a.device_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn memberships_list_and_tun_join_precheck() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.55.0.0/24").await;
    create_network(&srv, "net2", "10.55.1.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();

    // 设备侧名单（服务端权威）。
    let v: serde_json::Value = srv
        .client
        .get(format!("{}/api/memberships", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["networkName"], "net");
    // 无令牌 401。
    let resp = srv
        .client
        .get(format!("{}/api/memberships", srv.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // 心跳上报 mode=tun 后，强制 join 第二个网络被 TUN 预检拒绝。
    let resp = srv
        .client
        .post(format!("{}/api/heartbeat", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "mode": "tun" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = srv
        .client
        .post(format!("{}/admin/devices/{}/networks", srv.base_url, a.device_id))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "network": "net2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "TUN node rejected from joining a second network");

    // proxy 模式下正常强制 join（幂等：重复 join 返回现 IP）。
    let resp = srv
        .client
        .post(format!("{}/api/heartbeat", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "mode": "proxy" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    for _ in 0..2 {
        let resp = srv
            .client
            .post(format!("{}/admin/devices/{}/networks", srv.base_url, a.device_id))
            .header("X-Admin-Token", &srv.admin_token)
            .json(&serde_json::json!({ "network": "net2", "requestedIp": "10.55.1.9" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["ip"], "10.55.1.9");
    }
}

#[tokio::test]
async fn settings_adopt_fills_only_unmanaged_fields() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.56.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();

    // 初始：pathPolicy 已被管理员托管，其余未托管。
    let resp = srv
        .client
        .put(format!("{}/admin/devices/{}/settings", srv.base_url, a.device_id))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "pathPolicy": "relayUdp" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 节点收编遗留本地值：只填未托管字段（socks/forwards），已托管的
    // pathPolicy 不被节点覆盖。
    let v: serde_json::Value = srv
        .client
        .put(format!("{}/api/settings", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({
            "pathPolicy": "directUdp",
            "socksListen": "127.0.0.1:19090",
            "forwards": [{ "listen": "127.0.0.1:13306", "proto": "tcp", "dest": "10.56.0.5:3306" }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["pathPolicy"], "relayUdp", "已托管字段不被收编覆盖");
    assert_eq!(v["socksListen"], "127.0.0.1:19090");
    assert_eq!(v["forwards"].as_array().unwrap().len(), 1);

    // 幂等：重复收编相同值不产生新 revision。
    let before = v["revision"].as_i64().unwrap();
    let v: serde_json::Value = srv
        .client
        .put(format!("{}/api/settings", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "socksListen": "127.0.0.1:19090" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["revision"].as_i64().unwrap(), before, "无可收编项不递增 revision");

    // 无设备令牌 401。
    let resp = srv
        .client
        .put(format!("{}/api/settings", srv.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn settings_fail_report_rolls_back_to_last_good() {
    let srv = spawn_server().await;
    create_network(&srv, "net", "10.57.0.0/24").await;
    let token = create_token(&srv, "net").await;
    let a = enroll(&srv, &token, "a", None).await.unwrap();
    let put = |body: serde_json::Value| {
        srv.client
            .put(format!("{}/admin/devices/{}/settings", srv.base_url, a.device_id))
            .header("X-Admin-Token", &srv.admin_token)
            .json(&body)
            .send()
    };

    // 第 1 版（pathPolicy）被节点确认（心跳 appliedRevision 追平 → mark_applied
    // 固化为 last_good）。
    let v: serde_json::Value = put(serde_json::json!({ "pathPolicy": "relayUdp" }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev1 = v["revision"].as_i64().unwrap();
    let resp = srv
        .client
        .post(format!("{}/api/heartbeat", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "settingsRevision": rev1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 第 2 版（坏 listen）→ worker 启动失败上报 → 自动回滚到第 1 版内容。
    let v: serde_json::Value = put(serde_json::json!({ "listen": ["udp://203.0.113.1:1"] }))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev2 = v["revision"].as_i64().unwrap();
    let resp = srv
        .client
        .post(format!("{}/api/settings/fail", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "revision": rev2, "error": "UDP 监听绑定失败 203.0.113.1:1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let rev3 = v["rolledBackTo"].as_i64().unwrap();
    assert!(rev3 > rev2, "回滚递增 revision");

    // 回读：pathPolicy 恢复（last_good 内容），listen 消失；错误状态在设备列表。
    let v: serde_json::Value = srv
        .client
        .get(format!("{}/api/settings", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["revision"], rev3);
    assert_eq!(v["pathPolicy"], "relayUdp");
    assert!(v.get("listen").is_none());
    let devs: serde_json::Value = srv
        .client
        .get(format!("{}/admin/devices", srv.base_url))
        .header("X-Admin-Token", &srv.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let me = devs
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"].as_str() == Some(&a.device_id.to_string()))
        .unwrap();
    assert!(me["settingsError"].as_str().unwrap_or("").contains("绑定失败"));
    assert_eq!(me["settingsErrorRevision"], rev2);

    // 过期/重复上报被忽略（revision 已前进）。
    let resp = srv
        .client
        .post(format!("{}/api/settings/fail", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "revision": rev2, "error": "stale" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v["rolledBackTo"].is_null());

    // TUN 预检：多网络成员 + mode=tun → 409。
    create_network(&srv, "net2", "10.58.0.0/24").await;
    let resp = srv
        .client
        .post(format!("{}/admin/devices/{}/networks", srv.base_url, a.device_id))
        .header("X-Admin-Token", &srv.admin_token)
        .json(&serde_json::json!({ "network": "net2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = put(serde_json::json!({ "mode": "tun" })).await.unwrap();
    assert_eq!(resp.status(), 409, "TUN 多网络预检拒绝");

    // 无设备令牌 → 401。
    let resp = srv
        .client
        .post(format!("{}/api/settings/fail", srv.base_url))
        .json(&serde_json::json!({ "revision": 1, "error": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn admin_console_assets_served_with_cache_headers() {
    let srv = spawn_server().await;
    // Shell document: 200 + html + no-cache (placeholder or built bundle).
    let resp = srv.client.get(format!("{}/admin/", srv.base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers()["content-type"].to_str().unwrap().starts_with("text/html"));
    assert_eq!(resp.headers()["cache-control"], "no-cache");
    // Unknown asset: 404.
    let resp = srv.client.get(format!("{}/admin/assets/nope-123.js", srv.base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 404);
    // Redirects to the console (reqwest follows redirects by default).
    let resp = srv.client.get(format!("{}/admin", srv.base_url)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.url().path().ends_with("/admin/"));
}

#[tokio::test]
async fn join_leave_and_multi_network_ws() {
    let srv = spawn_server().await;
    create_network(&srv, "net1", "10.70.0.0/24").await;
    create_network(&srv, "net2", "10.71.0.0/24").await;
    let tok1 = create_token(&srv, "net1").await;
    let tok2 = create_token(&srv, "net2").await;
    let a = enroll(&srv, &tok1, "node-a", None).await.unwrap();

    // JOIN net2 with the existing device identity.
    let resp = srv
        .client
        .post(format!("{}/api/join", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "token": tok2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let joined: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(joined["networkName"], "net2");
    assert_eq!(joined["cidr"], "10.71.0.0/24");
    assert_eq!(joined["ip"], "10.71.0.1");
    // Same device, same token: the device id did not change.
    let cfg: ConfigResponse = srv
        .client
        .get(format!("{}/api/config?network=net2", srv.base_url))
        .bearer_auth(&a.device_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg.device_id, a.device_id);
    assert_eq!(cfg.ip, "10.71.0.1");

    // Idempotent join: same network again returns the same IP, no error.
    let resp = srv
        .client
        .post(format!("{}/api/join", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "token": create_token(&srv, "net2").await }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let again: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(again["ip"], "10.71.0.1");

    // Bad enroll token rejected.
    let resp = srv
        .client
        .post(format!("{}/api/join", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "token": "skk_nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Two parallel event sockets (net1 + net2) coexist without eviction.
    use futures_util::{SinkExt, StreamExt};
    let (ws1, _) = tokio_tungstenite::connect_async(format!(
        "{}/api/events?network=net1&token={}",
        srv.base_url.replace("http", "ws"),
        a.device_token
    ))
    .await
    .unwrap();
    let (ws2, _) = tokio_tungstenite::connect_async(format!(
        "{}/api/events?network=net2&token={}",
        srv.base_url.replace("http", "ws"),
        a.device_token
    ))
    .await
    .unwrap();
    let (mut w1, mut r1) = ws1.split();
    let (_w2, mut r2) = ws2.split();

    // Trigger a net2-only peers change; ws2 must see it and ws1 must not.
    let b = enroll(&srv, &create_token(&srv, "net2").await, "node-b", None).await.unwrap();
    let _ = b;
    let mut ws2_saw = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, r2.next()).await {
            Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) => {
                let v: serde_json::Value = serde_json::from_str(&text).unwrap();
                if v["type"] == "peers_changed" && v["networkId"] == joined["networkId"].as_str().map(|s| s.to_string()).unwrap_or_default() {
                    ws2_saw = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(ws2_saw, "net2 socket received its peers_changed");
    // ws1 stays open and receives nothing for net2 within a short window.
    let leak = tokio::time::timeout(std::time::Duration::from_millis(300), r1.next()).await;
    if let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) = leak {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_ne!(v["networkId"], joined["networkId"], "net1 socket must not receive net2 events");
    }
    w1.close().await.ok();

    // LEAVE net2; the last-network guard blocks leaving net1.
    let resp = srv
        .client
        .post(format!("{}/api/leave", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "network": "net2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = srv
        .client
        .post(format!("{}/api/leave", srv.base_url))
        .bearer_auth(&a.device_token)
        .json(&serde_json::json!({ "network": "net1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
