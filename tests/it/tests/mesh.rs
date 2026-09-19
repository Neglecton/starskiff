//! Ported mesh scenarios: enrollment/IP allocation, peer discovery, relay
//! TCP flow, SOCKS5, UDP forwarding, admin IP change propagation. All tests
//! run in parallel with independent servers (each on random ports).

use std::time::Duration;

use skiff_it::TestHarness;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_assigns_unique_sequential_ips_and_honors_manual() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("node-a", None).await;
    let pb = h.enroll_node("node-b", None).await;
    let pc = h.enroll_node("node-c", Some("10.99.0.200")).await;
    assert_eq!(h.virtual_ip_of(&pa).await, "10.99.0.1");
    assert_eq!(h.virtual_ip_of(&pb).await, "10.99.0.2");
    assert_eq!(h.virtual_ip_of(&pc).await, "10.99.0.200");
    let a = h.node_cfg(&pa);
    let b = h.node_cfg(&pb);
    assert_ne!(a.identity.device_token.expose(), b.identity.device_token.expose());

    // Duplicate manual IP is rejected with a 400-style error.
    let client = reqwest::Client::new();
    let keys = skiff_core::crypto::NodeKeys::generate();
    let resp: serde_json::Value = client
        .post(format!("{}/api/enroll", h.base_url()))
        .json(&serde_json::json!({
            "token": h.token,
            "name": "node-d",
            "signPubkey": keys.sign_public_hex(),
            "dhPubkey": keys.dh_public_hex(),
            "requestedIp": "10.99.0.1"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        resp["error"].as_str().unwrap_or("").contains("占用"),
        "got {resp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_discover_each_other_and_go_online() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("disc-a", None).await;
    let pb = h.enroll_node("disc-b", None).await;
    let ea = h.start_engine(&pa, |_| {}).await;
    let eb = h.start_engine(&pb, |_| {}).await;

    h.until(|| {
        ea.peers()
            .iter()
            .any(|(_, p)| p.name() == "disc-b" && p.online())
            && eb
                .peers()
                .iter()
                .any(|(_, p)| p.name() == "disc-a" && p.online())
    })
    .await;

    // Probing actually happens: RTT recorded, counters move.
    h.until(|| {
        let pa = ea.peers().into_iter().find(|(_, p)| p.name() == "disc-b").unwrap().1;
        let pb = eb.peers().into_iter().find(|(_, p)| p.name() == "disc-a").unwrap().1;
        pa.rtt_ms.load(std::sync::atomic::Ordering::Relaxed) >= 0
            && pb.rtt_ms.load(std::sync::atomic::Ordering::Relaxed) >= 0
            && pa.tx_packets.load(std::sync::atomic::Ordering::Relaxed) > 0
            && pb.rx_packets.load(std::sync::atomic::Ordering::Relaxed) > 0
    })
    .await;

    // The heartbeat path reports surface via /admin/devices with rttMs.
    let admin_token = h.admin_token.clone();
    let base = h.base_url();
    h.until_with_timeout(
        move || {
            tokio::task::block_in_place(|| {
                let rt = tokio::runtime::Handle::current();
                rt.block_on(async {
                    let admins: Vec<serde_json::Value> = reqwest::Client::new()
                        .get(format!("{base}/admin/devices"))
                        .header("X-Admin-Token", &admin_token)
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    admins.iter().any(|d| {
                        (d["paths"].as_array().unwrap_or(&vec![])).iter().any(|p| p["rttMs"].as_i64().unwrap_or(-1) >= 0)
                    })
                })
            })
        },
        std::time::Duration::from_secs(20),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_flow_carries_echo_through_relay_when_direct_forbidden() {
    let h = TestHarness::create().await;
    // Local echo service on B.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let sa = h.enroll_node("flow-a", None).await;
    let sb = h.enroll_node("flow-b", None).await;
    // 行为配置（force 开关 / exposes）由服务端托管下发。
    h.set_settings(&sa, serde_json::json!({ "pathPolicy": "relayUdp" })).await;
    let net_id = h.network_id_by_name("testnet").await;
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9070, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let _eb = h.start_engine(&sb, |_| {}).await;

    h.until(|| {
        ea.peers()
            .iter()
            .any(|(_, p)| p.name() == "flow-b" && p.online())
    })
    .await;
    let (net_id, peer) = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "flow-b")
        .unwrap();
    let peer_id = peer.id;

    let dest = format!("{}:9070", peer.virtual_ip());
    let flow = ea
        .flows()
        .open_tcp(net_id, peer_id, &dest, Duration::from_secs(10))
        .await
        .expect("flow opens through relay");

    let payload = b"starskiff relay echo";
    flow.write(payload);
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() && tokio::time::Instant::now() < deadline {
        if let Some(chunk) = flow.read().await {
            got.extend_from_slice(&chunk);
        }
    }
    assert_eq!(&got, payload);
    flow.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_connects_to_remote_expose() {
    let h = TestHarness::create().await;
    // Remote HTTP-ish echo on B's exposed port 8080.
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let sa = h.enroll_node("socks-a", None).await;
    let sb = h.enroll_node("socks-b", None).await;
    h.set_settings(&sa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;
    let net_id = h.network_id_by_name("testnet").await;
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 8080, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let _eb = h.start_engine(&sb, |_| {}).await;

    h.until(|| {
        ea.socks_port() > 0
            && ea
                .peers()
                .iter()
                .any(|(_, p)| p.name() == "socks-b" && p.online())
    })
    .await;
    let peer_ip = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "socks-b")
        .unwrap()
        .1
        .virtual_ip();

    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
        .await
        .unwrap();
    // Greeting.
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.unwrap();
    assert_eq!(&method, &[5, 0]);
    // CONNECT to the peer's virtual IP.
    let ip = peer_ip.octets();
    s.write_all(&[
        5,
        1,
        0,
        1,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
        8080u16.to_be_bytes()[0],
        8080u16.to_be_bytes()[1],
    ])
    .await
    .unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT succeeded");
    // Echo round trip.
    let payload = b"hello over socks";
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_forward_carries_datagrams() {
    let h = TestHarness::create().await;
    // UDP echo on B's exposed port 9053.
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            if let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        }
    });

    let sa = h.enroll_node("udp-a", None).await;
    let sb = h.enroll_node("udp-b", None).await;
    let b_ip = h.virtual_ip_of(&sb).await;
    let net_id = h.network_id_by_name("testnet").await;
    h.set_settings(
        &sa,
        serde_json::json!({ "forwards": [{
            "listen": "127.0.0.1:0", "proto": "udp", "dest": format!("{b_ip}:9053")
        }]}),
    )
    .await;
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9053, "proto": "udp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let _eb = h.start_engine(&sb, |_| {}).await;

    h.until(|| {
        !ea.forward_ports().is_empty()
            && ea.peers().iter().any(|(_, p)| p.name() == "udp-b" && p.online())
    })
    .await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"udp ping", ("127.0.0.1", ea.forward_ports()[0]))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut buf))
        .await
        .expect("datagram round trip within timeout")
        .unwrap();
    assert_eq!(&buf[..n], b"udp ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_ip_change_propagates_to_peers() {
    let h = TestHarness::create().await;
    let sa = h.enroll_node("ip-a", None).await;
    let sb_path = h.enroll_node("ip-b", None).await;
    let sb_id = h.device_id_of(&sb_path);
    let sb_net = h.network_id_by_name("testnet").await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let _eb = h.start_engine(&sb_path, |_| {}).await;

    h.until(|| ea.peers().iter().any(|(_, p)| p.name() == "ip-b"))
        .await;

    // Admin changes B's IP to 10.99.0.77.
    let resp = h
        .admin
        .post(format!(
            "{}/admin/networks/{}/devices/{}/ip",
            h.base_url(),
            sb_net.to_hex(),
            sb_id
        ))
        .header("X-Admin-Token", &h.admin_token)
        .json(&serde_json::json!({ "ip": "10.99.0.77" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A sees the new IP peer and the old one disappears.
    h.until_with_timeout(
        || {
            let new_ip: std::net::Ipv4Addr = "10.99.0.77".parse().unwrap();
            ea.peer_by_ip(new_ip).is_some() && ea.peer_by_ip("10.99.0.2".parse().unwrap()).is_none()
        },
        Duration::from_secs(20),
    )
    .await;
}

/// 服务端托管配置（DeviceSettings）：force 开关与 exposes 热生效；
/// 重启类字段（socksListen）写入文件并置 restart_pending；整个 PUT 是
/// 全量替换（未包含的字段回到未托管、沿用本地值）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_settings_hot_apply_and_pending() {
    let h = TestHarness::create().await;

    // B 的两个本地 TCP 服务：echo1（初始 expose，原样回显）与 echo2
    // （热更改后的 expose，回显带 v2: 前缀以区分流量命中了哪个）。
    let echo1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo1_port = echo1.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo1.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    let echo2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo2_port = echo2.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo2.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = s.read(&mut buf).await {
                        let mut out = b"v2:".to_vec();
                        out.extend_from_slice(&buf[..n]);
                        let _ = s.write_all(&out).await;
                    }
                });
            }
        }
    });

    let sa = h.enroll_node("set-a", None).await;
    let sb = h.enroll_node("set-b", None).await;
    let a_id = h.device_id_of(&sa);
    let b_id = h.device_id_of(&sb);
    let net_id = h.network_id_by_name("testnet").await;
    h.set_settings(&sa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;
    // 初始 expose（echo1）由服务端托管，启动时拉取生效。
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9080, "proto": "tcp", "dest": format!("127.0.0.1:{echo1_port}") }]
        }]}),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let eb = h.start_engine(&sb, |_| {}).await;
    h.until(|| ea.peers().iter().any(|(_, p)| p.name() == "set-b" && p.online()))
        .await;

    async fn admin_put(
        h: &TestHarness,
        device_id: u64,
        body: serde_json::Value,
    ) -> serde_json::Value {
        let resp: serde_json::Value = h
            .admin
            .put(format!("{}/admin/devices/{device_id}/settings", h.base_url()))
            .header("X-Admin-Token", &h.admin_token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        resp
    }

    // 1) pathPolicy=relayUdp 热应用到 A（引擎每帧现读生效策略）。
    // 注意 a 已有 socks 托管（revision 1），此处为 revision 2。
    let saved = admin_put(&h, a_id, serde_json::json!({ "pathPolicy": "relayUdp" })).await;
    assert_eq!(saved["revision"], 2, "admin PUT 响应异常: {saved}");
    let a_rev = 2;
    h.until(|| {
        *ea.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::RelayUdp
    })
    .await;
    h.until(|| ea.shared.applied_settings_revision.load(std::sync::atomic::Ordering::Relaxed) >= a_rev)
        .await;

    // 2) B 的 exposes 热更改：9080 从 echo1 指到 echo2，新连接立即命中新目标。
    let saved = admin_put(
        &h,
        b_id,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9080, "proto": "tcp", "dest": format!("127.0.0.1:{echo2_port}") }]
        }]}),
    )
    .await;
    assert_eq!(saved["revision"], 2, "b 的 exposes 第二版");
    let b_rev = 2;
    h.until(|| eb.shared.applied_settings_revision.load(std::sync::atomic::Ordering::Relaxed) >= b_rev)
        .await;

    // A 经 SOCKS CONNECT 到 B 的 9080，应答带 v2: 前缀。
    let b_ip = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "set-b")
        .map(|(_, p)| p.virtual_ip())
        .unwrap();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let oct = b_ip.octets();
    let port = 9080u16.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]])
        .await
        .unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "CONNECT ok");
    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut got))
        .await
        .expect("expose 回答")
        .unwrap();
    assert_eq!(&got[..n], b"v2:ping", "热更改后的 expose 立即生效");

    // 3) 重启类字段：socksListen 与启动时生效值不同 → 自动重启应用
    //    （worker 退出码 3；行为配置不落文件，重启时按服务端值重建）。
    //    in-process 测试断言停止原因为 Restart；整体 PUT 替换后 exposes
    //    回到未托管（默认无规则）。
    let saved = admin_put(&h, b_id, serde_json::json!({ "socksListen": "127.0.0.1:19999" })).await;
    assert_eq!(saved["revision"], 3);
    h.until(|| eb.shared.restart_pending.load(std::sync::atomic::Ordering::Relaxed)).await;
    tokio::time::timeout(Duration::from_secs(10), eb.stopped())
        .await
        .expect("重启类变更自动触发引擎重启");
    assert_eq!(eb.exit_code(), 3, "重启类变更 → worker 退出码 3（master 拉起）");
}

/// 远程重启指令：WS restart_requested → 引擎优雅停止且停止原因为
/// Restart（worker 退出码 3，由 master 重新拉起）。真进程行为无法在
/// 进程内测试，此处锁定引擎侧契约；先以 settings 收敛确认 WS 已连通
///（指令推送是 at-most-once，连接前发送会丢）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_restart_stops_engine_with_restart_reason() {
    let h = TestHarness::create().await;
    let sa = h.enroll_node("rst-a", None).await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let id = h.node_cfg(&sa).identity.device_id;

    // settings 下发并被应用 = WS 双向通路已建立（revision 动态取）。
    let resp: serde_json::Value = h
        .admin
        .put(format!("{}/admin/devices/{id}/settings", h.base_url()))
        .header("X-Admin-Token", &h.admin_token)
        .json(&serde_json::json!({ "pathPolicy": "auto" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rev = resp["revision"].as_i64().unwrap();
    assert!(rev >= 1);
    h.until(|| ea.shared.applied_settings_revision.load(std::sync::atomic::Ordering::Relaxed) >= rev as u64)
        .await;

    let resp = h
        .admin
        .post(format!("{}/admin/devices/{id}/restart", h.base_url()))
        .header("X-Admin-Token", &h.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    tokio::time::timeout(Duration::from_secs(10), ea.stopped())
        .await
        .expect("引擎按远程指令停止");
    assert_eq!(ea.exit_code(), 3, "重启请求映射为 worker 退出码 3");
}

/// 路径策略（PathPolicy）热切换：全局 relayTcp 激活 TCP 中继路径且流量
/// 真实经过服务器 TCP 中继（计数增长）；切回 auto 后按对端覆盖 directTcp
/// 只影响该对端；directUdp 覆盖同样生效；全局回落 auto 恢复状态机基线。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_policy_switches_routes() {
    let h = TestHarness::create().await;

    // B 的本地 echo（expose 9090/tcp），A 带 SOCKS。
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let sa = h.enroll_node("pol-a", None).await;
    let sb = h.enroll_node("pol-b", None).await;
    let sc = h.enroll_node("pol-c", None).await;
    let net_id = h.network_id_by_name("testnet").await;
    // directTcp 探测需要固定 TCP 监听端口（0=禁用）：预留两个随机端口。
    fn free_tcp_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }
    let a_tcp = free_tcp_port();
    let b_tcp = free_tcp_port();
    // listen 已全托管：固定 TCP 监听端口经启动前 PUT 下发（bootstrap 即
    // 拉取生效），不再走文件 tune。
    h.set_settings(
        &sa,
        serde_json::json!({
            "socksListen": "127.0.0.1:0",
            "listen": ["udp://0.0.0.0:0", format!("tcp://127.0.0.1:{a_tcp}")]
        }),
    )
    .await;
    h.set_settings(
        &sb,
        serde_json::json!({
            "exposes": [{
                "networkId": net_id.to_hex(),
                "rules": [{ "port": 9090, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
            }],
            "listen": ["udp://0.0.0.0:0", format!("tcp://127.0.0.1:{b_tcp}")]
        }),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let eb = h.start_engine(&sb, |_| {}).await;
    let _ec = h.start_engine(&sc, |_| {}).await;
    h.until(|| {
        ea.peers().iter().any(|(_, p)| p.name() == "pol-b" && p.online())
            && ea.peers().iter().any(|(_, p)| p.name() == "pol-c" && p.online())
    })
    .await;
    let b_id = h.device_id_of(&sb);

    // 1) 双向 relayTcp（模拟 webui 对称快捷设置）：relayTcp 的送达依赖
    //    接收方持有 TCP 中继连接（服务器按 dst 查连接转发），只 pin 发送
    //    方会黑洞——所以 B 也 pin。两端预热连接后路径与流量都走 TCP 中继。
    h.set_settings(&sa, serde_json::json!({ "pathPolicy": "relayTcp" })).await;
    // 注意 PUT 是全量替换：B 的策略下发必须连同 exposes 一起。
    h.set_settings(
        &sb,
        serde_json::json!({
            "pathPolicy": "relayTcp",
            "exposes": [{
                "networkId": net_id.to_hex(),
                "rules": [{ "port": 9090, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
            }]
        }),
    )
    .await;
    let peer_of = |name: &str| {
        ea.peers()
            .into_iter()
            .find(|(_, p)| p.name() == name)
            .map(|(_, p)| p)
            .unwrap()
    };
    h.until(|| {
        ea.shared.relay_tcp.is_connected()
            && eb.shared.relay_tcp.is_connected()
            && peer_of("pol-b").path() == skiff_node::session::PathKind::RelayTcp
            && peer_of("pol-c").path() == skiff_node::session::PathKind::RelayTcp
            && peer_of("pol-b").rtt_ms.load(std::sync::atomic::Ordering::Relaxed) >= 0
    })
    .await;
    let _ = &eb;
    let before = h.server.state.tcp_relay.forwarded_packets();
    // SOCKS CONNECT 到 B 的 expose，回显证明数据面仍通。
    let b_ip = peer_of("pol-b").virtual_ip();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let oct = b_ip.octets();
    let port = 9090u16.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]])
        .await
        .unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "CONNECT ok under relayTcp");
    s.write_all(b"pol").await.unwrap();
    let mut got = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut got))
        .await
        .expect("echo via relayTcp")
        .unwrap();
    assert_eq!(&got[..n], b"pol");
    h.until(|| h.server.state.tcp_relay.forwarded_packets() > before).await;

    // 2) 全局回 auto + 对 B 覆盖 directTcp：只有 B 变直连 TCP。
    h.set_settings(
        &sa,
        serde_json::json!({
            "pathPolicy": "auto",
            "peerPolicies": [{ "deviceId": b_id, "policy": "directTcp" }]
        }),
    )
    .await;
    h.until(|| peer_of("pol-b").path() == skiff_node::session::PathKind::DirectTcp).await;

    // 3) 覆盖改 directUdp：同机直连可达，升级为 DirectUdp。
    h.set_settings(
        &sa,
        serde_json::json!({
            "pathPolicy": "auto",
            "peerPolicies": [{ "deviceId": b_id, "policy": "directUdp" }]
        }),
    )
    .await;
    h.until(|| {
        peer_of("pol-b").path() == skiff_node::session::PathKind::DirectUdp
            && peer_of("pol-b").direct_endpoint.lock().unwrap().is_some()
    })
    .await;

    // 4) 全部清空（未托管）：策略回 Auto，对端覆盖表清空。
    h.set_settings(&sa, serde_json::json!({})).await;
    h.until(|| {
        *ea.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::Auto
            && ea.shared.peer_policies.is_empty()
    })
    .await;
}

/// 中继路径 PING/PONG 完整往返（回归锁定：中继转发的内层 wire 帧曾被
/// 误判为直连——PONG 裸发中继地址被服务端丢弃、last_pong 永不更新，
/// 数据面不受影响所以 flow 类测试测不到，见 AGENTS.md #20）。双节点在
/// 首个探测 tick（5s）之前均 pin relayUdp（无直连喷射），断言双方
/// last_pong 经中继往返被记录、direct_endpoint 不被污染（PONG 沿中继
/// 回程而非被当直连升级信号）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_udp_ping_pong_roundtrip_without_path_poisoning() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("rpong-a", None).await;
    let pb = h.enroll_node("rpong-b", None).await;
    let ea = h.start_engine(&pa, |_| {}).await;
    let eb = h.start_engine(&pb, |_| {}).await;

    // 立即双侧 pin relayUdp：必须赶在首个探测 tick（启动后 5s）之前——
    // Auto 阶段的直连喷射会学习 direct_endpoint，污染"无毒化"断言。
    h.set_settings(&pa, serde_json::json!({ "pathPolicy": "relayUdp" })).await;
    h.set_settings(&pb, serde_json::json!({ "pathPolicy": "relayUdp" })).await;
    h.until(|| {
        *ea.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::RelayUdp
            && *eb.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::RelayUdp
    })
    .await;

    // 中继 PING/PONG 往返：probe 经 route_sealed 走中继（RELAY 壳），服务
    // 端剥壳转发内层 PING；对端按 RelayUdp 到达分类、沿中继回 PONG；
    // 发起方记录 last_pong/RTT。对称侧同理。probe 周期 5s，留足余量。
    h.until_with_timeout(
        || {
            ea.peers().iter().any(|(_, p)| {
                p.name() == "rpong-b" && p.last_pong_ms.load(std::sync::atomic::Ordering::Relaxed) > 0
            }) && eb.peers().iter().any(|(_, p)| {
                p.name() == "rpong-a" && p.last_pong_ms.load(std::sync::atomic::Ordering::Relaxed) > 0
            })
        },
        Duration::from_secs(30),
    )
    .await;

    // 无路径毒化：pin 期间从未直连探测，PONG 全部经中继回程——若
    // direct_endpoint 被写入，说明中继帧又被误判为直连到达。
    for (side, e) in [("a", &ea), ("b", &eb)] {
        for (_, p) in e.peers() {
            assert!(
                p.direct_endpoint.lock().unwrap().is_none(),
                "side={side} peer={} direct_endpoint 被污染（中继帧误判直连）",
                p.name()
            );
        }
    }
}

/// directTcp pin 的连接建立与 PING/PONG 往返（回归锁定：TCP 探测此前
/// 只连 endpoints[0]，且失败/对端无 TCP 监听全程静默——"pin directTcp
/// 后 ping 全超时却无任何日志"的直接成因层，此前零测试覆盖）。双节点
/// 均在本机（观测端点即 127.0.0.1），断言 A 侧建立 TCP 连接并收到沿
/// 连接回程的 PONG。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_tcp_pin_probes_connect_and_carries_ping_pong() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("dtcp-a", None).await;
    let pb = h.enroll_node("dtcp-b", None).await;
    // 端口 0 = 随机（并行测试会争抢默认 24933）；listen 全托管，启动前
    // PUT（bootstrap 即拉到 pin + 随机端口，无启动后改配置的窗口）。
    let rnd_listen = serde_json::json!(["udp://0.0.0.0:0", "tcp://0.0.0.0:0"]);
    h.set_settings(&pa, serde_json::json!({ "pathPolicy": "directTcp", "listen": rnd_listen })).await;
    h.set_settings(&pb, serde_json::json!({ "pathPolicy": "directTcp", "listen": rnd_listen })).await;
    let ea = h.start_engine(&pa, |_| {}).await;
    let eb = h.start_engine(&pb, |_| {}).await;
    h.until(|| {
        *ea.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::DirectTcp
            && *eb.shared.path_policy.lock().unwrap() == skiff_core::models::PathPolicy::DirectTcp
    })
    .await;

    // A 侧：TCP 连接建立（探测 attach）+ PING 沿连接发出、PONG 沿连接
    // 回程被记录。探测周期 5s + 60s 失败冷却，留足余量。
    h.until_with_timeout(
        || {
            ea.peers().iter().any(|(_, p)| {
                p.name() == "dtcp-b"
                    && p.tcp_conn.lock().unwrap().is_some()
                    && p.last_pong_ms.load(std::sync::atomic::Ordering::Relaxed) > 0
            })
        },
        Duration::from_secs(30),
    )
    .await;

    // 建连后不再丢帧：PONG 已回程说明连接可用，此后 route_sealed 的
    // directTcp 出口应全部命中连接（计数在下一个探测周期内保持不变；
    // pin 生效→建连之间的窗口内探测 PING 丢一次是预期）。
    let base = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "dtcp-b")
        .map(|(_, p)| p.tx_dropped.load(std::sync::atomic::Ordering::Relaxed))
        .unwrap();
    tokio::time::sleep(Duration::from_secs(7)).await;
    for (_, p) in ea.peers() {
        assert_eq!(
            p.tx_dropped.load(std::sync::atomic::Ordering::Relaxed),
            if p.name() == "dtcp-b" { base } else { 0 },
            "directTcp 建连后仍有丢帧（peer={}）",
            p.name()
        );
    }
}

/// 中继 UDP 路径上的大流量 TCP flow 完整性（回归锁定：B 侧响应读块曾为
/// 64KiB——密封后 65592 > IPv4 UDP 数据报上限 65507，中继/直连 UDP 路径
/// send_to 必失败且被静默吞掉，bulk 传输=无痕黑洞；分块上限 FLOW_CHUNK
/// 与 per-socket writer 保序修复后应完整回环）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_udp_carries_bulk_tcp_flow_intact() {
    let h = TestHarness::create().await;
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });

    let sa = h.enroll_node("bulk-a", None).await;
    let sb = h.enroll_node("bulk-b", None).await;
    // 双侧 pin relayUdp：请求与响应全程经中继，最大化分片/分块压力。
    h.set_settings(&sa, serde_json::json!({ "pathPolicy": "relayUdp", "socksListen": "127.0.0.1:0" })).await;
    h.set_settings(&sb, serde_json::json!({ "pathPolicy": "relayUdp" })).await;
    let net_id = h.network_id_by_name("testnet").await;
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9090, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let _eb = h.start_engine(&sb, |_| {}).await;

    h.until(|| {
        ea.socks_port() > 0
            && ea
                .peers()
                .iter()
                .any(|(_, p)| p.name() == "bulk-b" && p.online())
    })
    .await;
    let peer_ip = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "bulk-b")
        .unwrap()
        .1
        .virtual_ip();

    // 经 SOCKS5 走真实反压路径（客户端 TCP 流控天然限制 in-flight，
    // 直连 flow.write 连发 16 帧大报文会打爆接收内核缓冲——UDP 静默
    // 丢包、无重传，属协议已知边界而非本测试目标）。
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(&m, &[5, 0]);
    let oct = peer_ip.octets();
    let port = 9090u16.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]])
        .await
        .unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "CONNECT ok");

    // 256KiB 确定性图案回环（B 侧 echo 回读块曾达 64KiB 触发必失败帧）。
    let total = 256 * 1024;
    let pattern: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let (mut rd, mut wr) = s.into_split();
    let writer = tokio::spawn(async move {
        for off in (0..total).step_by(16 * 1024) {
            wr.write_all(&pattern[off..off + 16 * 1024]).await.unwrap();
        }
        // 写半提前 drop 会向 SOCKS 服务端发 FIN 被视作客户端关闭、整条
        // 流拆除（合法的 TCP 半关闭语义本实现不支持）——保持存活直到
        // 读侧完成后由 abort 收尾。
        std::future::pending::<()>().await;
        let _ = wr;
    });
    let mut got = vec![0u8; total];
    let mut filled = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while filled < total && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), rd.read(&mut got[filled..])).await {
            Ok(Ok(0)) => {
                eprintln!("bulk diag: client EOF at filled={filled}");
                break;
            }
            Err(_) => {} // 本轮超时，继续等总 deadline
            Ok(Ok(n)) => filled += n,
            Ok(Err(e)) => panic!("读失败: {e}"),
        }
    }
    writer.abort();
    let expect: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    if filled != total || got != expect {
        let (_, p) = ea
            .peers()
            .into_iter()
            .find(|(_, p)| p.name() == "bulk-b")
            .unwrap();
        let (_, pb) = _eb
            .peers()
            .into_iter()
            .find(|(_, x)| x.name() == "bulk-a")
            .unwrap();
        let rs = h.server.state.udp_relay.stats();
        panic!(
            "bulk 回环不完整: got={filled} want={total}
A: tx_pkts={} tx_bytes={} tx_dropped={} send_errors={}
B: rx_pkts={} rx_bytes={} tx_pkts={}
relay: fwd_pkts={} fwd_bytes={} dropped={}",
            p.tx_packets.load(std::sync::atomic::Ordering::Relaxed),
            p.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
            p.tx_dropped.load(std::sync::atomic::Ordering::Relaxed),
            ea.shared.udp.send_errors.load(std::sync::atomic::Ordering::Relaxed),
            pb.rx_packets.load(std::sync::atomic::Ordering::Relaxed),
            pb.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
            pb.tx_packets.load(std::sync::atomic::Ordering::Relaxed),
            rs.forwarded_packets, rs.forwarded_bytes, rs.dropped_packets
        );
    }
}

/// 删除网络的收敛信号（回归锁定：曾零信号——节点对账只由推送/重连触发，
/// 5s 轮询遇 404 早退不清理，死网络的 peers/探测无限期续命）。删网后
/// NETWORKS_CHANGED 推送应触发节点对账，roster 即时修剪。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_network_converges_node_roster() {
    let h = TestHarness::create().await;
    let sa = h.enroll_node("del-a", None).await;
    let ea = h.start_engine(&sa, |_| {}).await;
    let net_id = h.network_id_by_name("testnet").await;
    // roster 就位（启动即写；WS 可能尚未连通——推送丢失时由 WS 404 拒绝
    // 触发的合成对账事件兜底收敛）。
    h.until(|| ea.shared.roster.lock().unwrap().contains(&net_id))
        .await;

    let resp = h
        .admin
        .delete(format!("{}/admin/networks/{}", h.base_url(), net_id.to_hex()))
        .header("X-Admin-Token", &h.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    h.until_with_timeout(
        || !ea.shared.roster.lock().unwrap().contains(&net_id),
        Duration::from_secs(15),
    )
    .await;
}

/// 首块回显固定标记的 echo 服务（返回监听端口）——用于验证数据落在
/// 哪个网络的 expose 规则上。
async fn spawn_marker_echo(marker: &'static [u8]) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            if let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let mut first = true;
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if first {
                            let _ = s.write_all(marker).await;
                            first = false;
                        }
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
    port
}

/// 同一设备跨两网络：(network, device) 双键 + 多 codec 试解链的引擎层
/// 锁定（AGENTS #0——密钥以 networkId 为派生盐，同一 deviceId 在两网各
/// 有独立会话，帧必须落在正确网络的会话）。B 在两网各暴露同端口不同
/// echo（回显不同标记），A 经 SOCKS 分别连两网 VIP：标记即落点证明。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_device_across_two_networks_lands_in_right_session() {
    let h = TestHarness::create().await;
    h.create_network("xdup2", "10.97.0.0/24").await;
    let tok2 = h.token_for("xdup2").await;
    let net1 = h.network_id_by_name("testnet").await;
    let net2 = h.network_id_by_name("xdup2").await;

    let echo1 = spawn_marker_echo(b"NET1:").await;
    let echo2 = spawn_marker_echo(b"NET2:").await;

    let pa = h.enroll_node("xdup-a", None).await;
    h.join_node(&pa, &tok2).await.expect("join net2");
    let pb = h.enroll_node("xdup-b", None).await;
    h.join_node(&pb, &tok2).await.expect("join net2");

    h.set_settings(&pa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;
    // 同端口 8100、两网不同 dest：应答标记 = OPEN 落点的网络。
    h.set_settings(
        &pb,
        serde_json::json!({ "exposes": [
            { "networkId": net1.to_hex(),
              "rules": [{ "port": 8100, "proto": "tcp", "dest": format!("127.0.0.1:{echo1}") }] },
            { "networkId": net2.to_hex(),
              "rules": [{ "port": 8100, "proto": "tcp", "dest": format!("127.0.0.1:{echo2}") }] }
        ]}),
    )
    .await;

    let ea = h.start_engine(&pa, |_| {}).await;
    let _eb = h.start_engine(&pb, |_| {}).await;

    // A 在两网各看到 B 的独立会话且均在线。
    h.until(|| {
        ea.peers().iter().filter(|(_, p)| p.name() == "xdup-b").filter(|(_, p)| p.online()).count() == 2
    })
    .await;
    let vips: Vec<(skiff_core::models::NetId, std::net::Ipv4Addr)> = ea
        .peers()
        .into_iter()
        .filter(|(_, p)| p.name() == "xdup-b")
        .map(|(n, p)| (n, p.virtual_ip()))
        .collect();
    assert_eq!(vips.len(), 2, "同一 device 双网会话独立存在");

    for (net, marker) in [(net1, &b"NET1:"[..]), (net2, &b"NET2:"[..])] {
        let vip = vips.iter().find(|(n, _)| *n == net).unwrap().1;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
            .await
            .unwrap();
        s.write_all(&[5, 1, 0]).await.unwrap();
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.unwrap();
        let oct = vip.octets();
        let port = 8100u16.to_be_bytes();
        s.write_all(&[5, 1, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]])
            .await
            .unwrap();
        let mut r = [0u8; 10];
        s.read_exact(&mut r).await.unwrap();
        assert_eq!(r[1], 0, "CONNECT ok (net={net:?})");
        s.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut got))
            .await
            .expect("echo 回答")
            .unwrap();
        assert_eq!(
            &got[..marker.len()],
            marker,
            "数据落在错误网络的会话（net={net:?}）"
        );
        assert_eq!(&got[marker.len()..n], b"ping");
    }
}

/// 多地址 listen 语义：通配端口被占→回退随机（标志置位）+ 指定地址共存
/// 多绑定；TCP 指定地址独立绑定。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_address_listen_fallback_and_extra_binds() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("mlisten-a", None).await;
    // 占住一个 UDP 端口（保持 socket 存活至引擎绑定之后）。
    let guard = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let occupied = guard.local_addr().unwrap().port();

    h.set_settings(
        &pa,
        serde_json::json!({ "listen": [
            format!("udp://0.0.0.0:{occupied}"),
            "udp://127.0.0.1:0",
            "tcp://127.0.0.1:0"
        ]}),
    )
    .await;
    let ea = h.start_engine(&pa, |_| {}).await;
    assert!(
        ea.shared.udp.used_fallback_port.load(std::sync::atomic::Ordering::Relaxed),
        "被占通配端口应回退随机"
    );
    assert!(
        ea.shared.udp.local_binds().len() >= 2,
        "回退绑定 + 指定地址共存"
    );
    assert_eq!(ea.shared.tcp_listen_ports.lock().unwrap().len(), 1);
}

/// 指定 IP（不在本机）绑定失败必须致命（显式意图，走配置回滚路径）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unassigned_ip_listen_is_fatal() {
    let h = TestHarness::create().await;
    let pa = h.enroll_node("mfail-a", None).await;
    // listen 全托管：先 PUT 再启动（bootstrap 拉到 TEST-NET-3 地址）。
    h.set_settings(&pa, serde_json::json!({ "listen": ["udp://203.0.113.1:0"] })).await;
    let cfg = skiff_node::node_config::load(&pa).unwrap();
    let log: skiff_core::logging::LogFn = std::sync::Arc::new(|_| {});
    let sink: skiff_node::engine::DataSink = Box::new(|_| {});
    let result = skiff_node::engine::NodeEngine::start(pa.clone(), cfg, sink, log).await;
    assert!(result.is_err(), "指定 IP 绑定失败应致命而非回退");
}
