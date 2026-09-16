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
    h.set_settings(&sa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;
    h.set_settings(
        &sb,
        serde_json::json!({ "exposes": [{
            "networkId": net_id.to_hex(),
            "rules": [{ "port": 9090, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    let ea = h
        .start_engine(&sa, |c| {
            c.listen.push(format!("tcp://127.0.0.1:{a_tcp}"));
        })
        .await;
    let eb = h
        .start_engine(&sb, |c| {
            c.listen.push(format!("tcp://127.0.0.1:{b_tcp}"));
        })
        .await;
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
