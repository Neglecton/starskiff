//! Multi-network scenarios: a node joins two networks and reaches peers in
//! both; leaving a network prunes its context.

use std::time::Duration;

use skiff_core::models::NetId;
use skiff_it::TestHarness;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_network_join_and_reach_both() {
    let h = TestHarness::create().await;
    h.create_network("net2", "10.98.0.0/24").await;
    let tok2 = h.token_for("net2").await;

    // Node A joins both networks (enrolled into testnet, joins net2)。
    // 名单由服务端权威维护，无需改本地文件。
    let pa = h.enroll_node("multi-a", None).await;
    let joined = h.join_node(&pa, &tok2).await.expect("join succeeds");
    assert_eq!(joined["networkName"], "net2");

    // Echo service for C.
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

    // B stays in testnet; C enrolls directly into net2（testnet 里的同名
    // 死设备用于验证按网络挑选 peer）。
    let pb = h.enroll_node("multi-b", None).await;
    let _pc_dead = h.enroll_node("multi-c", None).await;
    let pc = h.enroll_into(&tok2, "multi-c").await;
    let net2_id = NetId::from_hex(joined["networkId"].as_str().unwrap()).unwrap();
    // C 在 net2 的 expose 由服务端托管下发。
    h.set_settings(
        &pc,
        serde_json::json!({ "exposes": [{
            "networkId": net2_id.to_hex(),
            "rules": [{ "port": 8080, "proto": "tcp", "dest": format!("127.0.0.1:{echo_port}") }]
        }]}),
    )
    .await;
    h.set_settings(&pa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;

    let ea = h.start_engine(&pa, |_| {}).await;
    let _eb = h.start_engine(&pb, |_| {}).await;
    let _ec = h.start_engine(&pc, |_| {}).await;

    // A sees peers from BOTH networks, online (probing proves both relay
    // registrations are live — avoids the start race on the first flow).
    h.until(|| {
        let mut b = false;
        let mut c = false;
        for (_, p) in ea.peers() {
            if p.name() == "multi-b" && p.online() {
                b = true;
            }
            if p.name() == "multi-c" && p.online() {
                c = true;
            }
        }
        b && c
    })
    .await;

    // A reaches C's echo in net2 through SOCKS with real data. Pick the
    // multi-c that lives in net2 (a same-named dead device exists in testnet).
    let (net2_id, net2_c) = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "multi-c" && p.online())
        .expect("online multi-c in net2");
    let net2_ctx = ea.shared.networks.get(&net2_id).expect("net2 ctx");
    assert!(net2_ctx.ip_map.contains_key(&u32::from(net2_c.virtual_ip())), "peer lives in its network's ip map");
    drop(net2_ctx);
    let c_ip = net2_c.virtual_ip();
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port())).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let oct = c_ip.octets();
    let port = 8080u16.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]])
        .await
        .unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "CONNECT across networks succeeded");
    let payload = b"across networks";
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, payload);
}

/// SOCKS5 UDP ASSOCIATE 的数据报必须逐包按目的虚拟 IP 路由到所属网络：
/// 多网络节点上发往另一网络虚拟 IP 的数据报不得串扰进错误网络的 expose
/// （两个网络用同端口 expose，错网时端口正好撞上）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_udp_datagrams_route_to_destination_network() {
    let h = TestHarness::create().await;
    h.create_network("udpnet", "10.96.0.0/24").await;
    let tok2 = h.token_for("udpnet").await;

    // 每个远端各起一个 UDP echo，并把收到的内容上报 channel 以便断言归属。
    async fn spawn_echo() -> (u16, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((n, from)) = sock.recv_from(&mut buf).await {
                    let _ = tx.send(buf[..n].to_vec());
                    let _ = sock.send_to(&buf[..n], from).await;
                }
            }
        });
        (port, rx)
    }
    let (echo_b_port, mut echo_b_rx) = spawn_echo().await;
    let (echo_c_port, mut echo_c_rx) = spawn_echo().await;

    // A 同时在 testnet 与 udpnet（join 走服务端，无需改文件）；B 只在
    // testnet；C 直接注册进 udpnet。两网都在 9053 端口 expose UDP。
    let pa = h.enroll_node("xnet-a", None).await;
    h.join_node(&pa, &tok2).await.expect("join a");
    let pb = h.enroll_node("xnet-b", None).await;
    // C 直接注册进 udpnet；exposes 由服务端托管。
    let pc = h.enroll_into(&tok2, "xnet-c").await;
    let udpnet_id = h.network_id_by_name("udpnet").await;
    h.set_settings(&pa, serde_json::json!({ "socksListen": "127.0.0.1:0" })).await;
    h.set_settings(
        &pb,
        serde_json::json!({ "exposes": [{
            "networkId": h.network_id_by_name("testnet").await.to_hex(),
            "rules": [{ "port": 9053, "proto": "udp", "dest": format!("127.0.0.1:{echo_b_port}") }]
        }]}),
    )
    .await;
    h.set_settings(
        &pc,
        serde_json::json!({ "exposes": [{
            "networkId": udpnet_id.to_hex(),
            "rules": [{ "port": 9053, "proto": "udp", "dest": format!("127.0.0.1:{echo_c_port}") }]
        }]}),
    )
    .await;

    let ea = h.start_engine(&pa, |_| {}).await;
    let _eb = h.start_engine(&pb, |_| {}).await;
    let _ec = h.start_engine(&pc, |_| {}).await;

    // A 在两个网络里各看到在线 peer（探测打通了中继注册）。
    h.until(|| {
        let mut b = false;
        let mut c = false;
        for (_, p) in ea.peers() {
            if p.name() == "xnet-b" && p.online() {
                b = true;
            }
            if p.name() == "xnet-c" && p.online() {
                c = true;
            }
        }
        b && c
    })
    .await;

    // C 在 udpnet 的虚拟 IP。
    let c_ip = ea
        .peers()
        .into_iter()
        .find(|(_, p)| p.name() == "xnet-c")
        .map(|(_, p)| p.virtual_ip())
        .expect("xnet-c visible");

    // SOCKS5 UDP ASSOCIATE（0.0.0.0 目标——客户端默认行为）。
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", ea.socks_port()))
        .await
        .unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "UDP ASSOCIATE 成功");
    let assoc_port = u16::from_be_bytes([r[8], r[9]]);

    // 发往 udpnet 虚拟 IP 的数据报必须到达 C 的 expose，且不进 B 的。
    // 注意：同机测试里各 UDP 端口连续分配，邻近端口探测的密封 PING 会
    // 误入 echo 端口（AGENTS.md #15 的预期噪声），须按内容过滤。
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let oct = c_ip.octets();
    let port = 9053u16.to_be_bytes();
    let mut pkt = vec![0u8, 0, 0, 1, oct[0], oct[1], oct[2], oct[3], port[0], port[1]];
    pkt.extend_from_slice(b"cross-net-udp");
    client.send_to(&pkt, ("127.0.0.1", assoc_port)).await.unwrap();

    let got_c = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(d) = echo_c_rx.recv().await {
            if d == b"cross-net-udp" {
                return true;
            }
        }
        false
    })
    .await;
    assert!(got_c.expect("udpnet 的 expose 收到数据报"), "udpnet 的 expose 收到数据报");
    let leaked = tokio::time::timeout(Duration::from_millis(300), async {
        while let Some(d) = echo_b_rx.recv().await {
            if d == b"cross-net-udp" {
                return true;
            }
        }
        false
    })
    .await;
    assert!(!leaked.unwrap_or(false), "testnet 的 expose 不得收到跨网数据报");

    // 回程：echo 应答沿 flow 回到 SOCKS 客户端（带 10 字节 SOCKS 头）。
    let mut buf = [0u8; 64];
    let got_reply = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (n, _) = client.recv_from(&mut buf).await.unwrap();
            if buf[..n].ends_with(b"cross-net-udp") {
                return true;
            }
        }
    })
    .await;
    assert!(got_reply.expect("echo round trip"), "echo 应答回到 SOCKS 客户端");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leave_network_prunes_context() {
    let h = TestHarness::create().await;
    h.create_network("net2", "10.97.0.0/24").await;
    let tok2 = h.token_for("net2").await;

    let pa = h.enroll_node("leave-a", None).await;
    h.join_node(&pa, &tok2).await.expect("join");
    let ea = h.start_engine(&pa, |_| {}).await;
    h.until(|| ea.shared.networks.len() == 2).await;

    // `starskiff leave` semantics: stop the engine, call the API, restart
    //（名单由服务端维护，无需改本地文件）。
    ea.shutdown();
    let cfg = h.node_cfg(&pa);
    let resp = reqwest::Client::new()
        .post(format!("{}/api/leave", h.base_url()))
        .bearer_auth(cfg.identity.device_token.expose())
        .json(&serde_json::json!({ "network": "net2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let ea2 = h.start_engine(&pa, |_| {}).await;
    h.until_with_timeout(|| ea2.shared.networks.len() == 1, Duration::from_secs(10)).await;
    let names: Vec<String> = ea2.shared.networks.iter().map(|c| c.value().name.clone()).collect();
    assert!(names.iter().any(|n| n == "testnet"));
    assert!(!names.iter().any(|n| n == "net2"));
}

/// 管理员远程成员管理：强制 join → networks_changed → 节点置
/// restart_pending；模拟重启（shutdown + start_engine）后新网络完整可用
///（启动名单来自服务端，文件 networks[] 只是缓存）；强制 leave →
/// 运行时网络被修剪。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_forced_join_and_leave_drive_node_roster() {
    let h = TestHarness::create().await;
    h.create_network("net2", "10.95.0.0/24").await;
    let tok2 = h.token_for("net2").await;

    let pa = h.enroll_node("fj-a", None).await; // testnet
    let pc = h.enroll_node("fj-c", None).await; // testnet，稍后被强制拉入 net2
    let pd = h.enroll_into(&tok2, "fj-d").await; // 直接注册进 net2

    let _ea = h.start_engine(&pa, |_| {}).await;
    let ec = h.start_engine(&pc, |_| {}).await;
    let _ed = h.start_engine(&pd, |_| {}).await;
    h.until(|| ec.shared.networks.len() == 1).await;
    let c_id = h.device_id_of(&pc);

    // 强制 join net2 → networks_changed → restart_pending（新网络需重启）。
    let resp = h
        .admin
        .post(format!("{}/admin/devices/{c_id}/networks", h.base_url()))
        .header("X-Admin-Token", &h.admin_token)
        .json(&serde_json::json!({ "network": "net2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin forced join");
    h.until(|| ec.shared.restart_pending.load(std::sync::atomic::Ordering::Relaxed))
        .await;

    // 模拟重启（master 会做同样的事：停 worker → 以最新名单重启）。
    ec.shutdown();
    ec.stopped().await;
    let ec2 = h.start_engine(&pc, |_| {}).await;
    h.until_with_timeout(
        || {
            ec2.shared.networks.len() == 2
                && ec2.peers().iter().any(|(_, p)| p.name() == "fj-a" && p.online())
                && ec2.peers().iter().any(|(_, p)| p.name() == "fj-d" && p.online())
        },
        Duration::from_secs(30),
    )
    .await;

    // 强制 leave testnet（保留 net2）→ 运行时网络被修剪（roster 驱动）。
    let testnet_id = h.network_id_by_name("testnet").await;
    let resp = h
        .admin
        .delete(format!(
            "{}/admin/devices/{c_id}/networks/{}",
            h.base_url(),
            testnet_id.to_hex()
        ))
        .header("X-Admin-Token", &h.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin forced leave");
    h.until_with_timeout(
        || ec2.shared.networks.len() == 1,
        Duration::from_secs(30),
    )
    .await;
    let names: Vec<String> = ec2.shared.networks.iter().map(|c| c.value().name.clone()).collect();
    assert!(
        names.iter().any(|n| n == "net2") && !names.iter().any(|n| n == "testnet"),
        "剩余网络应为 net2：{names:?}（删除目标 testnet_id={testnet_id:?}）"
    );
}
