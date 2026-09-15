# AGENTS.md — starskiff 仓库工作指南

面向在此仓库工作的 AI 编码代理。先读本文件再动手。每次改完代码后看看本文档是否需要修改。

## 项目是什么

Rust 实现的异地组网工具（mesh VPN）：控制面中心化（REST + WebSocket + SQLite），数据面去中心化（节点间端到端加密，直连优先，仅在不能直连或用户指定时经服务器中继，中继无法解密）。双二进制（starskiff-server / starskiff），目标 Windows x64 + Linux x64，静态单文件分发（crt-static / musl）。

设计文档：`docs/protocol.md`（线协议字节布局、密钥派生、API 摘要——改协议前必读）。用户文档：`README.md`。

## 常用命令

```bash
cargo build --workspace -q         # 构建（应 0 警告 0 错误）
cargo test --workspace             # 全部测试（无需管理员、不依赖 TUN）
cargo test -p skiff-core           # 仅协议/加密单测
cargo test -p skiff-it             # 集成测试（进程内起真实 server + 多节点引擎）
cargo clippy --workspace --all-targets   # 必须 0 警告
cargo run -p skiff-server -- serve       # 本地起服务器
cargo run -p skiff-node -- enroll --server http://127.0.0.1:24930 --token <skk_...>
```

- 集成测试默认并行（每个测试自建随机端口 server + 临时目录）。并行暴露过多处真实 bug，不要用串行化"修"测试。
- TUN 模式需要管理员/root 和驱动（Windows wintun.dll / Linux /dev/net/tun），**无法在测试中自动化**；验证清单在 README 末尾，改 tun.rs / 服务安装后提醒用户手动验证。

## 项目结构与职责边界

```
crates/skiff-core     协议/加密/IPAM/模型/密封/滚动日志/平台工具（无 tokio 依赖）
crates/skiff-server   lib+bin：axum API/WS、rusqlite 存储、UDP/TCP 中继、presence/events、
                      TLS(rcgen+rustls+PEM)、rust-embed 管理页（web/ 下的 Vue 3 前端）、AdminCli、service
crates/skiff-node     lib+bin：NodeEngine 编排、UdpMesh/RelayTcp/PeerTcp、FlowManager、
                      SOCKS5/Forwarders、TunDevice(tun-rs)、SCM 宿主、systemd、CLI
tests/it              Harness（进程内 server+节点）+ mesh.rs 六场景
```

数据流心智模型（改动前先在脑中过一遍）：
- 入站：UdpMesh/PeerTcp/RelayTcp → EngineEvent::Frame → EngineShared.handle_frame（查 peer → codec.try_open 解密+防重放 → 按 type 分发：PING 沿到达路径回 PONG / PONG 升级直连路径 / DATA 写 TUN / FLOW 交 FlowManager）。
- 出站：route_sealed 按 CurrentPath 选路（DirectUdp → RelayUdp → DirectTcp/RelayTcp），forceRelay/forceDirect 全局覆盖。
- TUN 出站：TunDevice reader → EngineEvent::TunPacket → IPv4 过滤 → peer_by_ip → seal(FRAME_DATA) → route_sealed。

## 硬性约束与已知坑（违反会引入难查的 bug）

0. **多网络不变式**：`peers` 按 `(network, device)` 双键组织（每网络独立 codec——密钥以 networkId 为派生盐）；**`PacketCodec::try_open` 必须解密成功后才推进重放窗口**（多 codec 试解零副作用的前提，wire.rs 有注释与单测锁定）；**starskiff.json 是瘦配置**（server/mode/mtu/dataDir/listen 端口/identity——启动名单唯一来源是 GET /api/memberships、行为配置唯一来源是 GET /api/settings，文件不再有 networks/socks/forwards/force 字段；遗留文件的非默认值在首次启动经 PUT /api/settings adopt 收编，之后文件被重写、遗留键消失）；TUN 模式限单网络（服务端强制 join 预检 + 节点启动兜底）；WS 每网络一条连接，事件按 networkId 路由；**join/leave 双通道**：CLI join 走 /api/join，管理端强制 join/leave 走 /admin/devices/{id}/networks 并推 networks_changed（节点对账 roster：离开即时修剪、加入置 restartPending；推送丢失由 WS 重连自拉兜底）。
1. **首字节 magic 是协议级判别**：wire `0x0A`（version=2，帧头 11B 明文头进 AEAD AAD——头部可见但不可篡改，勿改回无 AAD）、中继 `0x0B`（version=1，未知版本静默丢弃）。两个 magic 必须落在 **0x04–0x13** 区间（避 QUIC/STUN/DTLS/IKE/ASCII，见 docs/protocol.md 判别表）。改任一值 = 破坏兼容；新增隧道协议复用现有端口按首字节分流。
2. **所有 JSON 走 serde camelCase + null 省略**（DTO 在 skiff-core/src/models.rs，全部双向 derive）；错误响应统一 `{"error":"..."}`；API DTO 放 core（两端共享）；**设备 id 在管理面 JSON 中以字符串传输**（AdminDevice.id / PeerPathReport.deviceId / PeerPolicy.deviceId——随机 u64 常超 JS Number 的 2^53 精度，按数字解析会失真导致"设备不存在"；节点内部仍按 u64 用，边界 parse）。
3. **存储是 rusqlite 手写 ADO**（单连接 Mutex + WAL，无 ORM）；行映射列名必须与 SQL 一致；enroll 是唯一事务（IP 分配优先级 requestedIp > token.requestedIp > 顺序）。
4. **UDP flow 有方向性**：发起方与响应方对同一 flowId 各持 `FlowCtx::Udp`，DATAGRAM 按 `outbound` 标志分流（flow.rs）——曾因 clippy fix 折叠掉方向检查引入 bug，改动此区域后必跑 `udp_forward_carries_datagrams` 测试。
5. **DashMap 引用不可重叠同 key**（分片读写锁自死锁）——UdpRelay 的 RELAY 分支曾因此冻结整个 current-thread runtime；同 key 的 get/get_mut 必须顺序化（先 drop 再取）。
6. **UdpRelay 只转发已注册地址间的流量**，RELAY 源地址必须与 srcId 注册地址一致（防伪造），此校验不可移除。**REGISTER nonce 防重放同样不可移除**（register_guard.rs：UDP/TCP 中继共享 (deviceId, nonce) 记忆）——重放 REGISTER 可改写注册地址劫持中继流量；节点侧必须每次发送/连接生成新 nonce（udp_mesh 不缓存报文、RelayTcpClient 不缓存 register body）。
7. **`/api/peers` 的 udpEndpoints[0] 必须是中继观测端点**（节点邻近端口探测 ±1..4 依赖此顺序）。
8. **PONG 沿到达路径回复**（DirectUdp 回真实源端口）——路径升级前提，别改成统一走 CurrentPath。
9. **节点 UDP 端口被占回退随机、TCP 禁用监听**——不要改成硬错误（同机多节点与并行测试依赖）。
10. **peers 刷新走 single-flight**（refresh_peers：try_lock + pending 标志）；并发直调 core 会导致旧数据覆盖新数据。新增刷新触发点一律调 `refresh_peers`。
11. **Windows 服务先报 RUNNING 再起引擎**（win_service.rs；master/worker 架构下服务体就是轻量 master，RUNNING 秒报，worker 的 FetchConfigOrFail 无限重试在 master 消化）；**worker 退出码契约**（supervisor.rs）：0=干净停止（master 一并退出）、1=异常、3=远程重启请求——master 退避重启（1/2/5/10/30s 封顶，稳定运行 60s 清零），worker 崩溃不传染 SCM（服务保持 RUNNING）；引擎永不自行 exit（stopped 通过 EngineShared.stopped_tx 交给宿主，**通道必须保留常驻接收者**——tokio watch 零接收者时 send 失败且不存储值）。
12. **node.json 是 DPAPI LocalMachine 密封**（SKF1 + entropy `starskiff.NodeState.v1`；Linux 明文；旧明文兼容加载、下次保存自动密封）。
13. **三段 TLS 信任**（pin 严格比对 / 公共 CA 直信不固定 / 自签 TOFU 写回）——CDN 部署依赖第②段，改校验逻辑三段都必须保留；服务器证书以 **PEM** 存 settings 表。
14. **rustls 全链路 ring provider**（main/start 里 install_default）——别引入 aws-lc（musl/cmake 构建坑）。
15. **探测 PING 可能误入同机其它 UDP 端口**（邻近端口预测副作用，sealed 帧被 forwarder 转发是预期噪声）——测试断言注意。
16. Git Bash 下 docker 的容器内路径加 `export MSYS_NO_PATHCONV=1`。
17. **默认端口 24930-24933**（API/RelayUdp/RelayTcp/节点监听）；防火墙规则名 `Starskiff {name} UDP/TCP`，remove 按名删除——改名要两处同步。
18. **设备托管配置（DeviceSettings）走 revision 收敛**：服务端权威递增 revision，节点只在 `settings_changed` 推送与每次 WS `connected` 时自拉并按 `revision` 幂等应用（多网络节点多连接重复投递必须安全）；PUT 是全量替换，字段缺省=未托管走默认值（socks 默认开启 127.0.0.1:1080）；节点侧 `PUT /api/settings`（adopt）仅填未托管字段（遗留值收编，幂等无新值不递增 revision）；Secret/身份/listen 端口/mode 永不进该通道；**重启类字段（mtu/socks/forwards）不落文件**——以 EngineShared.runtime_* 为生效基准做 restart_pending 比对，重启按拉取值重建。**路径策略（PathPolicy：auto/relayUdp/relayTcp/directAny/directUdp/directTcp，全局+按对端覆盖）热生效且只控本端出口**：中继回退与超时降级仅 auto；探测/升级以"资源是否就绪"判断而非 path（pin 下 apply 已把 path 置为 pin 值，以 path 判断会死锁）；**relayTcp 送达要求接收方持有 TCP 中继连接**（单向 pin 黑洞，管理页提供成对设置）；RelayTcpClient 收到 REGISTER ACK 必须继续读（曾 `_ => return` 僵尸——发送正常接收全失）。
19. **WS 握手请求必须经 `into_client_request()` 从 URL 生成**（control.rs run_ws_once）：手工 `Request::builder().uri()` 构造的请求缺 sec-websocket-key 等握手头，握手必被拒——曾因此引擎事件订阅整体静默失效，全靠 5s probe 轮询兜底。

## 结构化日志（稳定性/性能分析）

见 README「结构化日志」；`key=value`，grep/jq 后处理。

## 约定

- Rust stable，edition 2024；主分支 `master`；不做 git 提交除非用户明确要求。
- 依赖从简且必须利于静态链接：tokio/axum/rustls(ring)/rusqlite(bundled)/rcgen(ring)/tun-rs(async_tokio)/clap/serde/dashmap。新增依赖前先确认 BCL/现有包不能满足。
- 注释与标识符中文、面向约束而非流水账；用户可见字符串与文档中文。
- 错误处理：lib 用 thiserror，bin 用 anyhow。
- release profile：lto=fat + codegen-units=1 + strip + panic=abort（panic → 非零退出 → 服务恢复策略接管）。

## 改完之后

1. `cargo clippy --workspace --all-targets` 0 警告。
2. `cargo test --workspace` 全绿（集成测试多跑两遍确认非 flaky——并行下偶发失败通常是真实竞态，回代码找原因）。
3. 基于二进制的验证一律用静态产物：
   - Windows：`cargo build --release --workspace`（crt-static 已固化在 `.cargo/config.toml`）
   - Linux（交叉编译，本机直接出 musl 静态 ELF，首选）：`cargo zigbuild --release --workspace --target x86_64-unknown-linux-musl`（需 `python -m pip install cargo-zigbuild ziglang` 一次）
   - Linux 备选（容器）：`MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src rust:1 sh deploy/build-linux-musl.sh`
   - 交叉编译会检查被 cfg 隐藏的代码路径（unix extern 块等）——改动平台相关代码后两个 target 都要过 clippy
4. 涉及线协议/加密的改动：同步更新 `docs/protocol.md` 与 skiff-core 单测。
5. 涉及管理面的改动：Web 页（`crates/skiff-server/web/`，Vue 3 + Vite + Naive UI + vue-i18n；`npm run build` 产物 dist 不入库，`web/dist/index.html` 占位页入库保证无 Node 也能 cargo build——提交前还原占位页，详见 `web/README.md`）与 admin CLI 保持功能对齐；改文案必须走 i18n 语言包（zh-CN/en-US 双份），改后需重新 `npm run build`。
6. 需保证`cargo build --release --workspace`编译成功且无警告，若出现警告，无论是不是本次修改导致的都需要修复。
7. 结束后关闭所有`starskiff`和`starskiff-server`测试进程。

## 功能边界（当前版本刻意不做的）

- UDP 打洞 / NAT 类型探测 / ACL：未实现，别"顺手"实现。
- 前向保密：静态-静态 X25519（HKDF-SHA256），已知限制；Noise IK/密钥轮换是单独大改动。
- TUN 仅 IPv4（非 IPv4 包直接丢弃是故意的）。
- 客户端单网络。
