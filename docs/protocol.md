# starskiff 线协议与加密设计

## 总览

- **控制面**：HTTP REST + WebSocket（默认 TLS），JSON 编码（camelCase，null 字段省略）。承载设备注册、网段管理、节点发现、公钥交换、在线状态、配置变更推送。
- **数据面**：节点间端到端加密帧，可走直连 UDP / 直连 TCP / 服务器中继 UDP / 服务器中继 TCP。帧格式在四种路径上完全一致，服务器中继**无法解密**。
- 所有多字节整数为**小端**（SOCKS5 头内端口是大端，属代理层局部约定）。
- 时间戳一律 Unix 毫秒；网络 id 为 16 字节随机数（JSON 表示为 32 位小写 hex）。

## 控制面传输安全（TLS + 令牌内嵌指纹）

服务器默认生成自签证书（ECDSA P-256，CN=starskiff-server，有效期 10 年，以 PEM 持久化于 SQLite `settings` 表 `tls_pem`），身份锚点为证书 SHA-256 指纹（64 小写 hex，对 DER 计算）。**注册令牌即带外信任信道**：

- 令牌格式：`skd_`(设备)/`ska_`(管理)/`skk_`(注册) + base64url(24 随机字节，无填充)
- `token create` 返回的令牌自带 `.<64hex>` 指纹后缀；后缀判定规则：最后一个 `.` 之后恰好 64 个 hex 字符
- **三段信任模型**（CDN 兼容）：
  1. 有 pin（令牌后缀或 node.json 缓存）→ 严格比对指纹（大小写不敏感）
  2. 无 pin + 证书链经系统信任库验证通过 → 直接信任，**不固定**（CDN/反代 + 公共 CA，轮换不断连）
  3. 无 pin + 自签证书 → TOFU（首连接受并**即时固化内存 pin**，同进程后续握手落入第①段严格比对；指纹由引擎写回 node.json + 警告）
- `http://` 明文连接（服务器 `--no-tls`）直接放行并打警告

设备令牌不出现在服务器明文中：服务器只存 `token_hash = SHA256(令牌字符串)` 小写 hex；中继密钥 = 同一 SHA-256 的原始 32 字节。

## 密钥与身份

| 密钥 | 算法 | 用途 |
|---|---|---|
| 身份密钥对 | Ed25519（32B seed） | 节点身份，注册时上传公钥（v1 预留，暂不参与线上协议） |
| 静态 DH 密钥对 | X25519 | 会话密钥协商 |
| 设备令牌 | 随机 24B (`skd_` + base64url) | 控制面 Bearer 认证 |
| 中继密钥 | SHA256(设备令牌字符串) | 中继 REGISTER 的 HMAC 认证（服务器只存哈希） |

### 会话密钥派发

```
shared = X25519(myStaticPriv, peerStaticPub)        # 全零输出（小阶点）拒绝
okm    = HKDF-SHA256(ikm=shared,
                     salt=networkId(16B),
                     info="starskiff/session/v1" || lowPub || highPub,   # 公钥按字典序
                     L=64)
sendKey/recvKey = okm[0:32] / okm[32:64]   # 公钥较小一方用前半发送
```

限制：静态-静态 ECDH **无前向保密**；`networkId` 参与派生使不同网络密钥隔离。后续方向：Noise IK + 密钥轮换。

## 帧判别与协议版本

所有 starskiff 包的首字节落在 **0x04–0x13** 区间（wire 帧 `0x0A`、中继控制 `0x0B`）。该区间经过挑选，避开主流协议首字节特征：

| 区间 | 被避开的协议 |
|---|---|
| 0x00–0x03 | STUN / TURN |
| 0x14–0x19 | TLS / DTLS content type |
| 0x21+ | IKE / IPsec |
| 0x40–0xFF | QUIC 全部首字节空间（短头 0x40–0x7F、长头 0x80–0xFF） |
| 0x20–0x7E | ASCII 文本协议（HTTP、SSH 等） |

第二字节为**协议版本**（wire 帧当前为 2，中继控制为 1，未知版本静默丢弃）。判别链：magic → version → type/cmd 合法性 → 长度下限 → 最终由 AEAD 认证标签裁决。改任一 magic = 破坏兼容；新增隧道协议**复用现有端口按首字节分流**，不新占端口。

## 数据面帧（Wire Frame，magic 0x0A）

```
[magic u8 = 0x0A][version u8 = 2][senderId u64][type u8][nonce 24B][ciphertext+tag 16B]
```

- `type`：1=PING，2=PONG，3=DATA（TUN 模式的原始 IPv4 包），4=FLOW（非 TUN 流复用）
- PING 载荷 = 8B 当前 Unix 毫秒（LE）；PONG 原样回显，对端据此算 RTT（rtt<0 或 ≥600000 丢弃）
- `nonce` = 16B 每进程随机 bootNonce ‖ 8B LE 发送计数器（**从 1 起**）；AEAD 为 XChaCha20-Poly1305，**前 11 字节明文头（magic/version/senderId/type）作为 AAD** 参与认证——头部对中继可见但不可篡改，翻转任何一位即认证失败（防止 type 改写造成的类型混淆与 PONG 伪造路径劫持；tag 附在密文尾）
- 接收方按 (bootNonce, counter) 做 128 位滑动窗口防重放；**保留最近 32 代 bootNonce 水位**：未见过的 nonce 视为对端重启并开新代，只有最新代接受帧，旧代帧一律拒绝（防"重放旧代帧反复重置窗口"的翻转攻击，也封死跨重启延迟注入）
- **解密先行不变式**：AEAD 解密成功后才采纳 bootNonce / 推进重放窗口——多网络节点对同一发送者逐 codec 试解依赖"解密失败零副作用"
- 直连 TCP 上裸 wire 帧再加 `[len u32 LE]` 长度前缀（上限 512 KiB）；首帧 senderId 用于识别对端

## 中继协议（UDP，端口默认 24931，magic 0x0B）

```
[magic u8 = 0x0B][version u8 = 1][cmd u8][...]
REGISTER(1): [deviceId u64][nonce 16B][HMAC-SHA256(relayKey, "starskiff-relay-register"‖magic‖ver‖cmd‖deviceId‖nonce) 32B]   （59B 定长）
RELAY(2):    [srcId u64][dstId u64][wire frame...]     # 服务器校验 src 注册后原样转发内层帧
ACK(3):      [ipLen u8][ip ascii][port u16 LE]         # 回复 REGISTER，告知观测地址
ERROR(4):    [msgLen u8][msg utf-8]（截断 200B）
```

- 节点每 25–30s 重注册（保活 NAT 映射与注册表项；注册表 60s 过期，RELAY 活动也续期）；**每次 REGISTER 生成新 nonce**
- **REGISTER 防重放**：服务器记忆已用 (deviceId, nonce)（10 分钟 TTL，UDP/TCP 中继共享同一份记忆），重复即拒绝（UDP 静默丢弃 / TCP 回 ERROR 断开）——HMAC key 静态不轮换，报文自身无法证明新鲜度；重放 REGISTER 可改写注册地址劫持中继流量
- 服务器只转发**已注册地址之间**的流量，且 RELAY 包源地址必须与 srcId 注册地址一致（防伪造）——此校验不可移除
- HMAC key = SHA256(设备令牌字符串) 原始 32B；校验常数时间比较

## TCP 传输（端口默认 24932，中继；24933 直连）

帧格式：`[len u32 LE][payload]`（上限 512 KiB）。

- **直连 TCP**：payload = wire frame（首帧 senderId 识别对端）
- **中继 TCP**：payload = `[magic 0x0B][version 1][cmd][data]`，cmd：REGISTER(1，data 为 UDP REGISTER 去掉 3B 头后的 56B，HMAC 域仍含重构头)、ACK(3)、ERROR(4)、SEND(5，client→服务器 `[dstId u64][wire frame]`)、FRAME(6，服务器→client `[wire frame]`)、KEEPALIVE(7)/RESP(8)
- 服务器行为：首帧必须是 REGISTER（15s 超时，nonce 已用即回 ERROR 断开），失败回 ERROR；同 deviceId 重连踢旧连接；空闲 12h 断开；长度超限帧直接断开（流边界无法重新对齐）

### 端口演进约定

四个默认端口（24930–24933）按**接入点**而非协议分配，是天花板，不随隧道协议数增长：24930/tcp 管理面、24931/udp 数据面 UDP 接入点、24932/tcp 数据面 TCP 接入点、24933 节点 P2P 接入点（UDP/TCP 同号）。

## FLOW 子协议（非 TUN 模式）

载荷（type=4 帧解密后）：`[flowId u32 LE][flags u8][payload]`

| flags | payload | 说明 |
|---|---|---|
| OPEN(1) | `[proto u8: 1=TCP 2=UDP][addrLen u8]["ip:port"]` | 发起方打开流（flowId 由发起方随机生成，双方共用） |
| OPENED_OK(2) | 空 | 接收方确认 |
| OPENED_FAIL(3) | `[reasonLen u8][reason ≤200B]` | 无对应 expose 等 |
| CLOSE(4) | 空 | 关闭流 |
| DATA(5) | 字节块 | TCP 双向数据（按本地 socket 读到的块切片） |
| DATAGRAM(6) | `[addrLen u8]["ip:port"][数据报]` | UDP 数据报，addr 为目标虚拟 IP:端口；回程地址填本端虚拟 IP:服务端口 |

- 接收方按 `dst.Port` 查找 `exposes` 规则投递到本地服务，回程沿同一 flowId
- **FLOW 帧的传输路径与 flow 类型无关**：两类 flow 的帧都按发送方当前路径策略/CurrentPath 选路（直连 UDP / 直连 TCP / UDP 中继 / TCP 中继）。UDP 路径上**无应用层确认、重传与重组**——丢包即静默损坏流、分块（≤32KiB，`FLOW_CHUNK`）依赖 IP 分片；对完整性敏感的 bulk 场景应 pin `directTcp`/`relayTcp`（TCP 路径帧序由单写者队列保证）。数据面 UDP socket 已扩内核缓冲（4MB）缓解突发下的内核静默丢弃
- UDP flow 的空闲超时（5 分钟）由端口转发层负责 GC

## 控制面 API 摘要

节点侧（`Authorization: Bearer <设备令牌>` 或 `?token=`）：

| 端点 | 说明 |
|---|---|
| `POST /api/enroll` | 注册令牌 → deviceId + 设备令牌 + 虚拟 IP（可请求指定 IP）；IP 优先级：请求参数 > 令牌 requested_ip > 顺序分配 |
| `GET /api/config` | 本节点配置（网络、IP、MTU、中继端口） |
| `GET /api/peers` | 对端列表；`udpEndpoints[0]` **必须是中继观测端点**（客户端邻近端口探测依赖此顺序） |
| `GET /api/memberships` | 本设备的网络成员名单（**服务端权威**，节点启动名单的唯一来源；节点文件 networks[] 仅作缓存） |
| `GET /api/settings` | 本设备的服务端托管配置（DeviceSettings；revision 驱动幂等应用，字段缺省=未托管） |
| `POST /api/heartbeat` | 上报本地地址与监听端口（服务器清洗：仅 IPv4、去重、≤8 个；端口 1–65535；paths ≤64）；附 `settingsRevision`/`restartPending` 上报配置收敛状态（appliedRevision 追平当前 revision 时服务端固化 last_good 并清错误）；返回中继观测地址 + `heartbeatSecs`（自适应间隔建议：近期有管理端轮询 /admin/devices 时 5s，否则 15s；节点钳制 5–60s）。paths 各项含可选 `txBps`/`rxBps`——相邻心跳窗口内对端收发速率（密文整帧字节口径，含探测帧与加密开销；首窗/窗口 <1s 缺省） |
| `POST /api/settings/fail` | worker 以新配置启动失败上报 `{revision, error}`：匹配当前 revision 则自动回滚到 last_good 并重推；过期/重复忽略 |
| `POST /api/join` | 已注册设备用注册令牌加入**另一个**网络（幂等：已在网络则返回现 IP） |
| `POST /api/leave` | 设备移除自己在某网络的成员关系（禁止移除最后一个网络） |
| `WS /api/events` | 推送 peers_changed / device_online / device_offline / config_changed / settings_changed / networks_changed / restart_requested / reconnect_requested（同一设备可每网络一条连接并存） |

管理侧（`X-Admin-Token`，值先剥 `.<64hex>` 后缀再比对）：`/admin/summary`、`/admin/networks`（创建校验：name 1-32 位 `[a-zA-Z0-9_-]`、prefix ≤30）、`/admin/tokens`（uses 1–1000、有效期 1–8760h）、`/admin/devices`（含 settingsRevision/appliedRevision/restartPending 收敛状态）、`/admin/networks/{id}/devices/{id}/ip`（改 IP 实时下发 config_changed）、`GET|PUT /admin/devices/{id}/settings`（托管配置：PUT 全量替换，revision 服务端权威递增，保存后定向推送 settings_changed）、`POST /admin/devices/{id}/networks`（强制 join：TUN 节点超单网络预检拒绝，成功推送 networks_changed）、`DELETE /admin/devices/{id}/networks/{nid}`（强制 leave：修剪广播 + networks_changed）、`POST /admin/devices/{id}/restart|reconnect`（下发远程重启/轻量重连指令）。

### 网络成员权威模型

节点启动名单**只来自服务端**（GET /api/memberships，无限重试）；节点文件 networks[] 退化为展示缓存（每次成功拉取后按服务端顺序回写、按 networkId 合并保留本地 exposes）。`networks_changed` 推送为 at-most-once：节点在收到推送与每次 WS 连接（含重连）时对账 roster——成员减少即时修剪运行态，成员增加置 restartPending 待重启（新网络需要启动期资源：WS 循环/中继配置）；推送丢失由重连自拉兜底。心跳上报 `mode` 供服务端在强制 join 时预防性拒绝 TUN 节点超单网络。

### 设备托管配置（DeviceSettings）

服务端权威下发：`{revision, pathPolicy?, peerPolicies?[{deviceId, policy}], mode?("tun"/"proxy"), listen?["udp://ip:port",…], mtu?, socksListen?(空串=禁用), forwards?, exposes?[{networkId, rules}]}`，`Some` = 托管并覆盖默认值，缺省 = 未托管走默认（路径策略默认 `auto`、mode 默认文件值、socks 默认 `127.0.0.1:1080`）。**不落节点文件**——starskiff.json 只保留连接信息与本机部署参数。

**下发应答闭环**：路径策略与 exposes 热生效（应答即时）；重启类字段（mode/listen/mtu/socks/forwards）变更触发节点**自动重启**应用，应答由新 worker 启动成功给出（旧 worker 不代答——未真正生效的配置不得被固化为回滚锚点）。worker 以新配置启动失败时经 `POST /api/settings/fail {revision, error}` 上报，服务端自动回滚到 last_good（心跳 appliedRevision 追平当前 revision 时固化的内容；从未成功过则清空托管）并递增 revision 重推；过期/重复上报按 revision 比对忽略（幂等）。错误与失败 revision 随 `/admin/devices` 下发（settingsError/settingsErrorRevision），下一版成功应答后清除。

**监听地址（listen）**：URL 数组，每协议可多条、可绑定指定网卡与 IPv6（`udp://0.0.0.0:24933` / `tcp://[::]:24933` / `udp://192.168.1.5:24934`；端口 0=随机）。通配地址绑定失败沿用容错（UDP 回退随机端口/TCP 跳过——多节点同机依赖）；**指定 IP 绑定失败为致命错误**，走失败上报→回滚。UdpMesh 多 socket：primary（首项）承担中继注册/默认发送；PONG 沿到达 socket 回复、直连数据经学习端点时的同一 socket 发送（NAT 映射一致）；探测从全部 UDP socket 喷射。**mode=tun 需管理员/root**（无权限时启动失败自动回滚并显示原因；服务端预检拒绝多网络成员设备的 tun 下发）。

推送为 at-most-once：节点在收到 `settings_changed` 与每次 WS `connected` 时自拉，`revision` 单调递增做幂等去重（多网络节点多连接重复投递安全）。配置全托管：`GET /api/settings` 为节点唯一配置来源（未下发字段回退编译期默认值），节点侧不提供写端点。

#### 路径策略（PathPolicy）

`auto | relayUdp | relayTcp | directAny | directUdp | directTcp`，生效策略 = 对端覆盖 ?? 全局默认 ?? auto，按对端独立生效。要点：

- **只决定本端出口**：接收方在所有路径上收帧（解密分流），两端不一致产生**非对称路径**而非失败；直连 pin 会经对端 PONG/attach 机制"拉动"对端一起直连，Relay* pin 不被拉动。
- Relay* 跳过一切直连探测；directUdp/directTcp 只做对应协议探测（按资源是否就绪判断）；探测/超时降级仅 auto 保留。
- **relayTcp 送达要求接收方持有 TCP 中继连接**（服务器按 dst 查其 TCP 中继连接转发）——单向 pin 会黑洞，应成对设置（管理页保存对端覆盖时提供"同步反向方向"快捷确认）。
- 中继回退（直连资源缺失→UDP 中继）仅 auto 允许；pin 档丢帧确定性优先，靠探测自愈。

错误响应统一 `{"error":"..."}`。

## 路径状态机（客户端）

```
初始 → RelayUdp（保证连通）
     ↘ 探测对端端点（PING 直发：本地地址端点 ×4 + 观测端点 ±1~4 邻近端口预测 + 直连 TCP 3s 超时/60s 冷却）→ 收到直连 PONG → DirectUdp
DirectUdp 30s 无 PONG（10s × 3 次）→ 回退 RelayUdp
直连 TCP 连接建立（任一方向）→ DirectTcp
路径策略（PathPolicy，见「设备托管配置」）叠加在状态机之上：路由按生效策略解析、策略应用时同步 current_path、升级经 policy_allows 门控、探测按资源就绪度裁剪
```

**PONG 必须沿到达路径回复**（DirectUdp 回真实源端口）——这是对称 NAT 端口预测能升级路径的前提。

## 常量表

| 常量 | 值 |
|---|---|
| 默认端口 | API 24930 / RelayUdp 24931 / RelayTcp 24932 / 节点监听 24933 |
| MTU | 1300 |
| Presence 超时 | 45s（WS 连接即在线） |
| 心跳间隔 | 15s（每第 2 次附带中继 REGISTER + TCP KEEPALIVE） |
| 路径探测 | 5s；ping 10s×3 次未中降级；直连探测 2s；TCP 探测 3s 超时 + 60s 冷却 |
| 防重放窗口 | 128 计数器；bootNonce 保留最近 32 代（REGISTER nonce 记忆 10 分钟） |
| worker 退出码 | 0=干净停止 / 1=异常（配置启动失败经 /api/settings/fail 上报后回滚自愈）/ 3=重启请求（远程指令或重启类配置变更自动触发）；master 退避 1/2/5/10/30s（稳定 60s 清零），`__worker` 为内部子进程 |
| TCP 帧上限 | 512 KiB；UDP 收包缓冲 65535 |
| wintun ring | 4 MiB |
| 本地身份文件 | node.json，Windows DPAPI LocalMachine 密封（`SKF1` 头，entropy `starskiff.NodeState.v1`），非 Windows 明文 |
