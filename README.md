# Starskiff — 异地组网工具

Rust 实现的 mesh VPN：**控制面中心化、数据面去中心化**。业务流量端到端加密，节点间优先直连（UDP/TCP），仅在无法直连或用户指定时经由服务器中继（中继也无法解密流量）。

```
┌───────────────────┐  控制面: HTTPS + WSS (设备/身份/网段/发现/公钥交换/在线状态)
│ Starskiff.Server  │◄──────────────────────────────────────► 节点
│  + 中继(UDP/TCP)   │◄──────────────────────────────────────► 节点     数据面: P2P 直连或中继
└───────────────────┘                                            (端到端加密)
```

线协议与加密设计见 `docs/protocol.md`。

## 平台支持

| 平台 | TUN 模式 | 非 TUN 模式（SOCKS5/转发/暴露） | 服务化 |
|---|---|---|---|
| Windows x64 | ✅ wintun（管理员） | ✅ | ✅ Windows 服务 |
| Linux x64 | ✅ /dev/net/tun（root/CAP_NET_ADMIN） | ✅ | ✅ systemd |

## 命令一览

### starskiff-server（服务器）

| 命令 | 作用 | 用法 |
|---|---|---|
| `init` | 初始化数据库，打印管理令牌 | `starskiff-server init [--db PATH]`（默认 `starskiff.sqlite`） |
| `serve` | 启动服务器（API/中继/Web 管理页） | `starskiff-server serve [--db PATH] [--api-port N] [--relay-udp N] [--relay-tcp N] [--cert PATH --key PATH] [--no-tls] [--log-file PATH]` |
| `admin network list` | 列出所有虚拟网络 | `starskiff-server admin --server URL --token T network list` |
| `admin network create` | 创建虚拟网络 | `starskiff-server admin --server URL --token T network create NAME CIDR` |
| `admin network remove` | 删除虚拟网络（含成员关系与令牌） | `starskiff-server admin --server URL --token T network remove NAME_OR_ID` |
| `admin token create` | 生成注册令牌 | `starskiff-server admin --server URL --token T token create NETWORK USES HOURS [--ip ADDR]` |
| `admin token list` | 列出所有令牌 | `starskiff-server admin --server URL --token T token list` |
| `admin token revoke` | 吊销令牌 | `starskiff-server admin --server URL --token T token revoke TOKEN` |
| `admin device list` | 列出所有设备（含在线状态/路径） | `starskiff-server admin --server URL --token T device list` |
| `admin device remove` | 移除设备 | `starskiff-server admin --server URL --token T device remove ID` |
| `admin device set-ip` | 手动指定设备虚拟 IP（实时下发） | `starskiff-server admin --server URL --token T device set-ip DEVICE NETWORK IP` |
| `service install` | 安装为系统服务（保存完整 serve 参数） | `starskiff-server service install [--db PATH] [--api-port N] ...` | Win 需管理员 / Linux 需 root |
| `service start` | 启动已安装的服务 | `starskiff-server service start` | 同上 |
| `service stop` | 停止服务 | `starskiff-server service stop` | 同上 |
| `service status` | 查看服务运行状态 | `starskiff-server service status` | 同上 |
| `service remove` | 移除服务（含运行时防火墙规则清理） | `starskiff-server service remove` | 同上 |

### starskiff（节点客户端）

| 命令 | 作用 | 用法 | 平台 |
|---|---|---|---|
| `enroll` | 首次注册：创建身份并加入第一个网络 | `starskiff enroll -c starskiff.json --server URL --token TOKEN [--name NAME] [--ip ADDR]` | 全平台 |
| `join` | 已有身份的节点加入另一个网络（多网络） | `starskiff join -c starskiff.json --token TOKEN [--ip ADDR]` | 全平台 |
| `leave` | 退出一个网络（保留其他网络） | `starskiff leave -c starskiff.json --network NAME_OR_ID` | 全平台 |
| `up` | 以前台方式启动节点 | `starskiff up -c starskiff.json [--log-file PATH]` | 全平台 |
| `status` | 查看运行状态（各网络的在线节点/路径/RTT/流量） | `starskiff status [--data-dir PATH]` | 全平台 |
| `down` | 停止前台运行的节点 | `starskiff down [--data-dir PATH]` | 全平台 |
| `init-config` | 生成示例配置文件 | `starskiff init-config [--out PATH] [--force]`（默认 `starskiff.json`） | 全平台 |
| `service install` | 安装为系统服务（开机自启+崩溃重启） | `starskiff service install -c starskiff.json [--name NAME] [--display DESC] [--start auto\|delayed\|demand] [--no-restart]` | Win 需管理员 / Linux 需 root |
| `service start` | 启动已安装的服务 | `starskiff service start [--name NAME]` | 同上 |
| `service stop` | 停止服务 | `starskiff service stop [--name NAME]` | 同上 |
| `service status` | 查看服务运行状态 | `starskiff service status [--name NAME]` | 同上 |
| `service remove` | 移除服务（含运行时防火墙规则清理） | `starskiff service remove [--name NAME] [-c starskiff.json]` | 同上 |
| `service run` | 内部：服务宿主入口（由 SCM/systemd 调用） | `starskiff service run -c starskiff.json` | 同上 |

> `--server`/`--token` 也可用环境变量 `STARSKIFF_SERVER` / `STARSKIFF_ADMIN_TOKEN` 代替。

## 快速开始

> **快捷方式**：`deploy/deploy-server.sh` 与 `deploy/deploy-node.sh` 可与对应可执行文件放在同一目录直接运行（Linux / Windows Git Bash 通用）——交互式提问、回车即用默认值完成部署并在前台运行，同时打印（但不执行）安装为系统服务的命令。

### 1. 启动服务器（有公网 IP 的机器）

```bash
starskiff-server init --db starskiff.sqlite     # 首次：打印管理令牌（保存好）
starskiff-server serve --db starskiff.sqlite    # 启动
# 输出 API 端口(默认 24930/TLS)、中继端口(24931/24932)、管理令牌、证书指纹
```

**传输安全默认开启**：服务器自动生成自签证书（ECDSA P-256），注册令牌内嵌证书指纹（`skk_xxx.<指纹>`）——节点 enroll 时首连即验证服务器身份（无 TOFU 攻击窗口），控制面全程 HTTPS/WSS。也可前置 CDN/反向代理：服务器 `--no-tls` + CDN 终止 TLS（公共 CA 证书），客户端检测到可信证书链后直接信任（不做指纹固定，CDN 证书轮换不断连）。浏览器打开管理页时需手动接受自签证书告警；也可用 `--cert/--key` 提供自己的证书。

### 2. 创建网络与注册令牌

```bash
starskiff-server admin --server https://服务器:24930 --token "ska_xxxx.指纹" network create mycorp 10.10.0.0/16
starskiff-server admin --server https://服务器:24930 --token "ska_xxxx.指纹" token create mycorp 10 24
# 或浏览器打开 https://服务器:24930/admin/ 用 Web 管理页操作（接受自签证书告警）
```

### 3. 注册节点并运行

```bash
starskiff enroll -c starskiff.json --server https://服务器:24930 --token skk_xxxx.指纹 --name my-laptop
starskiff up -c starskiff.json --log-file /var/log/starskiff/node.log   # 前台运行（Ctrl+C 停止）；或 service install 安装为系统服务
```

**多网络**：一个节点（单设备身份）可同时加入多个虚拟网络：

```bash
starskiff join -c starskiff.json --token <另一网络的注册令牌>   # 加入第二个网络
starskiff leave -c starskiff.json --network lab                 # 退出某个网络
starskiff up -c starskiff.json                                  # 双网络同时在线
```

- proxy 模式（SOCKS5/转发/暴露）完整支持多网络；**TUN 模式当前限单网络**（配置多网络时报错，取第一个）
- 每个网络有独立会话密钥（以网络 id 为派生盐，跨网络流量天然隔离）；两个网络网段重叠时启动会告警

**日志**：`--log-file PATH`（节点 CLI/服务器 CLI）或 config 的 `logFile` 字段启用滚动文件日志——按天分文件（`node.20260912.log`），自动清理 14 天前的旧文件；不带参数时仅输出到控制台。作为系统服务运行时强制写文件（默认 `<dataDir>/service.log`）。

### 4. 验证

- TUN 模式：`ping 10.10.0.x`、直接访问虚拟 IP 的任意端口
- proxy 模式：浏览器/应用配 SOCKS5 `127.0.0.1:1080` 访问虚拟 IP；或用 forwards/exposes
- `starskiff status` 查看在线节点与当前路径（DirectUdp/RelayUdp/...）

## 节点配置（starskiff.json）

终态瘦配置文件只承载**连接信息 + 本机部署参数 + 设备身份**（敏感字段以 `sealed:…` 内嵌，Windows 上 DPAPI LocalMachine 字段级密封、Linux 明文）。**除 server/identity 外的一切配置由服务器权威下发**（dataDir/logFile 是本机部署参数，保留在文件）：

```json
{
  "server": "https://your-server:24930",
  "dataDir": "",
  "logFile": null,
  "identity": { "...": "enroll 自动生成" }
}
```

**全部节点配置由服务器权威下发、管理页全托管**（无"是否托管"开关，保存即全量下发）：网络成员（管理页或 CLI `device network add/remove`）、路径策略（`pathPolicy` 全局：自动/强制 UDP 中继/强制 TCP 中继/只许直连/强制 UDP 直连/强制 TCP 直连，热生效、只控本端出口；"按对端覆盖"不常驻页面，入口在保存确认弹窗的"同步对端反向"勾选）、**运行模式（`mode`：tun 需管理员/root，无权限自动回滚并显示原因）**、**监听地址（`listen`：URL 数组，每协议可多条、可绑定指定网卡/IPv6）**、`exposes`/`socksListen`/`forwards`/`mtu`（管理页「设备配置」；重启类字段旁标注"重启生效"）。未下发的字段节点回退编译期默认值（proxy/24933/1300）。热改项立即生效；重启类变更**自动重启应用并等待节点应答**，配置启动失败（端口占用/无 TUN 权限等）自动回滚到上一版成功配置并在页面显示原因。`starskiff up` 与服务模式均为 master/worker 架构：管理页的重启指令由 master 以最新配置重新拉起 worker，master 退出时自动清理运行时防火墙规则。

```json
{
  "server": "https://your-server:24930",
  "dataDir": "",
  "logFile": null,
  "identity": {
    "deviceId": 1314905287493620,
    "name": "my-laptop",
    "deviceToken": "sealed:U0tGMQEAAAD…",
    "signPublicKey": "ab12…",
    "signPrivateKey": "sealed:U0tGMQEAAAD…",
    "dhPublicKey": "cd34…",
    "dhPrivateKey": "sealed:U0tGMQEAAAD…",
    "serverCertPin": null
  }
}
```

| 字段 | 说明 |
|---|---|
| `server` | 控制面地址（必填） |
| `dataDir` | 数据目录（stop.flag/状态文件/运行时防火墙状态；默认 `%APPDATA%/Starskiff` 或 `~/.config/starskiff`） |
| `logFile` | 滚动日志文件路径（服务模式下默认 `<dataDir>/service.log`） |
| `identity` | 设备身份（enroll 自动生成；`sealed:` 字段勿手改） |

身份由 `enroll` 创建；**全部行为配置（运行模式/监听地址/mtu/路径策略/socks/forwards/exposes/成员关系）经管理页或 AdminCli 在服务端维护**，节点启动与重启后自动拉取生效（含旧版本文件遗留键的忽略）。

## 路径选择

- 默认：先经中继保证连通，同时探测对端公布的端点（服务端观测地址 + 本地网段地址），探测成功即升级为 **直连 UDP**；直连失活自动回退中继
- 同网段（LAN）节点可通过上报的本地地址直连；节点默认监听 **24933**（UDP/TCP 同号），被占用时 UDP 自动回退随机端口、TCP 监听禁用（不影响连通性，仅直连可用性下降）
- 探测包含对观测端点的**邻近端口**（±1~4）尝试，覆盖端口递增型对称 NAT
- 对端通告 TCP 监听时，UDP 被阻断的网络里会自动尝试**直连 TCP**隧道
- **防火墙运行时自动管理（Windows/Linux）**：节点每次启动按**当期实际生效**的监听端口自动放行（Windows 固定名规则 `Starskiff Node UDP/TCP`；Linux 走 ufw → firewalld → iptables 级联，按端口），在 Web 管理页修改监听地址并重启生效后规则自动跟进；节点退出时自动清理规则（master 进程负责，崩溃重启期间保持放行）；无管理员/root 权限时跳过并记录日志警告（不影响运行）。注意：第三方安全软件（如 360）的独立拦截不受系统防火墙规则影响；`service install` 不再预建端口规则；云厂商安全组需在控制台放行 24930-24933
- `forceRelay` / `forceDirect` 可全局强制
- 完整 UDP 打洞（对称↔对称）未实现，此类节点保持中继（设计内行为）；Web 管理页"设备"表可查看每个节点到各对端的实际路径分布

## 以系统服务运行（开机自启 + 崩溃自动重启）

### Windows

```powershell
# 管理员 PowerShell，先完成 enroll 并准备好 starskiff.json
starskiff service install -c C:\path\starskiff.json --log-file C:\path\log\node.log
starskiff service start
starskiff service status
starskiff service stop
starskiff service remove
```

- 服务以 LocalSystem 运行（TUN 模式可用），显示名/启动类型可用 `--display`、`--start auto|delayed|demand` 定制，`--no-restart` 关闭崩溃重启
- 日志文件（master + worker 引擎日志共用滚动文件）：`--log-file` > config 的 `logFile` > 默认 `<dataDir>/service.log`
- **服务模式用 `service stop` 停止**；`starskiff down`（stop.flag）只作用于前台模式
- `node.json` 用 Windows DPAPI 加密（绑定本机 LocalMachine 作用域），LocalSystem 服务与安装用户共用同一身份文件

### Linux

```bash
# root，先完成 enroll 并准备好 starskiff.json
starskiff service install -c /etc/starskiff/starskiff.json   # 默认 Restart=always/5s
starskiff service start && starskiff service status
starskiff service stop && starskiff service remove
```

- systemd unit 写入 `/etc/systemd/system/starskiff.service`，`service run` 处理 SIGTERM 优雅停机
- TUN 模式前提：`/dev/net/tun` 存在（`modprobe tun`；容器需 `--device /dev/net/tun`）+ root/CAP_NET_ADMIN
- `node.json` 在 Linux 为明文（无 DPAPI），请用文件权限保护；同一身份文件不可跨平台复用

## 安全模型与已知限制（v1）

- 会话密钥 = 静态-静态 X25519 ECDH + HKDF-SHA256，**无前向保密**（后续计划：Noise IK / 密钥轮换）
- 身份信任根为服务器（服务器分发节点公钥）；控制面默认 TLS（自签证书 + 令牌内嵌指纹，三段信任模型详见 `docs/protocol.md`）
- `node.json`（设备令牌 + 私钥）经 DPAPI **LocalMachine** 作用域加密：拷离本机后无法解密；代价是本机任意进程理论上可解（与 Windows 凭据管理器同级的保护边界）
- ACL / 访问控制、NAT 类型探测：数据库与 API 结构已预留，尚未实现
- TUN 模式仅支持 IPv4；wintun.dll 使用其[预编译二进制许可](native/wintun/LICENSE.txt)分发

## 发版与分发

- **GitHub Actions**（`.github/workflows/release.yml`）：推 `v*` tag 触发——GitHub Release 资产（Windows zip / Linux musl tar.gz）+ GHCR 镜像 `ghcr.io/<owner>/<repo>/starskiff-server` 与 `/starskiff`（linux/amd64，tag 版本号 + latest；手动触发只推 `sha-<短哈希>`）。首次使用需在仓库 Package 设置里允许 Actions 写入（默认 GITHUB_TOKEN 即可推送）。
- **本地封包**：`sh deploy/package.sh`（与 CI 同构；产物在 `target/dist/`）。
- **Docker 自建**：`docker build -f deploy/Dockerfile.server|Dockerfile.node .`（多阶段自包含：容器内构建管理页与 musl 静态二进制，不依赖预编译产物）。server 容器直接运行即可——首次启动自动生成管理令牌并打印在容器日志（`docker logs` 查看，仅一次），无需手动 init。节点容器两步（ENTRYPOINT 是 `up`，enroll 须 `--entrypoint` 覆盖）：
  ```bash
  # 1) 一次性注册（身份写入卷）
  docker run --rm -it --entrypoint /app/starskiff -v skiff-node:/data <镜像> \
      enroll -c /data/starskiff.json --server https://<server>:24930 --token skk_…
  # 2) 长期运行（推荐 Linux 宿主 --network host：SOCKS/端口转发/P2P 监听直接可用）
  docker run -d --restart unless-stopped --network host -v skiff-node:/data <镜像>
  ```
  bridge 网络需 `-p 24933:24933 -p 24933:24933/udp`（被直连），并把 socksListen 托管为 `0.0.0.0:1080` 后 `-p 1080:1080`；TUN 模式需 `--device /dev/net/tun --cap-add NET_ADMIN`。
- 管理页「设备」页显示各节点上报的软件版本（原样透传，不比较高低；兼容性判定走协议代次 protoVersion）。

## 结构化日志

`key=value` 一行一事件，便于 grep/jq 后处理：

- 节点：`STATS peer=NAME ip=IP online=B path=PATH ep=ENDPOINT rtt_ms=N tx=... rx=...`（每 5 分钟/peer）、`PATH_UP peer=NAME type=DirectUdp|DirectTcp ep=...`、`PATH_DOWN peer=NAME from=DirectUdp to=RelayUdp reason=timeout`、`HEARTBEAT_ERR uptime_s=N err=...`
- 服务器：`STATS uptime_s=N relay_fwd_bytes=... relay_fwd_pkts=... relay_drops=... devices_online=... mem=NKB`、`WS_CONNECT device=NAME(ID) ep=IP`

分析示例：`grep "^STATS" service.log | grep -o 'rtt_ms=[0-9]*' | sort -t= -k2 -n | tail -5` 提取最高 RTT。

## 项目结构

```
crates/skiff-core     共享协议库：加密、线协议、IPAM、模型、密封、日志
crates/skiff-server   控制面 + 中继 + Web 管理页（axum + SQLite）
└── web/              管理页前端（Vue 3 + Vite + Naive UI + vue-i18n，产物内嵌二进制）
crates/skiff-node     节点守护进程/CLI（enroll/up/status/down/service）
tests/it              全链路集成测试（进程内 Server + 多节点，并行）
docs/protocol.md      线协议与加密设计
deploy/               Dockerfile / compose / musl 构建脚本
native/wintun         wintun.dll（构建 TUN 模式时随 exe 分发）
```

## 开发者指南

### 从源码构建与测试

要求 Rust stable（edition 2024）。完整产物（含管理页）还需 Node.js：

```bash
# 1. 构建管理页前端（产物 dist/ 不入库；跳过时 /admin/ 显示占位提示页）
cd crates/skiff-server/web && npm install && npm run build && cd ../../..

# 2. 构建后端（0 警告基线；crt-static 已固化在 .cargo/config.toml）
cargo build --workspace -q
cargo test --workspace              # 单元测试 + 集成测试（无需管理员，不依赖 TUN）
cargo clippy --workspace --all-targets
```

开发时可用 `cargo run` 替代编译后的命令：

```bash
cargo run -p skiff-server -- serve --db starskiff.sqlite
cargo run -p skiff-node -- enroll --server https://... --token ...
```

### 静态发布产物

Client 与 Server 均为**静态单文件原生二进制**（免装运行时）。

#### Windows x64

```powershell
cargo build --release --workspace      # crt-static 已固化，无需额外参数
# 产物: target/release/starskiff.exe + starskiff-server.exe（无 vcruntime 依赖）
# wintun.dll 复制到 starskiff.exe 旁（仅 TUN 模式需要）
```

#### Linux x64（musl，在 Windows 上直接交叉编译）

```bash
python -m pip install cargo-zigbuild ziglang   # 一次性安装（zig 作为交叉链接器）
cargo zigbuild --release --workspace --target x86_64-unknown-linux-musl
# 产物: target/x86_64-unknown-linux-musl/release/{starskiff,starskiff-server}（完全静态 ELF）
```

备选（容器内构建，网络不畅时）：

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/src" -w /src rust:1 sh deploy/build-linux-musl.sh
```

> 注意：交叉编译会检查被 `#[cfg]` 隐藏的代码路径——改动平台相关代码后两个 target 都要过编译/clippy。基于二进制的验证一律使用静态产物。

### Docker

```bash
cd deploy && docker compose up -d --build   # 服务器容器（数据卷 /data）
# 节点二进制挂载进任意 Linux 容器联调；容器内 TUN 验证需
# docker run --cap-add NET_ADMIN --device /dev/net/tun ...
```

## 手动验证清单（无法自动化的部分）

改动 TUN / 服务安装 / 防火墙 / master-worker 进程架构后：

- [ ] Windows：管理员运行 `starskiff up -c cfg`（mode=tun）→ 确认适配器 "Starskiff" 与 on-link 路由出现；`ping` 对端虚拟 IP、互访服务；`service install` 后重启机器自动联网；`sc failure` 配置生效（kill 进程观察自动重启）；`service remove` 干净（服务+防火墙规则）
- [ ] Linux：root 运行 tun 模式（`ip addr` 看到 skiff0）；systemd unit 安装/开机自启/SIGTERM 优雅退出；防火墙规则（ufw/firewalld/iptables）add/remove 对称
- [ ] TLS 真链路：`https://` 首连（TOFU 写回 node.json）+ 令牌指纹 pin + 错误 pin 拒绝
- [ ] 云安全组放行 24930-24933
- [ ] master/worker：`starskiff up` 起的是 master（监督 `__worker` 子进程）；管理页「设备配置 → 重启节点」后 worker 退出码 3、master 立即拉起新 worker（改 socksListen 等重启类配置验证生效）；`taskkill /F` worker 后 master 退避重启；`service stop` / SIGTERM / Ctrl+C 优雅停止整套进程；Windows 服务在 worker 崩溃时保持 RUNNING（SCM 日志不被刷屏）、仅在 master 自身异常退出非 0 时触发 `sc failure`

## 公网加固验证清单（半开链路/限流，无法自动化）

- [ ] DirectTcp 半开降级：双节点 directTcp 建链后，在对端节点侧用防火墙规则静默丢弃该 TCP 流（模拟 NAT 丢映射，不要 RST）→ 发起端流量应在 ~30s 内 PATH_DOWN 降级中继（日志 `PATH_DOWN from=DirectTcp`），恢复放行后探测重建
- [ ] TCP 中继往返检测：拔网线/断 VPN 模拟链路死亡 → 节点 RelayTcp 应在 ~90s 内断开并懒重连（服务端 120s 空闲回收兜底）
- [ ] WS 半开：同样静默丢包场景下事件通道 ~60s 内重连（服务端 Ping / 客户端 Pong 超时）
- [ ] 丢块断流：UDP 路径上用 tc/netem 注入丢包，SOCKS bulk 传输应表现为断开后客户端自动重连（连接级重试），而非返回损坏数据
- [ ] 管理面限流：错误 token 连续 10 次后应 429（15 分钟），期间正确 token 也 429；`starskiff-server admin rotate` 后旧令牌失效、serve 启动日志无明文令牌

## 刻意不做（当前版本范围外）

UDP 打洞 / NAT 类型探测 / ACL（结构已预留）、前向保密（静态-静态 ECDH，Noise IK 是后续独立改动）、TUN IPv6、客户端多网络。
