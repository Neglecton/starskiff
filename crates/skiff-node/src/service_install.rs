//! `service` sub-command: install/remove/start/stop/status plus the SCM /
//! systemd host wiring (`service run`). Semantics: binPath quoting for
//! sc.exe, failure-recovery restart policy, firewall rule naming
//! ("Starskiff {name} UDP/TCP"), Linux firewall cascade.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
use skiff_core::models::NodeConfig;
#[cfg(not(windows))]
use skiff_core::platform::{linux_firewall_add, linux_firewall_remove};
use skiff_core::platform::{is_root, run_tool};
const DEFAULT_SERVICE_NAME: &str = if cfg!(windows) {
    "Starskiff"
} else {
    "starskiff"
};

fn service_name(explicit: Option<&str>) -> String {
    explicit.unwrap_or(DEFAULT_SERVICE_NAME).to_string()
}

pub fn install(
    name: Option<&str>,
    config: &std::path::Path,
    // Windows-only knobs; kept in the signature for CLI symmetry.
    #[cfg_attr(not(windows), allow(unused_variables))] start_mode: &str,
    #[cfg_attr(not(windows), allow(unused_variables))] display: Option<&str>,
    no_restart: bool,
    // 透传给 `service run`（→ worker）的滚动日志文件；服务模式下唯一
    // 的文件日志来源（SCM 不接收 stdout）。
    log_file: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let name = service_name(name);
    NodeConfig::load(config).map_err(|e| anyhow!("{e}"))?;
    if !is_root() {
        anyhow::bail!(
            "安装服务需要{}权限",
            if cfg!(windows) { "管理员" } else { " root" }
        );
    }
    // The NodeConfig::load at the top already validates the identity.

    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let timeout = Duration::from_secs(20);

    #[cfg(windows)]
    {
        let sc_query = run_tool("sc", &["query", &name], timeout).ok();
        if sc_query.is_some() {
            anyhow::bail!("服务 {name} 已存在");
        }
        // binPath 两步写（双机实测收敛的工程事实）：
        // 1) `sc create` 只传**最短 binPath（exe 纯路径）**——CreateService
        //    对创建时传入的长命令行（含 `-c`/`--log-file` 参数）存在拒绝
        //    （后续 StartService 恒报 87 参数错误，Server 2022 与 Win11 双
        //    机复现，与服务程序无关：cmd.exe 同样中招）；
        // 2) 再用 `reg add` 覆盖 ImagePath 为完整命令行——服务启动时 SCM
        //    从注册表读取，无此限制（同串 reg 写入后全生命周期 RUNNING、
        //    worker 正常产出日志已实测）。
        // ImagePath 形态：全裸（exe 与参数均不带引号，系统带参服务同款），
        // 三个路径都不能含空格——安装期显式校验，优于装出一个永远 87 的服务。
        let cfg_text = config.to_string_lossy().to_string();
        let lf_text = log_file
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        for (label, p) in [("程序", exe.as_ref()), ("配置", &cfg_text), ("日志", &lf_text)] {
            if !p.is_empty() && p.contains(' ') {
                anyhow::bail!(
                    "{label}路径含空格，服务 binPath 无法安全传递（SCM 对 ImagePath 引号的限制）：{p}。请移动到无空格路径后重装"
                );
            }
        }
        let mut bin_value = format!("{exe} service run -c {cfg_text}");
        if !lf_text.is_empty() {
            bin_value.push_str(&format!(" --log-file {lf_text}"));
        }
        let start_flag = match start_mode {
            "delayed" => "delayed-auto",
            "demand" => "demand",
            _ => "auto",
        };
        run_tool(
            "sc",
            &[
                "create",
                &name,
                &format!("binpath= {exe}"),
                "start=",
                start_flag,
            ],
            timeout,
        )?;
        // 第二步：reg 覆盖完整 ImagePath（见上方两步写注释）。
        run_tool(
            "reg",
            &[
                "add",
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{name}"),
                "/v",
                "ImagePath",
                "/t",
                "REG_EXPAND_SZ",
                "/d",
                &bin_value,
                "/f",
            ],
            timeout,
        )?;
        let display_text = display.unwrap_or(&name).to_string();
        let _ = run_tool(
            "sc",
            &[
                "description",
                &name,
                &format!("Starskiff mesh VPN node ({display_text})"),
            ],
            timeout,
        );
        if !no_restart {
            let _ = run_tool(
                "sc",
                &[
                    "failure",
                    &name,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/5000/restart/5000/restart/30000",
                ],
                timeout,
            );
        }
        // 防火墙不在此处配置：监听端口由服务端托管、只在运行时可知，
        // 规则由 worker 每次启动的 ensure_runtime_firewall 按当期端口
        // 重建、master 退出时清理（防火墙唯一真相 = 运行时规则）。
        println!("服务 {name} 已安装（开机自启，失败自动重启）");
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let unit_path = format!("/etc/systemd/system/{name}.service");
        if std::path::Path::new(&unit_path).exists() {
            anyhow::bail!("unit 文件已存在：{unit_path}");
        }
        let cfg_text = config.to_string_lossy();
        let restart = if no_restart { "no" } else { "always" };
        let log_tail = log_file
            .map(|lf| format!(" --log-file {}", lf.to_string_lossy()))
            .unwrap_or_default();
        let unit = format!(
            "[Unit]\nDescription=Starskiff mesh VPN node\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exe} service run -c {cfg_text}{log_tail}\nRestart={restart}\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
        );
        std::fs::write(&unit_path, unit)?;
        run_tool("systemctl", &["daemon-reload"], timeout)?;
        run_tool("systemctl", &["enable", &name], timeout)?;
        // 防火墙由运行时 ensure 按当期端口管理（同 Windows 注释）。
        println!("服务 {name} 已安装并启用");
        Ok(())
    }
}

pub fn remove(name: Option<&str>, config: Option<&PathBuf>) -> anyhow::Result<()> {
    let name = service_name(name);
    if !is_root() {
        anyhow::bail!(
            "移除服务需要{}权限",
            if cfg!(windows) { "管理员" } else { " root" }
        );
    }
    let timeout = Duration::from_secs(20);

    #[cfg(windows)]
    {
        let _ = run_tool("sc", &["stop", &name], timeout);
        let _ = config;
        // install 不再建规则，清理 = 运行时规则（与 master 退出清理同款）。
        for rule in [
            "Starskiff Node UDP".to_string(),
            "Starskiff Node TCP".to_string(),
        ] {
            let _ = run_tool(
                "netsh",
                &["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")],
                Duration::from_secs(15),
            );
        }
        std::thread::sleep(Duration::from_secs(2));
        run_tool("sc", &["delete", &name], timeout).map(|_| println!("已删除"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        run_tool("systemctl", &["disable", "--now", &name], timeout).ok();
        // Recover the config path from the unit to locate the runtime
        // firewall state (dataDir/runtime-firewall.json).
        let unit_path = format!("/etc/systemd/system/{name}.service");
        let unit = std::fs::read_to_string(&unit_path).unwrap_or_default();
        let config_path: Option<PathBuf> = config.cloned().or_else(|| {
            unit.lines()
                .find_map(|l| l.strip_prefix("ExecStart="))
                .and_then(|exec| {
                    exec.split_whitespace()
                        .position(|t| t == "-c")
                        .and_then(|i| exec.split_whitespace().nth(i + 1).map(PathBuf::from))
                })
        });
        if let Some(cfg) = &config_path {
            for line in cleanup_runtime_firewall(&crate::supervisor::data_dir_of(cfg)) {
                println!("{line}");
            }
        }
        std::fs::remove_file(&unit_path).ok();
        run_tool("systemctl", &["daemon-reload"], timeout).ok();
        println!("已移除");
        Ok(())
    }
}

/// Linux 运行时防火墙状态（上次 ensure 放行的端口集；dataDir 下的
/// runtime-firewall.json）。master 退出清理与端口 diff 同步都以它为
/// 唯一记忆——进程被强杀来不及清理时，下次启动按差集对齐自愈。
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FirewallState {
    pub udp: Vec<u16>,
    pub tcp: Vec<u16>,
}

#[cfg_attr(windows, allow(dead_code))]
fn firewall_state_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("runtime-firewall.json")
}

#[cfg_attr(windows, allow(dead_code))]
fn dedup_ports(ports: &[u16]) -> Vec<u16> {
    let mut v: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// 运行时防火墙同步：按**当期实际生效**的监听端口管理入站放行
/// （listen 托管变更 → worker 重启 → 规则自动跟进）。返回需写入引擎
/// 日志的结果行；无管理员/root 权限跳过并警告（不失败——前台非提权
/// 运行是合法形态，不影响配置下发）。
///
/// - Windows：固定名规则 `Starskiff Node UDP/TCP`，先删后建（幂等），
///   仅在该协议存在非 0 端口时建规则（program-only 放行过宽）。
/// - Linux：读状态文件取旧端口集，移除旧集差集、幂等添加当期全集、
///   写回状态文件（add 失败也写期望集——下次启动幂等重试自愈）。
///
/// 挂钩点在 main.rs 的 `__worker` 处理器而非 NodeEngine::start——后者
/// 被测试 harness 进程内直调，管理员 shell 下跑 cargo test 不能误改
/// 开发机防火墙。
#[cfg_attr(windows, allow(unused_variables))]
pub fn ensure_runtime_firewall(udp_ports: &[u16], tcp_ports: &[u16], data_dir: &std::path::Path) -> Vec<String> {
    let mut logs = Vec::new();
    #[cfg(windows)]
    {
        if !is_root() {
            logs.push(
                "防火墙：非管理员运行，跳过运行时规则同步（入站直连可能被系统防火墙拦截）"
                    .into(),
            );
            return logs;
        }
        let Ok(exe) = std::env::current_exe() else {
            logs.push("防火墙：无法确定可执行文件路径，跳过规则同步".into());
            return logs;
        };
        let program = format!("program={}", exe.to_string_lossy());
        for (suffix, proto, ports) in [
            ("UDP", "UDP", udp_ports),
            ("TCP", "TCP", tcp_ports),
        ] {
            let rule = format!("Starskiff Node {suffix}");
            let ports: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
            // 无监听不建规则；删除旧规则让端口收窄/清空可回收。
            let _ = run_tool(
                "netsh",
                &[
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={rule}"),
                ],
                Duration::from_secs(15),
            );
            if ports.is_empty() {
                continue;
            }
            let port_text = ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let args = vec![
                "advfirewall".to_string(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={rule}"),
                "dir=in".into(),
                "action=allow".into(),
                format!("protocol={proto}"),
                program.clone(),
                format!("localport={port_text}"),
            ];
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match run_tool("netsh", &refs, Duration::from_secs(15)) {
                Ok(_) => logs.push(format!("防火墙：规则 {rule} 已按当期端口更新（{port_text}）")),
                Err(e) => logs.push(format!("防火墙：规则 {rule} 更新失败（{e}）")),
            }
        }
    }
    #[cfg(not(windows))]
    {
        if !is_root() {
            logs.push("防火墙：非 root 运行，跳过运行时规则同步（入站直连可能被拦截）".into());
            return logs;
        }
        let state_path = firewall_state_path(data_dir);
        let old: FirewallState = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let new = FirewallState { udp: dedup_ports(udp_ports), tcp: dedup_ports(tcp_ports) };
        // 旧集差集移除（端口收窄/清空可回收；remove 不存在的规则报错即忽略）。
        let stale: Vec<(u16, &str)> = old
            .udp
            .iter()
            .filter(|p| !new.udp.contains(p))
            .map(|p| (*p, "udp"))
            .chain(old.tcp.iter().filter(|p| !new.tcp.contains(p)).map(|p| (*p, "tcp")))
            .collect();
        if !stale.is_empty() {
            let _ = linux_firewall_remove("node", &stale);
        }
        // 当期全集幂等添加（iptables -C / ufw / firewalld 均幂等）。
        let want: Vec<(u16, &str)> = new
            .udp
            .iter()
            .map(|p| (*p, "udp"))
            .chain(new.tcp.iter().map(|p| (*p, "tcp")))
            .collect();
        if !want.is_empty() {
            match linux_firewall_add("node", &want) {
                Ok(()) => logs.push(format!(
                    "防火墙：Linux 运行时规则已同步（udp={:?} tcp={:?}）",
                    new.udp, new.tcp
                )),
                Err(e) => logs.push(format!("防火墙：Linux 规则同步失败（{e}），不影响运行")),
            }
        }
        // 状态 = 期望集：add 失败下次启动幂等重试；强杀遗留下次差集对齐。
        if let Err(e) = std::fs::create_dir_all(data_dir)
            .and_then(|_| std::fs::write(&state_path, serde_json::to_vec(&new).unwrap_or_default()))
        {
            logs.push(format!("防火墙：状态文件写入失败（{e}），退出清理将退化为全量尝试"));
        }
    }
    logs
}

/// master 退出清理：移除运行时防火墙规则（系统配置不遗留）。仅在
/// master 最终退出时调用——worker 崩溃重启期间规则保留（保持连通）。
/// Windows 按规则名删除；Linux 按状态文件记忆的端口集删除并删文件。
/// 无权限仅返回警告行（强杀 master 无法清理，下次启动自动对齐）。
#[cfg_attr(windows, allow(unused_variables))]
pub fn cleanup_runtime_firewall(data_dir: &std::path::Path) -> Vec<String> {
    let mut logs = Vec::new();
    #[cfg(windows)]
    {
        for rule in ["Starskiff Node UDP", "Starskiff Node TCP"] {
            let _ = run_tool(
                "netsh",
                &["advfirewall", "firewall", "delete", "rule", &format!("name={rule}")],
                Duration::from_secs(15),
            );
        }
        logs.push("防火墙：运行时规则已随 master 退出清理".into());
    }
    #[cfg(not(windows))]
    {
        if !is_root() {
            logs.push("防火墙：非 root，跳过运行时规则清理（残留规则下次启动自动对齐）".into());
            return logs;
        }
        let state_path = firewall_state_path(data_dir);
        let state: FirewallState = std::fs::read(&state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let ports: Vec<(u16, &str)> = state
            .udp
            .iter()
            .map(|p| (*p, "udp"))
            .chain(state.tcp.iter().map(|p| (*p, "tcp")))
            .collect();
        if !ports.is_empty() {
            match linux_firewall_remove("node", &ports) {
                Ok(()) => logs.push("防火墙：Linux 运行时规则已随 master 退出清理".into()),
                Err(e) => logs.push(format!("防火墙：Linux 规则清理失败（{e}）",)),
            }
        }
        let _ = std::fs::remove_file(&state_path);
    }
    logs
}

pub fn start(name: Option<&str>) -> anyhow::Result<()> {    let name = service_name(name);
    let timeout = Duration::from_secs(20);
    #[cfg(windows)]
    {
        run_tool("sc", &["start", &name], timeout).map(|_| println!("已启动"))?;
    }
    #[cfg(not(windows))]
    {
        run_tool("systemctl", &["start", &name], timeout).map(|_| println!("已启动"))?;
    }
    Ok(())
}

pub fn stop(name: Option<&str>) -> anyhow::Result<()> {
    let name = service_name(name);
    let timeout = Duration::from_secs(20);
    #[cfg(windows)]
    {
        run_tool("sc", &["stop", &name], timeout).map(|_| println!("已停止"))?;
    }
    #[cfg(not(windows))]
    {
        run_tool("systemctl", &["stop", &name], timeout).map(|_| println!("已停止"))?;
    }
    Ok(())
}

pub fn status(name: Option<&str>) -> anyhow::Result<()> {
    let name = service_name(name);
    let timeout = Duration::from_secs(20);
    #[cfg(windows)]
    {
        let out = run_tool("sc", &["query", &name], timeout).map_err(|_| anyhow!("服务未安装"))?;
        let running = out.contains("RUNNING");
        println!("{out}");
        std::process::exit(if running { 0 } else { 1 });
    }
    #[cfg(not(windows))]
    {
        let out = run_tool("systemctl", &["status", &name, "--no-pager"], timeout)
            .map_err(|_| anyhow!("服务未安装"))?;
        println!("{out}");
        Ok(())
    }
}
