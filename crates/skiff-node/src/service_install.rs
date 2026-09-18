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
) -> anyhow::Result<()> {
    let name = service_name(name);
    let cfg = NodeConfig::load(config).map_err(|e| anyhow!("{e}"))?;
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
        // sc.exe binPath escaping: inner quotes escaped with \", whole value
        // wrapped in quotes by the argument itself.
        let cfg_text = config.to_string_lossy();
        let bin_value = format!("\\\"{exe}\\\" service run -c \\\"{cfg_text}\\\"");
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
                &format!("binpath= \"{bin_value}\""),
                "start=",
                start_flag,
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
        // Firewall: UDP and TCP in rules, named for symmetric removal.
        let program = format!("program={exe}");
        for (suffix, proto) in [("UDP", "UDP"), ("TCP", "TCP")] {
            let rule = format!("Starskiff {name} {suffix}");
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
            let mut args = vec![
                "advfirewall".to_string(),
                "firewall".into(),
                "add".into(),
                "rule".into(),
                format!("name={rule}"),
                "dir=in".into(),
                "action=allow".into(),
                format!("protocol={proto}"),
                program.clone(),
            ];
            // 从监听列表按协议收集非 0 端口（托管值运行时可变，防火墙规则
            // 只按安装时的文件默认打——托管端口变化需管理员同步调整）。
            let want = if proto == "UDP" { "udp" } else { "tcp" };
            let ports: Vec<u16> = cfg
                .listen
                .iter()
                .filter_map(|u| skiff_core::models::parse_listen_url(u).ok())
                .filter(|(pr, a)| {
                    let w = if proto == "UDP" { skiff_core::models::ListenProto::Udp } else { skiff_core::models::ListenProto::Tcp };
                    *pr == w && a.port() != 0
                })
                .map(|(_, a)| a.port())
                .collect();
            if !ports.is_empty() {
                args.push(format!("localport={}", ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")));
            }
            let _ = want;
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let _ = run_tool("netsh", &refs, Duration::from_secs(15));
        }
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
        let unit = format!(
            "[Unit]\nDescription=Starskiff mesh VPN node\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exe} service run -c {cfg_text}\nRestart={restart}\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
        );
        std::fs::write(&unit_path, unit)?;
        run_tool("systemctl", &["daemon-reload"], timeout)?;
        run_tool("systemctl", &["enable", &name], timeout)?;
        let mut ports: Vec<(u16, &str)> = Vec::new();
        for u in &cfg.listen {
            let Ok((pr, a)) = skiff_core::models::parse_listen_url(u) else { continue };
            if a.port() == 0 {
                continue;
            }
            match pr {
                skiff_core::models::ListenProto::Udp => ports.push((a.port(), "udp")),
                skiff_core::models::ListenProto::Tcp => ports.push((a.port(), "tcp")),
            }
        }
        if let Err(e) = linux_firewall_add(&name, &ports) {
            println!("警告：防火墙配置失败（{e}）；容器/无 CAP_NET_ADMIN 环境可忽略");
        }
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
        // 服务级规则 + worker 运行时规则一并清理（对称）。
        for rule in [
            format!("Starskiff {name} UDP"),
            format!("Starskiff {name} TCP"),
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
        // Recover the config path from the unit to mirror firewall rules.
        let unit_path = format!("/etc/systemd/system/{name}.service");
        let unit = std::fs::read_to_string(&unit_path).unwrap_or_default();
        let mut ports: Vec<(u16, &str)> = Vec::new();
        let cfg: Option<NodeConfig> =
            config.and_then(|c| NodeConfig::load(c).ok()).or_else(|| {
                unit.lines()
                    .find_map(|l| l.strip_prefix("ExecStart="))
                    .and_then(|exec| {
                        exec.split_whitespace()
                            .position(|t| t == "-c")
                            .and_then(|i| {
                                exec.split_whitespace()
                                    .nth(i + 1)
                                    .map(PathBuf::from)
                                    .and_then(|p| NodeConfig::load(&p).ok())
                            })
                    })
            });
        if let Some(cfg) = &cfg {
            for u in &cfg.listen {
                let Ok((pr, a)) = skiff_core::models::parse_listen_url(u) else { continue };
                if a.port() == 0 {
                    continue;
                }
                match pr {
                    skiff_core::models::ListenProto::Udp => ports.push((a.port(), "udp")),
                    skiff_core::models::ListenProto::Tcp => ports.push((a.port(), "tcp")),
                }
            }
        }
        std::fs::remove_file(&unit_path).ok();
        run_tool("systemctl", &["daemon-reload"], timeout).ok();
        if !ports.is_empty() {
            let _ = linux_firewall_remove(&name, &ports);
        }
        println!("已移除");
        Ok(())
    }
}

/// 运行时防火墙同步（仅 Windows）：按**当期实际生效**的监听端口重建
/// 固定名规则 `Starskiff Node UDP` / `Starskiff Node TCP`（先删后建，
/// 幂等；listen 托管变更 → worker 重启 → 规则自动跟进）。仅在该协议
/// 存在非 0 端口时建规则（program-only 放行过宽）。返回需写入引擎日志
/// 的结果行；非管理员跳过而非失败（前台非提权运行是合法形态）。
///
/// 挂钩点在 main.rs 的 `__worker` 处理器而非 NodeEngine::start——后者
/// 被测试 harness 进程内直调，管理员 shell 下跑 cargo test 不能误改
/// 开发机防火墙。
pub fn ensure_runtime_firewall(udp_ports: &[u16], tcp_ports: &[u16]) -> Vec<String> {
    // 非 Windows 分支只消费入参不写 logs（cfg 差异），抑制 unused_mut。
    #[cfg_attr(not(windows), allow(unused_mut))]
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
        // Linux 不做运行时同步：iptables 运行时规则不持久 + 注释键删除
        // 不对称（重装/卸载无法可靠回收）。变更端口后重跑 service install
        // 或手动放行（README 已记录）。
        let _ = (udp_ports, tcp_ports);
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
