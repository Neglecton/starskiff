//! starskiff-server CLI: init / serve / admin / service.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{Parser, Subcommand};
use skiff_core::crypto::tokens::make_admin_token;
use skiff_core::logging::{RollingFileLogger, composite_logger, console_logger, timestamped};
use skiff_server::admin_cli::AdminCli;
use skiff_server::app::{ServerOptions, start};
use skiff_server::repo::Repo;

#[derive(Parser)]
#[command(
    name = "starskiff-server",
    version,
    about = "Starskiff 控制面与中继服务器",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 初始化数据库并生成管理员令牌
    Init {
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// 运行服务器
    Serve {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, default_value_t = skiff_core::consts::DEFAULT_API_PORT)]
        api_port: u16,
        #[arg(long, default_value_t = skiff_core::consts::DEFAULT_RELAY_UDP_PORT)]
        relay_udp: u16,
        #[arg(long, default_value_t = skiff_core::consts::DEFAULT_RELAY_TCP_PORT)]
        relay_tcp: u16,
        #[arg(long)]
        cert: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        no_tls: bool,
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// 管理命令（REST 客户端）
    Admin {
        #[arg(
            long,
            env = "STARSKIFF_SERVER",
            default_value = "http://127.0.0.1:24930"
        )]
        server: String,
        #[arg(long, env = "STARSKIFF_ADMIN_TOKEN")]
        token: String,
        #[command(subcommand)]
        cmd: AdminCmd,
    },
    /// 服务安装与管理（Windows: sc.exe；Linux: systemd）
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// 列出网络
    Network {
        #[command(subcommand)]
        cmd: NetworkCmd,
    },
    /// 管理注册令牌
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// 管理设备
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// 轮换管理令牌（旧令牌立即失效，新令牌仅显示一次）
    Rotate,
}

#[derive(Subcommand)]
enum NetworkCmd {
    List,
    Create { name: String, cidr: String },
    Remove { name_or_id: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    List,
    Create {
        network: String,
        uses: i64,
        hours: i64,
        #[arg(long)]
        ip: Option<String>,
    },
    Revoke {
        token: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    List,
    Remove {
        id: u64,
    },
    SetIp {
        device: String,
        network: String,
        ip: String,
    },
    /// 查看或设置设备的托管配置（服务端权威下发）
    Settings {
        device: u64,
        #[command(subcommand)]
        cmd: DeviceSettingsCmd,
    },
    /// 管理设备的网络成员关系（强制 join/leave，节点收到通知）
    Network {
        device: u64,
        #[command(subcommand)]
        cmd: DeviceNetworkCmd,
    },
    /// 请求节点重启引擎
    Restart {
        id: u64,
    },
    /// 请求节点轻量重连（不重启）
    Reconnect {
        id: u64,
    },
}

#[derive(Subcommand)]
enum DeviceSettingsCmd {
    /// 查看当前托管配置
    Get,
    /// 设置托管配置；JSON 字符串或 @文件路径，字段缺省 = 未托管
    Set { json: String },
}

#[derive(Subcommand)]
enum DeviceNetworkCmd {
    /// 强制设备加入网络（节点收到通知；重启引擎后完全生效）
    Add {
        network: String,
        #[arg(long)]
        ip: Option<String>,
    },
    /// 强制设备退出网络（运行中的节点数秒内自动修剪）
    Remove { network: String },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// 安装服务（serve 参数原样传入）
    Install {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        serve_args: Vec<String>,
    },
    Start,
    Stop,
    Status,
    Remove,
}

const SERVICE_NAME: &str = "starskiff-server";

fn main() -> anyhow::Result<()> {
    // Process-wide crypto provider (ring keeps static builds simple).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Init { db } => runtime.block_on(cmd_init(db)),
        Cmd::Serve {
            db,
            api_port,
            relay_udp,
            relay_tcp,
            cert,
            key,
            no_tls,
            log_file,
        } => runtime.block_on(cmd_serve(
            db, api_port, relay_udp, relay_tcp, cert, key, no_tls, log_file,
        )),
        Cmd::Admin { server, token, cmd } => runtime.block_on(cmd_admin(server, token, cmd)),
        Cmd::Service { cmd } => cmd_service(cmd),
    }
}

fn default_db() -> PathBuf {
    PathBuf::from("starskiff.sqlite")
}

async fn cmd_init(db: Option<PathBuf>) -> anyhow::Result<()> {
    let db = db.unwrap_or_else(default_db);
    let repo = Repo::open(&db).with_context(|| format!("无法打开数据库 {}", db.display()))?;
    match repo.admin_token() {
        Some(_) => println!("数据库已初始化（{}）", db.display()),
        None => {
            let token = make_admin_token();
            repo.set_setting("admin_token", &token)?;
            println!("管理员令牌（请保存，仅显示一次）：{token}");
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_serve(
    db: Option<PathBuf>,
    api_port: u16,
    relay_udp: u16,
    relay_tcp: u16,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    no_tls: bool,
    log_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let log = match log_file {
        Some(path) => {
            let stem = path.clone();
            let file = std::sync::Arc::new(RollingFileLogger::new(&stem, 14));
            let file_log = file.clone();
            let combined = composite_logger(vec![
                console_logger(),
                std::sync::Arc::new(move |line: &str| file_log.write_line(line)),
            ]);
            timestamped(combined)
        }
        None => timestamped(console_logger()),
    };

    let opts = ServerOptions {
        db_path: db.unwrap_or_else(default_db),
        api_port,
        relay_udp_port: relay_udp,
        relay_tcp_port: relay_tcp,
        no_tls,
        cert_file: cert,
        key_file: key,
        log: log.clone(),
    };
    let server = start(opts).await?;
    let scheme = if no_tls { "http" } else { "https" };

    println!("Starskiff 服务器已启动");
    println!(
        "  API: {scheme}://0.0.0.0:{} （管理页 /admin/）",
        server.api_port
    );
    println!(
        "  中继: UDP {} / TCP {}",
        server.relay_udp_port, server.relay_tcp_port
    );
    // 管理令牌仅在首次生成时打印一次明文（落入服务日志即长期泄露面）；
    // 之后启动只提示去向，轮换用 admin rotate。
    if server.admin_token_fresh {
        match &server.cert_fingerprint {
            Some(fp) => {
                println!("  管理令牌（仅显示一次，请保存）: {}", server.admin_token);
                println!(
                    "  管理令牌(TLS，带指纹): {}.{}",
                    server.admin_token, fp
                );
            }
            None => println!(
                "  管理令牌（仅显示一次，请保存）: {} （--no-tls 模式，流量明文）",
                server.admin_token
            ),
        }
    } else {
        match &server.cert_fingerprint {
            Some(fp) => println!("  管理令牌: 已初始化（明文见首次启动输出；轮换：admin rotate；指纹 {fp}）"),
            None => println!("  管理令牌: 已初始化（明文见首次启动输出；轮换：admin rotate）"),
        }
    }

    // Ctrl+C / SIGTERM -> shutdown.
    let log2 = log.clone();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            (log2)("收到停止信号，正在退出……");
        }
    }
    server.shutdown();
    Ok(())
}

async fn cmd_admin(server: String, token: String, cmd: AdminCmd) -> anyhow::Result<()> {
    let cli = AdminCli::new(&server, &token)?;
    match cmd {
        AdminCmd::Network { cmd } => match cmd {
            NetworkCmd::List => cli.network_list().await,
            NetworkCmd::Create { name, cidr } => cli.network_create(&name, &cidr).await,
            NetworkCmd::Remove { name_or_id } => cli.network_remove(&name_or_id).await,
        },
        AdminCmd::Token { cmd } => match cmd {
            TokenCmd::List => cli.token_list().await,
            TokenCmd::Create {
                network,
                uses,
                hours,
                ip,
            } => cli.token_create(&network, uses, hours, ip.as_deref()).await,
            TokenCmd::Revoke { token } => cli.token_revoke(&token).await,
        },
        AdminCmd::Device { cmd } => match cmd {
            DeviceCmd::List => cli.device_list().await,
            DeviceCmd::Remove { id } => cli.device_remove(id).await,
            DeviceCmd::SetIp {
                device,
                network,
                ip,
            } => cli.device_set_ip(&device, &network, &ip).await,
            DeviceCmd::Settings { device, cmd } => match cmd {
                DeviceSettingsCmd::Get => cli.device_settings_get(device).await,
                DeviceSettingsCmd::Set { json } => {
                    let json = if let Some(path) = json.strip_prefix('@') {
                        std::fs::read_to_string(path)?.trim().to_string()
                    } else {
                        json
                    };
                    cli.device_settings_set(device, &json).await
                }
            },
            DeviceCmd::Network { device, cmd } => match cmd {
                DeviceNetworkCmd::Add { network, ip } => {
                    cli.device_network_add(device, &network, ip.as_deref()).await
                }
                DeviceNetworkCmd::Remove { network } => {
                    cli.device_network_remove(device, &network).await
                }
            },
            DeviceCmd::Restart { id } => cli.device_restart(id).await,
            DeviceCmd::Reconnect { id } => cli.device_reconnect(id).await,
        },
        AdminCmd::Rotate => cli.rotate_token().await,
    }
}

fn cmd_service(cmd: ServiceCmd) -> anyhow::Result<()> {
    #[cfg(windows)]
    return windows_service_cmd(cmd);
    #[cfg(not(windows))]
    return linux_service_cmd(cmd);
}

#[cfg(windows)]
fn windows_service_cmd(cmd: ServiceCmd) -> anyhow::Result<()> {
    use skiff_core::platform::run_tool;
    let exe = std::env::current_exe()?;
    let exe = exe.to_string_lossy();
    let timeout = Duration::from_secs(20);
    match cmd {
        ServiceCmd::Install { serve_args } => {
            if !skiff_core::platform::is_root() {
                anyhow::bail!("安装服务需要管理员权限");
            }
            // Pre-check: the database must be initializable.
            let db = serve_args
                .iter()
                .position(|a| a == "--db")
                .and_then(|i| serve_args.get(i + 1))
                .map(PathBuf::from)
                .unwrap_or_else(default_db);
            Repo::open(&db).with_context(|| "数据库预检失败")?;

            let query = run_tool("sc", &["query", SERVICE_NAME], timeout).ok();
            if query.is_some() {
                anyhow::bail!("服务 {SERVICE_NAME} 已存在");
            }
            let mut bin_value = format!("\"{exe}\" serve");
            for a in &serve_args {
                bin_value.push_str(&format!(" \"{a}\""));
            }
            // sc.exe binPath escaping: the whole value is wrapped in quotes
            // again by the argument below; inner quotes are literal.
            run_tool(
                "sc",
                &[
                    "create",
                    SERVICE_NAME,
                    &format!("binpath= \"{bin_value}\""),
                    "start=",
                    "auto",
                ],
                timeout,
            )?;
            let _ = run_tool(
                "sc",
                &[
                    "description",
                    SERVICE_NAME,
                    "Starskiff mesh VPN control plane and relay",
                ],
                timeout,
            );
            let _ = run_tool(
                "sc",
                &[
                    "failure",
                    SERVICE_NAME,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/5000/restart/5000/restart/30000",
                ],
                timeout,
            );
            let api = serve_args
                .iter()
                .position(|a| a == "--api-port")
                .and_then(|i| serve_args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "24930".to_string());
            let udp = serve_args
                .iter()
                .position(|a| a == "--relay-udp")
                .and_then(|i| serve_args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "24931".to_string());
            let tcp = serve_args
                .iter()
                .position(|a| a == "--relay-tcp")
                .and_then(|i| serve_args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "24932".to_string());
            for (name, port, proto) in [
                ("Starskiff Server API", api.clone(), "TCP"),
                ("Starskiff Server UDP", udp, "UDP"),
                ("Starskiff Server TCP", tcp, "TCP"),
            ] {
                let _ = run_tool(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name={name}"),
                        "dir=in",
                        "action=allow",
                        &format!("protocol={proto}"),
                        &format!("localport={port}"),
                    ],
                    Duration::from_secs(15),
                );
            }
            println!("服务 {SERVICE_NAME} 已安装（开机自启，失败自动重启）");
            Ok(())
        }
        ServiceCmd::Start => run_tool("sc", &["start", SERVICE_NAME], timeout)
            .map(|_| println!("已启动"))
            .map_err(anyhow::Error::from),
        ServiceCmd::Stop => run_tool("sc", &["stop", SERVICE_NAME], timeout)
            .map(|_| println!("已停止"))
            .map_err(anyhow::Error::from),
        ServiceCmd::Status => {
            let out = run_tool("sc", &["query", SERVICE_NAME], timeout)
                .map_err(|_| anyhow!("服务未安装"))?;
            let running = out.contains("RUNNING");
            println!("{out}");
            std::process::exit(if running { 0 } else { 1 });
        }
        ServiceCmd::Remove => {
            if !skiff_core::platform::is_root() {
                anyhow::bail!("移除服务需要管理员权限");
            }
            let _ = run_tool("sc", &["stop", SERVICE_NAME], timeout);
            for name in [
                "Starskiff Server API",
                "Starskiff Server UDP",
                "Starskiff Server TCP",
            ] {
                let _ = run_tool(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={name}"),
                    ],
                    Duration::from_secs(15),
                );
            }
            std::thread::sleep(Duration::from_secs(2));
            run_tool("sc", &["delete", SERVICE_NAME], timeout)
                .map(|_| println!("已删除"))
                .map_err(anyhow::Error::from)
        }
    }
}

#[cfg(not(windows))]
fn linux_service_cmd(cmd: ServiceCmd) -> anyhow::Result<()> {
    use skiff_core::platform::run_tool;
    let timeout = Duration::from_secs(20);
    let unit_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");
    let exe = std::env::current_exe()?.to_string_lossy().into_owned();
    match cmd {
        ServiceCmd::Install { serve_args } => {
            if !skiff_core::platform::is_root() {
                anyhow::bail!("安装服务需要 root 权限");
            }
            let db = serve_args
                .iter()
                .position(|a| a == "--db")
                .and_then(|i| serve_args.get(i + 1))
                .map(PathBuf::from)
                .unwrap_or_else(default_db);
            Repo::open(&db).with_context(|| "数据库预检失败")?;
            if std::path::Path::new(&unit_path).exists() {
                anyhow::bail!("unit 文件已存在：{unit_path}");
            }
            let mut args = String::new();
            for a in &serve_args {
                args.push(' ');
                args.push_str(a);
            }
            let unit = format!(
                "[Unit]\nDescription=Starskiff mesh VPN control plane and relay\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exe} serve{args}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
            );
            std::fs::write(&unit_path, unit)?;
            run_tool("systemctl", &["daemon-reload"], timeout)?;
            run_tool("systemctl", &["enable", SERVICE_NAME], timeout)?;
            // Best-effort firewall allow (containers / no CAP_NET_ADMIN tolerate failure).
            let api = serve_args
                .iter()
                .position(|a| a == "--api-port")
                .and_then(|i| serve_args.get(i + 1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "24930".into());
            let udp = serve_args
                .iter()
                .position(|a| a == "--relay-udp")
                .and_then(|i| serve_args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "24931".to_string());
            let tcp = serve_args
                .iter()
                .position(|a| a == "--relay-tcp")
                .and_then(|i| serve_args.get(i + 1))
                .cloned()
                .unwrap_or_else(|| "24932".to_string());
            let _ = skiff_core::platform::linux_firewall_add(
                SERVICE_NAME,
                &[
                    (api.parse().unwrap_or(24930), "tcp"),
                    (udp.parse().unwrap_or(24931), "udp"),
                    (tcp.parse().unwrap_or(24932), "tcp"),
                ],
            );
            println!("服务 {SERVICE_NAME} 已安装并启用");
            Ok(())
        }
        ServiceCmd::Start => run_tool("systemctl", &["start", SERVICE_NAME], timeout)
            .map(|_| println!("已启动"))
            .map_err(anyhow::Error::from),
        ServiceCmd::Stop => run_tool("systemctl", &["stop", SERVICE_NAME], timeout)
            .map(|_| println!("已停止"))
            .map_err(anyhow::Error::from),
        ServiceCmd::Status => {
            let out = run_tool(
                "systemctl",
                &["status", SERVICE_NAME, "--no-pager"],
                timeout,
            )
            .map_err(|_| anyhow!("服务未安装"))?;
            println!("{out}");
            Ok(())
        }
        ServiceCmd::Remove => {
            if !skiff_core::platform::is_root() {
                anyhow::bail!("移除服务需要 root 权限");
            }
            run_tool("systemctl", &["disable", "--now", SERVICE_NAME], timeout).ok();
            // Read the unit for ports so firewall removal stays symmetric.
            let unit = std::fs::read_to_string(&unit_path).unwrap_or_default();
            let mut ports: Vec<(u16, &str)> = Vec::new();
            for line in unit.lines() {
                if let Some(rest) = line.trim().strip_prefix("ExecStart=") {
                    for proto in ["api-port", "relay-udp", "relay-tcp"] {
                        if let Some(p) = extract_flag_value(rest, &format!("--{proto}")) {
                            let kind = match proto {
                                "relay-udp" => "udp",
                                _ => "tcp",
                            };
                            if let Ok(v) = p.parse::<u16>() {
                                ports.push((v, kind));
                            }
                        }
                    }
                }
            }
            std::fs::remove_file(&unit_path).ok();
            run_tool("systemctl", &["daemon-reload"], timeout).ok();
            if !ports.is_empty() {
                let _ = skiff_core::platform::linux_firewall_remove(SERVICE_NAME, &ports);
            }
            println!("已移除");
            Ok(())
        }
    }
}

#[cfg(not(windows))]
fn extract_flag_value<'a>(line: &'a str, flag: &str) -> Option<&'a str> {
    let pos = line.find(flag)?;
    let rest = &line[pos + flag.len()..].trim_start();
    rest.split_whitespace().next()
}
