//! starskiff node CLI: enroll / join / leave / up / status / down /
//! init-config / service.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use clap::{Parser, Subcommand};
use skiff_core::crypto::NodeKeys;
use skiff_core::crypto::tokens::split_token;
#[cfg(windows)]
use skiff_core::logging::LogFn;
use skiff_core::models::{EnrollRequest, Identity, NodeConfig};
use skiff_node::control::ControlClient;
use skiff_node::node_config;

#[derive(Parser)]
#[command(name = "starskiff", version, about = "Starskiff mesh VPN 节点")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 首次注册：创建设备身份并加入第一个网络
    Enroll {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        server: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        ip: Option<String>,
    },
    /// 已有身份的节点加入另一个网络（多网络）
    Join {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        token: String,
        #[arg(long)]
        ip: Option<String>,
    },
    /// 退出一个网络（保留其他网络）
    Leave {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        network: String,
    },
    /// 以前台方式启动节点（master 进程，监督 worker 子进程）
    Up {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// 内部命令：由 master（supervisor）拉起的 worker 子进程，勿手动调用
    // name 必须显式指定：clap 默认把变体名转成 kebab-case（Worker→worker），
    // 与 supervisor.rs 的 WORKER_SUBCOMMAND="__worker" 不一致会让 worker
    // 永远启动失败（曾因此循环崩溃重启）。
    #[command(name = "__worker", hide = true)]
    Worker {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        log_file: Option<PathBuf>,
    },
    /// 打印运行状态（status.json）
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// 停止前台运行的节点（写入 stop.flag）
    Down {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// 生成示例配置文件
    InitConfig {
        #[arg(long, default_value = "starskiff.json")]
        out: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// 服务安装与管理（Windows: sc.exe；Linux: systemd）
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    Install {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "auto")]
        start: String,
        #[arg(long)]
        no_restart: bool,
        #[arg(long)]
        display: Option<String>,
    },
    Remove {
        #[arg(long)]
        name: Option<String>,
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Start { #[arg(long)] name: Option<String> },
    Stop { #[arg(long)] name: Option<String> },
    Status { #[arg(long)] name: Option<String> },
    /// 服务宿主入口（SCM/systemd 调用）
    Run {
        #[arg(short, long, default_value = "starskiff.json")]
        config: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Enroll { config, server, token, name, ip } => {
            runtime.block_on(cmd_enroll(config, server, token, name, ip))
        }
        Cmd::Join { config, token, ip } => runtime.block_on(cmd_join(config, token, ip)),
        Cmd::Leave { config, network } => runtime.block_on(cmd_leave(config, network)),
        Cmd::Up { config, log_file } => {
            let log = skiff_node::make_logger_from_config_file(log_file.as_deref(), &config, false);
            let code = runtime.block_on(skiff_node::run_engine_until_stopped(
                config,
                log_file,
                log,
            ));
            std::process::exit(code);
        }
        Cmd::Worker { config, log_file } => {
            // worker：承载 NodeEngine 直到停止，退出码交由 master 解读
            //（0=干净停止 / 1=异常 / 3=远程重启请求）。
            let cfg = match NodeConfig::load(&config) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("配置加载失败: {e}");
                    std::process::exit(skiff_node::supervisor::EXIT_ERROR);
                }
            };
            let log = skiff_node::make_logger(log_file.as_deref(), &cfg, true);
            let code = runtime.block_on(async move {
                match skiff_node::start_engine(config, cfg, log).await {
                    Ok(engine) => {
                        // 控制台 Ctrl+C 会同时送达 worker 子进程（Windows
                        // console / 终端进程组）：默认处理直接终止进程，跳过
                        // 优雅收尾。注册处理器改为按正常停止处理，与 master
                        // 的 stop.flag 路径汇合（谁先到都幂等）。
                        let e2 = Arc::clone(&engine);
                        tokio::spawn(async move {
                            let _ = tokio::signal::ctrl_c().await;
                            skiff_node::engine::request_stop(
                                &e2.shared,
                                skiff_node::engine::StopReason::Stopped,
                            );
                        });
                        engine.stopped().await;
                        engine.exit_code()
                    }
                    Err(e) => {
                        eprintln!("引擎启动失败: {e}");
                        skiff_node::supervisor::EXIT_ERROR
                    }
                }
            });
            std::process::exit(code);
        }
        Cmd::Status { data_dir } => {
            let dir = data_dir.unwrap_or_else(skiff_node::default_data_dir);
            let path = dir.join("status.json");
            if !path.exists() {
                eprintln!("状态文件不存在（引擎未运行？）");
                std::process::exit(1);
            }
            let text = std::fs::read_to_string(&path).context("读取状态文件失败")?;
            println!("{text}");
            Ok(())
        }
        Cmd::Down { data_dir } => {
            let dir = data_dir.unwrap_or_else(skiff_node::default_data_dir);
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("stop.flag"), b"")?;
            println!("已写入 stop.flag（服务模式请使用 service stop）");
            Ok(())
        }
        Cmd::InitConfig { out, force } => cmd_init_config(out, force),
        Cmd::Service { cmd } => cmd_service(cmd),
    }
}

async fn cmd_enroll(
    config: PathBuf,
    server: String,
    token: String,
    name: Option<String>,
    ip: Option<String>,
) -> anyhow::Result<()> {
    if config.exists() {
        let existing = node_config::load(&config).map_err(|e| anyhow!("{e}"))?;
        if existing.identity.device_id != 0 {
            eprintln!("配置文件已包含身份（deviceId={}）。加入更多网络请使用 starskiff join。", existing.identity.device_id);
            std::process::exit(1);
        }
    }
    let name = name.unwrap_or_else(hostname);
    if server.starts_with("http://") {
        println!("警告：服务器使用明文 http://（--no-tls 模式），控制面流量不加密");
    } else if split_token(&token).1.is_none() {
        println!("提示：令牌未带证书指纹（CDN/TOFU 模式，首连后将固定服务器证书）");
    }

    let control = ControlClient::new(&server, "pending", None);
    let _req = EnrollRequest {
        token: token.clone(),
        name: name.clone(),
        sign_pubkey: String::new(),
        dh_pubkey: String::new(),
        requested_ip: ip.clone(),
    };
    // Build the identity first so we can submit real public keys.
    let keys = NodeKeys::generate();
    let req = EnrollRequest {
        token: token.clone(),
        name: name.clone(),
        sign_pubkey: keys.sign_public_hex(),
        dh_pubkey: keys.dh_public_hex(),
        requested_ip: ip.clone(),
    };
    let resp = control.enroll(&req).await.map_err(|e| anyhow!(e))?;

    // Trust pin: token suffix wins; TOFU next.
    let (_, token_fingerprint) = split_token(&token);
    let mut server_cert_pin = token_fingerprint.map(|fp| fp.to_lowercase());
    if server_cert_pin.is_none()
        && let Some(tofu) = control.tofu_fingerprint.lock().unwrap().clone() {
            println!("已固定服务器证书指纹 {}…（TOFU）", &tofu[..12.min(tofu.len())]);
            server_cert_pin = Some(tofu);
        }

    // 瘦配置：只写连接信息 + 本机部署参数 + 身份；网络成员与行为配置
    // 均由服务端权威下发（启动时拉取）。
    let cfg = NodeConfig {
        server: server.trim_end_matches('/').to_string(),
        mode: skiff_core::models::ClientMode::Proxy,
        mtu: resp.mtu,
        data_dir: String::new(),
        listen_udp_port: skiff_core::consts::DEFAULT_LISTEN_PORT,
        listen_tcp_port: skiff_core::consts::DEFAULT_LISTEN_PORT,
        log_file: None,
        identity: Identity {
            device_id: resp.device_id,
            name: name.clone(),
            device_token: skiff_core::secret::Secret::new(resp.device_token),
            sign_public_key: keys.sign_public_hex(),
            sign_private_key: skiff_core::secret::Secret::new(hex::encode(keys.sign_secret)),
            dh_public_key: keys.dh_public_hex(),
            dh_private_key: skiff_core::secret::Secret::new(hex::encode(keys.dh_secret)),
            server_cert_pin,
        },
    };
    node_config::save(&config, &cfg).map_err(|e| anyhow!("配置写入失败: {e}"))?;
    println!("注册成功：deviceId={} 网络={}（{}） 虚拟 IP={}", resp.device_id, resp.network_name, resp.cidr, resp.ip);
    println!("配置文件：{}", config.display());
    if cfg!(windows) {
        println!("（敏感字段已用 Windows DPAPI LocalMachine 密封；服务以 LocalSystem 运行时可直接读取）");
    } else {
        println!("（敏感字段为明文存储，请确保文件权限仅限本用户）");
    }
    println!("启动节点：starskiff up -c {}", config.display());
    Ok(())
}

async fn cmd_join(config: PathBuf, token: String, ip: Option<String>) -> anyhow::Result<()> {
    let cfg = node_config::load(&config).map_err(|e| anyhow!("{e}"))?;
    if cfg.identity.device_id == 0 {
        eprintln!("配置中没有身份，请先 starskiff enroll");
        std::process::exit(1);
    }
    let control = ControlClient::new(
        &cfg.server,
        cfg.identity.device_token.expose(),
        cfg.identity.server_cert_pin.as_deref(),
    );
    let resp = control.join(&token, ip.as_deref()).await.map_err(|e| anyhow!(e))?;
    println!("已加入网络 {}（{}） 虚拟 IP={}", resp.network_name, resp.cidr, resp.ip);
    println!("网络成员由服务器维护：重启节点引擎后生效（starskiff down && up，或管理页远程重启）");
    Ok(())
}

async fn cmd_leave(config: PathBuf, network: String) -> anyhow::Result<()> {
    let cfg = node_config::load(&config).map_err(|e| anyhow!("{e}"))?;
    if cfg.identity.device_id == 0 {
        eprintln!("配置中没有身份，请先 starskiff enroll");
        std::process::exit(1);
    }
    let control = ControlClient::new(
        &cfg.server,
        cfg.identity.device_token.expose(),
        cfg.identity.server_cert_pin.as_deref(),
    );
    control.leave(&network).await.map_err(|e| anyhow!(e))?;
    println!("已退出网络 {network}");
    println!("运行中的节点会自动修剪该网络；无需修改本地文件");
    Ok(())
}

fn cmd_init_config(out: PathBuf, force: bool) -> anyhow::Result<()> {
    if out.exists() && !force {
        anyhow::bail!("文件已存在：{}（--force 覆盖）", out.display());
    }
    // 瘦配置模板：网络成员与行为配置（exposes/socks/forwards/force 等）
    // 均由服务端权威下发，不在文件中。
    let sample = r#"{
  "server": "http://your-server:24930",
  "mode": "proxy",
  "mtu": 1300,
  "dataDir": "",
  "listenUdpPort": 24933,
  "listenTcpPort": 24933,
  "logFile": null,
  "identity": null
}
"#;
    let _ = sample;
    // identity: null 不满足模型——用 enroll 生成完整文件；此处生成说明性模板。
    std::fs::write(&out, sample)?;
    println!("已写入示例配置 {}（身份由 enroll 自动填入；网络与行为配置由服务器下发）", out.display());
    Ok(())
}

fn cmd_service(cmd: ServiceCmd) -> anyhow::Result<()> {
    use skiff_node::service_install as si;
    match cmd {
        ServiceCmd::Install { config, name, start, no_restart, display } => {
            si::install(name.as_deref(), config.as_path(), &start, display.as_deref(), no_restart)
        }
        ServiceCmd::Remove { name, config } => si::remove(name.as_deref(), config.as_ref()),
        ServiceCmd::Start { name } => si::start(name.as_deref()),
        ServiceCmd::Stop { name } => si::stop(name.as_deref()),
        ServiceCmd::Status { name } => si::status(name.as_deref()),
        ServiceCmd::Run { config } => {
            // master 不严格校验配置（worker 负责校验并报错，由 master 退避
            // 重启消化；服务保持 RUNNING，避免 SCM 日志被刷屏）。
            let log = skiff_node::make_logger_from_config_file(None, &config, true);
            #[cfg(windows)]
            {
                let name = name_of_from(&config);
                let config_for_body = config.clone();
                let log_for_body: LogFn = log.clone();
                let code = skiff_node::win_service::run(&name, move |stop| {
                    skiff_node::service_body_blocking(config_for_body.clone(), stop, log_for_body.clone())
                });
                std::process::exit(code);
            }
            #[cfg(not(windows))]
            {
                let runtime = tokio::runtime::Runtime::new()?;
                let code = runtime.block_on(skiff_node::run_engine_with_signals(config, log));
                std::process::exit(code);
            }
        }
    }
}

/// Windows 服务名从配置文件的网络列表推导（宽松解析，无需 validate）。
#[cfg(windows)]
fn name_of_from(config: &std::path::Path) -> String {
    let text = std::fs::read_to_string(config).unwrap_or_default();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(list) = v["networks"].as_array()
    {
        let nets: Vec<&str> = list.iter().filter_map(|n| n["network"].as_str()).collect();
        if !nets.is_empty() {
            return format!("Starskiff-{}", nets.join("+"));
        }
    }
    "Starskiff".to_string()
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "starskiff-node".into())
}
