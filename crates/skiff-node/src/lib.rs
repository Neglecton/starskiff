//! starskiff node library: engine, transports, proxy, TUN and service host.

pub mod control;
pub mod engine;
pub mod flow;
pub mod net_if;
pub mod node_config;
pub mod proxy;
pub mod service_install;
pub mod session;
pub mod supervisor;
pub mod tls_verifier;
pub mod transport;
pub mod tun;
pub mod win_service;

pub use net_if::local_ipv4_addrs;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use skiff_core::ipam::Cidr;
use skiff_core::logging::{
    LogFn, RollingFileLogger, composite_logger, console_logger, timestamped,
};
use skiff_core::models::{ClientMode, NodeConfig};
use tokio::sync::watch;

use engine::{DataSink, EngineEvent, NodeEngine};
use supervisor::EXIT_ERROR;

/// Default per-user data directory for node state.
pub fn default_data_dir() -> std::path::PathBuf {
    if cfg!(windows) {
        let appdata = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(appdata).join("Starskiff")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        std::path::PathBuf::from(home).join(".config/starskiff")
    }
}

/// Logger precedence: explicit path > config.logFile > (service)
/// dataDir/service.log > console only.
pub fn make_logger(explicit: Option<&Path>, cfg: &NodeConfig, as_service: bool) -> LogFn {
    if let Some(path) = explicit {
        return file_and_console(path);
    }
    if let Some(path) = &cfg.log_file {
        return file_and_console(Path::new(path));
    }
    if as_service {
        let dir = if cfg.data_dir.is_empty() {
            default_data_dir()
        } else {
            PathBuf::from(&cfg.data_dir)
        };
        return file_and_console(&dir.join("service.log"));
    }
    timestamped(console_logger())
}

fn file_and_console(path: &Path) -> LogFn {
    let file = Arc::new(RollingFileLogger::new(path, 14));
    let file_log = file;
    composite_logger(vec![
        console_logger(),
        Arc::new(move |line: &str| file_log.write_line(line)),
    ])
}

/// master 进程用的宽松日志构建：不做配置 validate（配置无效时 worker
/// 会报错并由 master 退避重启，master 自身必须始终能落日志）。
pub fn make_logger_from_config_file(explicit: Option<&Path>, config: &Path, as_service: bool) -> LogFn {
    if let Some(path) = explicit {
        return file_and_console(path);
    }
    let text = std::fs::read_to_string(config).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    if let Some(lf) = v["logFile"].as_str().filter(|s| !s.is_empty()) {
        return file_and_console(Path::new(lf));
    }
    if as_service {
        let dir = v["dataDir"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir);
        return file_and_console(&dir.join("service.log"));
    }
    timestamped(console_logger())
}

/// 前台 master（`starskiff up`）：监督 worker 子进程，Ctrl+C 优雅停止。
/// worker 崩溃/远程重启由 master 就地消化，进程退出码恒 0（干净停止）。
pub async fn run_engine_until_stopped(
    config_path: PathBuf,
    log_file: Option<PathBuf>,
    log: LogFn,
) -> i32 {
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut join = tokio::spawn(supervisor::run(config_path, log_file, log, stop_rx));
    tokio::select! {
        code = &mut join => code.unwrap_or(EXIT_ERROR),
        _ = tokio::signal::ctrl_c() => {
            let _ = stop_tx.send(true);
            join.await.unwrap_or(EXIT_ERROR)
        }
    }
}

/// Linux `service run` master：SIGTERM/SIGINT 优雅停止 worker。
#[cfg(not(windows))]
pub async fn run_engine_with_signals(config_path: PathBuf, log: LogFn) -> i32 {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("信号注册失败: {e}");
            return EXIT_ERROR;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("信号注册失败: {e}");
            return EXIT_ERROR;
        }
    };
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut join = tokio::spawn(supervisor::run(config_path, None, log, stop_rx));
    tokio::select! {
        code = &mut join => code.unwrap_or(EXIT_ERROR),
        _ = sigterm.recv() => {
            let _ = stop_tx.send(true);
            join.await.unwrap_or(EXIT_ERROR)
        }
        _ = sigint.recv() => {
            let _ = stop_tx.send(true);
            join.await.unwrap_or(EXIT_ERROR)
        }
    }
}

/// Windows SCM body bridge: master（监督 worker）跑在专用运行时线程上，
/// 监视 SCM stop 标志；返回 master 进程退出码（正常路径恒 0——worker
/// 异常由 master 就地重启消化，服务保持 RUNNING）。
pub fn service_body_blocking(
    config: PathBuf,
    stop: Arc<std::sync::atomic::AtomicBool>,
    log: LogFn,
) -> i32 {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            (log)(&format!("运行时创建失败: {e}"));
            return EXIT_ERROR;
        }
    };
    rt.block_on(async {
        let (stop_tx, stop_rx) = watch::channel(false);
        let join = tokio::spawn(supervisor::run(config, None, log, stop_rx));
        loop {
            if stop.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = stop_tx.send(true);
                break;
            }
            if join.is_finished() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        join.await.unwrap_or(EXIT_ERROR)
    })
}

/// Shared engine bootstrap (TUN wiring included). TUN mode uses
/// networks[0] (validated single). 由 worker 子进程调用。
pub async fn start_engine(config_path: PathBuf, cfg: NodeConfig, log: LogFn) -> anyhow::Result<Arc<NodeEngine>> {
    let data_dir = if cfg.data_dir.is_empty() { default_data_dir() } else { PathBuf::from(&cfg.data_dir) };
    let status_dir = data_dir.clone();

    let (data_sink, outbound_rx): (DataSink, Option<tokio::sync::mpsc::Receiver<Vec<u8>>>) = if cfg.mode == ClientMode::Tun {
        // TUN 设备必须在引擎之前创建，而名单以服务端为准——临时控制
        // 连接预拉首个网络与生效 MTU（引擎启动时会再拉全量名单，双拉幂等）。
        let (ip, cidr, mtu) = tun_first_network(&cfg, &log).await?;
        let (device, rx) = tun::TunDevice::start(ip, cidr, mtu, log.clone())?;
        let device = Arc::new(device);
        let sink: DataSink = Box::new(move |packet: &[u8]| device.write_packet(packet));
        (sink, Some(rx))
    } else {
        (Box::new(|_: &[u8]| {}), None)
    };

    let engine = NodeEngine::start(config_path, cfg, data_sink, log).await?;

    // TUN outbound packets flow into the engine as events.
    if let Some(mut rx) = outbound_rx {
        let events = engine.shared.events.clone();
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let _ = events.send(EngineEvent::TunPacket(pkt));
            }
        });
    }
    let _ = status_dir;
    Ok(engine)
}

/// TUN 模式预取首个网络的 ip/cidr 与生效 MTU（服务端权威名单 + 托管
/// 配置；无限重试直到成功——与引擎 FetchConfigOrFail 同语义，服务器
/// 不可达时 worker 不启动）。
async fn tun_first_network(cfg: &NodeConfig, log: &LogFn) -> anyhow::Result<(std::net::Ipv4Addr, Cidr, u32)> {
    let control = control::ControlClient::new(
        &cfg.server,
        cfg.identity.device_token.expose(),
        cfg.identity.server_cert_pin.as_deref(),
    );
    let mut attempt: u32 = 0;
    loop {
        if let Some(first) = control
            .get_memberships()
            .await
            .and_then(|list| list.first().cloned())
        {
            let mtu = control
                .get_settings()
                .await
                .and_then(|s| s.mtu)
                .unwrap_or(cfg.mtu);
            match (first.ip.parse::<std::net::Ipv4Addr>(), Cidr::parse(&first.cidr)) {
                (Ok(ip), Ok(cidr)) => return Ok((ip, cidr, mtu)),
                _ => anyhow::bail!(
                    "网络 {} 的 IP/网段无效: {}/{}",
                    first.network_name,
                    first.ip,
                    first.cidr
                ),
            }
        }
        attempt += 1;
        (log)(&format!("cannot reach control plane (attempt {attempt}); retrying in 3s"));
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}
