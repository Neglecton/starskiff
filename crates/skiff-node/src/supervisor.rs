//! master/worker 进程监督（nginx 式）：master 是常驻监督进程，worker 是
//! 承载 NodeEngine 的子进程。远程重启 = worker 优雅退出（退出码 3），
//! master 以最新配置文件拉起新 worker——进程边界天然回收全部
//! socket/TUN/task，规避引擎内自重启的资源泄漏。
//!
//! worker 退出码约定（AGENTS.md）：
//! - `0` 干净停止（stop.flag / 信号 / SCM stop）——master 一并退出；
//! - `1` 引擎异常（启动失败 / 运行错误）——master 退避后重启；
//! - `3` 重启请求（远程指令 / 托管配置重启生效）——master 立即重启。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use skiff_core::logging::LogFn;
use tokio::sync::watch;

pub const EXIT_OK: i32 = 0;
pub const EXIT_ERROR: i32 = 1;
pub const EXIT_RESTART: i32 = 3;

/// 内部子命令名（main.rs 中 hide 的 `__worker`）。
pub const WORKER_SUBCOMMAND: &str = "__worker";

/// 退避序列：连续异常重启时逐级放慢，30s 封顶。
const BACKOFF_STEPS: &[Duration] = &[
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
/// worker 稳定运行满此时长后，连续重启计数视为清零。
const STABLE_AFTER: Duration = Duration::from_secs(60);
/// 优雅停止的等待上限：worker 内部 stop.flag watcher 1s 轮询，正常
/// 秒级完成；超时强杀（Windows 无 SIGTERM）。
const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExitAction {
    /// worker 干净退出：master 一并退出（码 0）。
    Stop,
    /// worker 异常或请求重启：退避后拉起新 worker。
    Restart { backoff: Duration },
}

/// worker 退出后的决策（纯函数，单测锁定）。
///
/// `consecutive_restarts` 是此前连续重启次数；worker 若稳定运行超过
/// STABLE_AFTER，计数视为 0（新的一轮）。
pub fn action_for_exit(code: i32, consecutive_restarts: u32, uptime: Duration) -> WorkerExitAction {
    if code == EXIT_OK {
        return WorkerExitAction::Stop;
    }
    let rounds = if uptime >= STABLE_AFTER { 1 } else { consecutive_restarts + 1 };
    let idx = rounds.saturating_sub(1).min(BACKOFF_STEPS.len() as u32 - 1) as usize;
    WorkerExitAction::Restart { backoff: BACKOFF_STEPS[idx] }
}

/// 只解析 dataDir（不做 validate：无法启动的配置也要能算出 stop.flag 路径）。
pub(crate) fn data_dir_of(config: &Path) -> PathBuf {
    let text = std::fs::read_to_string(config).unwrap_or_default();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(dir) = v["dataDir"].as_str().filter(|s| !s.is_empty())
    {
        return PathBuf::from(dir);
    }
    crate::default_data_dir()
}

/// 写 stop.flag 并等待 worker 优雅退出；超时强杀。退出后删除 stop.flag——
/// worker 若先于本函数死亡（如 Windows 控制台 Ctrl+C 同时送达子进程、
/// 默认处理直接终止）就没有机会删标志，残留会导致下次启动被误停。
async fn graceful_stop(child: &mut tokio::process::Child, config: &Path, log: &LogFn) {
    let flag = data_dir_of(config).join("stop.flag");
    if let Err(e) = std::fs::write(&flag, b"") {
        (log)(&format!("无法写入 stop.flag（{e}），将强制结束 worker"));
    }
    let deadline = Instant::now() + GRACEFUL_TIMEOUT;
    loop {
        match tokio::time::timeout(Duration::from_secs(1), child.wait()).await {
            Ok(_) => break, // 已退出（Ok 或 Err 都不再等）
            Err(_) if Instant::now() < deadline => continue,
            Err(_) => break,
        }
    }
    if Instant::now() >= deadline {
        (log)("worker 优雅停止超时，强制结束");
        let _ = child.kill().await;
    }
    // 无论 worker 如何退出，标志都由 master 兜底清理。
    let _ = std::fs::remove_file(&flag);
}

/// 运行 master 监督循环，返回 master 进程退出码（正常路径恒 0——
/// worker 的异常由 master 消化，不向上传染给 SCM/systemd）。
///
/// `stop_rx` 置 true 时优雅停止 worker 并退出（SCM stop / SIGTERM /
/// Ctrl+C / `starskiff down`）。`worker_log_file` 透传给 worker 的
/// `--log-file`（`up --log-file x.log` 场景）。
pub async fn run(
    config: PathBuf,
    worker_log_file: Option<PathBuf>,
    log: LogFn,
    stop_rx: watch::Receiver<bool>,
) -> i32 {
    let code = run_inner(config.clone(), worker_log_file, log.clone(), stop_rx).await;
    // master 最终退出前清理运行时防火墙规则（AGENTS #17：系统配置不
    // 遗留）——worker 崩溃重启期间不清理，只有 master 真正退出才执行。
    for line in crate::service_install::cleanup_runtime_firewall(&data_dir_of(&config)) {
        (log)(&line);
    }
    code
}

async fn run_inner(
    config: PathBuf,
    worker_log_file: Option<PathBuf>,
    log: LogFn,
    mut stop_rx: watch::Receiver<bool>,
) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            (log)(&format!("无法定位自身可执行文件: {e}"));
            return EXIT_ERROR;
        }
    };
    let mut consecutive: u32 = 0;
    loop {
        let started = Instant::now();
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.arg(WORKER_SUBCOMMAND).arg("-c").arg(&config);
        if let Some(f) = &worker_log_file {
            cmd.arg("--log-file").arg(f);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                (log)(&format!("worker 启动失败: {e}"));
                return EXIT_ERROR;
            }
        };
        let code = tokio::select! {
            status = child.wait() => match status {
                Ok(s) => s.code().unwrap_or(EXIT_ERROR),
                Err(_) => EXIT_ERROR,
            },
            _ = stop_rx.changed() => {
                graceful_stop(&mut child, &config, &log).await;
                (log)("worker 已按外部请求停止，master 退出");
                return EXIT_OK;
            }
        };
        let uptime = started.elapsed();
        match action_for_exit(code, consecutive, uptime) {
            WorkerExitAction::Stop => {
                (log)(&format!("worker 正常退出（码 {code}），master 退出"));
                return EXIT_OK;
            }
            WorkerExitAction::Restart { backoff } => {
                consecutive = if uptime >= STABLE_AFTER { 1 } else { consecutive + 1 };
                (log)(&format!(
                    "WORKER_EXIT code={code} uptime_s={} restart_in_ms={} consecutive={consecutive}",
                    started.elapsed().as_secs(),
                    backoff.as_millis()
                ));
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stop_rx.changed() => {
                        // 退避等待期间收到外部停止：直接退出。
                        return EXIT_OK;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_stop_ends_master() {
        assert_eq!(action_for_exit(EXIT_OK, 0, Duration::from_secs(1)), WorkerExitAction::Stop);
        assert_eq!(action_for_exit(EXIT_OK, 9, Duration::from_secs(0)), WorkerExitAction::Stop);
    }

    #[test]
    fn restart_backoff_ladder() {
        // 首次重启（此前稳定运行）不等待。
        assert_eq!(
            action_for_exit(EXIT_RESTART, 0, Duration::from_secs(120)),
            WorkerExitAction::Restart { backoff: Duration::from_secs(1) }
        );
        // 连续快速失败逐级退避。
        assert_eq!(
            action_for_exit(EXIT_ERROR, 1, Duration::from_secs(2)),
            WorkerExitAction::Restart { backoff: Duration::from_secs(2) }
        );
        assert_eq!(
            action_for_exit(EXIT_ERROR, 3, Duration::from_secs(3)),
            WorkerExitAction::Restart { backoff: Duration::from_secs(10) }
        );
        // 封顶 30s。
        assert_eq!(
            action_for_exit(EXIT_ERROR, 99, Duration::from_secs(4)),
            WorkerExitAction::Restart { backoff: Duration::from_secs(30) }
        );
        // 稳定运行满 STABLE_AFTER 后计数清零（新的一轮）。
        assert_eq!(
            action_for_exit(EXIT_ERROR, 5, STABLE_AFTER),
            WorkerExitAction::Restart { backoff: Duration::from_secs(1) }
        );
    }

    #[test]
    fn data_dir_falls_back_to_default() {
        let tmp = std::env::temp_dir().join(format!("skiff-sv-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = tmp.join("starskiff.json");
        std::fs::write(&cfg, r#"{"dataDir":"DATA_DIR_PLACEHOLDER"}"#).unwrap();
        assert_eq!(data_dir_of(&cfg), PathBuf::from("DATA_DIR_PLACEHOLDER"));
        std::fs::write(&cfg, r#"{}"#).unwrap();
        assert_eq!(data_dir_of(&cfg), crate::default_data_dir());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
