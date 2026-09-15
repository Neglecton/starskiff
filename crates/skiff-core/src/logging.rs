//! Rolling per-day log file writer.
//!
//! Files are named `<stem>.<yyyyMMdd>.log` (UTC date). On every write the
//! current date is checked; a change reopens the file and cleans up logs
//! older than `keep_days`. Writes never propagate errors — logging must not
//! take the engine down.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RollingFileLogger {
    stem: PathBuf,
    keep_days: u32,
    inner: Mutex<Option<OpenState>>,
}

struct OpenState {
    date: String,
    file: File,
}

fn utc_date_string(now: SystemTime) -> String {
    // Days since epoch -> civil date (Howard Hinnant's algorithm).
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `[HH:mm:ss]` in UTC.
pub fn utc_time_prefix() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tod = secs % 86_400;
    format!(
        "[{:02}:{:02}:{:02}]",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Unix milliseconds.
pub fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl RollingFileLogger {
    pub fn new<P: AsRef<Path>>(stem: P, keep_days: u32) -> RollingFileLogger {
        RollingFileLogger {
            stem: stem.as_ref().to_path_buf(),
            keep_days,
            inner: Mutex::new(None),
        }
    }

    fn file_for(&self, date: &str) -> PathBuf {
        let mut p = self.stem.clone().into_os_string();
        p.push(format!(".{date}.log"));
        PathBuf::from(p)
    }

    fn open(&self, date: &str) -> Option<File> {
        let path = self.file_for(date);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        OpenOptions::new().create(true).append(true).open(path).ok()
    }

    /// Delete files older than `keep_days` matching `<stem>.<yyyyMMdd>.log`.
    fn cleanup_old(&self) {
        let Some(dir) = self.stem.parent() else {
            return;
        };
        let stem_file = match self.stem.file_name() {
            Some(n) => n.to_os_string(),
            None => return,
        };
        let prefix = {
            let mut p = stem_file.clone();
            p.push(".");
            p.to_string_lossy().into_owned()
        };
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let cutoff_days = (now_secs / 86_400) as i64 - self.keep_days as i64;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if !name_str.starts_with(&prefix) || !name_str.ends_with(".log") {
                continue;
            }
            let date_part = &name_str[prefix.len()..name_str.len() - 4];
            if date_part.len() != 8 || !date_str_is_valid(date_part) {
                continue;
            }
            let Ok(days) = date_part.parse::<i64>() else {
                continue;
            };
            // yyyyMMdd -> days since epoch is nontrivial; compare by parsing to
            // an approximate ordinal using the same civil algorithm backwards.
            let file_days = days_from_civil(
                days / 10_000,
                ((days / 100) % 100) as u32,
                (days % 100) as u32,
            );
            if file_days < cutoff_days {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Append one line (newline added). Never panics, never errors outward.
    pub fn write_line(&self, line: &str) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let today = utc_date_string(SystemTime::now());
        let reopen = match guard.as_ref() {
            Some(state) => state.date != today,
            None => true,
        };
        if reopen {
            let file = match self.open(&today) {
                Some(f) => f,
                None => return,
            };
            *guard = Some(OpenState {
                date: today.clone(),
                file,
            });
            self.cleanup_old();
        }
        if let Some(state) = guard.as_mut() {
            let _ = writeln!(state.file, "{line}");
            let _ = state.file.flush();
        }
    }
}

fn date_str_is_valid(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Pluggable logger used across the engine: console, file or both.
pub type LogFn = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

pub fn console_logger() -> LogFn {
    std::sync::Arc::new(|line: &str| println!("{line}"))
}

pub fn file_logger(stem: &Path, keep_days: u32) -> std::sync::Arc<RollingFileLogger> {
    std::sync::Arc::new(RollingFileLogger::new(stem, keep_days))
}

pub fn composite_logger(parts: Vec<LogFn>) -> LogFn {
    std::sync::Arc::new(move |line: &str| {
        for p in &parts {
            p(line);
        }
    })
}

pub fn timestamped(log: LogFn) -> LogFn {
    std::sync::Arc::new(move |line: &str| log(&format!("{} {}", utc_time_prefix(), line)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-09-13 (today at time of writing; 20709 days since epoch).
        assert_eq!(civil_from_days(20_709), (2026, 9, 13));
        for z in [0i64, 100, 20_000, 50_000, 19_000] {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn writes_rolls_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("skiff-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stem = dir.join("service");

        let logger = RollingFileLogger::new(&stem, 14);
        logger.write_line("hello");

        let today = utc_date_string(SystemTime::now());
        let current = dir.join(format!("service.{today}.log"));
        let content = std::fs::read_to_string(&current).unwrap();
        assert_eq!(content, "hello\n");

        // Plant an ancient log; a forced reopen (new logger) should delete it.
        let old = dir.join("service.20200101.log");
        std::fs::write(&old, "old").unwrap();
        let logger2 = RollingFileLogger::new(&stem, 14);
        logger2.write_line("again");
        assert!(!old.exists());
        assert!(current.exists());

        // Non-log siblings are untouched.
        let keep = dir.join("service.txt");
        std::fs::write(&keep, "x").unwrap();
        logger2.write_line("third");
        assert!(keep.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
