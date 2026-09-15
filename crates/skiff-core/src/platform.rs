//! OS integration helpers shared by server and node: external tool execution,
//! the Linux firewall cascade and small probes. Windows-specific service
//! hosts live in the crates that need them.

use std::io;
use std::process::Command;
use std::time::Duration;

/// Run an external tool with argv (never through a shell — argument
/// injection is structurally impossible). Returns trimmed stdout on exit 0.
pub fn run_tool(program: &str, args: &[&str], timeout: Duration) -> io::Result<String> {
    let out = spawn_and_wait(program, args, timeout)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "{program} 退出码 {}：{}{}",
            out.status.code().unwrap_or(-1),
            stderr.trim(),
            if stdout.trim().is_empty() {
                String::new()
            } else {
                format!(" / {}", stdout.trim())
            }
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub struct ToolOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Spawn and wait with a wall-clock timeout (the child is leaked if it
/// outlives the timeout — callers use this only for short-lived tools).
pub fn spawn_and_wait(program: &str, args: &[&str], timeout: Duration) -> io::Result<ToolOutput> {
    use std::sync::mpsc;
    let child = Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let out = child.wait_with_output();
        let _ = tx.send(out);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(out)) => Ok(ToolOutput {
            status: out.status,
            stdout: out.stdout,
            stderr: out.stderr,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{program} 执行超时"),
        )),
    }
}

pub fn tool_exists(program: &str) -> bool {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = if cfg!(windows) {
                dir.join(format!("{program}.exe"))
            } else {
                dir.join(program)
            };
            if candidate.is_file() {
                return true;
            }
        }
    }
    false
}

/// Whether the current process has root/admin privileges.
pub fn is_root() -> bool {
    #[cfg(windows)]
    {
        // Same practical check many installers use; sc.exe calls would fail
        // for a non-admin anyway.
        run_tool("net", &["session"], Duration::from_secs(10)).is_ok()
    }
    #[cfg(not(windows))]
    {
        unix_euid() == 0
    }
}

#[cfg(not(windows))]
fn unix_euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

/// Linux firewall cascade: ufw → firewalld → raw iptables. Add and remove
/// derive their rules from the same data so they stay symmetric. Failure is
/// reported as Err but must not abort installation (containers / no
/// CAP_NET_ADMIN); callers log a warning and continue.
pub fn linux_firewall_add(unit: &str, ports: &[(u16, &str)]) -> Result<(), String> {
    linux_firewall(unit, ports, true)
}

pub fn linux_firewall_remove(unit: &str, ports: &[(u16, &str)]) -> Result<(), String> {
    linux_firewall(unit, ports, false)
}

fn linux_firewall(unit: &str, ports: &[(u16, &str)], add: bool) -> Result<(), String> {
    let timeout = Duration::from_secs(20);
    if tool_exists("ufw") {
        for &(port, proto) in ports {
            let port_proto = format!("{port}/{proto}");
            let args: Vec<String> = if add {
                vec![
                    "allow".into(),
                    port_proto,
                    "comment".into(),
                    format!("starskiff {unit}"),
                ]
            } else {
                vec!["delete".into(), "allow".into(), port_proto]
            };
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_tool("ufw", &refs, timeout).map_err(|e| format!("ufw: {e}"))?;
        }
        return Ok(());
    }
    if tool_exists("firewall-cmd") {
        for &(port, proto) in ports {
            let spec = format!("{port}/{proto}");
            let verb = if add { "--add-port" } else { "--remove-port" };
            run_tool("firewall-cmd", &["--permanent", verb, &spec], timeout)
                .map_err(|e| format!("firewalld: {e}"))?;
        }
        let _ = run_tool("firewall-cmd", &["--reload"], timeout);
        return Ok(());
    }
    if tool_exists("iptables") {
        for &(port, proto) in ports {
            let comment = format!("starskiff-{unit}-{proto}");
            let spec = format!("--dport={port}");
            let (verb, pos) = if add { ("-I", "1") } else { ("-D", "-p") };
            // delete mirrors the add rule text (iptables -D matches the rule,
            // not a position), so the argument shapes differ slightly:
            let args: Vec<&str> = if add {
                vec![
                    "-I",
                    "INPUT",
                    pos,
                    "-p",
                    proto,
                    &*spec,
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                ]
            } else {
                vec![
                    verb,
                    "INPUT",
                    "-p",
                    proto,
                    &*spec,
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    &comment,
                ]
            };
            run_tool("iptables", &args, timeout).map_err(|e| format!("iptables: {e}"))?;
        }
        return Ok(());
    }
    Err("未找到 ufw/firewalld/iptables，请手动放行端口（云安全组亦需手动放行）".into())
}

/// Resident set size in KiB (for STATS lines).
pub fn rss_kib() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(field) = s.split_whitespace().nth(1) {
                if let Ok(pages) = field.parse::<u64>() {
                    return pages * 4;
                }
            }
        }
        0
    }
    #[cfg(windows)]
    {
        windows_rss_kib()
    }
    #[cfg(all(not(windows), not(target_os = "linux")))]
    {
        0
    }
}

#[cfg(windows)]
fn windows_rss_kib() -> u64 {
    // GetProcessMemoryInfo via raw LoadLibrary to keep this crate free of
    // additional windows features.
    use std::mem;
    #[repr(C)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryA(name: *const u8) -> usize;
        fn GetProcAddress(module: usize, name: *const u8) -> usize;
        fn GetCurrentProcess() -> usize;
    }
    type FnGetPMI = unsafe extern "system" fn(usize, *mut ProcessMemoryCounters, u32) -> i32;
    unsafe {
        let lib = LoadLibraryA(c"psapi.dll".as_ptr() as *const u8);
        if lib == 0 {
            return 0;
        }
        let proc = GetProcAddress(lib, c"GetProcessMemoryInfo".as_ptr() as *const u8);
        if proc == 0 {
            return 0;
        }
        let f: FnGetPMI = mem::transmute(proc);
        let mut pmc = ProcessMemoryCounters {
            cb: mem::size_of::<ProcessMemoryCounters>() as u32,
            page_fault_count: 0,
            peak_working_set_size: 0,
            working_set_size: 0,
            quota_peak_paged_pool_usage: 0,
            quota_paged_pool_usage: 0,
            quota_peak_non_paged_pool_usage: 0,
            quota_non_paged_pool_usage: 0,
            pagefile_usage: 0,
            peak_pagefile_usage: 0,
        };
        if f(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
            (pmc.working_set_size / 1024) as u64
        } else {
            0
        }
    }
}
