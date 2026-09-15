//! Windows service host (hand-rolled SCM P/Invoke port).
//!
//! Invariants:
//! - ServiceMain reports RUNNING *before* starting the engine — the engine's
//!   control-plane retry loop is unbounded and would blow the SCM 30s start
//!   deadline otherwise;
//! - the engine never calls exit itself: stop signals flow through a
//!   cancellation token and the host decides how to terminate;
//! - engine failure exits with code 1 so `sc failure` recovery restarts it;
//!   a clean stop exits 0.

#![cfg(windows)]

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, OnceLock};

use windows::Win32::Foundation::{
    ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, StartServiceCtrlDispatcherW,
};
use windows::core::PCWSTR;

const WAIT_HINT_MS: u32 = 20_000;
static STATUS_HANDLE: OnceLock<SendHandle> = OnceLock::new();
static EXIT_CODE: AtomicI32 = AtomicI32::new(0);
static STOP_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static SERVICE_NAME_W: OnceLock<Vec<u16>> = OnceLock::new();

/// SERVICE_STATUS_HANDLE is a raw pointer; SCM handles are plain values.
#[derive(Clone, Copy)]
struct SendHandle(SERVICE_STATUS_HANDLE);
unsafe impl Send for SendHandle {}
unsafe impl Sync for SendHandle {}
impl SendHandle {
    fn get(&self) -> SERVICE_STATUS_HANDLE {
        self.0
    }
}

unsafe extern "system" fn service_main(argc: u32, argv: *mut windows::core::PWSTR) {
    let _ = (argc, argv);
    let name = SERVICE_NAME_W.get().expect("service name initialized");
    let registration = unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(control_handler), None)
    };
    let Ok(handle) = registration else {
        return;
    };
    let _ = STATUS_HANDLE.set(SendHandle(handle));

    // Report RUNNING first: the engine startup (control-plane retries) can
    // legally take minutes.
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, 0);

    let body = BODY.get().expect("service body initialized");
    let stop = Arc::new(AtomicBool::new(false));
    let _ = STOP_FLAG.set(Arc::clone(&stop));
    let body = Arc::clone(body);
    std::thread::spawn(move || {
        let code = body(stop);
        EXIT_CODE.store(code, Ordering::SeqCst);
        // 上报真实退出码：master 自身异常（非 0）时 sc failure 恢复策略
        // 才能接管；干净停止恒 0，不触发重启。worker 的异常已由 master
        // 就地退避重启消化，不会走到这里。
        set_state(SERVICE_STOPPED, 0, code as u32, 0);
        std::process::exit(code);
    });
}

unsafe extern "system" fn control_handler(
    ctrl: u32,
    _etype: u32,
    _data: *mut core::ffi::c_void,
    _ctx: *mut core::ffi::c_void,
) -> u32 {
    if ctrl == SERVICE_CONTROL_STOP {
        set_state(SERVICE_STOP_PENDING, 0, 0, WAIT_HINT_MS);
        if let Some(stop) = STOP_FLAG.get() {
            stop.store(true, Ordering::SeqCst);
        }
    }
    0
}

fn set_state(
    state: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    accept: u32,
    exit_code: u32,
    wait_hint: u32,
) {
    let Some(handle) = STATUS_HANDLE.get().map(|h| h.get()) else {
        return;
    };
    #[allow(unused_mut)]
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accept,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint,
    };
    unsafe {
        let _ = windows::Win32::System::Services::SetServiceStatus(handle, &status);
    }
}

type Body = Arc<dyn Fn(Arc<AtomicBool>) -> i32 + Send + Sync>;
static BODY: OnceLock<Body> = OnceLock::new();

/// Run `body` as a Windows service named `name`. Outside the SCM (console
/// debug), falls back to running it directly.
pub fn run<F>(name: &str, body: F) -> i32
where
    F: Fn(Arc<AtomicBool>) -> i32 + Send + Sync + 'static,
{
    let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = SERVICE_NAME_W.set(name_w.clone());
    let _ = BODY.set(Arc::new(body));

    let name_ptr = name_w.as_ptr();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: windows::core::PWSTR(name_ptr as *mut _),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: windows::core::PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok.is_ok() {
        // Dispatcher returned after the service stopped.
        return EXIT_CODE.load(Ordering::SeqCst);
    }
    let err: WIN32_ERROR = unsafe { windows::Win32::Foundation::GetLastError() };
    if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
        // Not started by the SCM: console mode for debugging.
        let body = BODY.get().expect("body initialized");
        return body(Arc::new(AtomicBool::new(false)));
    }
    let _ = ERROR_SUCCESS;
    1
}
