//! Official client owns authorization; Cockpit observes credentials and imports them.
//! IDE sessions use disposable profiles. App sessions preserve and clear the previous
//! credentials while stopped, then launch the official client's own sign-in screen.
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter};

use crate::modules::{account, app_lifecycle, logger, process, qoder_account, qoder_oauth};
use crate::modules::qoder_variant::QoderVariantKind;

const MARKER: &str = ".cockpit-qoder-login";
const TIMEOUT: Duration = Duration::from_secs(600);
#[cfg(target_os = "macos")]
const MACOS_IPC_PATH_LIMIT: usize = 103;
// The client appends /<version[:4]>-<type[:6]>.sock inside userData.
#[cfg(target_os = "macos")]
const MACOS_IPC_SUFFIX_BYTES: usize = 17;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    pub session_id: String,
    pub variant: String,
    pub phase: String,
    pub account_id: Option<String>,
    pub error: Option<String>,
    pub cleanup_warning: Option<String>,
}

impl LoginStatus {
    fn finished(&self) -> bool {
        matches!(self.phase.as_str(), "completed" | "failed" | "cancelled")
    }
}

struct Session {
    status: LoginStatus,
    cancelled: bool,
    finished_at: Option<Instant>,
}

static SESSIONS: LazyLock<Mutex<HashMap<String, Session>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn sessions() -> std::sync::MutexGuard<'static, HashMap<String, Session>> {
    SESSIONS.lock().unwrap_or_else(|error| error.into_inner())
}

pub fn is_active(kind: QoderVariantKind) -> bool {
    sessions().values().any(|s| s.status.variant == kind.provider_key() && !s.status.finished())
}

fn root() -> Result<PathBuf, String> {
    Ok(account::get_data_dir()?.join("qoder-login"))
}

pub fn start(app: AppHandle, kind: QoderVariantKind) -> Result<LoginStatus, String> {
    let session_id = uuid::Uuid::new_v4();
    let id = session_id.to_string();
    let dir = if kind.is_app() {
        let params = qoder_oauth::resolve_qoder_variant_params(kind.provider_key())?;
        qoder_oauth::qoder_user_data_dir_for_variant(&params)?
    } else {
        // IDE IPC sockets live inside userData on macOS. Keep the full random UUID,
        // but omit its separators and shorten the parent to fit the socket path limit.
        let dir = root()?.join(session_id.simple().to_string());
        #[cfg(target_os = "macos")]
        if dir.to_string_lossy().len() + MACOS_IPC_SUFFIX_BYTES >= MACOS_IPC_PATH_LIMIT {
            return Err("临时登录目录路径过长，无法创建 macOS IPC socket，请缩短 Cockpit 数据目录路径".to_string());
        }
        dir
    };
    let status = LoginStatus {
        session_id: id.clone(), variant: kind.provider_key().to_string(),
        phase: "preparing".to_string(), account_id: None, error: None, cleanup_warning: None,
    };
    {
        let mut records = sessions();
        if records.values().any(|s| s.status.variant == kind.provider_key() && !s.status.finished()) {
            return Err("这个版本已有官方登录正在进行，请完成或取消后再试".to_string());
        }
        // A second window can start another login before the first polls its terminal result.
        records.retain(|_, s| !s.finished_at.is_some_and(|time| time.elapsed() >= TIMEOUT));
        records.insert(id.clone(), Session { status: status.clone(), cancelled: false, finished_at: None });
    }
    tauri::async_runtime::spawn_blocking(move || run(app, id, kind, dir));
    Ok(status)
}

pub fn status(id: &str) -> Result<LoginStatus, String> {
    sessions().get(id).map(|s| s.status.clone()).ok_or_else(|| "官方登录会话不存在".to_string())
}

pub fn cancel(id: &str) -> Result<(), String> {
    let mut records = sessions();
    let session = records.get_mut(id).ok_or_else(|| "官方登录会话不存在".to_string())?;
    if !session.status.finished() {
        session.cancelled = true;
        session.status.phase = "cancelling".to_string();
    }
    Ok(())
}

fn cancelled(id: &str) -> bool {
    app_lifecycle::is_shutdown_started() || sessions().get(id).is_none_or(|s| s.cancelled)
}

fn phase(id: &str, value: &str) {
    if let Some(s) = sessions().get_mut(id) {
        if !s.cancelled { s.status.phase = value.to_string(); }
    }
}

fn flow(
    id: &str, kind: QoderVariantKind, dir: &Path,
    launch_attempted: &mut bool, client_seen: &mut bool,
) -> Result<Option<String>, String> {
    let started = Instant::now();
    let app_lock = if kind.is_app() { Some(qoder_oauth::client_session_lock(kind)?) } else { None };
    // Serialize initial observation/launch with App switching and credential rotation.
    let launch_guard = app_lock.as_ref().map(|lock| lock.blocking_lock());
    if cancelled(id) { return Ok(None); }
    process::ensure_qoder_variant_launch_path(kind)?;
    if kind.is_app() {
        phase(id, "signing-out");
        process::close_qoder_variant_instances(kind, &[dir.to_string_lossy().to_string()], 20)
            .map_err(|e| format!("官方客户端未能关闭，未退出账号: {e}"))?;
        if cancelled(id) { return Ok(None); }
        let previous = qoder_account::read_official_login_candidate(kind, dir)?;
        let previous_lock = previous.as_ref()
            .map(|candidate| qoder_oauth::account_refresh_lock(&candidate.refresh_lock_key()))
            .transpose()?;
        let _previous_guard = previous_lock.as_ref().map(|lock| lock.blocking_lock());
        // Accepting cancellation and changing the active credentials must not race.
        let records = sessions();
        if app_lifecycle::is_shutdown_started() || records.get(id).is_none_or(|s| s.cancelled) {
            return Ok(None);
        }
        qoder_account::prepare_closed_app_official_login(kind, previous)?;
    } else {
        fs::create_dir_all(dir).map_err(|e| format!("创建临时登录目录失败: {e}"))?;
        fs::write(dir.join(MARKER), kind.provider_key()).map_err(|e| format!("标记临时登录目录失败: {e}"))?;
    }
    if cancelled(id) { return Ok(None); }
    phase(id, "launching");
    *launch_attempted = true;
    if kind.is_app() {
        process::launch_qoder_variant_client(kind)?;
    } else {
        // Empty profile: never seed it from the default account or instance bindings.
        process::start_qoder_variant_with_args_with_new_window(kind, &dir.to_string_lossy(), &[], true)?;
    }
    drop(launch_guard);
    phase(id, "waiting-login");
    let mut read_error = None;
    loop {
        if cancelled(id) { return Ok(None); }
        // Do not mistake a launcher's PID for the client. Require the matching profile.
        let running = process::resolve_qoder_pid_for_variant(kind, None, Some(&dir.to_string_lossy())).is_some();
        *client_seen |= running;
        let observation_guard = app_lock.as_ref().map(|lock| lock.blocking_lock());
        let observation = qoder_account::read_official_login_candidate(kind, dir);
        match observation {
            Ok(Some(candidate)) => {
                // Drain an older refresh before replacing its credentials. Lock order matches
                // App refresh: variant session -> account -> import commit.
                let account_lock = qoder_oauth::account_refresh_lock(&candidate.refresh_lock_key())?;
                let _account_guard = account_lock.blocking_lock();
                // Cancellation and the import commit share a boundary: no write after an accepted cancel.
                // Do not hold the session records while waiting for the account lock.
                let mut records = sessions();
                let session = records.get_mut(id).ok_or_else(|| "官方登录会话不存在".to_string())?;
                if session.cancelled || app_lifecycle::is_shutdown_started() { return Ok(None); }
                session.status.phase = "importing".to_string();
                let account = candidate.import()?;
                // Temporary IDE login does not change the default client's current account.
                if kind.is_app() {
                    if let Err(error) = crate::modules::provider_current_state::set_current_account_id(
                        kind.provider_key(), Some(&account.id),
                    ) {
                        // The import has committed; report the projection failure without hiding success.
                        session.status.error = Some(format!("账号已导入，但当前账号状态保存失败: {error}"));
                    }
                }
                return Ok(Some(account.id));
            }
            Ok(None) => { read_error = None; }
            // A partially written credential is never a successful login.
            Err(error) => { read_error = Some(error); }
        }
        drop(observation_guard);
        // Credentials may have been saved immediately before the client exited.
        // Only after the last credential read may an exit/timeout become a failure.
        if started.elapsed() >= TIMEOUT {
            return Err(read_error.unwrap_or_else(|| "等待官方客户端登录超时（10 分钟）".to_string()));
        }
        if !running {
            if !*client_seen && started.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            return Err(read_error.unwrap_or_else(|| "未检测到本次官方客户端，登录已停止".to_string()));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn cleanup(kind: QoderVariantKind, dir: &Path) -> Result<(), String> {
    if kind.is_app() || !dir.exists() { return Ok(()); }
    // Closing is profile-scoped. A failed close keeps the directory for a later sweep.
    process::close_qoder_variant_instances(kind, &[dir.to_string_lossy().to_string()], 20)?;
    fs::remove_dir_all(dir).map_err(|e| format!("清理临时登录目录失败: {e}"))
}

fn run(app: AppHandle, id: String, kind: QoderVariantKind, dir: PathBuf) {
    let mut launch_attempted = false;
    let mut client_seen = false;
    let outcome = flow(&id, kind, &dir, &mut launch_attempted, &mut client_seen);
    if !kind.is_app() { phase(&id, "cleaning"); }
    let warning = if !kind.is_app() && launch_attempted && !client_seen {
        // An unconfirmed launcher may still create its child. Keep the marker for a later sweep.
        Some("临时客户端启动未确认，目录已保留，将由清理巡检关闭实例后清理".to_string())
    } else { cleanup(kind, &dir).err() };
    let imported_id = outcome.as_ref().ok().and_then(|account_id| account_id.clone());
    let mut records = sessions();
    let mut imported = false;
    if let Some(session) = records.get_mut(&id) {
        session.status.cleanup_warning = warning;
        match outcome {
            Ok(Some(account_id)) => {
                session.status.phase = "completed".to_string();
                session.status.account_id = Some(account_id);
            }
            Ok(None) => session.status.phase = "cancelled".to_string(),
            Err(error) => { session.status.phase = "failed".to_string(); session.status.error = Some(error); }
        }
        imported = session.status.account_id.is_some();
        session.finished_at = Some(Instant::now());
    }
    drop(records);
    if let Some(account_id) = imported_id {
        crate::modules::qoder_webview::sync_after_login(app.clone(), account_id);
    }
    if imported || kind.is_app() {
        // No credentials in events. Consumers reload the authoritative account list.
        let _ = app.emit("accounts:changed", serde_json::json!({
            "platformId": kind.provider_key(), "reason": if imported { "import" } else { "official-login" },
        }));
        let _ = crate::modules::tray::update_tray_menu(&app);
    }
}

/// Recover only marked UUID directories. Never follow symlinks or touch default profiles.
fn sweep() -> Result<(), String> {
    sweep_root(&root()?)?;
    // Earlier login attempts used a longer path. Recover their marked profiles too.
    sweep_root(&account::get_data_dir()?.join("qoder-official-login"))
}

fn sweep_root(base: &Path) -> Result<(), String> {
    if !base.exists() { return Ok(()); }
    for entry in fs::read_dir(base).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() { continue; }
        let Ok(id) = uuid::Uuid::parse_str(&entry.file_name().to_string_lossy()) else { continue; };
        // Directory UUIDs are compact; session IDs keep their public hyphenated form.
        let id = id.to_string();
        if sessions().get(&id).is_some_and(|s| !s.status.finished()) { continue; }
        let dir = entry.path();
        // Avoid racing a child that starts after the launcher's acknowledgement.
        let old_enough = fs::metadata(dir.join(MARKER)).ok()
            .and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= Duration::from_secs(60));
        if !old_enough { continue; }
        let Ok(marker) = fs::read_to_string(dir.join(MARKER)) else { continue; };
        let Ok(kind) = QoderVariantKind::parse(Some(marker.trim())) else { continue; };
        if !kind.supports_instances() { continue; }
        if let Err(error) = cleanup(kind, &dir) {
            logger::log_warn(&format!("[Qoder Official Login] 临时配置清理失败: {error}"));
        }
    }
    Ok(())
}

pub fn ensure_cleanup_loop_started() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) { return; }
    tauri::async_runtime::spawn(async {
        tokio::time::sleep(Duration::from_secs(8)).await;
        loop {
            let result = tauri::async_runtime::spawn_blocking(sweep).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => logger::log_warn(&format!("[Qoder Official Login] 清理巡检失败: {error}")),
                Err(error) => logger::log_warn(&format!("[Qoder Official Login] 清理巡检任务失败: {error}")),
            }
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    });
}
