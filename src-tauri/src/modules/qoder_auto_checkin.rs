//! Qoder daily scheduling and the shared manual/automatic request queue.
//! Settings and daily attempts belong to this backend, independent of WebView lifetime.
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{Local, Timelike};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::sync::{watch, Mutex as AsyncMutex, Notify, OwnedMutexGuard};

use crate::models::qoder::QoderClaimRewardResult;
use crate::modules::{atomic_write, config, logger, qoder_account};

static STORAGE_LOCK: Mutex<()> = Mutex::new(());
static CLAIM_QUEUE: LazyLock<Arc<AsyncMutex<Option<Instant>>>> =
    LazyLock::new(|| Arc::new(AsyncMutex::new(None)));
static WAKE: Notify = Notify::const_new();
static MANUAL_BATCHES: LazyLock<Mutex<HashMap<String, watch::Sender<bool>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn start_manual_batch() -> Result<String, String> {
    let id = uuid::Uuid::new_v4().to_string();
    let (sender, _) = watch::channel(false);
    MANUAL_BATCHES.lock().map_err(|_| "签到任务锁已损坏")?.insert(id.clone(), sender);
    Ok(id)
}

/// Removal ends the batch and wakes any pending queue/interval wait.
pub fn cancel_manual_batch(id: &str) -> Result<(), String> {
    if let Some(sender) = MANUAL_BATCHES.lock().map_err(|_| "签到任务锁已损坏")?.remove(id) {
        sender.send_replace(true);
    }
    Ok(())
}

pub struct ClaimCancellation(watch::Receiver<bool>);

pub fn manual_batch_cancellation(id: &str) -> Result<Option<ClaimCancellation>, String> {
    Ok(MANUAL_BATCHES.lock().map_err(|_| "签到任务锁已损坏")?
        .get(id).map(|sender| ClaimCancellation(sender.subscribe())))
}

async fn wait_for_cancellation(cancellation: Option<&mut ClaimCancellation>) {
    let Some(cancellation) = cancellation else {
        return std::future::pending().await;
    };
    while !*cancellation.0.borrow() {
        if cancellation.0.changed().await.is_err() { break; }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QoderAutoCheckinSettings {
    pub enabled: bool,
    pub time: String,
    pub request_interval_seconds: u64,
    pub account_ids: Vec<String>,
}

impl Default for QoderAutoCheckinSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            time: "10:05".into(),
            request_interval_seconds: 3,
            account_ids: Vec::new(),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredState {
    settings: QoderAutoCheckinSettings,
    #[serde(default)]
    attempted_dates: HashMap<String, String>,
}

fn time_minutes(time: &str) -> Option<u32> {
    let bytes = time.as_bytes();
    if bytes.len() != 5 || bytes[2] != b':'
        || ![bytes[0], bytes[1], bytes[3], bytes[4]].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let hour = time[..2].parse::<u32>().ok()?;
    let minute = time[3..].parse::<u32>().ok()?;
    (hour < 24 && minute < 60).then_some(hour * 60 + minute)
}

fn validate(settings: &QoderAutoCheckinSettings) -> Result<(), String> {
    if time_minutes(&settings.time).is_none() {
        return Err("自动签到时间必须为 HH:mm".into());
    }
    if settings.request_interval_seconds > 300 {
        return Err("签到请求间隔须为 0 至 300 秒".into());
    }
    if settings.enabled && settings.account_ids.is_empty() {
        return Err("请至少选择一个自动签到账号".into());
    }
    Ok(())
}

fn state_path() -> std::path::PathBuf {
    config::get_shared_dir().join("qoder_auto_checkin.json")
}

fn read_state() -> Result<StoredState, String> {
    let content = match std::fs::read_to_string(state_path()) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(StoredState::default()),
        Err(err) => return Err(format!("读取 Qoder 自动签到设置失败: {err}")),
    };
    let state: StoredState = serde_json::from_str(&content)
        .map_err(|err| format!("解析 Qoder 自动签到设置失败: {err}"))?;
    validate(&state.settings)?;
    Ok(state)
}

fn write_state(state: &StoredState) -> Result<(), String> {
    let content = serde_json::to_string_pretty(state).map_err(|err| err.to_string())?;
    atomic_write::write_string_atomic(&state_path(), &content)
}

pub fn get_settings() -> Result<QoderAutoCheckinSettings, String> {
    let _lock = STORAGE_LOCK.lock().map_err(|_| "自动签到设置锁已损坏")?;
    Ok(read_state()?.settings)
}

fn apply_settings(state: &mut StoredState, settings: QoderAutoCheckinSettings, today: &str) {
    // Keep today's attempts even after deselecting/reselecting an account.
    state.attempted_dates.retain(|_, date| date == today);
    state.settings = settings;
}

pub fn save_settings(mut settings: QoderAutoCheckinSettings) -> Result<QoderAutoCheckinSettings, String> {
    validate(&settings)?;
    // Resolve legacy aliases and keep just one request per regional account.
    let mut ids = Vec::new();
    for id in &settings.account_ids {
        // Deleted accounts must not prevent disabling or updating the remaining schedule.
        let Some(account) = qoder_account::load_account(id) else { continue; };
        if !ids.contains(&account.id) {
            ids.push(account.id);
        }
    }
    settings.account_ids = ids;
    validate(&settings)?;
    let _lock = STORAGE_LOCK.lock().map_err(|_| "自动签到设置锁已损坏")?;
    let mut state = read_state()?;
    apply_settings(&mut state, settings.clone(), &Local::now().format("%Y-%m-%d").to_string());
    write_state(&state)?;
    WAKE.notify_one();
    Ok(settings)
}

fn is_due(state: &StoredState, id: &str, date: &str, minute: u32) -> bool {
    state.settings.enabled
        && state.settings.account_ids.iter().any(|candidate| candidate == id)
        && time_minutes(&state.settings.time).is_some_and(|scheduled| minute >= scheduled)
        && state.attempted_dates.get(id).is_none_or(|attempted| attempted != date)
}

/// Hold through credential preparation, claim, and quota synchronization. Drop records
/// completion even on failure, so the following account observes the configured gap.
pub struct ClaimPermit(OwnedMutexGuard<Option<Instant>>);

impl Drop for ClaimPermit {
    fn drop(&mut self) {
        *self.0 = Some(Instant::now());
    }
}

fn remaining_delay(completed: Option<Instant>, now: Instant, seconds: u64) -> Duration {
    completed.map(|completed| {
        Duration::from_secs(seconds).saturating_sub(now.saturating_duration_since(completed))
    }).unwrap_or_default()
}

pub async fn acquire_claim_slot(
    account_id: &str,
    scheduled_date: Option<&str>,
    mut cancellation: Option<ClaimCancellation>,
) -> Result<Option<ClaimPermit>, String> {
    let guard = tokio::select! {
        biased;
        _ = wait_for_cancellation(cancellation.as_mut()) => return Ok(None),
        guard = CLAIM_QUEUE.clone().lock_owned() => guard,
    };
    loop {
        if cancellation.as_ref().is_some_and(|c| *c.0.borrow()) { return Ok(None); }
        let state = {
            let _lock = STORAGE_LOCK.lock().map_err(|_| "自动签到设置锁已损坏")?;
            read_state()?
        };
        if let Some(date) = scheduled_date {
            let now = Local::now();
            if now.format("%Y-%m-%d").to_string() != date
                || !is_due(&state, account_id, date, now.hour() * 60 + now.minute())
            {
                return Ok(None);
            }
        }
        let remaining = remaining_delay(*guard, Instant::now(), state.settings.request_interval_seconds);
        if remaining.is_zero() {
            break;
        }
        // Cancel queue waits immediately; let an already dispatched official flow finish.
        tokio::select! {
            biased;
            _ = wait_for_cancellation(cancellation.as_mut()) => return Ok(None),
            _ = tokio::time::sleep(remaining.min(Duration::from_secs(1))) => {},
        }
    }
    {
        let _lock = STORAGE_LOCK.lock().map_err(|_| "自动签到设置锁已损坏")?;
        let mut state = read_state()?;
        // Last cancellation check before committing the attempt and starting the flow.
        if cancellation.as_ref().is_some_and(|c| *c.0.borrow()) { return Ok(None); }
        let now = Local::now();
        let today = now.format("%Y-%m-%d").to_string();
        let due = is_due(&state, account_id, &today, now.hour() * 60 + now.minute());
        if let Some(date) = scheduled_date {
            if today != date || !due {
                return Ok(None);
            }
        }
        if due {
            // A manual claim after the scheduled time consumes today's pending automatic
            // attempt too. Both paths run under the same queue and storage lock.
            state.attempted_dates.retain(|_, date| date == &today);
            state.attempted_dates.insert(account_id.to_string(), today);
            write_state(&state)?;
        }
    }
    Ok(Some(ClaimPermit(guard)))
}

/// Composition injects the same complete claim flow used by the manual command.
pub fn start_scheduler<F, Fut>(app: AppHandle, claim: F)
where
    F: Fn(String, Option<String>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<QoderClaimRewardResult>, String>> + Send,
{
    tauri::async_runtime::spawn(async move {
        loop {
            let cycle = async {
                let now = Local::now();
                let date = now.format("%Y-%m-%d").to_string();
                let minute = now.hour() * 60 + now.minute();
                let state = {
                    let _lock = STORAGE_LOCK.lock().map_err(|_| "自动签到设置锁已损坏")?;
                    read_state()?
                };
                let due = state.settings.account_ids.iter()
                    .filter(|id| is_due(&state, id, &date, minute)).cloned().collect::<Vec<_>>();
                if due.is_empty() {
                    return Ok::<(), String>(());
                }
                let existing = qoder_account::list_accounts_checked()?;
                let mut changed = false;
                let mut failed = 0;
                for id in due {
                    if !existing.iter().any(|account| account.id == id) {
                        continue;
                    }
                    match claim(id, Some(date.clone())).await {
                        Ok(None) => break,
                        Ok(Some(result)) => {
                            changed = true;
                            if !result.success { failed += 1; }
                        }
                        Err(_) => { changed = true; failed += 1; }
                    }
                    // No credential or official response body in automatic logs/events.
                    let _ = app.emit("qoder-accounts-updated", ());
                }
                if changed {
                    logger::log_info(&format!("[Qoder AutoCheckin] 当日签到完成，失败 {failed} 个"));
                }
                Ok(())
            }.await;
            if cycle.is_err() {
                logger::log_warn("[Qoder AutoCheckin] 无法读取或保存签到设置，本轮已停止");
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                _ = WAKE.notified() => {},
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_due_respects_time_selection_and_attempted_day() {
        let mut state = StoredState::default();
        state.settings.enabled = true;
        state.settings.account_ids = vec!["cn-account".into()];
        assert!(!is_due(&state, "cn-account", "2026-10-09", 604));
        assert!(is_due(&state, "cn-account", "2026-10-09", 605));
        assert!(is_due(&state, "cn-account", "2026-10-09", 900)); // restart catch-up
        assert!(!is_due(&state, "other", "2026-10-09", 900));
        state.attempted_dates.insert("cn-account".into(), "2026-10-09".into());
        assert!(!is_due(&state, "cn-account", "2026-10-09", 900));
        assert!(is_due(&state, "cn-account", "2026-10-10", 605));
        state.settings.enabled = false;
        assert!(!is_due(&state, "cn-account", "2026-10-10", 605));
    }

    #[test]
    fn rejects_invalid_times_intervals_and_empty_enabled_selection() {
        let mut settings = QoderAutoCheckinSettings::default();
        for time in ["24:00", "10:60", "1:00", "ab:cd", "+1:00", "🕒"] {
            settings.time = time.into();
            assert!(validate(&settings).is_err());
        }
        settings.time = "23:59".into();
        settings.request_interval_seconds = 300;
        assert!(validate(&settings).is_ok());
        settings.request_interval_seconds = 301;
        assert!(validate(&settings).is_err());
        settings.request_interval_seconds = 0;
        settings.enabled = true;
        assert!(validate(&settings).is_err());
    }

    #[test]
    fn serialized_attempts_survive_restart_and_settings_changes() {
        let mut state = StoredState::default();
        state.settings.enabled = true;
        state.settings.account_ids = vec!["cn-account".into()];
        state.attempted_dates.insert("cn-account".into(), "2026-10-09".into());
        let json = serde_json::to_string(&state).unwrap();
        let mut restored: StoredState = serde_json::from_str(&json).unwrap();
        restored.settings.time = "11:00".into();
        restored.settings.request_interval_seconds = 20;
        assert!(!is_due(&restored, "cn-account", "2026-10-09", 700));
        assert!(is_due(&restored, "cn-account", "2026-10-10", 700));
    }

    #[tokio::test]
    async fn permit_serializes_accounts_and_records_completion_on_drop() {
        // An isolated queue: no account files, official requests or real credentials.
        let queue = Arc::new(AsyncMutex::new(None));
        let permit = ClaimPermit(queue.clone().lock_owned().await);
        assert!(queue.try_lock().is_err());
        drop(permit); // Covers both success and early error exits from the claim flow.
        let completed = queue.lock().await;
        assert!(completed.is_some());
    }

    #[test]
    fn gap_is_measured_from_completion_and_can_be_zero() {
        let completed = Instant::now();
        assert_eq!(remaining_delay(None, completed, 3), Duration::ZERO);
        assert_eq!(remaining_delay(Some(completed), completed, 3), Duration::from_secs(3));
        assert_eq!(remaining_delay(Some(completed), completed + Duration::from_secs(2), 3), Duration::from_secs(1));
        assert_eq!(remaining_delay(Some(completed), completed + Duration::from_secs(3), 3), Duration::ZERO);
        assert_eq!(remaining_delay(Some(completed), completed, 0), Duration::ZERO);
    }

    #[test]
    fn deselecting_and_reenabling_does_not_reset_todays_attempt() {
        let mut state = StoredState::default();
        state.attempted_dates.insert("cn-account".into(), "2026-10-09".into());
        state.attempted_dates.insert("old-account".into(), "2026-10-08".into());
        apply_settings(&mut state, QoderAutoCheckinSettings::default(), "2026-10-09");
        let settings = QoderAutoCheckinSettings {
            enabled: true, account_ids: vec!["cn-account".into()], ..Default::default()
        };
        apply_settings(&mut state, settings, "2026-10-09");
        assert!(!is_due(&state, "cn-account", "2026-10-09", 700));
        assert!(!state.attempted_dates.contains_key("old-account"));
    }
}
