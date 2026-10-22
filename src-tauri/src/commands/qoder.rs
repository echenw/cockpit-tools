use std::time::Instant;
use tauri::{AppHandle, Emitter};

use crate::models::qoder::{QoderAccount, QoderClaimRewardResult, QoderOAuthStartResponse};
use crate::modules::qoder_variant::QoderVariantKind;
use crate::modules::{logger, qoder_account, qoder_oauth};

fn resolve_variant_key(raw: Option<&str>) -> Result<String, String> {
    QoderVariantKind::parse(raw).map(|kind| kind.provider_key().to_string())
}

/// 每个地区共用 App 授权；旧 IDE 入口也进入同一会话，切号目标不影响授权。
fn resolve_oauth_variant_key(raw: Option<&str>) -> Result<String, String> {
    let kind = QoderVariantKind::parse(raw)?;
    Ok(kind.app_variant().provider_key().to_string())
}

fn account_belongs_to_variant(account: &QoderAccount, variant_key: &str) -> bool {
    qoder_account::account_variant_kind(account)
        .map(|kind| QoderVariantKind::parse(Some(variant_key)).is_ok_and(|requested| kind.site() == requested.site()))
        .unwrap_or(false)
}

/// 刷新变体一致性（纯函数）：请求键缺省 → 以账号自身变体为权威（不拒绝）；
/// 显式请求键选择同地区客户端，跨地区拒绝。
fn resolve_refresh_variant(account_variant: &str, requested: Option<&str>) -> Result<(), String> {
    if let Some(raw) = requested {
        let requested = resolve_variant_key(Some(raw))?;
        if QoderVariantKind::parse(Some(&requested))?.site() != QoderVariantKind::parse(Some(account_variant))?.site() {
            return Err(format!(
                "刷新请求变体与账号变体不一致: account={}, requested={}",
                account_variant, requested
            ));
        }
    }
    Ok(())
}

/// 有客户端上下文时按请求入口刷新；后台无上下文时刷新最近使用的客户端凭据。
async fn refresh_account_by_variant(
    account_id: &str,
    requested_variant: Option<&str>,
) -> Result<QoderAccount, String> {
    let account = qoder_account::load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let source = qoder_account::account_variant_kind(&account)?;
    resolve_refresh_variant(source.provider_key(), requested_variant)?;
    let variant = requested_variant.map(|raw| resolve_variant_key(Some(raw)))
        .transpose()?.unwrap_or_else(|| source.provider_key().to_string());
    let account_with_campaign = qoder_oauth::refresh_account_and_campaigns(&variant, account_id).await?;
    Ok(account_with_campaign)
}

/// 仅 CN IDE 保留刷新写回；App 由官方客户端管理当前会话，禁止后台热写认证文件。
fn should_write_back_after_refresh(
    current_id: Option<&str>,
    refreshed_account_id: &str,
    kind: QoderVariantKind,
) -> bool {
    if kind != QoderVariantKind::QoderCnIde {
        return false;
    }
    current_id == Some(refreshed_account_id)
}

/// 单账号与批量刷新共用的纯筛选点：给定本轮刷新成功的账号（按序）与各变体当前账号解析器，
/// 返回需要回写客户端的子集。保持输入顺序。
fn select_refresh_write_back_targets<F>(
    refreshed: Vec<(QoderVariantKind, String)>,
    current_id_for_kind: F,
) -> Vec<(QoderVariantKind, String)>
where
    F: Fn(QoderVariantKind) -> Option<String>,
{
    refreshed
        .into_iter()
        .filter(|(kind, account_id)| {
            should_write_back_after_refresh(
                current_id_for_kind(*kind).as_deref(),
                account_id,
                *kind,
            )
        })
        .collect()
}

/// 刷新成功后的最佳努力回写：失败仅告警，不影响刷新命令返回（账号库更新才是事实源）。
async fn run_refresh_write_back(refreshed: Vec<(QoderVariantKind, String)>) {
    for (kind, account_id) in refreshed {
        if kind != QoderVariantKind::QoderCnIde { continue; }
        let variant_key = kind.provider_key();
        let write_back = async {
            let session_lock = qoder_oauth::client_session_lock(kind)?;
            let _session_guard = session_lock.lock().await;
            let _app_guard = qoder_oauth::client_session_lock(kind.app_variant())?.lock_owned().await;
            let account_lock = qoder_oauth::account_refresh_lock(&account_id)?;
            let _account_guard = account_lock.lock().await;
            // Resolve inside the session lock: a completed switch invalidates this target.
            let accounts = qoder_account::list_accounts_checked()?;
            if let Some(account) = accounts.iter().find(|account| account.id == account_id) {
                if qoder_account::native_ide_owns_refresh(account)?
                    || qoder_account::app_owned_session(&account.id)?.is_some() {
                    return Ok::<(), String>(());
                }
            }
            let targets = select_refresh_write_back_targets(vec![(kind, account_id.clone())], |kind| {
                qoder_account::resolve_current_account_id_for_variant(&accounts, kind)
            });
            if !targets.is_empty() {
                qoder_account::inject_to_qoder_for_variant(variant_key, &account_id)?;
            }
            Ok::<(), String>(())
        }.await;
        if let Err(err) = write_back {
            logger::log_warn(&format!(
                "[Qoder Refresh] 变体当前账号回写失败（刷新已成功，仅告警）: variant={}, account_id={}, error={}",
                variant_key, account_id, err
            ));
        }
    }
}

async fn write_back_current_account_if_auth_changed(before: Option<QoderAccount>, account_id: &str) {
    if let (Some(before), Some(after)) = (before, qoder_account::load_account(account_id)) {
        if before.auth_user_info_raw != after.auth_user_info_raw {
            if let Ok(kind) = qoder_account::account_variant_kind(&after) {
                run_refresh_write_back(vec![(kind, account_id.to_string())]).await;
            }
        }
    }
}

#[tauri::command]
pub fn list_qoder_accounts() -> Result<Vec<QoderAccount>, String> {
    qoder_account::list_accounts_checked()
        .map(|accounts| accounts.into_iter().map(QoderAccount::for_ipc).collect())
}

#[tauri::command]
pub fn delete_qoder_account(account_id: String) -> Result<(), String> {
    qoder_account::remove_account(&account_id)
}

#[tauri::command]
pub fn delete_qoder_accounts(account_ids: Vec<String>) -> Result<(), String> {
    qoder_account::remove_accounts(&account_ids)
}

#[tauri::command]
pub async fn import_qoder_from_json(
    json_content: String,
    variant_key: Option<String>,
) -> Result<Vec<QoderAccount>, String> {
    let variant = resolve_variant_key(variant_key.as_deref())?;
    tauri::async_runtime::spawn_blocking(move || {
        qoder_account::import_from_json_for_variant(&json_content, &variant)
    }).await.map_err(|error| format!("Qoder JSON 导入任务失败: {error}"))?
        .map(|accounts| accounts.into_iter().map(QoderAccount::for_ipc).collect())
}

#[tauri::command]
pub async fn import_qoder_from_local(
    app: AppHandle,
    variant_key: Option<String>,
) -> Result<Vec<QoderAccount>, String> {
    let variant = resolve_variant_key(variant_key.as_deref())?;
    let imported = tauri::async_runtime::spawn_blocking(move || {
        qoder_account::import_from_local_for_variant(&variant)
    })
    .await
    .map_err(|err| format!("Qoder 本地导入任务失败: {err}"))??;
    match imported {
        Some(result) => {
            let account = result.into_imported_account()?;
            let _ = crate::modules::tray::update_tray_menu(&app);
            Ok(vec![account.for_ipc()])
        }
        None => Err("未找到本地 Qoder 登录信息".to_string()),
    }
}

#[tauri::command]
pub async fn qoder_oauth_login_start(
    variant_key: Option<String>,
) -> Result<QoderOAuthStartResponse, String> {
    let started_at = Instant::now();
    let variant = resolve_oauth_variant_key(variant_key.as_deref())?;
    logger::log_info(&format!(
        "[Qoder OAuth] start 命令触发: variant={}",
        variant
    ));
    let result = qoder_oauth::start_login_for_variant(&variant).await;
    match &result {
        Ok(response) => logger::log_info(&format!(
            "[Qoder OAuth] start 命令完成: variant={}, login_id={}, verification_uri_len={}, elapsed={}ms",
            variant,
            response.login_id,
            response.verification_uri.len(),
            started_at.elapsed().as_millis()
        )),
        Err(err) => logger::log_warn(&format!(
            "[Qoder OAuth] start 命令失败: variant={}, elapsed={}ms, error={}",
            variant,
            started_at.elapsed().as_millis(),
            err
        )),
    }
    result
}

#[tauri::command]
pub fn qoder_oauth_login_peek(
    variant_key: Option<String>,
) -> Result<Option<QoderOAuthStartResponse>, String> {
    let variant = resolve_oauth_variant_key(variant_key.as_deref())?;
    let pending = qoder_oauth::peek_pending_login_for_variant(&variant);
    if let Some(state) = pending.as_ref() {
        logger::log_info(&format!(
            "[Qoder OAuth] peek 命令命中会话: variant={}, login_id={}, verification_uri_len={}",
            variant,
            state.login_id,
            state.verification_uri.len()
        ));
    } else {
        logger::log_info(&format!(
            "[Qoder OAuth] peek 命令未命中会话: variant={}",
            variant
        ));
    }
    Ok(pending)
}

#[tauri::command]
pub async fn qoder_oauth_login_complete(
    app: AppHandle,
    login_id: String,
    variant_key: Option<String>,
) -> Result<QoderAccount, String> {
    let started_at = Instant::now();
    let variant = resolve_oauth_variant_key(variant_key.as_deref())?;
    logger::log_info(&format!(
        "[Qoder OAuth] complete 命令触发: variant={}, login_id={}",
        variant, login_id
    ));
    let account = match qoder_oauth::complete_login(&login_id, &variant).await {
        Ok(account) => account,
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder OAuth] complete 命令失败: variant={}, login_id={}, elapsed={}ms, error={}",
                variant,
                login_id,
                started_at.elapsed().as_millis(),
                err
            ));
            return Err(err);
        }
    };
    let account_variant = qoder_account::account_variant_kind(&account)?
        .provider_key()
        .to_string();
    if account_variant != variant {
        return Err(format!(
            "Qoder 登录结果变体不一致: 请求={}, 入库={}，请重新发起登录",
            variant, account_variant
        ));
    }
    let granted = account.clone();
    let hydration_variant = variant.clone();
    let hydration_app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(err) = qoder_oauth::hydrate_login_account(granted.clone(), &hydration_variant).await {
            // 身份不一致等错误只中止资料同步，不伪造登录失败或已领福利。
            if let Ok(kind) = QoderVariantKind::parse(Some(&hydration_variant)) {
                if let Some(token) = qoder_oauth::extract_access_token_from_account(&granted) {
                    let _ = qoder_account::update_login_profile_if_current(
                        &granted.id, kind, &token, None, None, None,
                        Some(format!("设备授权已保存，资料同步失败：{}", err)),
                    );
                }
            }
            logger::log_warn(&format!("[Qoder OAuth] 授权后资料同步失败: variant={}, error={}",
                hydration_variant, err));
        }
        let _ = hydration_app.emit("qoder-accounts-updated", ());
        let _ = crate::modules::tray::update_tray_menu(&hydration_app);
    });
    let _ = crate::modules::tray::update_tray_menu(&app);
    logger::log_info(&format!(
        "[Qoder OAuth] complete 命令完成: variant={}, login_id={}, account_id={}, elapsed={}ms",
        variant,
        login_id,
        account.id,
        started_at.elapsed().as_millis()
    ));
    Ok(account.for_ipc())
}

#[tauri::command]
pub fn qoder_oauth_login_cancel(
    login_id: Option<String>,
    variant_key: Option<String>,
) -> Result<(), String> {
    let variant = match variant_key.as_deref() {
        Some(raw) => Some(resolve_oauth_variant_key(Some(raw))?),
        None => None,
    };
    logger::log_info(&format!(
        "[Qoder OAuth] cancel 命令触发: variant={}, login_id={}",
        variant.as_deref().unwrap_or("<all>"),
        login_id.as_deref().unwrap_or("<none>")
    ));
    qoder_oauth::cancel_login_for_variant(login_id.as_deref(), variant.as_deref())
}

#[tauri::command]
pub fn export_qoder_accounts(
    account_ids: Vec<String>,
    include_credentials: Option<bool>,
) -> Result<String, String> {
    qoder_account::export_accounts(&account_ids, include_credentials.unwrap_or(true))
}

#[tauri::command]
pub async fn refresh_qoder_token(
    app: AppHandle,
    account_id: String,
    variant_key: Option<String>,
) -> Result<QoderAccount, String> {
    let started_at = Instant::now();
    logger::log_info(&format!(
        "[Qoder Command] 手动刷新账号开始: account_id={}",
        account_id
    ));
    match refresh_account_by_variant(&account_id, variant_key.as_deref()).await {
        Ok(account) => {
            let kind = variant_key.as_deref().map(|raw| QoderVariantKind::parse(Some(raw)))
                .unwrap_or_else(|| qoder_account::account_variant_kind(&account));
            if let Ok(kind) = kind { run_refresh_write_back(vec![(kind, account.id.clone())]).await; }
            if let Err(err) = qoder_account::run_quota_alert_if_needed() {
                logger::log_warn(&format!("[QuotaAlert][Qoder] 预警检查失败: {}", err));
            }
            let _ = crate::modules::tray::update_tray_menu(&app);
            logger::log_info(&format!(
                "[Qoder Command] 刷新完成: account_id={}, email={}, elapsed={}ms",
                account.id,
                account.email,
                started_at.elapsed().as_millis()
            ));
            Ok(account.for_ipc())
        }
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder Command] 刷新失败: account_id={}, elapsed={}ms, error={}",
                account_id,
                started_at.elapsed().as_millis(),
                err
            ));
            Err(err)
        }
    }
}

#[tauri::command]
pub async fn refresh_all_qoder_tokens(
    app: AppHandle,
    variant_key: Option<String>,
) -> Result<i32, String> {
    let started_at = Instant::now();
    // 有客户端上下文时按请求变体刷新该地区账号；`None` 用于全变体后台刷新。
    let variant = match variant_key.as_deref() {
        Some(raw) => Some(resolve_variant_key(Some(raw))?),
        None => None,
    };
    let scope_label = variant.as_deref().unwrap_or("<all>");
    logger::log_info(&format!("[Qoder Command] 批量刷新开始: variant={}", scope_label));
    let mut refreshed: i32 = 0;
    let mut write_back_targets: Vec<(QoderVariantKind, String)> = Vec::new();
    for account in qoder_account::list_accounts_checked()? {
        if variant
            .as_deref()
            .is_some_and(|scope| !account_belongs_to_variant(&account, scope))
        {
            continue;
        }
        match refresh_account_by_variant(&account.id, variant.as_deref()).await {
            Ok(refreshed_account) => {
                refreshed += 1;
                let kind = variant.as_deref().map(|raw| QoderVariantKind::parse(Some(raw)))
                    .unwrap_or_else(|| qoder_account::account_variant_kind(&refreshed_account));
                if let Ok(kind) = kind { write_back_targets.push((kind, refreshed_account.id.clone())); }
            }
            Err(err) => logger::log_warn(&format!(
                "[Qoder Command] 批量刷新失败: variant={}, account_id={}, email={}, error={}",
                scope_label, account.id, account.email, err
            )),
        }
    }
    run_refresh_write_back(write_back_targets).await;
    if refreshed > 0 {
        if let Err(err) = qoder_account::run_quota_alert_if_needed() {
            logger::log_warn(&format!(
                "[QuotaAlert][Qoder] 全量刷新后预警检查失败: {}",
                err
            ));
        }
    }
    let _ = crate::modules::tray::update_tray_menu(&app);
    logger::log_info(&format!(
        "[Qoder Command] 批量刷新完成: variant={}, refreshed={}, elapsed={}ms",
        scope_label,
        refreshed,
        started_at.elapsed().as_millis()
    ));
    Ok(refreshed)
}

fn recover_closed_app_switch(
    was_running: bool,
    error: qoder_account::AppInjectionError,
    restart: impl FnOnce() -> Result<u32, String>,
) -> String {
    use qoder_account::AppLoginState;
    if error.login_state == AppLoginState::Unknown {
        return format!("{}；登录文件状态未确认，未自动启动客户端", error.message);
    }
    if !was_running { return error.message; }
    let state = match error.login_state {
        AppLoginState::Original => "切号已中止，原登录态保留",
        AppLoginState::Target => "目标登录态已写入并保留",
        AppLoginState::Unknown => unreachable!(),
    };
    match restart() {
        Ok(_) => format!("{}；{}，已重新启动客户端", error.message, state),
        Err(restart_error) => format!("{}；{}，恢复启动客户端失败: {}", error.message, state, restart_error),
    }
}

#[tauri::command]
pub async fn inject_qoder_account(
    app: AppHandle,
    account_id: String,
    variant_key: Option<String>,
) -> Result<String, String> {
    let started_at = Instant::now();
    logger::log_info(&format!(
        "[Qoder Switch] 开始切换账号: account_id={}",
        account_id
    ));

    let account = qoder_account::load_account(&account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let kind = match variant_key.as_deref() {
        Some(raw) => QoderVariantKind::parse(Some(raw))?,
        None => qoder_account::account_variant_kind(&account)?,
    };
    if !qoder_account::account_supports_variant(&account, kind) {
        return Err("Qoder 国内与国际账号不能互通".into());
    }
    let account_id = account.id;
    let variant = kind.provider_key();
    let session_lock = qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;
    if let Err(err) = crate::modules::process::ensure_qoder_variant_launch_path(kind) {
        if err.starts_with("APP_PATH_NOT_FOUND:") {
            let _ = app.emit("app:path_missing", serde_json::json!({
                "app": variant, "retry": { "kind": "switchAccount", "accountId": account_id }
            }));
        }
        return Err(err);
    }
    let data_dir = crate::modules::process::qoder_variant_default_user_data_dir(kind)
        .ok_or_else(|| format!("无法解析 {} 的数据目录", kind.display_name()))?;
    let app_dir = if kind.is_app() {
        let params = qoder_oauth::resolve_qoder_variant_params(variant)?;
        Some(qoder_oauth::qoder_user_data_dir_for_variant(&params)?)
    } else { None };
    if let Some(dir) = &app_dir {
        let previous = qoder_account::read_official_login_candidate(kind, dir)?;
        let target = qoder_account::load_account(&account_id).ok_or("Qoder 账号已被删除")?;
        if target.native_ide_session
            || previous.as_ref().is_none_or(|previous| previous.account_id() != account_id)
        {
            // Even the same App account must not take over a running default IDE's grant.
            // Reject that handoff before interrupting the current App.
            // Recheck under a fresh guard after closing/saving its final session below.
            let _preflight_guard = qoder_oauth::prepare_account_for_launch(kind, &account_id).await?;
        }
    } else {
        let target = qoder_account::load_account(&account_id).ok_or("Qoder 账号已被删除")?;
        // 原生 IDE 持有的凭据必须先关闭回收；其他账号仍可提前校验。
        // 这里只做预检查，不跨越旧账号回收持有目标账号锁。
        if !target.native_ide_session {
            let _preflight_guard = qoder_oauth::prepare_account_for_launch(kind, &account_id).await?;
        }
    }
    let was_running = kind.is_app()
        && crate::modules::process::resolve_qoder_pid_for_variant_checked(kind, None, Some(&data_dir))?.is_some();
    crate::modules::process::close_qoder_variant_instances(kind, &[data_dir], 20)
        .map_err(|err| format!("{} 未能关闭，切号已中止: {}", kind.display_name(), err))?;
    let _account_guard = if let Some(dir) = &app_dir {
        // Save the official client's final credentials before preparing another projection.
        let prepared = async {
            if let Some(previous) = qoder_account::read_official_login_candidate(kind, dir)? {
                let lock = qoder_oauth::account_refresh_lock(&previous.refresh_lock_key())?;
                let _previous_guard = lock.lock().await;
                qoder_account::save_closed_app_session(kind)?;
            }
            qoder_oauth::prepare_account_for_launch(kind, &account_id).await
        }.await;
        prepared.map_err(|error| recover_closed_app_switch(
            was_running, error.into(), || crate::modules::process::launch_qoder_variant_client(kind),
        ))?
    } else {
        qoder_account::reconcile_default_ide_session(kind).await?;
        qoder_oauth::prepare_account_for_launch(kind, &account_id).await?
    };
    let injection_error = if kind.is_app() {
        match qoder_account::inject_to_qoder_app_checked(kind, &account_id) {
            Ok(()) => None,
            Err(error) if error.login_state == qoder_account::AppLoginState::Target => {
                // Auth was committed; still synchronize current-account bookkeeping.
                Some(error.message)
            }
            Err(error) => return Err(recover_closed_app_switch(was_running, error, ||
                crate::modules::process::launch_qoder_variant_client(kind))),
        }
    } else {
        qoder_account::inject_to_qoder_for_variant(variant, &account_id)?;
        None
    };
    // The disk session has changed even if bookkeeping or the following launch fails.
    let current_state = crate::modules::provider_current_state::set_current_account_id(variant, Some(&account_id));
    let post_write_error = match (injection_error, current_state) {
        (None, Ok(())) => None,
        (Some(error), Ok(())) => Some(error),
        (None, Err(error)) => Some(error),
        (Some(error), Err(state_error)) => Some(format!("{}；当前账号记录更新失败: {}", error, state_error)),
    };
    if let Some(message) = post_write_error {
        return Err(if kind.is_app() {
            recover_closed_app_switch(was_running, qoder_account::AppInjectionError {
                message,
                login_state: qoder_account::AppLoginState::Target,
            }, || crate::modules::process::launch_qoder_variant_client(kind))
        } else { message });
    }
    if kind.supports_instances() {
        crate::modules::qoder_instance::update_default_settings_for_variant(
            kind, Some(Some(account_id.clone())), None, Some(false),
        )?;
    }
    crate::modules::process::launch_qoder_variant_client(kind)
        .map_err(|err| format!("{} 登录态已写入，但客户端启动未确认: {}", kind.display_name(), err))?;
    let _ = crate::modules::tray::update_tray_menu(&app);
    logger::log_info(&format!("[Qoder Switch] 切换完成: variant={}, elapsed={}ms", variant, started_at.elapsed().as_millis()));
    Ok(format!("切换完成（{}）：已写入本地登录态并启动客户端", kind.display_name()))
}

#[tauri::command]
pub fn update_qoder_account_tags(
    account_id: String,
    tags: Vec<String>,
) -> Result<QoderAccount, String> {
    qoder_account::update_account_tags(&account_id, tags).map(QoderAccount::for_ipc)
}

#[tauri::command]
pub async fn claim_qoder_reward(
    account_id: String,
) -> Result<QoderClaimRewardResult, String> {
    run_reward_claim(account_id, None).await?
        .ok_or_else(|| "签到任务已取消".to_string())
}

pub(crate) async fn run_reward_claim(
    account_id: String,
    scheduled_date: Option<String>,
) -> Result<Option<QoderClaimRewardResult>, String> {
    run_reward_claim_with_cancellation(account_id, scheduled_date, None).await
}

#[tauri::command]
pub fn start_qoder_reward_batch() -> Result<String, String> {
    crate::modules::qoder_auto_checkin::start_manual_batch()
}

#[tauri::command]
pub fn cancel_qoder_reward_batch(batch_id: String) -> Result<(), String> {
    crate::modules::qoder_auto_checkin::cancel_manual_batch(&batch_id)
}

#[tauri::command]
pub async fn claim_qoder_batch_reward(
    account_id: String,
    batch_id: String,
) -> Result<Option<QoderClaimRewardResult>, String> {
    let Some(cancellation) = crate::modules::qoder_auto_checkin::manual_batch_cancellation(&batch_id)? else {
        return Ok(None);
    };
    run_reward_claim_with_cancellation(account_id, None, Some(cancellation)).await
}

async fn run_reward_claim_with_cancellation(
    account_id: String,
    scheduled_date: Option<String>,
    cancellation: Option<crate::modules::qoder_auto_checkin::ClaimCancellation>,
) -> Result<Option<QoderClaimRewardResult>, String> {
    let Some(_permit) = crate::modules::qoder_auto_checkin::acquire_claim_slot(
        &account_id, scheduled_date.as_deref(), cancellation,
    ).await? else {
        return Ok(None);
    };
    let before = qoder_account::load_account(&account_id);
    let result = qoder_oauth::claim_daily_reward(&account_id).await;
    write_back_current_account_if_auth_changed(before, &account_id).await;
    let result = result?;
    Ok(Some(result.for_ipc()))
}

#[tauri::command]
pub fn get_qoder_auto_checkin_settings() -> Result<crate::modules::qoder_auto_checkin::QoderAutoCheckinSettings, String> {
    crate::modules::qoder_auto_checkin::get_settings()
}

#[tauri::command]
pub fn recover_qoder_auto_checkin_settings() -> Result<crate::modules::qoder_auto_checkin::QoderAutoCheckinSettings, String> {
    crate::modules::qoder_auto_checkin::recover_settings()
}

#[tauri::command]
pub fn save_qoder_auto_checkin_settings(
    settings: crate::modules::qoder_auto_checkin::QoderAutoCheckinSettings,
) -> Result<crate::modules::qoder_auto_checkin::QoderAutoCheckinSettings, String> {
    crate::modules::qoder_auto_checkin::save_settings(settings)
}

#[tauri::command]
pub async fn check_qoder_reward_status(
    account_id: String,
) -> Result<QoderAccount, String> {
    let result = qoder_oauth::query_qoder_campaign_status(&account_id).await;
    result.map(QoderAccount::for_ipc)
}

#[tauri::command]
pub async fn batch_check_qoder_reward_statuses(
    account_ids: Vec<String>,
) -> Result<Vec<QoderAccount>, String> {
    let mut results = Vec::new();
    for id in account_ids {
        match qoder_oauth::query_qoder_campaign_status(&id).await {
            Ok(acc) => results.push(acc.for_ipc()),
            Err(err) => {
                logger::log_warn(&format!("[Qoder Campaign] 查询活动状态失败: id={}, err={}", id, err));
                // Only confirmed queries are returned. Existing snapshots remain in storage;
                // the caller must be able to distinguish failures for delayed retry.
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_uses_the_regional_app_without_changing_client_operation_targets() {
        for (requested, expected) in [
            ("qoder", "qoder_app"),
            ("qoder_app", "qoder_app"),
            ("qoder_cn_ide", "qoder_cn_app"),
            ("qoder_cn_app", "qoder_cn_app"),
        ] {
            let oauth = resolve_oauth_variant_key(Some(requested)).unwrap();
            assert_eq!(oauth, expected);
            assert!(qoder_oauth::resolve_qoder_variant_params(&oauth).unwrap().is_app_line);
            assert_eq!(resolve_variant_key(Some(requested)).unwrap(), requested,
                "local import, switching and refresh must retain their explicit client");
        }
        assert_eq!(resolve_oauth_variant_key(None).unwrap(), "qoder_app");
        assert_eq!(resolve_oauth_variant_key(Some("qoder-cn-ide")).unwrap(), "qoder_cn_app");
        assert!(resolve_oauth_variant_key(Some("qoder_eu")).is_err());
    }

    #[test]
    fn failed_app_preparation_only_restarts_a_previously_running_client() {
        let error = recover_closed_app_switch(false, "credential failure".to_string().into(), || {
            panic!("an offline App must stay offline after a failed switch");
        });
        assert_eq!(error, "credential failure");
        let mut restarts = 0;
        let error = recover_closed_app_switch(true, "credential failure".to_string().into(), || {
            restarts += 1;
            Ok(42)
        });
        assert_eq!(restarts, 1);
        assert!(error.contains("credential failure"));
        assert!(error.contains("原登录态保留"));
        assert!(error.contains("已重新启动客户端"));
        let error = recover_closed_app_switch(true, "credential failure".to_string().into(), || {
            Err("launch failure".into())
        });
        assert!(error.contains("credential failure"));
        assert!(error.contains("launch failure"));
        assert!(!error.contains("已重新启动"));
    }

    #[test]
    fn failed_app_switch_keeps_committed_auth_and_does_not_launch_unknown_auth() {
        let error = recover_closed_app_switch(true, qoder_account::AppInjectionError {
            message: "metadata failure".into(),
            login_state: qoder_account::AppLoginState::Target,
        }, || Ok(42));
        assert!(error.contains("metadata failure"));
        assert!(error.contains("目标登录态已写入并保留"));
        assert!(error.contains("已重新启动客户端"));
        assert!(!error.contains("原登录态保留"));
        let error = recover_closed_app_switch(true, qoder_account::AppInjectionError {
            message: "rollback failure".into(),
            login_state: qoder_account::AppLoginState::Unknown,
        }, || panic!("must not launch an unconfirmed auth file"));
        assert!(error.contains("rollback failure"));
        assert!(error.contains("未自动启动客户端"));
    }

    #[test]
    fn refresh_never_hot_writes_app_credentials() {
        assert!(should_write_back_after_refresh(
            Some("acct-1"), "acct-1", QoderVariantKind::QoderCnIde,
        ));
        for kind in [
            QoderVariantKind::QoderApp,
            QoderVariantKind::QoderCnApp,
        ] {
            assert!(
                !should_write_back_after_refresh(Some("acct-1"), "acct-1", kind),
                "App credentials must never be hot-written: {kind:?}"
            );
        }
        // non-current → false
        assert!(!should_write_back_after_refresh(
            Some("acct-2"),
            "acct-1",
            QoderVariantKind::QoderApp
        ));
        // Intl IDE keeps its own native session; background refresh does not hot-write it.
        assert!(!should_write_back_after_refresh(
            Some("acct-1"),
            "acct-1",
            QoderVariantKind::Qoder
        ));
        // no current id → false
        assert!(!should_write_back_after_refresh(
            None,
            "acct-1",
            QoderVariantKind::QoderApp
        ));
    }

    #[test]
    fn batch_target_selection_excludes_app_sessions() {
        let refreshed = vec![
            (QoderVariantKind::Qoder, "default-current".to_string()),
            (QoderVariantKind::QoderApp, "app-current".to_string()),
            (QoderVariantKind::QoderCnIde, "cn-ide-stale".to_string()),
            (QoderVariantKind::QoderCnIde, "cn-ide-other".to_string()),
            (QoderVariantKind::QoderCnApp, "cn-app-current".to_string()),
        ];
        let current = [
            (QoderVariantKind::Qoder, "default-current"),
            (QoderVariantKind::QoderApp, "app-current"),
            (QoderVariantKind::QoderCnIde, "cn-ide-other"),
            (QoderVariantKind::QoderCnApp, "cn-app-current"),
        ];
        let resolver = |kind: QoderVariantKind| {
            current
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, id)| (*id).to_string())
        };
        assert_eq!(
            select_refresh_write_back_targets(refreshed, resolver),
            vec![(QoderVariantKind::QoderCnIde, "cn-ide-other".to_string())]
        );
    }

    #[test]
    fn single_refresh_uses_same_selection_guard_as_batch() {
        let current = |_kind: QoderVariantKind| Some("acct-1".to_string());
        assert_eq!(
            select_refresh_write_back_targets(
                vec![(QoderVariantKind::QoderCnIde, "acct-1".to_string())],
                current,
            )
            .len(),
            1
        );
        assert!(select_refresh_write_back_targets(
            vec![(QoderVariantKind::Qoder, "acct-1".to_string())],
            |_kind| Some("acct-1".to_string()),
        )
        .is_empty());
    }

    #[test]
    fn refresh_variant_guard_accepts_account_scope_and_rejects_mismatch() {
        // 缺省请求键（保活/自动刷新路径）→ 以账号自身变体为权威，不拒绝。
        assert!(resolve_refresh_variant("qoder", None).is_ok());
        assert!(resolve_refresh_variant("qoder_cn_app", None).is_ok());
        // 显式且一致 → 放行（含连字符别名归一）。
        assert!(resolve_refresh_variant("qoder", Some("qoder")).is_ok());
        assert!(resolve_refresh_variant("qoder_cn_ide", Some("qoder-cn-ide")).is_ok());
        // Same-region client requests are allowed; cross-region requests are rejected.
        assert!(resolve_refresh_variant("qoder", Some("qoder_app")).is_ok());
        assert!(resolve_refresh_variant("qoder_cn_app", Some("qoder_cn_ide")).is_ok());
        let err = resolve_refresh_variant("qoder", Some("qoder_cn_app"))
            .expect_err("mismatched request must be rejected");
        assert!(err.contains("不一致"), "{err}");
        assert!(err.contains("account=qoder"), "{err}");
        assert!(err.contains("requested=qoder_cn_app"), "{err}");
        // 未知请求键 → 拒绝。
        assert!(resolve_refresh_variant("qoder", Some("qoder_eu")).is_err());
    }
}
