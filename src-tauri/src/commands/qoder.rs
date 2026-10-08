use std::time::Instant;
use tauri::{AppHandle, Emitter};

use crate::models::qoder::{QoderAccount, QoderClaimRewardResult, QoderOAuthStartResponse};
use crate::modules::qoder_variant::QoderVariantKind;
use crate::modules::{logger, qoder_account, qoder_oauth};

fn resolve_variant_key(raw: Option<&str>) -> Result<String, String> {
    QoderVariantKind::parse(raw).map(|kind| kind.provider_key().to_string())
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
    let refreshed_account = {
        let refreshed =
            qoder_oauth::refresh_account_token_for_variant(&variant, account_id, false).await?;
        if !qoder_oauth::variant_supports_job_line(&variant) {
            refreshed
        } else {
            // App 系 device 行已落库；job 行失败不回滚 device 会话，仅告警。
            match qoder_oauth::refresh_account_token_for_variant(&variant, account_id, true).await {
                Ok(job_account) => job_account,
                Err(err) => {
                    logger::log_warn(&format!(
                        "[Qoder Refresh] App jobToken 刷新失败，保留 device 会话: variant={}, account_id={}, error={}",
                        variant, account_id, err
                    ));
                    refreshed
                }
            }
        }
    };

    // 刷新时同步拉取 100 积分活动状态（弱依赖，失败不阻断账号正常刷新）
    let account_with_campaign = match qoder_oauth::query_qoder_campaign_status(account_id).await {
        Ok(account_with_campaign) => account_with_campaign,
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder Refresh] 同步活动状态失败（沿用账号）: account_id={}, error={}",
                account_id, err
            ));
            refreshed_account
        }
    };

    Ok(try_refresh_qoder_web_quota(account_with_campaign).await)
}

async fn try_refresh_qoder_web_quota(account: QoderAccount) -> QoderAccount {
    if account.web_session_cookie.as_deref().filter(|c| !c.trim().is_empty()).is_none() {
        return account;
    }
    match crate::modules::qoder_webview::refresh_web_quota(&account.id, None).await {
        Ok(updated) => return updated,
        Err(err) => logger::log_warn(&format!(
            "[Qoder Refresh] 网页配额查询失败: account_id={}, error={}", account.id, err
        )),
    }
    account
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
            let account_lock = qoder_oauth::account_refresh_lock(&account_id)?;
            let _account_guard = account_lock.lock().await;
            // Resolve inside the session lock: a completed switch invalidates this target.
            let accounts = qoder_account::list_accounts_checked()?;
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
pub fn import_qoder_from_json(
    json_content: String,
    variant_key: Option<String>,
) -> Result<Vec<QoderAccount>, String> {
    let variant = resolve_variant_key(variant_key.as_deref())?;
    qoder_account::import_from_json_for_variant(&json_content, &variant)
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
        Some(account) => {
            let _ = crate::modules::tray::update_tray_menu(&app);
            Ok(vec![account.for_ipc()])
        }
        None => Err("未找到本地 Qoder 登录信息".to_string()),
    }
}

#[tauri::command]
pub fn start_qoder_official_login(
    app: AppHandle,
    variant_key: String,
) -> Result<crate::modules::qoder_official_login::LoginStatus, String> {
    let kind = QoderVariantKind::parse(Some(&variant_key))?;
    crate::modules::qoder_official_login::start(app, kind)
}

#[tauri::command]
pub fn get_qoder_official_login_status(
    session_id: String,
) -> Result<crate::modules::qoder_official_login::LoginStatus, String> {
    crate::modules::qoder_official_login::status(&session_id)
}

#[tauri::command]
pub fn cancel_qoder_official_login(session_id: String) -> Result<(), String> {
    crate::modules::qoder_official_login::cancel(&session_id)
}

#[tauri::command]
pub async fn qoder_oauth_login_start(
    variant_key: Option<String>,
) -> Result<QoderOAuthStartResponse, String> {
    let started_at = Instant::now();
    let variant = resolve_variant_key(variant_key.as_deref())?;
    logger::log_info(&format!(
        "[Qoder OAuth] start 命令触发: variant={}",
        variant
    ));
    let result = qoder_oauth::start_login_for_variant(&variant).await;
    match &result {
        Ok(response) => logger::log_info(&format!(
            "[Qoder OAuth] start 命令完成: variant={}, login_id={}, verification_uri_len={}, callback_url={}, elapsed={}ms",
            variant,
            response.login_id,
            response.verification_uri.len(),
            response.callback_url.as_deref().unwrap_or("<none>"),
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
    let variant = resolve_variant_key(variant_key.as_deref())?;
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
    let variant = resolve_variant_key(variant_key.as_deref())?;
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
    crate::modules::qoder_webview::sync_after_login(app.clone(), account.id.clone());
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
        Some(raw) => Some(resolve_variant_key(Some(raw))?),
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
    // 前端入口始终显式传当前标签页变体；托盘菜单入口无变体上下文（`None`），覆盖全部变体。
    let variant = match variant_key.as_deref() {
        Some(raw) => Some(resolve_variant_key(Some(raw))?),
        None => None,
    };
    let scope_label = variant.as_deref().unwrap_or("<all>");
    logger::log_info(&format!("[Qoder Command] 批量刷新开始: variant={}", scope_label));
    let mut refreshed: i32 = 0;
    let mut write_back_targets: Vec<(QoderVariantKind, String)> = Vec::new();
    for account in qoder_account::list_accounts() {
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
    if kind.is_app() && crate::modules::qoder_official_login::is_active(kind) {
        return Err("官方客户端登录正在进行，请完成或取消后再切换账号".into());
    }
    if let Err(err) = crate::modules::process::ensure_qoder_variant_launch_path(kind) {
        if err.starts_with("APP_PATH_NOT_FOUND:") {
            let _ = app.emit("app:path_missing", serde_json::json!({
                "app": variant, "retry": { "kind": "switchAccount", "accountId": account_id }
            }));
        }
        return Err(err);
    }
    // IDE preparation fails before touching its existing running client.
    let mut account_guard = if !kind.is_app() {
        Some(qoder_oauth::prepare_account_for_launch(kind, &account_id).await?)
    } else { None };
    let data_dir = crate::modules::process::qoder_variant_default_user_data_dir(kind)
        .ok_or_else(|| format!("无法解析 {} 的数据目录", kind.display_name()))?;
    crate::modules::process::close_qoder_variant_instances(kind, &[data_dir], 20)
        .map_err(|err| format!("{} 未能关闭，切号已中止: {}", kind.display_name(), err))?;
    if kind.is_app() {
        // Save the official client's final credentials before preparing another projection.
        let params = qoder_oauth::resolve_qoder_variant_params(variant)?;
        let dir = qoder_oauth::qoder_user_data_dir_for_variant(&params)?;
        if let Some(previous) = qoder_account::read_official_login_candidate(kind, &dir)? {
            let lock = qoder_oauth::account_refresh_lock(&previous.refresh_lock_key())?;
            let _previous_guard = lock.lock().await;
            qoder_account::save_closed_app_session(kind)?;
        }
        account_guard = Some(qoder_oauth::prepare_account_for_launch(kind, &account_id).await?);
    }
    let _account_guard = account_guard;
    qoder_account::inject_to_qoder_for_variant(variant, &account_id)?;
    // The disk session has changed even if the following launch fails.
    crate::modules::provider_current_state::set_current_account_id(variant, Some(&account_id))?;
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
pub fn get_qoder_accounts_index_path() -> Result<String, String> {
    qoder_account::accounts_index_path_string()
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
    let mut result = result?;
    // 领取中的用量查询会使网页配额缓存失效；与普通刷新一样，
    // 用已验证的网页会话同步礼包明细后再返回账号。
    if let Some(account) = result.account.take() {
        result.account = Some(try_refresh_qoder_web_quota(account).await);
    }
    Ok(Some(result.for_ipc()))
}

#[tauri::command]
pub fn get_qoder_auto_checkin_settings() -> Result<crate::modules::qoder_auto_checkin::QoderAutoCheckinSettings, String> {
    crate::modules::qoder_auto_checkin::get_settings()
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

#[tauri::command]
pub async fn open_qoder_webview(
    app: AppHandle,
    account_id: String,
) -> Result<crate::modules::qoder_webview::QoderWebviewSessionInfo, String> {
    crate::modules::qoder_webview::open_qoder_webview(app, account_id).await
}

#[tauri::command]
pub async fn close_qoder_webview(
    app: AppHandle,
    account_id: String,
) -> Result<(), String> {
    crate::modules::qoder_webview::close_qoder_webview(app, account_id).await
}

#[tauri::command]
pub fn list_qoder_webview_sessions(
    app: AppHandle,
) -> Result<Vec<crate::modules::qoder_webview::QoderWebviewSessionInfo>, String> {
    crate::modules::qoder_webview::list_qoder_webview_sessions(app)
}

#[tauri::command]
pub async fn sync_qoder_web_quota_from_webview(
    window: tauri::WebviewWindow,
) -> Result<(), String> {
    crate::modules::qoder_webview::sync_qoder_web_quota(window).await?;
    // 远程页面不接收本地账号记录；本地页面通过事件重新读取。
    Ok(())
}

#[tauri::command]
pub async fn bind_qoder_web_cookie(
    app: AppHandle,
    account_id: String,
    cookie: String,
) -> Result<QoderAccount, String> {
    let clean_cookie = cookie.trim().to_string();
    if clean_cookie.is_empty() {
        return Err("Cookie 不能为空".to_string());
    }
    let updated = crate::modules::qoder_webview::refresh_web_quota(&account_id, Some(clean_cookie)).await?;
    let _ = crate::modules::tray::update_tray_menu(&app);
    let _ = app.emit("qoder-accounts-updated", ());
    Ok(updated.for_ipc())
}

#[cfg(test)]
mod tests {
    use super::*;

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
