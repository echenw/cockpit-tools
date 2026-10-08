use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

use crate::modules::logger;
use crate::modules::qoder_account;
use crate::modules::qoder_variant::QoderVariantKind;

const QODER_INTL_WEB_URL: &str = "https://qoder.com/account/usage";
const QODER_CN_WEB_URL: &str = "https://qoder.cn/account/usage";
const SYNC_QUOTA_COMMAND: &str = "sync_qoder_web_quota_from_webview";

fn is_qoder_webview_label(label: &str) -> bool {
    label.starts_with("qoder-webview-")
}

fn webview_command_allowed(label: &str, command: &str) -> bool {
    !is_qoder_webview_label(label) || command == SYNC_QUOTA_COMMAND
}

/// Tauri 2.10 的自定义命令默认不受远程 capability 限制，在正式分发前收紧 Qoder 网页权限。
pub(crate) fn guard_commands<R: tauri::Runtime>(
    handler: impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static,
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    move |invoke| {
        if !webview_command_allowed(invoke.message.webview_ref().label(), invoke.message.command()) {
            invoke.resolver.reject("Qoder 网页无权调用此应用命令");
            return true;
        }
        handler(invoke)
    }
}

fn web_origin(account: &crate::models::qoder::QoderAccount) -> Result<&'static str, String> {
    Ok(if qoder_account::account_variant_kind(account)?.is_cn() {
        "https://qoder.cn"
    } else {
        "https://qoder.com"
    })
}

fn quota_payload(body: Value) -> Result<Value, String> {
    let payload = body
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(&body);
    let has_quota = [
        payload.get("account_quota"),
        payload.get("plan_quota")
            .and_then(|quota| quota.get("quota_summary")),
        payload.get("resource_package_quota"),
        payload.get("resource_package_quota")
            .and_then(|quota| quota.get("quota_summary")),
        payload.get("total_quota")
            .and_then(|quota| quota.get("quota_summary")),
    ]
    .into_iter()
    .flatten()
    .any(|quota| {
        ["limit_value", "used_value"].into_iter().all(|key| {
            quota.get(key).is_some_and(|value| {
                value.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0)
            })
        })
    });
    if !has_quota {
        return Err("Qoder 网页响应缺少有效配额，拒绝覆盖缓存".to_string());
    }
    Ok(payload.clone())
}

fn verify_web_identity(
    account: &crate::models::qoder::QoderAccount,
    body: &Value,
) -> Result<(), String> {
    let profile = body
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(body);
    let web_id = profile
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let saved_id = account.user_id.as_deref().filter(|id| !id.is_empty());
    if saved_id.is_none() || web_id != saved_id {
        return Err("网页登录账号与所选 Qoder 账号不一致，拒绝同步配额".to_string());
    }
    Ok(())
}

/// 只向账号所属官网发送 Cookie，并用同一份 Cookie 校验身份和查询配额。
async fn fetch_verified_web_quota(
    account: &crate::models::qoder::QoderAccount,
    cookie: &str,
) -> Result<Value, String> {
    if cookie.trim().is_empty() {
        return Err("Qoder 网页尚未登录".to_string());
    }
    let origin = web_origin(account)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "创建 Qoder 网页请求客户端失败".to_string())?;
    let profile = fetch_web_json(&client, origin, "/api/v1/me", cookie).await?;
    verify_web_identity(account, &profile)?;
    // A valid website session is useful even if the quota request fails. Persist
    // it only after identity verification; never tie cookie capture to quota success.
    qoder_account::update_verified_web_session(&account.id, cookie.to_string())?;
    let quota = fetch_web_json(&client, origin, "/api/v2/me/usages/big_model_credits", cookie).await?;
    quota_payload(quota)
}

pub(crate) async fn refresh_web_quota(
    account_id: &str,
    new_cookie: Option<String>,
) -> Result<crate::models::qoder::QoderAccount, String> {
    let lock = crate::modules::qoder_oauth::account_refresh_lock(account_id)?;
    let _guard = lock.lock().await;
    let account = qoder_account::load_account(account_id)
        .ok_or_else(|| "Qoder 账号不存在".to_string())?;
    let cookie = new_cookie
        .or_else(|| account.web_session_cookie.clone())
        .ok_or_else(|| "Qoder 网页尚未登录".to_string())?;
    let payload = fetch_verified_web_quota(&account, &cookie).await?;
    qoder_account::update_account_web_quota(account_id, payload, Some(cookie))
}

/// Chrome owns browser credentials; Cockpit imports only a same-site session
/// whose /me ID matches the already imported account. Native auth remains untouched.
pub(crate) async fn capture_chrome_session(account_id: &str) -> Result<crate::models::qoder::QoderAccount, String> {
    let lock = crate::modules::qoder_oauth::account_refresh_lock(account_id)?;
    let account = qoder_account::load_account(account_id).ok_or("Qoder 账号不存在")?;
    let origin = web_origin(&account)?;
    let is_cn = qoder_account::account_variant_kind(&account)?.is_cn();
    let candidates = tauri::async_runtime::spawn_blocking(move || {
        crate::modules::qoder_browser_cookie::candidates(is_cn)
    }).await.map_err(|_| "读取 Chrome Qoder 会话任务失败".to_string())??;
    if candidates.is_empty() { return Err("Chrome 中未找到 Qoder 官网 Cookie，请在 Chrome 完成该账号的网页登录".to_string()); }
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none()).build().map_err(|_| "创建 Qoder 网页客户端失败")?;
    // Bound multi-profile identity checks. Quota is queried only for a matching ID.
    let matching = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for cookie in candidates {
            let Ok(profile) = fetch_web_json(&client, origin, "/api/v1/me", &cookie).await else { continue; };
            if verify_web_identity(&account, &profile).is_ok() { return Some(cookie); }
        }
        None
    }).await.map_err(|_| "核对 Chrome Qoder 会话超时")?
        .ok_or("Chrome 当前网页登录账号与此 Qoder 账号不一致，未绑定 Cookie")?;
    // Keychain prompts and unrelated Chrome profiles must not block account
    // switching. Acquire the account lock only for the identity-checked commit.
    let _guard = lock.lock().await;
    let current = qoder_account::load_account(account_id).ok_or("Qoder 账号不存在")?;
    if current.user_id != account.user_id || web_origin(&current)? != origin {
        return Err("Qoder 账号身份已变化，未绑定旧网页登录会话".to_string());
    }
    qoder_account::update_verified_web_session(account_id, matching)
}

fn report_web_sync_failure(app: &AppHandle, account_id: &str, error: &str) {
    let Some(account) = qoder_account::load_account(account_id) else { return; };
    let Ok(kind) = qoder_account::account_variant_kind(&account) else { return; };
    let _ = app.emit("qoder-web-sync-failed", serde_json::json!({
        "platformId": kind.provider_key(),
        "error": error,
        "requiresChromePermission": cfg!(target_os = "macos")
            && error == crate::modules::qoder_browser_cookie::CHROME_PERMISSION_DENIED_ERROR,
    }));
}

/// Login success must not wait for a browser keychain prompt or weak quota API.
/// Completion emits no secrets and reloads the authoritative account list.
pub(crate) fn sync_after_login(app: AppHandle, account_id: String) {
    tauri::async_runtime::spawn(async move {
        let variant = qoder_account::load_account(&account_id)
            .and_then(|account| qoder_account::account_variant_kind(&account).ok())
            .map(|kind| kind.provider_key());
        // Capture first, before the user starts another login in the same Chrome
        // profile. A later native usage update invalidates web quota, so re-pull it.
        if let Err(error) = capture_chrome_session(&account_id).await {
            logger::log_warn(&format!("[Qoder WebView] 登录后 Cookie/明细同步未完成: {error}"));
            if qoder_account::load_account(&account_id)
                .is_some_and(|account| account.web_session_cookie.as_deref().is_none_or(|cookie| cookie.trim().is_empty())) {
                report_web_sync_failure(&app, &account_id, &error);
            }
        }
        // Native login initially imports auth only. Query usage without rotating RT.
        if let Err(error) = crate::modules::qoder_oauth::refresh_account_usage_only(&account_id).await {
            logger::log_warn(&format!("[Qoder WebView] 登录后用量同步失败: {error}"));
        }
        let has_cookie = qoder_account::load_account(&account_id)
            .is_some_and(|account| account.web_session_cookie.is_some());
        if has_cookie {
            if let Err(error) = refresh_web_quota(&account_id, None).await {
                logger::log_warn(&format!("[Qoder WebView] 登录后网页明细刷新未完成: {error}"));
                report_web_sync_failure(&app, &account_id, &error);
            }
        }
        let _ = app.emit("qoder-accounts-updated", ());
        if let Some(variant) = variant {
            let _ = app.emit("accounts:changed", serde_json::json!({"platformId": variant, "reason": "web-quota"}));
        }
        let _ = crate::modules::tray::update_tray_menu(&app);
    });
}

async fn fetch_web_json(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    cookie: &str,
) -> Result<Value, String> {
    let response = client
        .get(format!("{origin}{path}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .header("X-Requested-With", "XMLHttpRequest")
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .map_err(|_| "Qoder 网页请求失败".to_string())?;
    if !response.status().is_success() {
        return Err(format!("Qoder 网页请求失败: status={}", response.status()));
    }
    response
        .json()
        .await
        .map_err(|_| "Qoder 网页响应不是有效 JSON".to_string())
}

pub struct QoderWebviewSession {
    pub id: String,
    pub account_id: String,
    pub email: String,
    pub webview_label: String,
    pub console_url: String,
    pub started_at: i64,
}

static SESSIONS: Mutex<Option<HashMap<String, QoderWebviewSession>>> = Mutex::new(None);

fn sessions() -> std::sync::MutexGuard<'static, Option<HashMap<String, QoderWebviewSession>>> {
    let mut g = SESSIONS.lock().unwrap();
    if g.is_none() {
        *g = Some(HashMap::new());
    }
    g
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QoderWebviewSessionInfo {
    pub id: String,
    pub account_id: String,
    pub email: String,
    pub webview_label: String,
    pub console_url: String,
    pub started_at: i64,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn session_to_info(s: &QoderWebviewSession) -> QoderWebviewSessionInfo {
    QoderWebviewSessionInfo {
        id: s.id.clone(),
        account_id: s.account_id.clone(),
        email: s.email.clone(),
        webview_label: s.webview_label.clone(),
        console_url: s.console_url.clone(),
        started_at: s.started_at,
    }
}

pub fn resolve_qoder_web_url_for_account(account: &crate::models::qoder::QoderAccount) -> &'static str {
    match qoder_account::account_variant_kind(account) {
        Ok(QoderVariantKind::QoderCnIde) | Ok(QoderVariantKind::QoderCnApp) => QODER_CN_WEB_URL,
        _ => QODER_INTL_WEB_URL,
    }
}

async fn seed_verified_webview(window: WebviewWindow, account: &crate::models::qoder::QoderAccount) -> Result<(), String> {
    let cookie_header = account.web_session_cookie.clone();
    let cookie_domain = if qoder_account::account_variant_kind(account)?.is_cn() { "qoder.cn" } else { "qoder.com" };
    let target_url = resolve_qoder_web_url_for_account(account).parse().map_err(|_| "Qoder 网页地址无效")?;
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        if let Some(cookie_header) = cookie_header {
            for pair in cookie_header.split(';') {
                let Some((name, value)) = pair.trim().split_once('=') else { continue; };
                if !crate::modules::qoder_browser_cookie::valid_pair(name, value) { continue; }
                let cookie = tauri::webview::Cookie::build((name.to_string(), value.to_string()))
                    .domain(cookie_domain).path("/").secure(true).http_only(true).build();
                window.set_cookie(cookie).map_err(|_| "设置 Qoder 网页 Cookie 失败")?;
            }
        }
        window.navigate(target_url).map_err(|_| "打开 Qoder 网页失败".to_string())
    }).await.map_err(|_| "初始化 Qoder 网页会话任务失败".to_string())?
}

pub async fn open_qoder_webview(
    app: AppHandle,
    account_id: String,
) -> Result<QoderWebviewSessionInfo, String> {
    let mut account = qoder_account::load_account(&account_id)
        .ok_or_else(|| format!("Qoder 账号不存在：{}", account_id))?;

    let email = account.email.clone();
    let webview_label = format!("qoder-webview-{:x}", Sha256::digest(account_id.as_bytes()));

    // 同一账号只允许一个活跃会话
    let existing_info = {
        let s = sessions();
        s.as_ref().and_then(|map| map.get(&account_id))
            .filter(|existing| app.get_webview_window(&existing.webview_label).is_some())
            .map(session_to_info)
    };

    // This explicit browser action can recover a Chrome session for an account
    // imported before cookie capture existed. Background timers do not scan Chrome.
    if account.web_session_cookie.as_deref().is_none_or(|cookie| cookie.trim().is_empty()) {
        if let Err(error) = capture_chrome_session(&account_id).await {
            logger::log_warn(&format!("[Qoder WebView] Chrome 会话未绑定，将打开网页登录: {error}"));
            report_web_sync_failure(&app, &account_id, &error);
        }
        account = qoder_account::load_account(&account_id).ok_or("Qoder 账号不存在")?;
    }
    if let Some(info) = existing_info {
        if let Some(window) = app.get_webview_window(&info.webview_label) {
            seed_verified_webview(window.clone(), &account).await?;
            window.set_focus().map_err(|_| "激活 Qoder 网页窗口失败")?;
            return Ok(info);
        }
    }

    // Windows/Linux 使用独立目录；WKWebView 在下方单独选择网站数据存储。
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("获取应用数据目录失败：{}", e))?
        .join("webviews")
        .join("qoder")
        .join(&account_id);
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("创建 Qoder webview 数据目录失败：{}", e))?;

    let url = resolve_qoder_web_url_for_account(&account).to_string();
    let console_url = url.clone();
    let webview_label_for_window = webview_label.clone();
    let email_for_window = email.clone();
    let data_dir_for_window = data_dir;
    let account_id_key = account_id.clone();
    let origin_json = serde_json::to_string(web_origin(&account)?).map_err(|e| e.to_string())?;

    // 注入自动拦截配额脚本
    let init_script = format!(
        r#"(function() {{
            try {{
                const targetOrigin = {origin_json};
                if (location.origin !== targetOrigin) return;
                const origFetch = window.fetch;
                if (origFetch) {{
                    window.fetch = async function(...args) {{
                        const resp = await origFetch.apply(this, args);
                        try {{
                            const url = (args[0] && typeof args[0] === 'string') ? args[0] : (args[0] && args[0].url ? args[0].url : '');
                            const parsed = new URL(url, location.href);
                            if (resp.ok && parsed.origin === targetOrigin && parsed.pathname === '/api/v2/me/usages/big_model_credits' && window.__TAURI_INTERNALS__) {{
                                // 页面只能请求同步；后端自行读取 Cookie、核对身份并查询额度。
                                window.__TAURI_INTERNALS__.invoke('sync_qoder_web_quota_from_webview').catch(function() {{}});
                            }}
                        }} catch(e) {{}}
                        return resp;
                    }};
                }}
            }} catch(e) {{}}
        }})();"#,
        origin_json = origin_json,
    );

    let app_for_thread = app.clone();
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<tauri::WebviewWindow, tauri::Error>>();
    app.run_on_main_thread(move || {
        let builder = WebviewWindowBuilder::new(
            &app_for_thread,
            &webview_label_for_window,
            // Seed the verified account's session before the first website request.
            WebviewUrl::External("about:blank".parse().unwrap()),
        )
        .title(format!("Qoder 控制台 - {}", email_for_window))
        .data_directory(data_dir_for_window)
        .inner_size(1280.0, 800.0)
        .min_inner_size(800.0, 600.0)
        .center()
        .focused(true)
        .on_navigation(|url| url.scheme() == "https" || url.as_str() == "about:blank")
        .on_page_load(|window, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished
                && payload.url().path() == "/account/usage"
            {
                // 登录回到用量页时同步一次，不依赖官网采用 fetch 还是 XMLHttpRequest。
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = sync_qoder_web_quota(window).await {
                        logger::log_warn(&format!("[Qoder WebView] 页面加载后同步未成功: {err}"));
                    }
                });
            }
        })
        .initialization_script(&init_script);

        #[cfg(target_os = "macos")]
        let builder = {
            let os_version = objc2_foundation::NSProcessInfo::processInfo().operatingSystemVersion();
            if os_version.majorVersion >= 14 {
                let hash = Sha256::digest(
                    format!("cockpit-qoder-webview:{webview_label_for_window}").as_bytes(),
                );
                let mut identifier = [0u8; 16];
                identifier.copy_from_slice(&hash[..16]);
                builder.data_store_identifier(identifier)
            } else {
                // macOS 12/13 不支持持久化独立存储，每窗口使用独立临时会话。
                builder.incognito(true)
            }
        };

        let _ = tx.send(builder.build());
    })
    .map_err(|e| format!("调度主线程创建 Qoder WebView 窗口失败：{}", e))?;

    let window = rx
        .await
        .map_err(|_| "创建 Qoder WebView 窗口任务已取消".to_string())?
        .map_err(|e| format!("创建 Qoder 网页窗口失败：{}", e))?;

    let session = QoderWebviewSession {
        id: account_id_key.clone(),
        account_id: account_id_key.clone(),
        email,
        webview_label: webview_label.clone(),
        console_url: console_url.clone(),
        started_at: now_ms(),
    };

    {
        let mut s = sessions();
        if let Some(map) = s.as_mut() {
            map.insert(account_id_key.clone(), session);
        }
    }

    let setup = seed_verified_webview(window, &account).await;
    if let Err(error) = setup {
        let _ = close_qoder_webview(app.clone(), account_id_key.clone()).await;
        return Err(error);
    }

    logger::log_info(&format!(
        "[Qoder WebView] 已打开账号 {} 的网页会话（独立网站存储）",
        account_id_key
    ));

    let info = {
        let s = sessions();
        s.as_ref()
            .and_then(|m| m.get(&account_id_key))
            .map(session_to_info)
            .unwrap()
    };
    Ok(info)
}

pub async fn close_qoder_webview(app: AppHandle, account_id: String) -> Result<(), String> {
    let label = {
        let s = sessions();
        s.as_ref()
            .and_then(|m| m.get(&account_id))
            .map(|sess| sess.webview_label.clone())
    };

    if let Some(label) = label {
        let app_for_window = app.clone();
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), tauri::Error>>();
        app.run_on_main_thread(move || {
            let result = if let Some(window) = app_for_window.get_webview_window(&label) {
                window.close()
            } else {
                Ok(())
            };
            let _ = tx.send(result);
        })
        .map_err(|e| format!("调度主线程关闭 Qoder WebView 窗口失败：{}", e))?;

        rx.await
            .map_err(|_| "关闭 Qoder WebView 窗口任务已取消".to_string())?
            .map_err(|e| format!("关闭 Qoder 网页窗口失败：{}", e))?;

        let mut s = sessions();
        if let Some(map) = s.as_mut() {
            map.remove(&account_id);
        }
        logger::log_info(&format!(
            "[Qoder WebView] 已关闭账号 {} 的网页会话",
            account_id
        ));
    }
    Ok(())
}

pub fn list_qoder_webview_sessions(app: AppHandle) -> Result<Vec<QoderWebviewSessionInfo>, String> {
    let mut s = sessions();
    let map = match s.as_mut() {
        Some(m) => m,
        None => return Ok(Vec::new()),
    };

    let mut to_remove = Vec::new();
    for (account_id, sess) in map.iter() {
        if app.get_webview_window(&sess.webview_label).is_none() {
            to_remove.push(account_id.clone());
        }
    }
    for id in to_remove {
        map.remove(&id);
    }

    let infos: Vec<QoderWebviewSessionInfo> = map.values().map(session_to_info).collect();
    Ok(infos)
}

pub async fn sync_qoder_web_quota(
    window: WebviewWindow,
) -> Result<crate::models::qoder::QoderAccount, String> {
    let app = window.app_handle().clone();
    let account_id = {
        let s = sessions();
        s.as_ref()
            .and_then(|map| map.values().find(|session| session.webview_label == window.label()))
            .map(|session| session.account_id.clone())
            .ok_or_else(|| "Qoder 网页会话不存在，拒绝同步".to_string())?
    };
    let account = qoder_account::load_account(&account_id)
        .ok_or_else(|| "Qoder 账号不存在".to_string())?;
    let origin = web_origin(&account)?;
    let page_url = window.url().map_err(|e| e.to_string())?;
    if page_url.origin().ascii_serialization() != origin {
        return Err("当前网页不是该账号所属的 Qoder 官网，拒绝同步".to_string());
    }
    let cookie_url = format!("{origin}/api/v2/me/usages/big_model_credits")
        .parse()
        .map_err(|_| "Qoder 配额地址无效".to_string())?;
    // WebView2 的 Cookie 读取必须在异步命令的独立线程执行，避免阻塞 UI。
    let cookie = tauri::async_runtime::spawn_blocking(move || {
        window.cookies_for_url(cookie_url).map(|cookies| {
            cookies
                .into_iter()
                .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
                .collect::<Vec<_>>()
                .join("; ")
        })
    })
    .await
    .map_err(|_| "读取 Qoder 网页会话任务失败".to_string())?
    .map_err(|_| "读取 Qoder 网页会话失败".to_string())?;
    let updated = refresh_web_quota(&account_id, Some(cookie)).await?;
    logger::log_info(&format!(
        "[Qoder WebView] 同步账号 {} 网页端配额数据",
        account_id
    ));
    let _ = crate::modules::tray::update_tray_menu(&app);
    let _ = app.emit("qoder-accounts-updated", ());
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> crate::models::qoder::QoderAccount {
        serde_json::from_value(serde_json::json!({
            "id": "qoder_app_uid_fixture", "variant": "qoder_app",
            "email": "user@example.invalid", "user_id": "fixture-user",
            "created_at": 1, "last_used": 1
        })).unwrap()
    }

    #[test]
    fn remote_qoder_pages_can_only_request_quota_sync() {
        assert!(webview_command_allowed("qoder-webview-fixture", SYNC_QUOTA_COMMAND));
        for command in ["export_qoder_accounts", "delete_qoder_account", "bind_qoder_web_cookie", "list_accounts"] {
            assert!(!webview_command_allowed("qoder-webview-fixture", command));
        }
        assert!(webview_command_allowed("main", "export_qoder_accounts"));
    }

    #[test]
    fn website_login_must_match_the_saved_user_id() {
        let account = account();
        assert!(verify_web_identity(&account, &serde_json::json!({"id": "fixture-user"})).is_ok());
        assert!(verify_web_identity(&account, &serde_json::json!({"data": {"id": "another-user"}})).is_err());
        assert!(verify_web_identity(&account, &serde_json::json!({"email": account.email})).is_err());
        let mut missing_id = account;
        missing_id.user_id = None;
        assert!(verify_web_identity(&missing_id, &serde_json::json!({"id": "fixture-user"})).is_err());
    }

    #[test]
    fn invalid_web_responses_cannot_replace_quota_cache() {
        assert!(quota_payload(serde_json::json!({"error": "session expired"})).is_err());
        assert!(quota_payload(serde_json::json!({"account_quota": {"limit_value": 300}})).is_err());
        assert!(quota_payload(serde_json::json!({"data": {
            "account_quota": {"limit_value": 300, "used_value": 10}
        }})).is_ok());
    }
}
