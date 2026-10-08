use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use url::Url;
use uuid::Uuid;

use crate::models::qoder::{QoderAccount, QoderClaimRewardResult, QoderOAuthStartResponse};
use crate::modules::qoder_variant::QoderVariantKind;
use crate::modules::{config, logger, qoder_account, qoder_instance, qoder_platform_paths};

const OAUTH_TIMEOUT_SECONDS: i64 = 600;
const OAUTH_POLL_INTERVAL_MS: u64 = 1000;

// device/job 刷新共享账号锁，从读取凭证到落库串行执行；不同账号仍可并行。
// Weak 仅保留正在执行或排队的锁，避免长期积累已删除账号。
static ACCOUNT_REFRESH_LOCKS: std::sync::LazyLock<
    Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>,
> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// 用量与凭证刷新共享账号锁，避免较早的网页查询覆盖后续刷新结果。
pub(crate) fn account_refresh_lock(account_id: &str) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
    let canonical_key = qoder_account::load_account(account_id).and_then(|account| {
        let kind = qoder_account::account_variant_kind(&account).ok()?;
        account.user_id.map(|uid| format!("qoder-account:{}:{}", kind.site().as_str(), uid))
    }).unwrap_or_else(|| account_id.to_string());
    let mut locks = ACCOUNT_REFRESH_LOCKS
        .lock()
        .map_err(|_| "获取 Qoder 刷新锁失败".to_string())?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(&canonical_key).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(canonical_key, Arc::downgrade(&lock));
    Ok(lock)
}

/// 默认客户端会话按变体串行；先取会话锁，再取账号锁。
/// 切号、默认实例启动和后台写回必须共用此锁。
pub(crate) fn client_session_lock(
    kind: QoderVariantKind,
) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
    account_refresh_lock(&format!("client-session:{}", kind.provider_key()))
}

const DEFAULT_LOGIN_BASE_URL: &str = "https://qoder.com/device/selectAccounts";
const DEFAULT_OPENAPI_BASE_URL: &str = "https://openapi.qoder.sh";
const QODER_IDE_REDIRECT_URI: &str = "qoder://aicoding.aicoding-agent/login-success";
const QODER_DEVICE_LOGIN_CHALLENGE_METHOD: &str = "S256";
const DEVICE_TOKEN_POLL_PATH: &str = "/api/v1/deviceToken/poll";
const USER_INFO_PATH: &str = "/api/v1/userinfo";
const USER_STATUS_PATH: &str = "/api/v3/user/status";
const DATA_POLICY_PATH: &str = "/api/v2/config/getDataPolicy";
const USER_PLAN_PATH: &str = "/api/v2/user/plan";
const CREDIT_USAGE_PATH: &str = "/api/v2/quota/usage";
// Sash 配额主链路：GET {openapi}/sash/api/v2/me/usage
// （`Bearer <dt>` + `cosy-clienttype: 10` + `UA: Qoder`，intl/CN 同形）。
const QODER_SASH_USAGE_PATH: &str = "/sash/api/v2/me/usage";
const AUTH_STATUS_AUTHORIZED: i64 = 2;
const AUTH_STATUS_IP_BANNED_ERROR: i64 = 6;
const AUTH_STATUS_APP_DISABLED_ERROR: i64 = 7;
const AUTH_STATUS_LOGIN_EXPIRED: i64 = 3;
const WHITELIST_NOT_WHITELIST: i64 = 1;
const WHITELIST_WAIT_PASS: i64 = 2;
const WHITELIST_PASS: i64 = 3;
const WHITELIST_NO_LICENCE: i64 = 5;
const WHITELIST_ORG_EXPIRED: i64 = 6;
const WHITELIST_NOT_ALLOW: i64 = 7;

pub const QODER_VARIANT_QODER: &str = "qoder";
pub const QODER_VARIANT_QODER_APP: &str = "qoder_app";
pub const QODER_VARIANT_QODER_CN_IDE: &str = "qoder_cn_ide";
pub const QODER_VARIANT_QODER_CN_APP: &str = "qoder_cn_app";

const QODER_CN_LOGIN_BASE_URL: &str = "https://qoder.cn/device/selectAccounts";
const QODER_CN_OPENAPI_BASE_URL: &str = "https://openapi.qoder.com.cn";
const QODER_APP_SIGN_IN_PATH: &str = "/users/sign-in";
const QODER_APP_SHARED_CLIENT_ID: &str = "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa";
const QODER_APP_USAGE_USER_AGENT: &str = "Qoder";
// App-line token endpoints (device → job two-level credentials).
// Same contract on both channels: intl `openapi.qoder.sh`, CN `openapi.qoder.com.cn`.
// `/api/v3/user/refresh*` is absent from all four current bundles: never reference it here.
const QODER_APP_JOB_TOKEN_PATH: &str = "/api/v1/me/jobToken";
const QODER_APP_DEVICE_REFRESH_PATH: &str = "/api/v1/deviceToken/refresh";
const QODER_APP_JOB_REFRESH_PATH: &str = "/api/v1/jobToken/refresh";
// Intl App (`qoder_app`) identity provider note: the browser authorize step on
// `qoder.com/users/sign-in` uses Google as IdP. Cockpit only opens
// `verification_uri` for the user to click through in their own browser;
// IdP credentials must never be automated, logged, or persisted.
const QODER_CN_IDE_CHANNEL: &str = "DedicatedQoderCn";
// CN IDE 工作台字面量透传（含义未全抠，仅透传、不断言、不分支）。
const QODER_CN_IDE_PROTOCOL_MARKER: &str = "qodercn_2_0";
const QODER_CN_APP_CHANNEL: &str = "qoder-cn";
const QODER_CN_APP_SIGN_IN_BIZ_VARIANT: &str = "qoder";
// 四个变体的 Keychain 服务名（与各客户端落盘命名一致）。
const QODER_IDE_KEYCHAIN_SERVICE: &str = "Qoder Safe Storage";
const QODER_APP_KEYCHAIN_SERVICE: &str = "Qoder App Safe Storage";
const QODER_CN_IDE_KEYCHAIN_SERVICE: &str = "Qoder CN Safe Storage";
const QODER_CN_APP_KEYCHAIN_SERVICE: &str = "Qoder CN App Safe Storage";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoderVariantLoginMode {
    IdeDirect,
    AppSignIn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QoderVariantParams {
    pub kind: QoderVariantKind,
    pub variant_key: &'static str,
    pub display_name: &'static str,
    pub site: &'static str,
    pub login_mode: QoderVariantLoginMode,
    pub login_base_url: &'static str,
    pub openapi_base_url: &'static str,
    pub client_id: Option<&'static str>,
    pub sign_in_biz_variant: Option<&'static str>,
    pub vendor_channel: Option<&'static str>,
    pub protocol_marker: Option<&'static str>,
    pub keychain_service: Option<&'static str>,
    pub is_app_line: bool,
    pub usage_user_agent: Option<&'static str>,
}

pub fn resolve_qoder_variant_params(variant_key: &str) -> Result<QoderVariantParams, String> {
    let kind = QoderVariantKind::parse(Some(variant_key))?;
    Ok(match kind {
        QoderVariantKind::Qoder => QoderVariantParams {
            kind,
            variant_key: QODER_VARIANT_QODER,
            display_name: kind.display_name(),
            site: kind.site().as_str(),
            login_mode: QoderVariantLoginMode::IdeDirect,
            login_base_url: DEFAULT_LOGIN_BASE_URL,
            openapi_base_url: DEFAULT_OPENAPI_BASE_URL,
            client_id: None,
            sign_in_biz_variant: None,
            vendor_channel: None,
            protocol_marker: None,
            keychain_service: Some(QODER_IDE_KEYCHAIN_SERVICE),
            is_app_line: kind.is_app(),
            usage_user_agent: None,
        },
        QoderVariantKind::QoderApp => QoderVariantParams {
            kind,
            variant_key: QODER_VARIANT_QODER_APP,
            display_name: kind.display_name(),
            site: kind.site().as_str(),
            login_mode: QoderVariantLoginMode::AppSignIn,
            login_base_url: DEFAULT_LOGIN_BASE_URL,
            openapi_base_url: DEFAULT_OPENAPI_BASE_URL,
            client_id: Some(QODER_APP_SHARED_CLIENT_ID),
            sign_in_biz_variant: None,
            vendor_channel: None,
            protocol_marker: None,
            keychain_service: Some(QODER_APP_KEYCHAIN_SERVICE),
            is_app_line: kind.is_app(),
            usage_user_agent: Some(QODER_APP_USAGE_USER_AGENT),
        },
        QoderVariantKind::QoderCnIde => QoderVariantParams {
            kind,
            variant_key: QODER_VARIANT_QODER_CN_IDE,
            display_name: kind.display_name(),
            site: kind.site().as_str(),
            login_mode: QoderVariantLoginMode::IdeDirect,
            login_base_url: QODER_CN_LOGIN_BASE_URL,
            openapi_base_url: QODER_CN_OPENAPI_BASE_URL,
            client_id: None,
            sign_in_biz_variant: None,
            vendor_channel: Some(QODER_CN_IDE_CHANNEL),
            protocol_marker: Some(QODER_CN_IDE_PROTOCOL_MARKER),
            keychain_service: Some(QODER_CN_IDE_KEYCHAIN_SERVICE),
            is_app_line: kind.is_app(),
            usage_user_agent: None,
        },
        QoderVariantKind::QoderCnApp => QoderVariantParams {
            kind,
            variant_key: QODER_VARIANT_QODER_CN_APP,
            display_name: kind.display_name(),
            site: kind.site().as_str(),
            login_mode: QoderVariantLoginMode::AppSignIn,
            login_base_url: QODER_CN_LOGIN_BASE_URL,
            openapi_base_url: QODER_CN_OPENAPI_BASE_URL,
            client_id: Some(QODER_APP_SHARED_CLIENT_ID),
            sign_in_biz_variant: Some(QODER_CN_APP_SIGN_IN_BIZ_VARIANT),
            vendor_channel: Some(QODER_CN_APP_CHANNEL),
            protocol_marker: None,
            keychain_service: Some(QODER_CN_APP_KEYCHAIN_SERVICE),
            is_app_line: kind.is_app(),
            usage_user_agent: Some(QODER_APP_USAGE_USER_AGENT),
        },
    })
}

fn qoder_auth_site_base(login_base_url: &str) -> Result<String, String> {
    let url =
        Url::parse(login_base_url).map_err(|err| format!("解析 Qoder 登录地址失败: {}", err))?;
    let host = url
        .host_str()
        .ok_or_else(|| "Qoder 登录地址缺少 host".to_string())?;
    Ok(format!("{}://{}", url.scheme(), host))
}

pub fn qoder_user_data_dir_for_variant(
    params: &QoderVariantParams,
) -> Result<PathBuf, String> {
    if params.variant_key == QODER_VARIANT_QODER {
        return qoder_instance::get_default_qoder_user_data_dir();
    }
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or("无法获取用户主目录")?;
        let leaf: &str = match params.kind {
            QoderVariantKind::QoderApp => "com.qoder.app.stable",
            QoderVariantKind::QoderCnIde => "QoderCN",
            QoderVariantKind::QoderCnApp => "com.qodercn.app.stable",
            QoderVariantKind::Qoder => {
                return qoder_instance::get_default_qoder_user_data_dir();
            }
        };
        return Ok(home.join("Library/Application Support").join(leaf));
    }
    #[cfg(target_os = "windows")]
    {
        return qoder_platform_paths::windows_data_dir(params.kind);
    }
    #[cfg(target_os = "linux")]
    {
        return qoder_platform_paths::linux_data_dir(params.kind);
    }
    #[allow(unreachable_code)]
    Err(format!(
        "Qoder 变体 {} 在当前平台缺少可用的路径配置，请在设置中手动指定",
        params.variant_key
    ))
}

#[derive(Debug, Clone)]
struct PendingOAuthState {
    variant_key: String,
    login_id: String,
    expected_nonce: String,
    code_verifier: String,
    challenge_method: String,
    openapi_base_url: String,
    machine_info: Option<QoderMachineInfo>,
    verification_uri: String,
    expires_at: i64,
    cancelled: bool,
}

#[derive(Debug, Clone)]
struct QoderMachineInfo {
    token: String,
    machine_type: Option<String>,
    machine_code: Option<String>,
    machine_id: Option<String>,
    machine_hostname: Option<String>,
    machine_os: Option<String>,
    cosy_version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QoderMachineTokenCache {
    #[serde(default)]
    token: Option<String>,
    #[serde(default, rename = "type")]
    machine_type: Option<String>,
    #[serde(default, rename = "code")]
    machine_code: Option<String>,
    #[serde(default, rename = "id")]
    machine_id: Option<String>,
    #[serde(default, rename = "hostname")]
    machine_hostname: Option<String>,
    #[serde(default, rename = "os")]
    machine_os: Option<String>,
    #[serde(default, rename = "version")]
    cosy_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QoderDeviceTokenPollResult {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    refresh_token_id: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    refresh_token_expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QoderPollClass {
    Waiting,
    Authorized,
    NeedsRelogin,
    Retryable,
}

fn classify_poll_http_status(status: u16) -> QoderPollClass {
    match status {
        200..=299 => QoderPollClass::Authorized,
        404 => QoderPollClass::Waiting,
        401 | 403 => QoderPollClass::NeedsRelogin,
        _ => QoderPollClass::Retryable,
    }
}

#[derive(Debug)]
enum QoderPollOutcome {
    Waiting,
    Authorized(QoderDeviceTokenPollResult),
    NeedsRelogin(u16),
}

#[derive(Debug, Clone)]
struct QoderJobTokenBundle {
    token: String,
    refresh_token: Option<String>,
    expires_in_ms: Option<String>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct QoderRefreshedDeviceToken {
    token: String,
    refresh_token: Option<String>,
    expires_at: Option<String>,
    refresh_token_expires_at: Option<String>,
    raw: Value,
}

#[derive(Debug, Clone)]
struct QoderRefreshedJobToken {
    token: String,
    refresh_token: Option<String>,
    raw: Value,
}

fn parse_job_token_body(body: &Value) -> Result<QoderJobTokenBundle, String> {
    let token = body
        .get("token")
        .and_then(value_to_string)
        .ok_or_else(|| "Qoder jobToken 响应缺少 token，无法完成 App 登录".to_string())?;
    Ok(QoderJobTokenBundle {
        token,
        refresh_token: body.get("refresh_token").and_then(value_to_string),
        expires_in_ms: body.get("expires_in").and_then(value_to_string),
        raw: body.clone(),
    })
}

fn parse_device_refresh_body(body: &Value) -> Result<QoderRefreshedDeviceToken, String> {
    let token = ["device_token", "token", "access_token"]
        .iter()
        .filter_map(|key| body.get(*key).and_then(value_to_string))
        .next()
        .ok_or_else(|| "Qoder deviceToken/refresh 响应缺少 device_token".to_string())?;
    Ok(QoderRefreshedDeviceToken {
        token,
        refresh_token: body.get("refresh_token").and_then(value_to_string),
        expires_at: body.get("expires_at").and_then(value_to_string),
        refresh_token_expires_at: body
            .get("refresh_token_expires_at")
            .and_then(value_to_string),
        raw: body.clone(),
    })
}

fn parse_job_refresh_body(body: &Value) -> Result<QoderRefreshedJobToken, String> {
    let token = ["token", "device_token", "job_token", "access_token"]
        .iter()
        .filter_map(|key| body.get(*key).and_then(value_to_string))
        .next()
        .ok_or_else(|| "Qoder jobToken/refresh 响应缺少 token".to_string())?;
    Ok(QoderRefreshedJobToken {
        token,
        refresh_token: body.get("refresh_token").and_then(value_to_string),
        raw: body.clone(),
    })
}

fn is_refresh_token_invalid_status(status: u16) -> bool {
    matches!(status, 400 | 401)
}

fn qoder_error_requires_relogin(err: &str) -> bool {
    err.contains("refresh token 已失效")
}

fn validate_cn_app_device_quad(quad: &QoderDeviceTokenPollResult) -> Result<(), String> {
    let token = quad
        .token
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)))
        .ok_or_else(|| "Qoder CN App device 四件套缺少 token".to_string())?;
    if !token.starts_with("dt-") {
        return Err("Qoder CN App device token 前缀非 dt-".to_string());
    }
    let refresh = quad
        .refresh_token
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)))
        .ok_or_else(|| "Qoder CN App device 四件套缺少 refresh_token".to_string())?;
    if !refresh.starts_with("drt-") {
        return Err("Qoder CN App device refresh_token 前缀非 drt-".to_string());
    }
    match quad.code_challenge_method.as_deref() {
        Some(method) if method == QODER_DEVICE_LOGIN_CHALLENGE_METHOD => Ok(()),
        _ => Err("Qoder CN App device 四件套 PKCE 方法非 S256".to_string()),
    }
}

fn cn_app_quad_validity_days(quad: &QoderDeviceTokenPollResult) -> Option<f64> {
    let created = quad.created_at.as_deref()?;
    let expires = quad.expires_at.as_deref()?;
    let start = chrono::DateTime::parse_from_rfc3339(created).ok()?;
    let end = chrono::DateTime::parse_from_rfc3339(expires).ok()?;
    Some((end - start).num_milliseconds() as f64 / 86_400_000.0)
}

fn validate_cn_app_job_token_body(body: &Value) -> Result<(), String> {
    let token = body
        .get("token")
        .and_then(value_to_string)
        .ok_or_else(|| "Qoder CN App jobToken 缺少 token".to_string())?;
    if !token.starts_with("jt-") {
        return Err("Qoder CN App jobToken 前缀非 jt-".to_string());
    }
    if let Some(refresh) = body.get("refresh_token").and_then(value_to_string) {
        if !refresh.starts_with("jrt-") {
            return Err("Qoder CN App job refresh_token 前缀非 jrt-".to_string());
        }
    }
    match body.get("expires_in").and_then(value_to_string) {
        Some(value) if value == "86400000" => Ok(()),
        other => Err(format!(
            "Qoder CN App jobToken expires_in 非 24h(86400000): {:?}",
            other
        )),
    }
}

fn build_app_login_user_info_raw(
    device: &QoderDeviceTokenPollResult,
    job: Option<&QoderJobTokenBundle>,
    user_info_response: Option<&Value>,
) -> Value {
    let mut user_info = build_initial_user_info_raw(device, user_info_response);
    if let (Some(map), Some(bundle)) = (user_info.as_object_mut(), job) {
        map.insert(
            "job_token".to_string(),
            Value::String(bundle.token.clone()),
        );
        if let Some(refresh_token) = bundle.refresh_token.as_deref() {
            map.insert(
                "job_refresh_token".to_string(),
                Value::String(refresh_token.to_string()),
            );
        }
        if let Some(expires_in) = bundle.expires_in_ms.as_deref() {
            map.insert(
                "job_token_expires_in".to_string(),
                Value::String(expires_in.to_string()),
            );
        }
    }
    user_info
}

lazy_static::lazy_static! {
    static ref PENDING_OAUTH_STATES: Arc<Mutex<HashMap<String, PendingOAuthState>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

fn insert_pending_state(state: PendingOAuthState) {
    if let Ok(mut guard) = PENDING_OAUTH_STATES.lock() {
        guard.insert(state.variant_key.clone(), state);
    }
}

fn take_pending_state_snapshot(login_id: &str) -> Result<PendingOAuthState, String> {
    let guard = PENDING_OAUTH_STATES
        .lock()
        .map_err(|_| "获取 Qoder OAuth 状态锁失败".to_string())?;
    guard
        .values()
        .find(|state| state.login_id == login_id)
        .cloned()
        .ok_or_else(|| {
            if guard.is_empty() {
                "没有进行中的 Qoder OAuth 登录会话".to_string()
            } else {
                "Qoder OAuth 登录会话已变更，请重新发起".to_string()
            }
        })
}

/// Final validation and persistence share the cancellation boundary. No await is
/// allowed in the commit: cancellation either wins first or observes a completed save.
fn commit_active_login<T>(
    login_id: &str,
    expected_variant_key: &str,
    commit: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let mut states = PENDING_OAUTH_STATES
        .lock()
        .map_err(|_| "获取 Qoder OAuth 状态锁失败".to_string())?;
    let state = states
        .get(expected_variant_key)
        .filter(|state| state.login_id == login_id)
        .ok_or_else(|| "Qoder OAuth 登录已取消或会话已变更".to_string())?;
    if state.cancelled || now_timestamp() > state.expires_at {
        return Err("Qoder OAuth 登录已取消或超时".into());
    }
    let account = commit()?;
    states.remove(expected_variant_key);
    Ok(account)
}

fn peek_pending_state_for_variant(variant_key: &str) -> Option<PendingOAuthState> {
    let guard = PENDING_OAUTH_STATES.lock().ok()?;
    let state = guard.get(variant_key)?;
    if state.cancelled || now_timestamp() > state.expires_at {
        return None;
    }
    Some(state.clone())
}

fn pending_state_to_response(state: &PendingOAuthState, now: i64) -> QoderOAuthStartResponse {
    QoderOAuthStartResponse {
        login_id: state.login_id.clone(),
        verification_uri: state.verification_uri.clone(),
        expires_in: (state.expires_at - now).max(0) as u64,
        interval_seconds: (OAUTH_POLL_INTERVAL_MS / 1000).max(1),
        callback_url: None,
    }
}

fn now_timestamp() -> i64 {
    chrono::Utc::now().timestamp()
}

fn normalize_non_empty(value: Option<&str>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_app_pkce_verifier() -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();
    (0..64)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % UNRESERVED.len();
            UNRESERVED[idx] as char
        })
        .collect()
}

fn generate_verifier_for_variant(params: &QoderVariantParams) -> String {
    if params.is_app_line {
        generate_app_pkce_verifier()
    } else {
        generate_pkce_verifier()
    }
}

fn generate_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn generate_login_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

fn normalize_url_origin_and_path(raw: &str) -> Option<String> {
    let url = Url::parse(raw).ok()?;
    let host = url.host_str()?;
    let mut normalized = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        normalized.push(':');
        normalized.push_str(&port.to_string());
    }
    normalized.push_str(url.path());
    Some(normalized)
}

fn resolve_qoder_cli_login_endpoint() -> String {
    normalize_url_origin_and_path(DEFAULT_LOGIN_BASE_URL)
        .unwrap_or_else(|| DEFAULT_LOGIN_BASE_URL.to_string())
}

fn build_cli_device_login_url(
    login_base_url: &str,
    nonce: &str,
    challenge: &str,
    challenge_method: &str,
    machine_id: Option<&str>,
) -> Result<String, String> {
    let mut url =
        Url::parse(login_base_url).map_err(|err| format!("解析 Qoder 登录地址失败: {}", err))?;
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("nonce", nonce);
        query_pairs.append_pair("challenge", challenge);
        query_pairs.append_pair("challenge_method", challenge_method);
        query_pairs.append_pair("redirect_uri", QODER_IDE_REDIRECT_URI);
        if let Some(machine_id) = machine_id.and_then(|value| normalize_non_empty(Some(value))) {
            query_pairs.append_pair("machine_id", &machine_id);
        }
    }
    Ok(url.to_string())
}

fn build_ide_device_login_url_for_variant(
    params: &QoderVariantParams,
    nonce: &str,
    challenge: &str,
    challenge_method: &str,
    machine_id: Option<&str>,
) -> Result<String, String> {
    let mut url =
        Url::parse(params.login_base_url).map_err(|err| format!("解析 Qoder 登录地址失败: {}", err))?;
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("nonce", nonce);
        query_pairs.append_pair("challenge", challenge);
        query_pairs.append_pair("challenge_method", challenge_method);
        query_pairs.append_pair("redirect_uri", QODER_IDE_REDIRECT_URI);
        if let Some(client_id) = params.client_id {
            query_pairs.append_pair("client_id", client_id);
        } else if params.variant_key == QODER_VARIANT_QODER_CN_IDE {
            logger::log_warn(
                "[Qoder OAuth] Qoder CN IDE 缺少 client_id 配置，将降级为无 client_id 直连（待运行时捕获回填）",
            );
        }
        if let Some(machine_id) = machine_id.and_then(|value| normalize_non_empty(Some(value))) {
            query_pairs.append_pair("machine_id", &machine_id);
        }
        if params.variant_key == QODER_VARIANT_QODER_CN_IDE {
            query_pairs.append_pair("sourceType", "IDE");
        }
    }
    Ok(url.to_string())
}

fn build_app_inner_select_accounts_url(
    params: &QoderVariantParams,
    nonce: &str,
    challenge: &str,
    challenge_method: &str,
    machine_id: Option<&str>,
) -> Result<String, String> {
    let client_id = params
        .client_id
        .ok_or_else(|| format!("Qoder 变体 {} 缺少 client_id，无法构造 App 登录链接", params.variant_key))?;
    let mut url =
        Url::parse(params.login_base_url).map_err(|err| format!("解析 Qoder 登录地址失败: {}", err))?;
    {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs.append_pair("nonce", nonce);
        query_pairs.append_pair("challenge", challenge);
        query_pairs.append_pair("challenge_method", challenge_method);
        query_pairs.append_pair("client_id", client_id);
        if let Some(machine_id) = machine_id.and_then(|value| normalize_non_empty(Some(value))) {
            query_pairs.append_pair("machine_id", &machine_id);
        }
    }
    Ok(url.to_string())
}

fn build_app_sign_in_login_url(
    params: &QoderVariantParams,
    nonce: &str,
    challenge: &str,
    challenge_method: &str,
    machine_id: Option<&str>,
) -> Result<String, String> {
    let site_base = qoder_auth_site_base(params.login_base_url)?;
    let inner = build_app_inner_select_accounts_url(
        params,
        nonce,
        challenge,
        challenge_method,
        machine_id,
    )?;
    let mut url = Url::parse(&format!("{}{}", site_base, QODER_APP_SIGN_IN_PATH))
        .map_err(|err| format!("解析 Qoder 登录地址失败: {}", err))?;
    {
        let mut query_pairs = url.query_pairs_mut();
        if let Some(biz_variant) = params.sign_in_biz_variant {
            query_pairs.append_pair("biz_variant", biz_variant);
        }
        query_pairs.append_pair("oauth_callback", &inner);
    }
    Ok(url.to_string())
}

fn generate_variant_login_nonce(params: &QoderVariantParams) -> String {
    if params.is_app_line {
        Uuid::new_v4().to_string()
    } else {
        generate_login_nonce()
    }
}

fn parse_expire_timestamp_ms(raw: Option<&str>) -> Option<String> {
    let text = normalize_non_empty(raw)?;
    if let Ok(number) = text.parse::<i64>() {
        let millis = if number > 1_000_000_000_000 {
            number
        } else {
            number.saturating_mul(1000)
        };
        return Some(millis.to_string());
    }

    chrono::DateTime::parse_from_rfc3339(&text)
        .ok()
        .map(|value| value.timestamp_millis().to_string())
}

fn insert_string_field(map: &mut serde_json::Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(text) = value {
        map.insert(key.to_string(), Value::String(text));
    }
}

fn insert_i64_field(map: &mut serde_json::Map<String, Value>, key: &str, value: i64) {
    map.insert(
        key.to_string(),
        Value::Number(serde_json::Number::from(value)),
    );
}

fn copy_optional_field(
    from: &Value,
    to: &mut serde_json::Map<String, Value>,
    source_key: &str,
    target_key: &str,
) {
    if let Some(value) = from.get(source_key) {
        to.insert(target_key.to_string(), value.clone());
    }
}

fn calculate_auth_status(user_status: &Value) -> (i64, i64) {
    let has_user_id = user_status
        .get("id")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
        .is_some();
    if !has_user_id {
        return (AUTH_STATUS_LOGIN_EXPIRED, WHITELIST_NOT_WHITELIST);
    }

    match user_status
        .get("whitelistStatus")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
        .as_deref()
    {
        Some("NoIpPermission") => (AUTH_STATUS_IP_BANNED_ERROR, WHITELIST_NOT_WHITELIST),
        Some("AppDisable") => (AUTH_STATUS_APP_DISABLED_ERROR, WHITELIST_NOT_WHITELIST),
        Some("LoginExpire") => (AUTH_STATUS_LOGIN_EXPIRED, WHITELIST_NOT_WHITELIST),
        Some("PASS") => (AUTH_STATUS_AUTHORIZED, WHITELIST_PASS),
        Some("WAIT") => (AUTH_STATUS_AUTHORIZED, WHITELIST_WAIT_PASS),
        Some("NoLicense") => (AUTH_STATUS_AUTHORIZED, WHITELIST_NO_LICENCE),
        Some("NoQuota") | Some("EXPIRED") => (AUTH_STATUS_AUTHORIZED, WHITELIST_ORG_EXPIRED),
        Some("NotAllow") | Some("NOT_ALLOW") => (AUTH_STATUS_AUTHORIZED, WHITELIST_NOT_ALLOW),
        _ => (AUTH_STATUS_AUTHORIZED, WHITELIST_NOT_WHITELIST),
    }
}

fn ensure_user_status_allowed(user_status: &Value) -> Result<(), String> {
    let whitelist_status = user_status
        .get("whitelistStatus")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)));
    let has_user_id = user_status
        .get("id")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
        .is_some();

    if !has_user_id {
        return Err("Qoder 用户状态缺少 id，无法确认登录身份".to_string());
    }

    match whitelist_status.as_deref() {
        Some("NoIpPermission") => Err("企业设置了 IP 白名单，当前 IP 无法登录".to_string()),
        Some("AppDisable") => Err("Qoder 应用已被停用，无法登录".to_string()),
        Some("LoginExpire") => Err("Qoder 登录已失效，请重试".to_string()),
        Some("NotAllow") | Some("NOT_ALLOW") => Err("当前账号暂无 Qoder 使用权限".to_string()),
        _ => Ok(()),
    }
}

fn build_cosy_machine_os() -> String {
    let arch = match std::env::consts::ARCH {
        "arm64" => "aarch64",
        value => value,
    };
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        value => value,
    };
    format!("{}_{}", arch, os)
}

fn build_qoder_product_file_candidates(base_path: &Path) -> Vec<PathBuf> {
    let mut app_roots: Vec<PathBuf> = Vec::new();
    for ancestor in base_path.ancestors() {
        let Some(name) = ancestor.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.eq_ignore_ascii_case("Qoder.app") || name.eq_ignore_ascii_case("Qoder IDE.app") {
            app_roots.push(ancestor.to_path_buf());
            break;
        }
    }

    if base_path
        .file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("Qoder.app"))
        .unwrap_or(false)
    {
        app_roots.push(base_path.to_path_buf());
    }

    if app_roots.is_empty() {
        app_roots.push(base_path.to_path_buf());
    }

    let mut candidates = Vec::new();
    for root in app_roots {
        candidates.push(
            root.join("Contents")
                .join("Resources")
                .join("app")
                .join("product.json"),
        );
        candidates.push(
            root.join("Contents")
                .join("Resources")
                .join("app")
                .join("package.json"),
        );
        candidates.push(root.join("resources").join("app").join("product.json"));
        candidates.push(root.join("resources").join("app").join("package.json"));
        candidates.push(root.join("product.json"));
        candidates.push(root.join("package.json"));
    }
    candidates
}

fn read_version_from_json_file(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let parsed = serde_json::from_str::<Value>(&content).ok()?;
    parsed
        .get("productVersion")
        .and_then(|value| value.as_str())
        .or_else(|| parsed.get("version").and_then(|value| value.as_str()))
        .and_then(|value| normalize_non_empty(Some(value)))
}

/// 变体产品版本探测的基路径选择。每个变体只读取自己的显式路径，
/// 避免不同 Qoder 产品之间共享路径或版本信息。
fn build_variant_product_base_paths(kind: QoderVariantKind, configured_path: &str) -> Vec<PathBuf> {
    let mut base_paths: Vec<PathBuf> = Vec::new();
    let configured = configured_path.trim();
    if !configured.is_empty() {
        base_paths.push(PathBuf::from(configured));
    }

    #[cfg(target_os = "macos")]
    {
        base_paths.extend(qoder_platform_paths::macos_exec_candidates(kind));
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(candidates) = qoder_platform_paths::windows_install_candidates(kind) {
            base_paths.extend(candidates);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(candidates) = qoder_platform_paths::linux_install_candidates(kind) {
            base_paths.extend(candidates);
        }
    }

    base_paths
}

/// 按变体探测客户端版本，复用统一的平台路径表。
pub fn detect_qoder_product_version_for_variant(kind: QoderVariantKind) -> Option<String> {
    let user_config = config::get_user_config();
    let configured_path = match kind {
        QoderVariantKind::Qoder => user_config.qoder_app_path,
        QoderVariantKind::QoderApp => user_config.qoder_app_variant_path,
        QoderVariantKind::QoderCnIde => user_config.qoder_cn_ide_app_path,
        QoderVariantKind::QoderCnApp => user_config.qoder_cn_app_path,
    };
    for base_path in build_variant_product_base_paths(kind, &configured_path) {
        for candidate in build_qoder_product_file_candidates(&base_path) {
            if let Some(version) = read_version_from_json_file(&candidate) {
                return Some(version);
            }
        }
    }

    None
}

fn build_qoder_headers(
    kind: QoderVariantKind,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};

    let mut headers = HeaderMap::new();
    let bearer = format!("Bearer {}", token);
    if let Ok(value) = HeaderValue::from_str(&bearer) {
        headers.insert(AUTHORIZATION, value);
    }
    if let Ok(value) = HeaderValue::from_str("application/json") {
        headers.insert(ACCEPT, value);
    }
    let cosy_version = machine_info
        .and_then(|value| value.cosy_version.clone())
        .or_else(|| detect_qoder_product_version_for_variant(kind));
    if let Some(version) = cosy_version.as_deref() {
        if let Ok(value) = HeaderValue::from_str(&version) {
            headers.insert("Cosy-Version", value);
        }
    }
    if let Some(machine_token) = machine_info
        .map(|value| value.token.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
    {
        if let Ok(value) = HeaderValue::from_str(&machine_token) {
            headers.insert("Cosy-MachineToken", value);
        }
    }
    if let Some(machine_type) = machine_info
        .and_then(|value| value.machine_type.as_deref())
        .and_then(|value| normalize_non_empty(Some(value)))
    {
        if let Ok(value) = HeaderValue::from_str(&machine_type) {
            headers.insert("Cosy-MachineType", value);
        }
    }
    let machine_os = machine_info
        .and_then(|value| value.machine_os.as_deref())
        .and_then(|value| normalize_non_empty(Some(value)))
        .unwrap_or_else(build_cosy_machine_os);
    if let Ok(value) = HeaderValue::from_str(&machine_os) {
        headers.insert("Cosy-MachineOS", value);
    }
    for (header, value) in [
        (
            "Cosy-MachineCode",
            machine_info.and_then(|v| v.machine_code.as_deref()),
        ),
        (
            "Cosy-MachineId",
            machine_info.and_then(|v| v.machine_id.as_deref()),
        ),
        (
            "Cosy-MachineHostname",
            machine_info.and_then(|v| v.machine_hostname.as_deref()),
        ),
    ] {
        if let Some(value) = value.and_then(|value| normalize_non_empty(Some(value))) {
            if let Ok(header_value) = HeaderValue::from_str(&value) {
                headers.insert(header, header_value);
            }
        }
    }
    if let Ok(value) = HeaderValue::from_str("0") {
        headers.insert("Cosy-ClientType", value);
    }
    logger::log_info(&format!(
        "[Qoder OAuth] 构造请求头: has_cosy_version={}, has_machine_token={}, has_machine_type={}, machine_os={}",
        cosy_version.is_some(),
        machine_info.is_some_and(|value| !value.token.is_empty()),
        machine_info.and_then(|value| value.machine_type.as_ref()).is_some(),
        machine_os
    ));
    headers
}

fn build_qoder_app_usage_headers(token: &str) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};

    let mut headers = HeaderMap::new();
    let bearer = format!("Bearer {}", token);
    if let Ok(value) = HeaderValue::from_str(&bearer) {
        headers.insert(AUTHORIZATION, value);
    }
    if let Ok(value) = HeaderValue::from_str("application/json") {
        headers.insert(ACCEPT, value);
    }
    if let Ok(value) = HeaderValue::from_str("10") {
        headers.insert("cosy-clienttype", value);
    }
    if let Ok(value) = HeaderValue::from_str(QODER_APP_USAGE_USER_AGENT) {
        headers.insert(USER_AGENT, value);
    }
    headers
}

fn build_qoder_headers_for_variant(
    params: &QoderVariantParams,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> reqwest::header::HeaderMap {
    if params.is_app_line {
        build_qoder_app_usage_headers(token)
    } else {
        build_qoder_headers(params.kind, token, machine_info)
    }
}

fn build_initial_user_info_raw(
    token_data: &QoderDeviceTokenPollResult,
    user_info_response: Option<&Value>,
) -> Value {
    let mut user_info = serde_json::Map::new();
    insert_string_field(
        &mut user_info,
        "id",
        normalize_non_empty(token_data.user_id.as_deref()).or_else(|| {
            user_info_response
                .and_then(|value| value.get("id"))
                .and_then(|value| value.as_str())
                .and_then(|value| normalize_non_empty(Some(value)))
        }),
    );
    insert_string_field(
        &mut user_info,
        "token",
        normalize_non_empty(token_data.token.as_deref()),
    );
    insert_string_field(
        &mut user_info,
        "refreshToken",
        normalize_non_empty(token_data.refresh_token.as_deref()),
    );
    insert_string_field(
        &mut user_info,
        "expireTime",
        parse_expire_timestamp_ms(token_data.expires_at.as_deref()),
    );
    insert_string_field(
        &mut user_info,
        "refreshTokenExpireTime",
        parse_expire_timestamp_ms(token_data.refresh_token_expires_at.as_deref()),
    );
    if let Some(value) = user_info_response {
        copy_optional_field(value, &mut user_info, "name", "name");
        copy_optional_field(value, &mut user_info, "email", "email");
        copy_optional_field(value, &mut user_info, "avatarUrl", "avatarUrl");
        copy_optional_field(value, &mut user_info, "avatar_url", "avatarUrl");
        copy_optional_field(value, &mut user_info, "security_mobile", "security_mobile");
    }
    Value::Object(user_info)
}

fn merge_user_status_into_user_info(
    user_info: &mut Value,
    user_status: &Value,
    data_policy: Option<&Value>,
) {
    let Some(map) = user_info.as_object_mut() else {
        return;
    };

    copy_optional_field(user_status, map, "id", "id");
    copy_optional_field(user_status, map, "name", "name");
    copy_optional_field(user_status, map, "email", "email");
    copy_optional_field(user_status, map, "avatarUrl", "avatarUrl");
    copy_optional_field(user_status, map, "userType", "userType");
    copy_optional_field(user_status, map, "userTag", "userTag");
    copy_optional_field(user_status, map, "isSubAccount", "isSubAccount");
    copy_optional_field(user_status, map, "quota", "quota");
    copy_optional_field(user_status, map, "isQuotaExceeded", "isQuotaExceeded");
    copy_optional_field(user_status, map, "orgId", "orgId");
    copy_optional_field(user_status, map, "orgName", "orgName");
    copy_optional_field(user_status, map, "yxUid", "yxUid");
    copy_optional_field(user_status, map, "staffId", "staffId");
    copy_optional_field(user_status, map, "cloudType", "cloudType");
    copy_optional_field(
        user_status,
        map,
        "isPrivacyPolicyModifiable",
        "isPrivacyPolicyModifiable",
    );
    copy_optional_field(
        user_status,
        map,
        "isPrivacyPolicyVisible",
        "isPrivacyPolicyVisible",
    );

    let (status, whitelist) = calculate_auth_status(user_status);
    insert_i64_field(map, "status", status);
    insert_i64_field(map, "whitelist", whitelist);

    if let Some(policy) = data_policy {
        let agreed = policy
            .get("success")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
            && policy
                .get("result")
                .and_then(|value| value.get("status"))
                .and_then(|value| value.as_str())
                == Some("AGREE");
        map.insert("privacyPolicyAgreed".to_string(), Value::Bool(agreed));
    }
}

fn cn_ide_access_token_is_current(user_info: &Value) -> bool {
    user_info
        .get("token")
        .and_then(Value::as_str)
        .is_some_and(|token| !token.trim().is_empty())
        && user_info
            .get("expireTime")
            .and_then(value_to_string)
            .and_then(|expiry| expiry.parse::<i64>().ok())
            .is_some_and(|expiry| expiry > chrono::Utc::now().timestamp_millis())
}

pub(crate) fn ensure_cn_ide_login_info_ready(user_info: &Value) -> Result<(), String> {
    let has_identity_and_refresh = ["id", "refreshToken"].iter().all(|field| {
        user_info
            .get(*field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    });
    // 与官方 IDE 的 isUserLoggedIn 保持一致，缺失状态不能默认成已授权。
    let authorized =
        user_info.get("status").and_then(Value::as_i64) == Some(AUTH_STATUS_AUTHORIZED);
    let allowed = matches!(
        user_info.get("whitelist").and_then(Value::as_i64),
        Some(WHITELIST_PASS) | Some(WHITELIST_NO_LICENCE) | Some(WHITELIST_ORG_EXPIRED)
    );
    if has_identity_and_refresh && cn_ide_access_token_is_current(user_info) && authorized && allowed {
        Ok(())
    } else {
        Err("Qoder CN IDE 登录资料不完整或未获授权，切换已中止".to_string())
    }
}

fn invalidate_cn_ide_login_status(user_info: &mut Value) {
    if let Some(map) = user_info.as_object_mut() {
        map.remove("status");
        map.remove("whitelist");
    }
}

fn merge_cn_ide_login_status(
    target: &QoderAccount,
    user_info: &mut Value,
    user_status: &Value,
    data_policy: Option<&Value>,
) -> Result<(), String> {
    ensure_user_status_allowed(user_status)?;
    ensure_refresh_identity_consistent(target, user_status)?;
    merge_user_status_into_user_info(user_info, user_status, data_policy);
    ensure_cn_ide_login_info_ready(user_info)
}

fn build_reqwest_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|err| format!("创建 Qoder HTTP 客户端失败: {}", err))
}

fn parse_device_token_poll_response(
    text: &str,
) -> Result<Option<QoderDeviceTokenPollResult>, String> {
    let payload = serde_json::from_str::<QoderDeviceTokenPollResult>(text)
        .map_err(|err| format!("解析 Qoder device token 响应失败: {}", err))?;
    if payload
        .token
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)))
        .is_some()
    {
        return Ok(Some(payload));
    }
    Ok(None)
}

async fn poll_device_token_outcome(
    client: &reqwest::Client,
    openapi_base_url: &str,
    nonce: &str,
    verifier: &str,
    challenge_method: &str,
) -> Result<QoderPollOutcome, String> {
    let response = client
        .get(format!("{}{}", openapi_base_url, DEVICE_TOKEN_POLL_PATH))
        .query(&[
            ("nonce", nonce),
            ("verifier", verifier),
            ("challenge_method", challenge_method),
        ])
        .send()
        .await
        .map_err(|err| format!("轮询 Qoder device token 失败: {}", err))?;

    let status = response.status();
    match classify_poll_http_status(status.as_u16()) {
        QoderPollClass::Waiting => Ok(QoderPollOutcome::Waiting),
        QoderPollClass::NeedsRelogin => Ok(QoderPollOutcome::NeedsRelogin(status.as_u16())),
        QoderPollClass::Authorized => {
            let body = response
                .text()
                .await
                .map_err(|err| format!("解析 Qoder device token 响应失败: {}", err))?;
            match parse_device_token_poll_response(&body)? {
                Some(payload) => Ok(QoderPollOutcome::Authorized(payload)),
                None => Ok(QoderPollOutcome::Waiting),
            }
        }
        QoderPollClass::Retryable => {
            let body = response.text().await.unwrap_or_default();
            Err(format!(
                "轮询 Qoder device token 失败: status={}, body_len={}",
                status,
                body.len()
            ))
        }
    }
}

async fn exchange_app_job_token(
    client: &reqwest::Client,
    openapi_base_url: &str,
    device_token: &str,
    client_id: &str,
) -> Result<QoderJobTokenBundle, String> {
    let response = client
        .post(format!("{}{}", openapi_base_url, QODER_APP_JOB_TOKEN_PATH))
        .bearer_auth(device_token)
        .json(&serde_json::json!({ "clientId": client_id }))
        .send()
        .await
        .map_err(|err| format!("兑换 Qoder jobToken 失败: {}", err))?;

    let status = response.status();
    if !status.is_success() {
        let body_len = response.text().await.unwrap_or_default().len();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(format!(
                "兑换 Qoder jobToken 被拒绝: status={}，device 会话已失效，请重新登录",
                status
            ));
        }
        return Err(format!(
            "兑换 Qoder jobToken 失败: status={}, body_len={}，device 会话已保留",
            status, body_len
        ));
    }

    let body = response
        .json::<Value>()
        .await
        .map_err(|err| format!("解析 Qoder jobToken 响应失败: {}", err))?;
    parse_job_token_body(&body)
}

async fn post_app_refresh_no_auth(
    client: &reqwest::Client,
    url: String,
    path_label: &str,
    refresh_token: &str,
) -> Result<Value, String> {
    let response = client
        .post(url)
        .json(&serde_json::json!({ "refresh_token": refresh_token }))
        .send()
        .await
        .map_err(|err| format!("刷新 Qoder App token 失败 ({}): {}", path_label, err))?;

    let status = response.status();
    if !status.is_success() {
        let body_len = response.text().await.unwrap_or_default().len();
        if is_refresh_token_invalid_status(status.as_u16()) {
            return Err(format!(
                "Qoder App token 刷新被拒绝 ({}: status={})，refresh token 已失效，请重新登录",
                path_label, status
            ));
        }
        return Err(format!(
            "刷新 Qoder App token 失败 ({}): status={}, body_len={}",
            path_label, status, body_len
        ));
    }

    response
        .json::<Value>()
        .await
        .map_err(|err| {
            format!(
                "解析 Qoder App token 刷新响应失败 ({}): {}",
                path_label, err
            )
        })
}

async fn refresh_app_device_token(
    client: &reqwest::Client,
    openapi_base_url: &str,
    refresh_token: &str,
) -> Result<QoderRefreshedDeviceToken, String> {
    let body = post_app_refresh_no_auth(
        client,
        format!("{}{}", openapi_base_url, QODER_APP_DEVICE_REFRESH_PATH),
        QODER_APP_DEVICE_REFRESH_PATH,
        refresh_token,
    )
    .await?;
    parse_device_refresh_body(&body)
}

async fn refresh_app_job_token(
    client: &reqwest::Client,
    openapi_base_url: &str,
    refresh_token: &str,
) -> Result<QoderRefreshedJobToken, String> {
    let body = post_app_refresh_no_auth(
        client,
        format!("{}{}", openapi_base_url, QODER_APP_JOB_REFRESH_PATH),
        QODER_APP_JOB_REFRESH_PATH,
        refresh_token,
    )
    .await?;
    parse_job_refresh_body(&body)
}

fn mask_token_for_log(token: &str) -> String {
    // Char-boundary-safe: byte slicing (`&token[..7]`) panics on non-ASCII.
    const PREFIX_CHARS: usize = 7;
    const SUFFIX_CHARS: usize = 4;
    let char_len = token.chars().count();
    if char_len <= 12 {
        return "***".to_string();
    }
    let prefix: String = token.chars().take(PREFIX_CHARS).collect();
    let suffix: String = token.chars().skip(char_len - SUFFIX_CHARS).collect();
    format!("{prefix}…{suffix} len={char_len}")
}

fn extract_cn_app_stored_refresh_tokens(user_info_raw: &Value) -> (Option<String>, Option<String>) {
    let device = user_info_raw
        .get("refreshToken")
        .and_then(value_to_string)
        .filter(|value| value.starts_with("drt-"));
    let job = user_info_raw
        .get("job_refresh_token")
        .and_then(value_to_string)
        .filter(|value| value.starts_with("jrt-"));
    (device, job)
}

fn apply_refreshed_device_token(
    user_info: &mut Value,
    refreshed: &QoderRefreshedDeviceToken,
) {
    if !user_info.is_object() {
        *user_info = Value::Object(serde_json::Map::new());
    }
    if let Some(map) = user_info.as_object_mut() {
        map.insert(
            "token".to_string(),
            Value::String(refreshed.token.clone()),
        );
        if let Some(refresh) = refreshed.refresh_token.as_deref() {
            map.insert(
                "refreshToken".to_string(),
                Value::String(refresh.to_string()),
            );
        }
        if let Some(expires) = refreshed
            .expires_at
            .as_deref()
            .and_then(|value| parse_expire_timestamp_ms(Some(value)))
        {
            if map.contains_key("schemaVersion") {
                if let Some(iso) = expires.parse::<i64>().ok()
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .map(|time| time.to_rfc3339())
                {
                    map.insert("expiresAt".to_string(), Value::String(iso));
                }
            }
            map.insert("expireTime".to_string(), Value::String(expires));
        }
        if let Some(expires) = refreshed
            .refresh_token_expires_at
            .as_deref()
            .and_then(|value| parse_expire_timestamp_ms(Some(value)))
        {
            if map.contains_key("schemaVersion") {
                if let Some(iso) = expires.parse::<i64>().ok()
                    .and_then(chrono::DateTime::from_timestamp_millis)
                    .map(|time| time.to_rfc3339())
                {
                    map.insert("refreshTokenExpiresAt".to_string(), Value::String(iso));
                }
            }
            map.insert("refreshTokenExpireTime".to_string(), Value::String(expires));
        }
    }
}

fn apply_refreshed_job_token(user_info: &mut Value, refreshed: &QoderRefreshedJobToken) {
    if !user_info.is_object() {
        *user_info = Value::Object(serde_json::Map::new());
    }
    if let Some(map) = user_info.as_object_mut() {
        map.insert(
            "job_token".to_string(),
            Value::String(refreshed.token.clone()),
        );
        if let Some(refresh) = refreshed.refresh_token.as_deref() {
            map.insert(
                "job_refresh_token".to_string(),
                Value::String(refresh.to_string()),
            );
        }
    }
}

// ---- 变体刷新分派（配额走 `fetch_qoder_sash_usage` + `validate_sash_usage_schema`）----

// 配额主链路为 `fetch_qoder_credit_usage`（sash 主 + 旧接口回退，按变体 host）。

fn variant_supports_device_refresh(variant_key: &str) -> bool {
    matches!(
        variant_key,
        QODER_VARIANT_QODER | QODER_VARIANT_QODER_APP | QODER_VARIANT_QODER_CN_IDE | QODER_VARIANT_QODER_CN_APP
    )
}

pub fn variant_supports_job_line(variant_key: &str) -> bool {
    matches!(
        variant_key,
        QODER_VARIANT_QODER_APP | QODER_VARIANT_QODER_CN_APP
    )
}

fn check_variant_refresh_route(variant_key: &str, want_job_line: bool) -> Result<(), String> {
    resolve_qoder_variant_params(variant_key)
        .map_err(|err| format!("未知 Qoder 变体，无法刷新: {err}"))?;
    if want_job_line && !variant_supports_job_line(variant_key) {
        return Err(format!(
            "Qoder 变体 {variant_key} 为 IDE 线（单级 device token），不支持 jobToken 刷新"
        ));
    }
    if !want_job_line && !variant_supports_device_refresh(variant_key) {
        return Err(format!(
            "Qoder 变体 {variant_key} 不支持 deviceToken 刷新"
        ));
    }
    Ok(())
}

fn extract_variant_device_refresh_token(
    user_info_raw: &Value,
    variant_key: &str,
) -> Option<String> {
    if variant_key == QODER_VARIANT_QODER_CN_APP {
        return extract_cn_app_stored_refresh_tokens(user_info_raw).0;
    }
    user_info_raw
        .get("refreshToken")
        .and_then(value_to_string)
}

fn extract_variant_job_refresh_token(
    user_info_raw: &Value,
    variant_key: &str,
) -> Option<String> {
    if variant_key == QODER_VARIANT_QODER_CN_APP {
        return extract_cn_app_stored_refresh_tokens(user_info_raw).1;
    }
    user_info_raw
        .get("job_refresh_token")
        .and_then(value_to_string)
}

async fn refresh_variant_token_for_account(
    variant_key: &str,
    account_id: &str,
    want_job_line: bool,
) -> Result<QoderAccount, String> {
    check_variant_refresh_route(variant_key, want_job_line)?;
    let params = resolve_qoder_variant_params(variant_key)
        .map_err(|err| format!("解析 Qoder 变体参数失败: {}", err))?;
    let saved = qoder_account::load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let target = qoder_account::account_for_variant(&saved, params.kind)?;
    if let Some(session) = qoder_account::app_owned_session(&target)? {
        // job 会话同样由 App 管理；device 分支只查询额度，绝不兑换 refresh token。
        return if want_job_line {
            Ok(target)
        } else {
            refresh_app_owned_usage(&session, &params).await
        };
    }
    let stored = target.auth_user_info_raw.clone().unwrap_or(Value::Null);
    let refresh_token = if want_job_line {
        extract_variant_job_refresh_token(&stored, variant_key)
    } else {
        Some(extract_variant_device_refresh_token(&stored, variant_key)
            .ok_or_else(|| "Qoder 账号缺少共享 device RT，请重新登录".to_string())?)
    };
    logger::log_info(&format!(
        "[Qoder OAuth] 变体 token 刷新开始: variant={}, account_id={}, line={}, refresh={}",
        variant_key,
        account_id,
        if want_job_line { "job" } else { "device" },
        refresh_token.as_deref().map(mask_token_for_log).unwrap_or_else(|| "acquire-job".into()),
    ));
    let client = build_reqwest_client()?;
    let machine_info = match read_qoder_machine_info_cache_for_variant(&params) {
        Ok(value) => value,
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder Refresh] 读取官方 machine token 缓存失败，将继续尝试无机器标识链路: variant={}, error={}",
                variant_key, err
            ));
            None
        }
    };
    let mut user_info = stored;
    if want_job_line {
        if let Some(refresh_token) = refresh_token.as_deref() {
            let refreshed = refresh_app_job_token(&client, params.openapi_base_url, refresh_token).await?;
            apply_refreshed_job_token(&mut user_info, &refreshed);
        } else {
            let token = user_info.get("token").and_then(value_to_string)
                .ok_or("Qoder App 缺少 device AT，无法兑换 jobToken")?;
            let bundle = exchange_app_job_token(&client, params.openapi_base_url, &token,
                params.client_id.ok_or("Qoder App 缺少 client_id")?).await?;
            let refreshed = QoderRefreshedJobToken {
                token: bundle.token, refresh_token: bundle.refresh_token, raw: bundle.raw,
            };
            apply_refreshed_job_token(&mut user_info, &refreshed);
        }
        upsert_account_from_snapshot_for_variant(&params, user_info.clone(), None, None)?;
    } else {
        let refreshed = match refresh_app_device_token(&client, params.openapi_base_url,
            refresh_token.as_deref().ok_or("Qoder 缺少共享 RT")?).await {
            Ok(value) => value,
            Err(err) => {
                if qoder_error_requires_relogin(&err) {
                    let _ = qoder_account::mark_account_needs_relogin(&target.id, err.clone());
                } else {
                    let _ = qoder_account::update_quota_query_error(&target.id, Some(err.clone()));
                }
                return Err(err);
            }
        };
        apply_refreshed_device_token(&mut user_info, &refreshed);
        if !params.kind.is_app() { invalidate_cn_ide_login_status(&mut user_info); }
        // Persist rotated RT before subsequent network queries can fail.
        upsert_account_from_snapshot_for_variant(&params, user_info.clone(), None, None)?;
        if !params.kind.is_app() {
            let (status, policy) = fetch_qoder_user_status_bundle(&client, &params,
                params.openapi_base_url, &refreshed.token, machine_info.as_ref()).await?;
            if params.kind.is_cn() {
                merge_cn_ide_login_status(&target, &mut user_info, &status, policy.as_ref())?;
            } else {
                ensure_refresh_identity_consistent(&target, &status)?;
                merge_user_status_into_user_info(&mut user_info, &status, policy.as_ref());
            }
        }
    }
    let quota_token = user_info.get("token").and_then(value_to_string);
    if let Some(token) = quota_token.as_deref() {
        backfill_security_mobile_if_needed(
            &client,
            &params,
            &target,
            &mut user_info,
            token,
            machine_info.as_ref(),
        )
        .await;
    }
    let user_plan_raw = match quota_token.as_deref() {
        Some(token) => fetch_user_plan_for_refresh(&client, &params, token, machine_info.as_ref()).await,
        None => None,
    };
    let mut quota_error = None;
    let quota_raw = match quota_token {
        Some(token) => {
            match fetch_qoder_credit_usage(
                &client,
                &params,
                params.openapi_base_url,
                &token,
                machine_info.as_ref(),
            )
            .await
            {
                Ok(value) => Some(value),
                Err(err) => {
                    logger::log_warn(&format!(
                        "[Qoder Refresh] 变体用量刷新失败，将沿用本地缓存: variant={}, error={}",
                        variant_key, err
                    ));
                    quota_error = Some(err);
                    None
                }
            }
        }
        None => {
            quota_error = Some("Qoder 账号缺少配额查询 token".to_string());
            None
        },
    };
    let account =
        upsert_account_from_snapshot_for_variant(&params, user_info, user_plan_raw, quota_raw)?;
    if account.id != target.id {
        return Err(format!(
            "刷新结果账号不一致: target_id={}, actual_id={}",
            target.id, account.id
        ));
    }
    let cleared = qoder_account::update_quota_query_error(&account.id, quota_error)?;
    Ok(cleared.unwrap_or(account))
}

// 四个客户端共用 device RT 刷新，App 客户端另有独立 job 凭据。
pub async fn refresh_account_token_for_variant(
    variant_key: &str,
    account_id: &str,
    want_job_line: bool,
) -> Result<QoderAccount, String> {
    let kind = QoderVariantKind::parse(Some(variant_key))?;
    let session_lock = if kind.is_app() {
        Some(client_session_lock(kind)?)
    } else {
        None
    };
    let _session_guard = match session_lock.as_ref() {
        Some(lock) => Some(lock.lock().await),
        None => None,
    };
    let lock = account_refresh_lock(account_id)?;
    let _guard = lock.lock().await;
    refresh_variant_token_for_account(variant_key, account_id, want_job_line).await
}

/// 返回的账号锁须持有至注入/启动结束，避免刷新在切号中途撤掉授权状态。
/// 所有远端资料准备均在关闭当前 IDE 之前完成。
pub(crate) async fn prepare_account_for_launch(
    kind: QoderVariantKind,
    account_id: &str,
) -> Result<tokio::sync::OwnedMutexGuard<()>, String> {
    let guard = account_refresh_lock(account_id)?.lock_owned().await;
    let saved = qoder_account::load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let target = qoder_account::account_for_variant(&saved, kind)?;
    let mut raw = target.auth_user_info_raw.clone().ok_or("Qoder 账号缺少认证资料")?;
    let token_current = client_access_token_is_current(&raw);
    let has_projection = qoder_account::has_client_auth(&saved, kind);
    if !has_projection || !token_current {
        refresh_variant_token_for_account(kind.provider_key(), &target.id, false).await?;
    } else if !kind.is_app() && (kind.is_cn() && ensure_cn_ide_login_info_ready(&raw).is_err()
        || raw.get("status").and_then(Value::as_i64) != Some(AUTH_STATUS_AUTHORIZED)) {
        let params = resolve_qoder_variant_params(kind.provider_key())?;
        let client = build_reqwest_client()?;
        let machine = read_qoder_machine_info_cache_for_variant(&params)?;
        let token = extract_access_token_from_account(&target).ok_or("Qoder IDE 缺少 AT")?;
        let (status, policy) = fetch_qoder_user_status_bundle(&client, &params, params.openapi_base_url,
            &token, machine.as_ref()).await?;
        if kind.is_cn() {
            merge_cn_ide_login_status(&target, &mut raw, &status, policy.as_ref())?;
        } else {
            ensure_refresh_identity_consistent(&target, &status)?;
            merge_user_status_into_user_info(&mut raw, &status, policy.as_ref());
        }
        upsert_account_from_snapshot_for_variant(&params, raw, None, None)?;
    }
    if kind.is_app() {
        let saved = qoder_account::load_account(&target.id).ok_or("Qoder 账号已被删除")?;
        let app = qoder_account::account_for_variant(&saved, kind)?;
        let raw = app.auth_user_info_raw.as_ref().ok_or("Qoder App 缺少认证资料")?;
        // Native App sessions acquire jobs themselves; converted/OAuth sessions need the job line.
        if raw.get("schemaVersion").is_none() && raw.get("job_token").and_then(Value::as_str).is_none() {
            refresh_variant_token_for_account(kind.provider_key(), &target.id, true).await?;
        }
    }
    let saved = qoder_account::load_account(&target.id).ok_or("Qoder 账号已被删除")?;
    let prepared = qoder_account::account_for_variant(&saved, kind)?;
    let raw = prepared.auth_user_info_raw.as_ref().ok_or("Qoder 客户端凭据准备失败")?;
    if kind == QoderVariantKind::QoderCnIde { ensure_cn_ide_login_info_ready(raw)?; }
    if !client_access_token_is_current(raw) { return Err("Qoder 客户端 AT 已过期，切换已中止".into()); }
    Ok(guard)
}

fn client_access_token_is_current(raw: &Value) -> bool {
    raw.get("token").and_then(Value::as_str).is_some_and(|token| !token.trim().is_empty())
        && raw.get("expireTime").or_else(|| raw.get("expiresAt")).and_then(value_to_string)
            .and_then(|value| parse_expire_timestamp_ms(Some(&value)))
            .and_then(|value| value.parse::<i64>().ok())
            .is_some_and(|expiry| expiry > chrono::Utc::now().timestamp_millis())
}

async fn refresh_app_owned_usage(
    session: &QoderAccount,
    params: &QoderVariantParams,
) -> Result<QoderAccount, String> {
    let result = async {
        let token = extract_access_token_from_account(session)
            .ok_or_else(|| "Qoder App 当前会话缺少凭证，请在客户端登录".to_string())?;
        let client = build_reqwest_client()?;
        let machine_info = match read_qoder_machine_info_cache_for_variant(params) {
            Ok(value) => value,
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder Refresh] 读取机器标识失败，继续查询额度: variant={}, error={}",
                    params.variant_key, err
                ));
                None
            }
        };
        let usage = fetch_qoder_credit_usage(
            &client,
            params,
            params.openapi_base_url,
            &token,
            machine_info.as_ref(),
        )
        .await?;
        let user_plan = fetch_user_plan_for_refresh(&client, params, &token, machine_info.as_ref()).await;
        qoder_account::update_account_usage(&session.id, usage, user_plan)
    }
    .await;
    if let Err(err) = &result {
        // 配额请求失败不能替官方客户端判定 refresh token 已失效。
        if let Err(record_err) =
            qoder_account::update_quota_query_error(&session.id, Some(err.clone()))
        {
            logger::log_warn(&format!(
                "[Qoder Refresh] 记录 App 配额查询错误失败，保留原始错误: account_id={}, error={}",
                session.id, record_err
            ));
        }
    }
    result
}

/// Read-only credential use for post-login quota hydration. This never exchanges
/// an RT or injects client credentials; App session ownership and lock order match refresh.
pub(crate) async fn refresh_account_usage_only(account_id: &str) -> Result<QoderAccount, String> {
    let initial = qoder_account::load_account(account_id).ok_or("Qoder 账号不存在")?;
    let kind = qoder_account::account_variant_kind(&initial)?;
    let _app_guard = if kind.is_app() {
        Some(client_session_lock(kind)?.lock_owned().await)
    } else { None };
    let _account_guard = account_refresh_lock(account_id)?.lock_owned().await;
    let saved = qoder_account::load_account(account_id).ok_or("Qoder 账号不存在")?;
    let target = qoder_account::account_for_variant(&saved, kind)?;
    let params = resolve_qoder_variant_params(kind.provider_key())?;
    let session = if kind.is_app() { qoder_account::app_owned_session(&target)?.unwrap_or(target) } else { target };
    refresh_app_owned_usage(&session, &params).await
}

async fn fetch_openapi_json(
    client: &reqwest::Client,
    openapi_base_url: &str,
    path: &str,
    mut headers: reqwest::header::HeaderMap,
    query: &[(&str, String)],
) -> Result<Value, String> {
    use reqwest::header::{HeaderValue, ACCEPT};

    if !headers.contains_key(ACCEPT) {
        if let Ok(value) = HeaderValue::from_str("application/json") {
            headers.insert(ACCEPT, value);
        }
    }
    let request = client
        .get(format!("{}{}", openapi_base_url, path))
        .headers(headers)
        .query(query);
    let response = request
        .send()
        .await
        .map_err(|err| format!("请求 Qoder OpenAPI 失败 ({}): {}", path, err))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "请求 Qoder OpenAPI 失败 ({}): status={}, body_len={}",
            path,
            status,
            body.len()
        ));
    }
    response
        .json::<Value>()
        .await
        .map_err(|err| format!("解析 Qoder OpenAPI 响应失败 ({}): {}", path, err))
}

async fn fetch_qoder_user_info(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Result<Value, String> {
    let headers = build_qoder_headers_for_variant(params, token, machine_info);
    fetch_openapi_json(client, openapi_base_url, USER_INFO_PATH, headers, &[]).await
}

fn user_info_missing_security_mobile(user_info: &Value) -> bool {
    user_info
        .get("security_mobile")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
        .is_none()
}

/// 仅把 `security_mobile` 键并入既有对象，保留其余键逐字节不变；返回是否实际写入。
fn merge_security_mobile(user_info: &mut Value, user_info_response: &Value) -> bool {
    let Some(mobile) = user_info_response
        .get("security_mobile")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)))
    else {
        return false;
    };
    if !user_info.is_object() {
        *user_info = Value::Object(serde_json::Map::new());
    }
    match user_info.as_object_mut() {
        Some(map) => {
            map.insert("security_mobile".to_string(), Value::String(mobile));
            true
        }
        None => false,
    }
}

/// best-effort：CN 账号（哨兵/空 email）缺 security_mobile 时补拉一次 userinfo，
/// 只并入该键；任何失败仅告警，绝不中止刷新、不改 token 语义。成功后键存在 → 幂等跳过。
async fn backfill_security_mobile_if_needed(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    target: &QoderAccount,
    user_info: &mut Value,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) {
    if !qoder_account::account_email_is_sentinel(&target.email)
        || !user_info_missing_security_mobile(user_info)
    {
        return;
    }
    match fetch_qoder_user_info(client, params, params.openapi_base_url, token, machine_info).await {
        Ok(response) => {
            if merge_security_mobile(user_info, &response) {
                logger::log_info(&format!(
                    "[Qoder Refresh] security_mobile 回填成功: variant={}, account_id={}",
                    params.variant_key, target.id
                ));
            }
        }
        Err(err) => logger::log_warn(&format!(
            "[Qoder Refresh] security_mobile 回填失败，忽略并继续: variant={}, account_id={}, error={}",
            params.variant_key, target.id, err
        )),
    }
}

async fn fetch_qoder_user_status_bundle(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Result<(Value, Option<Value>), String> {
    let status_headers = build_qoder_headers_for_variant(params, token, machine_info);
    let status = fetch_openapi_json(
        client,
        openapi_base_url,
        USER_STATUS_PATH,
        status_headers.clone(),
        &[],
    )
    .await?;
    ensure_user_status_allowed(&status)?;

    let data_policy = fetch_openapi_json(
        client,
        openapi_base_url,
        DATA_POLICY_PATH,
        status_headers,
        &[("requestId", Uuid::new_v4().to_string())],
    )
    .await
    .ok();
    Ok((status, data_policy))
}

async fn fetch_qoder_user_plan(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Result<Value, String> {
    let headers = build_qoder_headers_for_variant(params, token, machine_info);
    fetch_openapi_json(client, openapi_base_url, USER_PLAN_PATH, headers, &[]).await
}

fn user_plan_has_tier(value: &Value) -> bool {
    qoder_account::plan_type_from_user_plan(value).is_some()
}

/// 套餐查询只读且为用量刷新弱依赖；失败时采用用量中的明确档位或已有套餐。
async fn fetch_user_plan_for_refresh(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Option<Value> {
    match fetch_qoder_user_plan(
        client,
        params,
        params.openapi_base_url,
        token,
        machine_info,
    )
    .await
    {
        Ok(value) if user_plan_has_tier(&value) => Some(value),
        Ok(_) => {
            logger::log_warn(&format!(
                "[Qoder Refresh] 套餐响应缺少档位，继续采用用量档位或已有套餐: variant={}",
                params.variant_key
            ));
            None
        }
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder Refresh] 套餐查询失败，继续采用用量档位或已有套餐: variant={}, error={}",
                params.variant_key, err
            ));
            None
        }
    }
}

fn sash_usage_numeric_field(node: &Value, bucket: &str, field: &str) -> Result<(), String> {
    let present = node.get(field).and_then(|value| value.as_f64().or_else(|| {
        value.as_str().and_then(|text| text.trim().parse::<f64>().ok())
    })).is_some_and(|number| number.is_finite() && number >= 0.0);
    if present {
        Ok(())
    } else {
        Err(format!(
            "Qoder sash 用量缺少数值字段 qoderUsage.{}.{}，无法采用主路",
            bucket, field
        ))
    }
}

fn validate_sash_usage_schema(body: &Value) -> Result<(), String> {
    let usage = body
        .get("qoderUsage")
        .ok_or_else(|| "Qoder sash 用量缺少 qoderUsage，无法采用主路".to_string())?;
    for bucket in ["userQuota", "addOnQuota"] {
        let node = usage
            .get(bucket)
            .ok_or_else(|| format!("Qoder sash 用量缺少 qoderUsage.{}，无法采用主路", bucket))?;
        for field in ["total", "used"] {
            sash_usage_numeric_field(node, bucket, field)?;
        }
        if node.get("remaining").is_some() { sash_usage_numeric_field(node, bucket, "remaining")?; }
    }
    // App 0.4.3's consumer derives remaining and does not require these legacy
    // summary fields. Rejecting their absence discards dedicatedResourcePackages.
    if usage.get("dedicatedResourcePackages").is_some_and(|packages| !packages.is_array()) {
        return Err("Qoder 积分包明细不是数组".to_string());
    }
    Ok(())
}

async fn fetch_qoder_sash_usage(
    client: &reqwest::Client,
    openapi_base_url: &str,
    token: &str,
) -> Result<Value, String> {
    let headers = build_qoder_app_usage_headers(token);
    let response = client
        .get(format!("{}{}", openapi_base_url, QODER_SASH_USAGE_PATH))
        .headers(headers)
        .send()
        .await
        .map_err(|err| {
            format!(
                "请求 Qoder sash 用量失败 ({}): {}",
                QODER_SASH_USAGE_PATH, err
            )
        })?;
    let status = response.status();
    if !status.is_success() {
        let body_len = response.text().await.unwrap_or_default().len();
        return Err(format!(
            "请求 Qoder sash 用量失败 ({}): status={}, body_len={}",
            QODER_SASH_USAGE_PATH, status, body_len
        ));
    }
    let body = response.json::<Value>().await.map_err(|err| {
        format!(
            "解析 Qoder sash 用量响应失败 ({}): {}",
            QODER_SASH_USAGE_PATH, err
        )
    })?;
    validate_sash_usage_schema(&body)?;
    Ok(body)
}

async fn fetch_qoder_credit_legacy_usage(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Result<Value, String> {
    let headers = build_qoder_headers_for_variant(params, token, machine_info);
    fetch_openapi_json(client, openapi_base_url, CREDIT_USAGE_PATH, headers, &[]).await
}

async fn fetch_qoder_credit_usage(
    client: &reqwest::Client,
    params: &QoderVariantParams,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> Result<Value, String> {
    match fetch_qoder_sash_usage(client, openapi_base_url, token).await {
        Ok(value) => Ok(value),
        Err(sash_err) => {
            logger::log_warn(&format!(
                "[Qoder Refresh] sash 用量主路失败，将回落 legacy {}: {}",
                CREDIT_USAGE_PATH, sash_err
            ));
            fetch_qoder_credit_legacy_usage(client, params, openapi_base_url, token, machine_info)
                .await
        }
    }
}

fn get_string_at_path(root: &Value, path: &[&str]) -> Option<String> {
    let mut current = root;
    for key in path {
        current = current.get(*key)?;
    }
    value_to_string(current)
}

pub(crate) fn extract_access_token_from_account(account: &QoderAccount) -> Option<String> {
    let user_info = account.auth_user_info_raw.as_ref()?;
    let candidate_paths: &[&[&str]] = &[
        &["token"],
        &["securityOauthToken"],
        &["accessToken"],
        &["access_token"],
        &["result", "token"],
        &["data", "token"],
        &["result", "accessToken"],
        &["data", "accessToken"],
    ];
    for path in candidate_paths {
        if let Some(value) = get_string_at_path(user_info, path) {
            return Some(value);
        }
    }
    None
}

fn ensure_refresh_identity_consistent(
    target: &QoderAccount,
    user_status: &Value,
) -> Result<(), String> {
    let target_user_id = target
        .user_id
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let status_user_id = user_status
        .get("id")
        .and_then(|value| value.as_str())
        .and_then(|value| normalize_non_empty(Some(value)));

    if let (Some(target_uid), Some(status_uid)) = (target_user_id.as_ref(), status_user_id.as_ref())
    {
        if !target_uid.eq_ignore_ascii_case(status_uid) {
            return Err(format!(
                "官方接口返回账号与目标账号不一致: target_user_id={}, actual_user_id={}",
                target_uid, status_uid
            ));
        }
    } else {
        let target_email =
            normalize_non_empty(Some(target.email.as_str())).map(|value| value.to_lowercase());
        let status_email = user_status
            .get("email")
            .and_then(|value| value.as_str())
            .and_then(|value| normalize_non_empty(Some(value)))
            .map(|value| value.to_lowercase());
        if let (Some(left), Some(right)) = (target_email.as_ref(), status_email.as_ref()) {
            if left != right {
                return Err(format!(
                    "官方接口返回账号与目标账号不一致: target_email={}, actual_email={}",
                    left, right
                ));
            }
        }
    }

    Ok(())
}

pub async fn refresh_all_accounts_from_openapi() -> Result<i32, String> {
    let accounts = qoder_account::list_accounts();
    if accounts.is_empty() {
        return Ok(0);
    }

    let mut success_count: i32 = 0;
    for account in accounts {
        // Intl App / IDE share the regional account; never send CN credentials to Intl.
        match qoder_account::account_variant_kind(&account) {
            Ok(kind) if !kind.is_cn() => {}
            Ok(kind) => {
                logger::log_info(&format!(
                    "[Qoder Refresh] 批量刷新跳过国内账号: account_id={}, variant={}",
                    account.id,
                    kind.provider_key()
                ));
                continue;
            }
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder Refresh] 批量刷新跳过变体字段无效账号: account_id={}, error={}",
                    account.id, err
                ));
                continue;
            }
        }
        match refresh_account_token_for_variant(QODER_VARIANT_QODER, &account.id, false).await {
            Ok(_) => {
                success_count += 1;
            }
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder Refresh] 批量刷新失败: account_id={}, email={}, error={}",
                    account.id, account.email, err
                ));
            }
        }
    }

    Ok(success_count)
}

fn clear_pending_if_matches(login_id: &str) {
    if let Ok(mut guard) = PENDING_OAUTH_STATES.lock() {
        guard.retain(|_, state| state.login_id != login_id);
    }
}

fn cosy_info_path_for_variant(params: &QoderVariantParams) -> Result<PathBuf, String> {
    let user_data = qoder_user_data_dir_for_variant(params)?;
    Ok(user_data.join("SharedClientCache"))
}

fn read_qoder_machine_info_cache_for_variant(
    params: &QoderVariantParams,
) -> Result<Option<QoderMachineInfo>, String> {
    let cache_dir = cosy_info_path_for_variant(params)?.join("cache");
    read_machine_info_from_cache_dir(&cache_dir)
}

fn read_machine_info_from_cache_dir(cache_dir: &Path) -> Result<Option<QoderMachineInfo>, String> {
    let cache_path = cache_dir.join("machine_token.json");
    if !cache_path.exists() {
        logger::log_warn(&format!(
            "[Qoder OAuth] 未找到官方 machine token 缓存，将跳过机器标识注入: {}",
            cache_path.to_string_lossy()
        ));
        return Ok(None);
    }

    let content = fs::read_to_string(&cache_path)
        .map_err(|err| format!("读取 Qoder machine_token.json 失败: {}", err))?;
    let parsed = serde_json::from_str::<QoderMachineTokenCache>(&content)
        .map_err(|err| format!("解析 Qoder machine_token.json 失败: {}", err))?;

    let token = parsed
        .token
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let machine_type = parsed
        .machine_type
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let machine_code = parsed
        .machine_code
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let machine_id = parsed
        .machine_id
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let machine_hostname = parsed
        .machine_hostname
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let machine_os = parsed
        .machine_os
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));
    let cosy_version = parsed
        .cosy_version
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)));

    logger::log_info(&format!(
        "[Qoder OAuth] 官方 machine token 缓存已加载: path={}, has_token={}, has_machine_type={}",
        cache_path.to_string_lossy(),
        token.is_some(),
        machine_type.is_some()
    ));

    Ok(token.map(|token| QoderMachineInfo {
        token,
        machine_type,
        machine_code,
        machine_id,
        machine_hostname,
        machine_os,
        cosy_version,
    }))
}

fn read_qoder_cached_machine_id_for_variant(
    params: &QoderVariantParams,
) -> Result<Option<String>, String> {
    let cache_dir = cosy_info_path_for_variant(params)?.join("cache");
    read_cached_machine_id_from_cache_dir(&cache_dir)
}

fn read_cached_machine_id_from_cache_dir(cache_dir: &Path) -> Result<Option<String>, String> {
    let cache_path = cache_dir.join("id");
    if !cache_path.exists() {
        logger::log_warn(&format!(
            "[Qoder OAuth] 未找到官方 machine id 缓存，将继续使用无机器标识链路: {}",
            cache_path.to_string_lossy()
        ));
        return Ok(None);
    }

    let raw = fs::read_to_string(&cache_path)
        .map_err(|err| format!("读取 Qoder cache/id 失败: {}", err))?;
    let machine_id = normalize_non_empty(Some(raw.trim()));
    logger::log_info(&format!(
        "[Qoder OAuth] 官方 machine id 缓存已加载: path={}, has_machine_id={}",
        cache_path.to_string_lossy(),
        machine_id.is_some()
    ));
    Ok(machine_id)
}

fn summarize_url_for_log(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(url) => {
            let host = url.host_str().unwrap_or("<unknown>");
            let path = url.path();
            let query_keys = url
                .query_pairs()
                .map(|(key, _)| key.to_string())
                .collect::<Vec<String>>();
            if query_keys.is_empty() {
                format!("{}://{}{} (len={})", url.scheme(), host, path, raw.len())
            } else {
                format!(
                    "{}://{}{}?keys={} (len={})",
                    url.scheme(),
                    host,
                    path,
                    query_keys.join(","),
                    raw.len()
                )
            }
        }
        Err(_) => format!("<invalid-url len={}>", raw.len()),
    }
}

fn get_object_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = object.get(*key) {
            if !value.is_null() {
                return Some(value);
            }
        }
    }
    None
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => normalize_non_empty(Some(text.as_str())),
        Value::Number(number) => {
            let text = number.to_string();
            normalize_non_empty(Some(text.as_str()))
        }
        Value::Bool(flag) => Some(if *flag { "true" } else { "false" }.to_string()),
        _ => None,
    }
}

fn get_string_from_object(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    get_object_field(object, keys).and_then(value_to_string)
}
pub async fn start_login_for_variant(
    variant_key: &str,
) -> Result<QoderOAuthStartResponse, String> {
    let params = resolve_qoder_variant_params(variant_key)?;
    logger::log_info(&format!(
        "[Qoder OAuth] 开始创建登录会话: variant={}",
        params.variant_key
    ));
    let machine_info = match read_qoder_machine_info_cache_for_variant(&params) {
        Ok(value) => value,
        Err(err) => {
            logger::log_warn(&format!(
                "[Qoder OAuth] 读取官方 machine token 缓存失败，将继续使用无机器标识链路: {}",
                err
            ));
            None
        }
    };
    let login_machine_id = if let Some(machine_token) = machine_info
        .as_ref()
        .and_then(|value| normalize_non_empty(Some(value.token.as_str())))
    {
        Some(machine_token)
    } else {
        match read_qoder_cached_machine_id_for_variant(&params) {
            Ok(value) => value,
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder OAuth] 读取官方 machine id 缓存失败，将继续使用无机器标识链路: {}",
                    err
                ));
                None
            }
        }
    };
    let expected_nonce = generate_variant_login_nonce(&params);
    let code_verifier = generate_verifier_for_variant(&params);
    let challenge_method = QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string();
    let code_challenge = generate_pkce_challenge(&code_verifier);
    let verification_uri = match params.login_mode {
        QoderVariantLoginMode::IdeDirect => {
            let login_base_url = resolve_qoder_cli_login_endpoint();
            if params.variant_key == QODER_VARIANT_QODER {
                build_cli_device_login_url(
                    &login_base_url,
                    &expected_nonce,
                    &code_challenge,
                    &challenge_method,
                    login_machine_id.as_deref(),
                )?
            } else {
                build_ide_device_login_url_for_variant(
                    &params,
                    &expected_nonce,
                    &code_challenge,
                    &challenge_method,
                    login_machine_id.as_deref(),
                )?
            }
        }
        QoderVariantLoginMode::AppSignIn => build_app_sign_in_login_url(
            &params,
            &expected_nonce,
            &code_challenge,
            &challenge_method,
            login_machine_id.as_deref(),
        )?,
    };
    let login_machine_id_source = if machine_info.is_some() {
        "machine_token"
    } else if login_machine_id.is_some() {
        "cache_id"
    } else {
        "none"
    };
    let login_id = Uuid::new_v4().to_string();
    logger::log_info(&format!(
        "[Qoder OAuth] 已生成官方 CLI device login 链接: variant={}, login_id={}, verification_uri={}, nonce_len={}, has_machine_token={}, has_machine_type={}, has_login_machine_id={}, login_machine_id_source={}",
        params.variant_key,
        login_id,
        summarize_url_for_log(&verification_uri),
        expected_nonce.len(),
        machine_info.is_some(),
        machine_info
            .as_ref()
            .and_then(|value| value.machine_type.as_deref())
            .is_some(),
        login_machine_id.is_some(),
        login_machine_id_source
    ));

    let state = PendingOAuthState {
        variant_key: params.variant_key.to_string(),
        login_id: login_id.clone(),
        expected_nonce: expected_nonce.clone(),
        code_verifier,
        challenge_method: challenge_method.clone(),
        openapi_base_url: params.openapi_base_url.to_string(),
        machine_info,
        verification_uri: verification_uri.clone(),
        expires_at: now_timestamp() + OAUTH_TIMEOUT_SECONDS,
        cancelled: false,
    };

    insert_pending_state(state);

    logger::log_info(&format!(
        "[Qoder OAuth] 登录会话已创建: variant={}, display={}, site={}, vendor_channel={}, protocol={}, keychain={}, login_id={}, redirect_uri={}, expires_in={}s",
        params.variant_key,
        params.display_name,
        params.site,
        params.vendor_channel.unwrap_or("-"),
        params.protocol_marker.unwrap_or("-"),
        params.keychain_service.unwrap_or("-"),
        login_id,
        QODER_IDE_REDIRECT_URI,
        OAUTH_TIMEOUT_SECONDS
    ));

    Ok(QoderOAuthStartResponse {
        login_id,
        verification_uri,
        expires_in: OAUTH_TIMEOUT_SECONDS as u64,
        interval_seconds: (OAUTH_POLL_INTERVAL_MS / 1000).max(1),
        callback_url: None,
    })
}

fn upsert_account_from_snapshot_for_variant(
    params: &QoderVariantParams,
    user_info_raw: Value,
    user_plan_raw: Option<Value>,
    credit_usage_raw: Option<Value>,
) -> Result<QoderAccount, String> {
    logger::log_info(&format!(
        "[Qoder OAuth] 变体入库路由: variant={}, site={}, vendor_channel={}, protocol={}",
        params.variant_key,
        params.site,
        params.vendor_channel.unwrap_or("-"),
        params.protocol_marker.unwrap_or("-"),
    ));
    qoder_account::upsert_account_from_snapshot_for_variant(
        params.variant_key,
        user_info_raw,
        user_plan_raw,
        credit_usage_raw,
    )
}

pub async fn complete_login(
    login_id: &str,
    expected_variant_key: &str,
) -> Result<QoderAccount, String> {
    logger::log_info(&format!(
        "[Qoder OAuth] 开始等待回调完成: login_id={}",
        login_id
    ));
    let wait_started = Instant::now();
    let mut next_wait_log_at = Duration::from_secs(5);
    let client = build_reqwest_client()?;
    let mut last_poll_error: Option<String> = None;

    loop {
        let snapshot = {
            let state = take_pending_state_snapshot(login_id)?;
            if state.variant_key != expected_variant_key {
                return Err(format!(
                    "Qoder 登录会话变体不一致: 请求={}, 会话={}，请重新发起登录",
                    expected_variant_key, state.variant_key
                ));
            }
            if state.cancelled {
                return Err("Qoder OAuth 登录已取消".to_string());
            }
            if now_timestamp() > state.expires_at {
                clear_pending_if_matches(login_id);
                return Err(
                    last_poll_error.unwrap_or_else(|| "Qoder OAuth 登录已超时，请重试".to_string())
                );
            }

            (
                state.expected_nonce.clone(),
                state.code_verifier.clone(),
                state.challenge_method.clone(),
                state.openapi_base_url.clone(),
                state.machine_info.clone(),
                resolve_qoder_variant_params(&state.variant_key)?,
            )
        };

        match poll_device_token_outcome(&client, &snapshot.3, &snapshot.0, &snapshot.1, &snapshot.2)
            .await
        {
            Ok(QoderPollOutcome::Authorized(token_data)) => {
                logger::log_info(&format!(
                    "[Qoder OAuth] deviceToken/poll 命中: login_id={}, elapsed={}ms",
                    login_id,
                    wait_started.elapsed().as_millis()
                ));

                let access_token = normalize_non_empty(token_data.token.as_deref())
                    .ok_or_else(|| "Qoder device token 响应缺少 token".to_string())?;

                let job_bundle = if snapshot.5.login_mode == QoderVariantLoginMode::AppSignIn {
                    match snapshot.5.client_id {
                        Some(client_id) => {
                            match exchange_app_job_token(
                                &client,
                                &snapshot.3,
                                &access_token,
                                client_id,
                            )
                            .await
                            {
                                Ok(bundle) => {
                                    logger::log_info(&format!(
                                        "[Qoder OAuth] jobToken 兑换成功: variant={}, login_id={}",
                                        snapshot.5.variant_key, login_id
                                    ));
                                    Some(bundle)
                                }
                                Err(err) => {
                                    logger::log_warn(&format!(
                                        "[Qoder OAuth] jobToken 兑换失败，保留 device 会话继续入库: variant={}, login_id={}, error={}",
                                        snapshot.5.variant_key, login_id, err
                                    ));
                                    None
                                }
                            }
                        }
                        None => {
                            logger::log_warn(&format!(
                                "[Qoder OAuth] App 变体缺少 client_id，跳过 jobToken 兑换，保留 device 会话: variant={}, login_id={}",
                                snapshot.5.variant_key, login_id
                            ));
                            None
                        }
                    }
                } else {
                    None
                };

                let user_info_response = match fetch_qoder_user_info(
                    &client,
                    &snapshot.5,
                    &snapshot.3,
                    &access_token,
                    snapshot.4.as_ref(),
                )
                .await
                {
                    Ok(value) => Some(value),
                    Err(err) => {
                        logger::log_warn(&format!(
                            "[Qoder OAuth] 获取 /userinfo 失败，将继续使用 user/status: {}",
                            err
                        ));
                        None
                    }
                };

                let (user_status, data_policy) = fetch_qoder_user_status_bundle(
                    &client,
                    &snapshot.5,
                    &snapshot.3,
                    &access_token,
                    snapshot.4.as_ref(),
                )
                .await?;

                let mut user_info_raw = if snapshot.5.login_mode == QoderVariantLoginMode::AppSignIn
                {
                    build_app_login_user_info_raw(
                        &token_data,
                        job_bundle.as_ref(),
                        user_info_response.as_ref(),
                    )
                } else {
                    build_initial_user_info_raw(&token_data, user_info_response.as_ref())
                };
                merge_user_status_into_user_info(
                    &mut user_info_raw,
                    &user_status,
                    data_policy.as_ref(),
                );

                let user_plan_raw = match fetch_qoder_user_plan(
                    &client,
                    &snapshot.5,
                    &snapshot.3,
                    &access_token,
                    snapshot.4.as_ref(),
                )
                .await
                {
                    Ok(value) => Some(value),
                    Err(err) => {
                        logger::log_warn(&format!(
                            "[Qoder OAuth] 获取 /api/v2/user/plan 失败，将以缺省快照继续: {}",
                            err
                        ));
                        None
                    }
                };

                let credit_usage_raw = match fetch_qoder_credit_usage(
                    &client,
                    &snapshot.5,
                    &snapshot.3,
                    &access_token,
                    snapshot.4.as_ref(),
                )
                .await
                {
                    Ok(value) => Some(value),
                    Err(err) => {
                        logger::log_warn(&format!(
                            "[Qoder OAuth] 获取 /api/v2/quota/usage 失败，将以缺省快照继续: {}",
                            err
                        ));
                        None
                    }
                };

                let uid = user_info_raw.get("id").or_else(|| user_info_raw.get("user").and_then(|user| user.get("id")))
                    .and_then(Value::as_str).ok_or("Qoder 授权缺少用户 ID")?;
                let identity_lock = account_refresh_lock(&format!("qoder-account:{}:{}", snapshot.5.site, uid))?;
                let _identity_guard = identity_lock.lock().await;
                let account = commit_active_login(login_id, expected_variant_key, || {
                    upsert_account_from_snapshot_for_variant(
                        &snapshot.5,
                        user_info_raw,
                        user_plan_raw,
                        credit_usage_raw,
                    )
                })?;
                logger::log_info(&format!(
                    "[Qoder OAuth] 登录完成并入库成功: login_id={}, account_id={}, email={}",
                    login_id, account.id, account.email
                ));
                return Ok(account);
            }
            Ok(QoderPollOutcome::Waiting) => {}
            Ok(QoderPollOutcome::NeedsRelogin(status)) => {
                if snapshot.5.login_mode == QoderVariantLoginMode::AppSignIn {
                    clear_pending_if_matches(login_id);
                    return Err(format!(
                        "Qoder 登录授权被拒绝 (status={})，请重新发起登录",
                        status
                    ));
                }
                let err = format!(
                    "轮询 Qoder device token 被拒绝: status={}，等待重试",
                    status
                );
                last_poll_error = Some(err.clone());
                logger::log_warn(&format!(
                    "[Qoder OAuth] deviceToken/poll 失败，等待重试: login_id={}, error={}",
                    login_id, err
                ));
            }
            Err(err) => {
                last_poll_error = Some(err.clone());
                logger::log_warn(&format!(
                    "[Qoder OAuth] deviceToken/poll 失败，等待重试: login_id={}, error={}",
                    login_id, err
                ));
            }
        }

        let elapsed = wait_started.elapsed();
        if elapsed >= next_wait_log_at {
            logger::log_info(&format!(
                "[Qoder OAuth] 等待 device token 中: login_id={}, elapsed={}s",
                login_id,
                elapsed.as_secs()
            ));
            next_wait_log_at += Duration::from_secs(5);
        }
        tokio::time::sleep(Duration::from_millis(OAUTH_POLL_INTERVAL_MS)).await;
    }
}

pub fn peek_pending_login_for_variant(variant_key: &str) -> Option<QoderOAuthStartResponse> {
    let state = peek_pending_state_for_variant(variant_key)?;
    let now = now_timestamp();
    Some(pending_state_to_response(&state, now))
}

pub fn cancel_login_for_variant(
    login_id: Option<&str>,
    variant_key: Option<&str>,
) -> Result<(), String> {
    let mut guard = PENDING_OAUTH_STATES
        .lock()
        .map_err(|_| "获取 Qoder OAuth 状态锁失败".to_string())?;

    let targets: Vec<String> = match (login_id, variant_key) {
        (Some(target), _) => guard
            .iter()
            .filter(|(_, state)| state.login_id == target)
            .map(|(key, _)| key.clone())
            .collect(),
        (None, Some(variant)) => guard
            .keys()
            .filter(|key| key.as_str() == variant)
            .cloned()
            .collect(),
        (None, None) => guard.keys().cloned().collect(),
    };

    for key in targets {
        if let Some(state) = guard.remove(&key) {
            logger::log_info(&format!(
                "[Qoder OAuth] 取消登录会话: variant={}, login_id={}",
                state.variant_key, state.login_id
            ));
        }
    }
    Ok(())
}

fn build_qoder_claim_headers(
    kind: QoderVariantKind,
    openapi_base_url: &str,
    token: &str,
    machine_info: Option<&QoderMachineInfo>,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};

    let mut headers = HeaderMap::new();
    let bearer = format!("Bearer {}", token);
    if let Ok(value) = HeaderValue::from_str(&bearer) {
        headers.insert(AUTHORIZATION, value);
    }
    if let Ok(value) = HeaderValue::from_str("application/json") {
        headers.insert(ACCEPT, value);
    }
    if let Ok(value) = HeaderValue::from_str("10") {
        headers.insert(reqwest::header::HeaderName::from_static("cosy-clienttype"), value);
    }

    let cosy_version = machine_info
        .and_then(|v| v.cosy_version.clone())
        .or_else(|| detect_qoder_product_version_for_variant(kind))
        .unwrap_or_else(|| "0.4.2".to_string());
    if let Ok(value) = HeaderValue::from_str(&cosy_version) {
        headers.insert(reqwest::header::HeaderName::from_static("cosy-version"), value);
    }

    let machine_os = machine_info
        .and_then(|v| v.machine_os.as_deref())
        .and_then(|v| normalize_non_empty(Some(v)))
        .unwrap_or_else(build_cosy_machine_os);
    if let Ok(value) = HeaderValue::from_str(&machine_os) {
        headers.insert(reqwest::header::HeaderName::from_static("cosy-machineos"), value);
    }

    if let Some(m) = machine_info {
        if let Some(h) = m.machine_hostname.as_deref().and_then(|v| normalize_non_empty(Some(v))) {
            if let Ok(v) = HeaderValue::from_str(&h) {
                headers.insert(reqwest::header::HeaderName::from_static("cosy-machinehostname"), v);
            }
        }
        if let Some(id) = m.machine_id.as_deref().and_then(|v| normalize_non_empty(Some(v))) {
            if let Ok(v) = HeaderValue::from_str(&id) {
                headers.insert(reqwest::header::HeaderName::from_static("cosy-machineid"), v);
            }
        }
        if let Some(tok) = normalize_non_empty(Some(m.token.as_str())) {
            if let Ok(v) = HeaderValue::from_str(&tok) {
                headers.insert(reqwest::header::HeaderName::from_static("cosy-machinetoken"), v);
            }
        }
        if let Some(code) = m.machine_code.as_deref().and_then(|v| normalize_non_empty(Some(v))) {
            if let Ok(v) = HeaderValue::from_str(&code) {
                headers.insert(reqwest::header::HeaderName::from_static("cosy-machinecode"), v);
            }
        }
        if let Some(t) = m.machine_type.as_deref().and_then(|v| normalize_non_empty(Some(v))) {
            if let Ok(v) = HeaderValue::from_str(&t) {
                headers.insert(reqwest::header::HeaderName::from_static("cosy-machinetype"), v);
            }
        }
    }

    if let Ok(url) = Url::parse(openapi_base_url) {
        if let Some(host) = url.host_str() {
            let iframe_url = format!("https://{}/growth-page/activity-iframe", host);
            if let Ok(v) = HeaderValue::from_str(&iframe_url) {
                headers.insert(reqwest::header::HeaderName::from_static("origin"), v.clone());
                headers.insert(reqwest::header::HeaderName::from_static("referer"), v);
            }
        }
    }

    if let Ok(value) = HeaderValue::from_str(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    ) {
        headers.insert(USER_AGENT, value);
    }

    headers
}

fn select_unique_100_campaign(campaigns: &[Value]) -> Result<Option<&Value>, String> {
    let mut matches = campaigns.iter().filter(|campaign| {
        campaign.get("benefit").and_then(|benefit| benefit.get("amount"))
            .and_then(Value::as_i64) == Some(100)
            && campaign.get("campaignId").and_then(Value::as_str)
                .is_some_and(|id| !id.trim().is_empty())
            && campaign.get("actionType").and_then(Value::as_str) != Some("VIEW_DETAILS")
    });
    let selected = matches.next();
    if matches.next().is_some() {
        return Err("当前账号存在多个 100 积分活动，无法确定每日领取目标".to_string());
    }
    Ok(selected)
}

pub async fn claim_daily_reward(account_id: &str) -> Result<QoderClaimRewardResult, String> {
    let target = qoder_account::load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let kind = qoder_account::account_variant_kind(&target)?;
    let variant_key = kind.provider_key();
    let params = resolve_qoder_variant_params(variant_key)
        .map_err(|err| format!("解析 Qoder 变体参数失败: {}", err))?;

    // 当前 App 只查询额度，离线账号才可轮换；共同入口负责会话归属与切号互斥。
    let target = if variant_supports_device_refresh(variant_key) {
        refresh_account_token_for_variant(variant_key, account_id, false).await?
    } else {
        target
    };
    let target = qoder_account::app_owned_session(&target)?.unwrap_or(target);
    let access_token = extract_access_token_from_account(&target)
        .ok_or_else(|| "Qoder 账号缺少可用凭证，请重新登录".to_string())?;

    let client = build_reqwest_client()?;
    let machine_info = read_qoder_machine_info_cache_for_variant(&params).ok().flatten();
    let headers = build_qoder_claim_headers(kind, params.openapi_base_url, &access_token, machine_info.as_ref());

    let campaigns_url = format!("{}/sash/api/v1/me/campaigns", params.openapi_base_url.trim_end_matches('/'));
    let campaigns_resp = client
        .get(&campaigns_url)
        .headers(headers.clone())
        .send()
        .await
        .map_err(|err| format!("获取 Qoder 活动列表网络错误: {}", err))?;

    let status = campaigns_resp.status();
    if !status.is_success() {
        return Err(format!("获取活动列表失败 (HTTP {})", status));
    }

    let campaigns_json: Value = campaigns_resp
        .json()
        .await
        .map_err(|err| format!("解析 Qoder 活动列表失败: {}", err))?;

    let campaigns_arr = campaigns_json
        .get("campaigns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Qoder 活动列表为空".to_string())?;

    let target_campaign = select_unique_100_campaign(campaigns_arr)?
        .ok_or_else(|| "当前账号活动列表中无可确认的 100 积分领取活动".to_string())?;

    let benefit_amount = target_campaign
        .get("benefit")
        .and_then(|b| b.get("amount"))
        .and_then(|a| a.as_i64())
        .ok_or_else(|| "Qoder 活动缺少可确认的积分数量".to_string())?;

    let claim_status_val = target_campaign.get("claimStatus").and_then(|v| v.as_str());
    if claim_status_val == Some("CLAIMED") {
        let saved = qoder_account::update_reward_status(
            account_id,
            Some("CLAIMED".to_string()),
            target_campaign.get("endAt").and_then(|v| v.as_i64()),
            None,
        )?;
        return Ok(QoderClaimRewardResult {
            account_id: account_id.to_string(),
            success: true,
            replayed: true,
            amount: Some(benefit_amount),
            message: format!("今日已领取过 {} 积分", benefit_amount),
            account: Some(saved),
        });
    }

    let campaign_id = target_campaign
        .get("campaignId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Qoder 活动缺少 campaignId".to_string())?;

    let claim_url = format!(
        "{}/sash/api/v1/me/campaigns/{}/claim",
        params.openapi_base_url.trim_end_matches('/'),
        campaign_id
    );

    let claim_resp = client
        .post(&claim_url)
        .headers(headers)
        .header(reqwest::header::CONTENT_LENGTH, 0)
        .send()
        .await
        .map_err(|err| format!("领取 Qoder 积分网络请求错误: {}", err))?;

    let claim_status = claim_resp.status();
    if !claim_status.is_success() {
        let err_body = claim_resp.text().await.unwrap_or_default();
        let parsed_err = serde_json::from_str::<Value>(&err_body).ok();
        let error_msg = parsed_err.as_ref().and_then(|v| {
            let msg = v.get("errorMessage").or_else(|| v.get("message")).and_then(|m| m.as_str());
            let code = v.get("errorCode").or_else(|| v.get("code")).and_then(|c| c.as_str());
            match (code, msg) {
                (Some(c), Some(m)) => Some(format!("{}: {}", c, m)),
                (None, Some(m)) => Some(m.to_string()),
                (Some(c), None) => Some(c.to_string()),
                (None, None) => None,
            }
        });
        let detail = error_msg.unwrap_or_else(|| {
            if err_body.trim().is_empty() {
                format!("HTTP {}", claim_status)
            } else {
                err_body
            }
        });
        return Err(format!("领取失败 (HTTP {}): {}", claim_status, detail));
    }

    let claim_json: Value = claim_resp
        .json()
        .await
        .map_err(|err| format!("解析 Qoder 领取结果失败: {}", err))?;

    let replayed = claim_json
        .get("replayed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let amount = claim_json
        .get("benefit")
        .and_then(|b| b.get("amount"))
        .and_then(|a| a.as_i64())
        .or_else(|| {
            target_campaign
                .get("benefit")
                .and_then(|b| b.get("amount"))
                .and_then(|a| a.as_i64())
        })
        .ok_or_else(|| "Qoder 领取结果缺少可确认的积分数量".to_string())?;

    if replayed {
        let saved = qoder_account::update_reward_status(
            account_id,
            Some("CLAIMED".to_string()),
            target_campaign.get("endAt").and_then(|v| v.as_i64()),
            None,
        )?;
        Ok(QoderClaimRewardResult {
            account_id: account_id.to_string(),
            success: true,
            replayed: true,
            amount: Some(amount),
            message: format!("今日已领取过 {} 积分", amount),
            account: Some(saved),
        })
    } else {
        let refresh_result = refresh_account_token_for_variant(variant_key, account_id, false).await;
        let refreshed = match refresh_result {
            Ok(account) => Some(account),
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder Claim] 领取成功后刷新账号失败: variant={}, account_id={}, error={}",
                    variant_key, account_id, err
                ));
                None
            }
        };

        let final_acc = if refreshed.is_some() || qoder_account::load_account(account_id).is_some() {
            Some(qoder_account::update_reward_status(
                account_id,
                Some("CLAIMED".to_string()),
                target_campaign.get("endAt").and_then(|v| v.as_i64()),
                None,
            )?)
        } else {
            None
        };

        Ok(QoderClaimRewardResult {
            account_id: account_id.to_string(),
            success: true,
            replayed: false,
            amount: Some(amount),
            message: format!("成功领取 {} 积分！", amount),
            account: final_acc,
        })
    }
}

pub async fn query_qoder_campaign_status(account_id: &str) -> Result<QoderAccount, String> {
    let target = qoder_account::load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let target = qoder_account::app_owned_session(&target)?.unwrap_or(target);
    let kind = qoder_account::account_variant_kind(&target)?;
    let variant_key = kind.provider_key();
    let params = resolve_qoder_variant_params(variant_key)
        .map_err(|err| format!("解析 Qoder 变体参数失败: {}", err))?;

    // 活动是弱依赖：复用已保存的会话，不轮换 token，也不判定账号需要重登。
    let access_token = extract_access_token_from_account(&target)
        .ok_or_else(|| "Qoder 账号缺少可用凭证，无法查询活动状态".to_string())?;

    let client = build_reqwest_client()?;
    let machine_info = read_qoder_machine_info_cache_for_variant(&params).ok().flatten();
    let headers = build_qoder_claim_headers(kind, params.openapi_base_url, &access_token, machine_info.as_ref());

    let campaigns_url = format!("{}/sash/api/v1/me/campaigns", params.openapi_base_url.trim_end_matches('/'));
    let campaigns_resp = client
        .get(&campaigns_url)
        .headers(headers)
        .send()
        .await
        .map_err(|err| format!("获取 Qoder 活动列表网络错误: {}", err))?;

    let status = campaigns_resp.status();
    if !status.is_success() {
        return Err(format!("获取活动列表失败 (HTTP {})", status));
    }

    let campaigns_json: Value = campaigns_resp
        .json()
        .await
        .map_err(|err| format!("解析 Qoder 活动列表失败: {}", err))?;

    let campaigns_arr = campaigns_json
        .get("campaigns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Qoder 活动列表响应格式无效".to_string())?;
    // 空列表与歧义/格式错误分开；后两者不能覆盖为「无活动」。
    let target_campaign = select_unique_100_campaign(campaigns_arr)?;

    let (claim_status, window_end_at) = if let Some(camp) = target_campaign {
        let claim_status = camp.get("claimStatus").and_then(|v| v.as_str())
            .ok_or_else(|| "Qoder 活动缺少领取状态".to_string())?;
        (
            Some(claim_status.to_string()),
            camp.get("endAt").and_then(|v| v.as_i64()),
        )
    } else {
        (Some("NONE".to_string()), None)
    };

    // 存储层在同一锁内检查快照并局部更新，避免旧响应覆盖领取结果或轮换后的凭证。
    qoder_account::update_reward_status(account_id, claim_status, window_end_at, Some(&target))
}


#[cfg(test)]
mod tests {
    use super::*;

    fn cn_ide_login_fixture() -> (QoderAccount, Value) {
        let raw = serde_json::json!({
            "id": "fixture-cn-user",
            "name": "fixture-name",
            "token": "dt-SYNTH-old",
            "refreshToken": "drt-SYNTH-old",
            "expireTime": "4102444800000"
        });
        let target = serde_json::from_value(serde_json::json!({
            "id": "qoder_cn_ide_uid_fixture-cn-user",
            "variant": QODER_VARIANT_QODER_CN_IDE,
            "email": "fixture@qoder.local",
            "user_id": "fixture-cn-user",
            "auth_user_info_raw": raw.clone(),
            "created_at": 0,
            "last_used": 0
        })).expect("synthetic CN IDE account");
        (target, raw)
    }

    #[test]
    fn cn_ide_login_requires_native_status_and_preserves_rotated_credentials() {
        let (target, mut raw) = cn_ide_login_fixture();
        // App 的 RT 可以兑换 token，但 token 本身不足以启动 IDE 的服务登录。
        assert!(cn_ide_access_token_is_current(&raw));
        assert!(ensure_cn_ide_login_info_ready(&raw).is_err());
        let refreshed = parse_device_refresh_body(&serde_json::json!({
            "device_token": "dt-SYNTH-new",
            "refresh_token": "drt-SYNTH-new",
            "expires_at": "2100-01-01T00:00:00Z"
        })).expect("synthetic refreshed credentials");
        apply_refreshed_device_token(&mut raw, &refreshed);
        merge_cn_ide_login_status(
            &target, &mut raw,
            &serde_json::json!({"id": "fixture-cn-user", "whitelistStatus": "PASS"}),
            Some(&serde_json::json!({"success": true, "result": {"status": "AGREE"}})),
        ).expect("native login profile completed");
        assert_eq!(raw["token"], "dt-SYNTH-new");
        assert_eq!(raw["refreshToken"], "drt-SYNTH-new");
        assert_eq!(raw["status"], AUTH_STATUS_AUTHORIZED);
        assert_eq!(raw["whitelist"], WHITELIST_PASS);
        assert_eq!(raw["privacyPolicyAgreed"], true);
        assert!(ensure_cn_ide_login_info_ready(&raw).is_ok());
        // 资料查询失败时保存的检查点仍保留新 RT，但不得被当成可注入登录态。
        invalidate_cn_ide_login_status(&mut raw);
        assert_eq!(raw["refreshToken"], "drt-SYNTH-new");
        assert!(ensure_cn_ide_login_info_ready(&raw).is_err());
    }

    #[test]
    fn cn_ide_login_rejects_foreign_identity_disallowed_status_and_bad_expiry() {
        let (target, mut raw) = cn_ide_login_fixture();
        let original = raw.clone();
        assert!(merge_cn_ide_login_status(
            &target, &mut raw,
            &serde_json::json!({"id": "foreign-user", "whitelistStatus": "PASS"}),
            None,
        ).is_err());
        assert_eq!(raw, original);
        for status in ["WAIT", "NotAllow", "unknown"] {
            let mut raw = original.clone();
            assert!(merge_cn_ide_login_status(
                &target, &mut raw,
                &serde_json::json!({"id": "fixture-cn-user", "whitelistStatus": status}),
                None,
            ).is_err());
        }
        for status in ["PASS", "NoLicense", "NoQuota", "EXPIRED"] {
            let mut raw = original.clone();
            merge_cn_ide_login_status(
                &target, &mut raw,
                &serde_json::json!({"id": "fixture-cn-user", "whitelistStatus": status}),
                None,
            ).expect("official IDE accepts this authorized state");
            for expiry in [Value::Null, Value::from("invalid"), Value::from("0")] {
                raw["expireTime"] = expiry;
                assert!(ensure_cn_ide_login_info_ready(&raw).is_err());
            }
        }
    }

    #[test]
    fn plan_refresh_accepts_only_explicit_tier_responses() {
        assert!(user_plan_has_tier(&serde_json::json!({
            "plan_tier_name": "Pro"
        })));
        assert!(user_plan_has_tier(&serde_json::json!({
            "userType": "enterprise",
            "planTierName": "Enterprise VPC"
        })));
        assert!(user_plan_has_tier(&serde_json::json!({
            "user_type": "personal_ultra",
            "plan_tier_name": "Ultra"
        })));
        assert!(user_plan_has_tier(&serde_json::json!({
            "userType": "personal_professional",
            "planName": "Pro"
        })));
        assert!(!user_plan_has_tier(&serde_json::json!({
            "userType": "enterprise",
            "name": "account nickname"
        })));
        assert!(!user_plan_has_tier(&serde_json::json!({
            "userType": "enterprise",
            "planTierName": " "
        })));
    }

    #[test]
    fn daily_reward_selects_only_one_campaign_with_verified_amount() {
        let campaigns = vec![
            serde_json::json!({"campaignId": "wrong-title", "placements": ["100 Credits"]}),
            serde_json::json!({"campaignId": "wrong-date", "campaignKey": "20260923"}),
            serde_json::json!({"campaignId": "view-only", "actionType": "VIEW_DETAILS", "benefit": {"amount": 100}}),
            serde_json::json!({"campaignId": "daily-100", "benefit": {"amount": 100}}),
        ];
        assert_eq!(select_unique_100_campaign(&campaigns).unwrap().unwrap()["campaignId"].as_str(), Some("daily-100"));
        let ambiguous = [campaigns[3].clone(), serde_json::json!({
            "campaignId": "another-100", "benefit": {"amount": 100}
        })];
        assert!(select_unique_100_campaign(&ambiguous).is_err());
        assert!(select_unique_100_campaign(&[]).unwrap().is_none());
        assert!(select_unique_100_campaign(&campaigns[..3]).unwrap().is_none());
    }

    #[test]
    fn imported_app_refresh_updates_client_expiry_fields() {
        let mut raw = serde_json::json!({
            "schemaVersion": 1,
            "token": "old-device-token",
            "refreshToken": "old-refresh-token",
            "expiresAt": "2020-01-01T00:00:00+00:00",
            "refreshTokenExpiresAt": "2020-01-02T00:00:00+00:00",
            "user": {"id": "fixture-user"}
        });
        let refreshed = parse_device_refresh_body(&serde_json::json!({
            "device_token": "new-device-token",
            "refresh_token": "new-refresh-token",
            "expires_at": "2030-01-01T00:00:00Z",
            "refresh_token_expires_at": "2030-01-02T00:00:00Z"
        })).expect("parse refreshed credentials");
        apply_refreshed_device_token(&mut raw, &refreshed);
        assert_eq!(raw["token"], "new-device-token");
        assert_eq!(raw["refreshToken"], "new-refresh-token");
        assert_eq!(raw["expiresAt"], "2030-01-01T00:00:00+00:00");
        assert_eq!(raw["refreshTokenExpiresAt"], "2030-01-02T00:00:00+00:00");
        assert_eq!(raw["user"]["id"], "fixture-user");
    }

    #[test]
    fn baseline_single_slot_overwrite_semantics() {
        let _serial = SLOT_TEST_SERIAL.lock().expect("serial slot tests");
        let first = PendingOAuthState {
            variant_key: QODER_VARIANT_QODER.to_string(),
            login_id: "baseline-first".to_string(),
            expected_nonce: "n".to_string(),
            code_verifier: "v".to_string(),
            challenge_method: QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string(),
            openapi_base_url: DEFAULT_OPENAPI_BASE_URL.to_string(),
            machine_info: None,
            verification_uri: "https://qoder.com/device/selectAccounts?nonce=n".to_string(),
            expires_at: now_timestamp() + OAUTH_TIMEOUT_SECONDS,
            cancelled: false,
        };
        let second = PendingOAuthState {
            login_id: "baseline-second".to_string(),
            ..first.clone()
        };
        insert_pending_state(first);
        insert_pending_state(second);
        {
            let guard = PENDING_OAUTH_STATES.lock().expect("lock slots");
            assert_eq!(
                guard
                    .get(QODER_VARIANT_QODER)
                    .map(|s| s.login_id.as_str()),
                Some("baseline-second")
            );
            assert!(!guard.values().any(|s| s.login_id == "baseline-first"));
        }
        let _ = cancel_login_for_variant(Some("baseline-second"), Some(QODER_VARIANT_QODER));
    }

    #[test]
    fn baseline_ide_login_url_shape_is_frozen() {
        let url = build_cli_device_login_url(
            DEFAULT_LOGIN_BASE_URL,
            "test-nonce",
            "test-challenge",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            Some("test-machine-id"),
        )
        .expect("build login url");

        let parsed = Url::parse(&url).expect("parse login url");
        let query = parsed
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();

        assert!(query.contains(&("nonce".to_string(), "test-nonce".to_string())));
        assert!(query.contains(&("challenge".to_string(), "test-challenge".to_string())));
        assert!(query.contains(&(
            "challenge_method".to_string(),
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string()
        )));
        assert!(query.contains(&(
            "redirect_uri".to_string(),
            QODER_IDE_REDIRECT_URI.to_string()
        )));
        assert!(query.contains(&("machine_id".to_string(), "test-machine-id".to_string())));
        assert!(!query.iter().any(|(key, _)| key == "client_id"));
        let mut keys = query
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<&str>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "challenge",
                "challenge_method",
                "machine_id",
                "nonce",
                "redirect_uri"
            ]
        );

        let bare = build_cli_device_login_url(
            DEFAULT_LOGIN_BASE_URL,
            "test-nonce",
            "test-challenge",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            None,
        )
        .expect("build login url without machine id");
        let bare_parsed = Url::parse(&bare).expect("parse bare login url");
        let bare_keys = bare_parsed
            .query_pairs()
            .map(|(key, _)| key.to_string())
            .collect::<Vec<String>>();
        assert!(!bare_keys.iter().any(|key| key == "machine_id"));
        assert!(!bare_keys.iter().any(|key| key == "client_id"));
    }

    #[test]
    fn builds_current_official_cosy_headers_from_machine_cache() {
        let machine = QoderMachineInfo {
            token: "machine-token".to_string(),
            machine_type: Some("machine-type".to_string()),
            machine_code: Some("machine-code".to_string()),
            machine_id: Some("machine-id".to_string()),
            machine_hostname: Some("machine-hostname".to_string()),
            machine_os: Some("aarch64_darwin".to_string()),
            cosy_version: Some("1.27.1".to_string()),
        };
        let headers = build_qoder_headers(QoderVariantKind::Qoder, "access-token", Some(&machine));

        assert_eq!(headers["Cosy-Version"], "1.27.1");
        assert_eq!(headers["Cosy-MachineToken"], "machine-token");
        assert_eq!(headers["Cosy-MachineType"], "machine-type");
        assert_eq!(headers["Cosy-MachineCode"], "machine-code");
        assert_eq!(headers["Cosy-MachineId"], "machine-id");
        assert_eq!(headers["Cosy-MachineHostname"], "machine-hostname");
        assert_eq!(headers["Cosy-MachineOS"], "aarch64_darwin");
        assert_eq!(headers["Cosy-ClientType"], "0");
        assert_eq!(
            headers.get("authorization").map(|v| v.to_str().ok()),
            Some(Some("Bearer access-token"))
        );
        assert!(!headers.contains_key("user-agent"));
    }

    static SLOT_TEST_SERIAL: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));
    fn test_variant_keys() -> [&'static str; 4] {
        crate::modules::qoder_variant::all_qoder_variant_kinds().map(|kind| kind.provider_key())
    }
    fn test_pending_state(variant_key: &str, login_id: &str) -> PendingOAuthState {        PendingOAuthState {
            variant_key: variant_key.to_string(),
            login_id: login_id.to_string(),
            expected_nonce: "n".to_string(),
            code_verifier: "v".to_string(),
            challenge_method: QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string(),
            openapi_base_url: DEFAULT_OPENAPI_BASE_URL.to_string(),
            machine_info: None,
            verification_uri: "https://example.invalid/login".to_string(),
            expires_at: now_timestamp() + OAUTH_TIMEOUT_SECONDS,
            cancelled: false,
        }
    }

    #[test]
    fn qoder_login_slots_variant_matrix_resolves() {
        let keys = test_variant_keys();
        assert_eq!(
            keys,
            ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"]
        );

        let ide = resolve_qoder_variant_params("qoder").expect("qoder params");
        assert_eq!(ide.display_name, "Qoder IDE");
        assert_eq!(ide.site, "intl");
        assert_eq!(ide.login_mode, QoderVariantLoginMode::IdeDirect);
        assert_eq!(ide.login_base_url, DEFAULT_LOGIN_BASE_URL);
        assert_eq!(ide.openapi_base_url, DEFAULT_OPENAPI_BASE_URL);
        assert_eq!(ide.client_id, None);
        assert_eq!(ide.keychain_service, Some("Qoder Safe Storage"));
        assert!(!ide.is_app_line);

        let app = resolve_qoder_variant_params("qoder_app").expect("qoder_app params");
        assert_eq!(app.display_name, "Qoder");
        assert_eq!(app.keychain_service, Some("Qoder App Safe Storage"));
        assert_eq!(app.site, "intl");
        assert_eq!(app.login_mode, QoderVariantLoginMode::AppSignIn);
        assert_eq!(app.openapi_base_url, DEFAULT_OPENAPI_BASE_URL);
        assert_eq!(app.client_id, Some(QODER_APP_SHARED_CLIENT_ID));
        assert!(app.is_app_line);

        let cn_ide = resolve_qoder_variant_params("qoder_cn_ide").expect("cn ide params");
        assert_eq!(cn_ide.display_name, "Qoder CN IDE");
        assert_eq!(cn_ide.site, "cn");
        assert_eq!(cn_ide.login_mode, QoderVariantLoginMode::IdeDirect);
        assert_eq!(cn_ide.login_base_url, QODER_CN_LOGIN_BASE_URL);
        assert_eq!(cn_ide.openapi_base_url, QODER_CN_OPENAPI_BASE_URL);
        assert_eq!(cn_ide.client_id, None);
        assert_eq!(cn_ide.vendor_channel, Some(QODER_CN_IDE_CHANNEL));
        assert_eq!(cn_ide.keychain_service, Some("Qoder CN Safe Storage"));
        assert!(!cn_ide.is_app_line);

        let cn_app = resolve_qoder_variant_params("qoder_cn_app").expect("cn app params");
        assert_eq!(cn_app.display_name, "Qoder CN");
        assert_eq!(cn_app.site, "cn");
        assert_eq!(cn_app.login_mode, QoderVariantLoginMode::AppSignIn);
        assert_eq!(cn_app.login_base_url, QODER_CN_LOGIN_BASE_URL);
        assert_eq!(cn_app.openapi_base_url, QODER_CN_OPENAPI_BASE_URL);
        assert_eq!(cn_app.client_id, Some(QODER_APP_SHARED_CLIENT_ID));
        assert_eq!(cn_app.vendor_channel, Some(QODER_CN_APP_CHANNEL));
        assert_eq!(cn_app.keychain_service, Some("Qoder CN App Safe Storage"));
        assert!(cn_app.is_app_line);

        let err = resolve_qoder_variant_params("qoder_eu").expect_err("unknown key errors");
        assert!(err.contains("qoder_eu"));
    }

    #[test]
    fn qoder_variant_keychain_service_set_is_proven() {
        let mut services = Vec::new();
        for key in test_variant_keys() {
            let params = resolve_qoder_variant_params(key).expect("variant params");
            let service = params
                .keychain_service
                .unwrap_or_else(|| panic!("variant {key} must carry a proven keychain name"));
            services.push((key, service));
        }
        assert_eq!(
            services,
            vec![
                ("qoder", "Qoder Safe Storage"),
                ("qoder_app", "Qoder App Safe Storage"),
                ("qoder_cn_ide", "Qoder CN Safe Storage"),
                ("qoder_cn_app", "Qoder CN App Safe Storage"),
            ]
        );
        println!("keychain service set -> {services:?}");
    }

    #[test]
    fn qoder_login_slots_concurrent_variants_coexist() {
        let _serial = SLOT_TEST_SERIAL.lock().expect("serial slot tests");
        for key in test_variant_keys() {
            let _ = cancel_login_for_variant(None, Some(key));
        }
        for key in test_variant_keys() {
            insert_pending_state(test_pending_state(key, &format!("slot-{}", key)));
        }
        {
            let guard = PENDING_OAUTH_STATES.lock().expect("lock slots");
            assert_eq!(guard.len(), 4);
            for key in test_variant_keys() {
                let expected = format!("slot-{}", key);
                assert_eq!(
                    guard.get(key).map(|s| s.login_id.as_str()),
                    Some(expected.as_str()),
                    "variant slot mismatch"
                );
            }
        }
        insert_pending_state(test_pending_state("qoder", "slot-qoder-retry"));
        assert!(take_pending_state_snapshot("slot-qoder").is_err());
        let stale_err = take_pending_state_snapshot("slot-qoder").expect_err("stale id rejected");
        assert!(stale_err.contains("已变更"));
        let live = take_pending_state_snapshot("slot-qoder-retry").expect("live snapshot");
        assert_eq!(live.variant_key, "qoder");
        assert!(take_pending_state_snapshot("slot-qoder_app").is_ok());
        assert!(take_pending_state_snapshot("slot-qoder_cn_ide").is_ok());
        assert!(take_pending_state_snapshot("slot-qoder_cn_app").is_ok());
        for key in test_variant_keys() {
            let _ = cancel_login_for_variant(None, Some(key));
        }
        assert!(take_pending_state_snapshot("slot-qoder-retry").is_err());
    }

    #[test]
    fn oauth_cancelled_after_an_earlier_snapshot_cannot_commit() {
        let _serial = SLOT_TEST_SERIAL.lock().expect("serial slot tests");
        for key in test_variant_keys() {
            let id = format!("cancel-before-commit-{key}");
            insert_pending_state(test_pending_state(key, &id));
            assert!(!take_pending_state_snapshot(&id).unwrap().cancelled);
            cancel_login_for_variant(Some(&id), Some(key)).unwrap();
            let mut committed = false;
            let result = commit_active_login(&id, key, || {
                committed = true;
                Ok(())
            });
            assert!(result.is_err());
            assert!(
                !committed,
                "an accepted cancel must prevent persistence even after an earlier valid snapshot"
            );
        }
    }

    #[test]
    fn oauth_commit_holds_the_cancel_boundary_and_removes_only_the_completed_session() {
        let _serial = SLOT_TEST_SERIAL.lock().expect("serial slot tests");
        insert_pending_state(test_pending_state(QODER_VARIANT_QODER, "commit-current"));
        insert_pending_state(test_pending_state(QODER_VARIANT_QODER_APP, "commit-other"));
        let committed = commit_active_login("commit-current", QODER_VARIANT_QODER, || {
            assert!(
                matches!(
                    PENDING_OAUTH_STATES.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ),
                "cancellation must not be accepted between the final check and persistence"
            );
            Ok("saved-account-fixture")
        })
        .unwrap();
        assert_eq!(committed, "saved-account-fixture");
        assert!(take_pending_state_snapshot("commit-current").is_err());
        assert!(take_pending_state_snapshot("commit-other").is_ok());
        cancel_login_for_variant(Some("commit-other"), None).unwrap();
    }

    #[test]
    fn oauth_failed_commit_keeps_the_live_session_for_retry() {
        let _serial = SLOT_TEST_SERIAL.lock().expect("serial slot tests");
        insert_pending_state(test_pending_state(QODER_VARIANT_QODER, "failed-commit"));
        let result: Result<(), String> =
            commit_active_login("failed-commit", QODER_VARIANT_QODER, || {
                Err("isolated persistence failure".into())
            });
        assert_eq!(result.unwrap_err(), "isolated persistence failure");
        assert!(take_pending_state_snapshot("failed-commit").is_ok());
        cancel_login_for_variant(Some("failed-commit"), None).unwrap();
    }

    #[test]
    fn qoder_login_slots_header_surface() {
        let machine = QoderMachineInfo {
            token: "machine-token".to_string(),
            machine_type: Some("machine-type".to_string()),
            machine_code: None,
            machine_id: None,
            machine_hostname: None,
            machine_os: Some("aarch64_darwin".to_string()),
            cosy_version: Some("1.27.1".to_string()),
        };
        let ide_params = resolve_qoder_variant_params("qoder").expect("qoder params");
        let ide_headers = build_qoder_headers_for_variant(&ide_params, "dt-token", Some(&machine));
        assert_eq!(ide_headers["Cosy-ClientType"], "0");
        assert_eq!(ide_headers["Cosy-MachineToken"], "machine-token");
        assert!(!ide_headers.contains_key("user-agent"));

        let app_params = resolve_qoder_variant_params("qoder_cn_app").expect("cn app params");
        let app_headers = build_qoder_headers_for_variant(&app_params, "dt-token", Some(&machine));
        assert_eq!(app_headers["cosy-clienttype"], "10");
        assert_eq!(
            app_headers.get("user-agent").and_then(|v| v.to_str().ok()),
            Some("Qoder")
        );
        assert!(!app_headers.contains_key("Cosy-MachineToken"));
    }

    #[test]
    fn qoder_login_slots_qoder_frozen_shapes() {
        let params = resolve_qoder_variant_params("qoder").expect("qoder params");
        for machine_id in [Some("mid-1"), None] {
            let frozen = build_cli_device_login_url(
                DEFAULT_LOGIN_BASE_URL,
                "n123",
                "c123",
                QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
                machine_id,
            )
            .expect("frozen builder");
            let variant = build_ide_device_login_url_for_variant(
                &params,
                "n123",
                "c123",
                QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
                machine_id,
            )
            .expect("variant builder");
            assert_eq!(variant, frozen);
        }
        let machine = QoderMachineInfo {
            token: "machine-token".to_string(),
            machine_type: None,
            machine_code: None,
            machine_id: None,
            machine_hostname: None,
            machine_os: None,
            cosy_version: None,
        };
        let frozen_headers = build_qoder_headers(QoderVariantKind::Qoder, "dt-token", Some(&machine));
        let variant_headers =
            build_qoder_headers_for_variant(&params, "dt-token", Some(&machine));
        assert_eq!(variant_headers, frozen_headers);
    }

    #[test]
    fn qoder_login_slots_app_login_url_shape() {
        let cn_app = resolve_qoder_variant_params("qoder_cn_app").expect("cn app params");
        let url = build_app_sign_in_login_url(
            &cn_app,
            "nonce-1",
            "challenge-1",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            Some("mid-1"),
        )
        .expect("cn app login url");
        let parsed = Url::parse(&url).expect("parse cn app login url");
        assert_eq!(parsed.host_str(), Some("qoder.cn"));
        assert_eq!(parsed.path(), "/users/sign-in");
        let outer = parsed
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(outer.contains(&("biz_variant".to_string(), "qoder".to_string())));
        let callback = outer
            .iter()
            .find(|(key, _)| key == "oauth_callback")
            .map(|(_, value)| value.clone())
            .expect("oauth_callback present");
        let inner = Url::parse(&callback).expect("parse inner selectAccounts");
        assert_eq!(inner.path(), "/device/selectAccounts");
        let inner_query = inner
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(inner_query.contains(&(
            "client_id".to_string(),
            QODER_APP_SHARED_CLIENT_ID.to_string()
        )));
        assert!(!inner_query.iter().any(|(key, _)| key == "redirect_uri"));

        let intl_app = resolve_qoder_variant_params("qoder_app").expect("intl app params");
        let intl_url = build_app_sign_in_login_url(
            &intl_app,
            "nonce-1",
            "challenge-1",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            None,
        )
        .expect("intl app login url");
        let intl_parsed = Url::parse(&intl_url).expect("parse intl app login url");
        assert_eq!(intl_parsed.host_str(), Some("qoder.com"));
        assert_eq!(intl_parsed.path(), "/users/sign-in");
        assert!(!intl_parsed
            .query_pairs()
            .any(|(key, _)| key == "biz_variant"));
    }

    #[test]
    fn qoder_login_slots_machine_absent_proceeds_unidentified() {
        let missing = PathBuf::from("/definitely/not/here/qoder-variants-t2");
        assert!(!missing.exists());
        let info = read_machine_info_from_cache_dir(&missing).expect("absent cache is Ok");
        assert!(info.is_none());
        let id = read_cached_machine_id_from_cache_dir(&missing).expect("absent id is Ok");
        assert!(id.is_none());

        for key in test_variant_keys() {
            let params = resolve_qoder_variant_params(key).expect("params");
            let dir = qoder_user_data_dir_for_variant(&params).expect("user data dir");
            let cache_dir = dir.join("SharedClientCache").join("cache");
            assert!(
                cache_dir.ends_with("SharedClientCache/cache"),
                "unexpected cache dir for {}",
                key
            );
        }
        let ide_dir = qoder_user_data_dir_for_variant(
            &resolve_qoder_variant_params("qoder").expect("qoder params"),
        )
        .expect("ide dir");
        let app_dir = qoder_user_data_dir_for_variant(
            &resolve_qoder_variant_params("qoder_app").expect("app params"),
        )
        .expect("app dir");
        assert_ne!(ide_dir, app_dir);
    }

    #[test]
    fn qoder_cn_ide_direct_login_url_shape() {
        let params = resolve_qoder_variant_params("qoder_cn_ide").expect("cn ide params");
        let url = build_ide_device_login_url_for_variant(
            &params,
            "cn-nonce",
            "cn-challenge",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            Some("cn-machine-id"),
        )
        .expect("cn ide login url");
        let parsed = Url::parse(&url).expect("parse cn ide login url");
        assert_eq!(parsed.host_str(), Some("qoder.cn"));
        assert_eq!(parsed.path(), "/device/selectAccounts");
        let query = parsed
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(query.contains(&("nonce".to_string(), "cn-nonce".to_string())));
        assert!(query.contains(&("challenge".to_string(), "cn-challenge".to_string())));
        assert!(query.contains(&(
            "challenge_method".to_string(),
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string()
        )));
        assert!(query.contains(&(
            "redirect_uri".to_string(),
            QODER_IDE_REDIRECT_URI.to_string()
        )));
        assert!(query.contains(&("sourceType".to_string(), "IDE".to_string())));
        assert!(query.contains(&("machine_id".to_string(), "cn-machine-id".to_string())));
        assert!(
            !query.iter().any(|(key, _)| key == "client_id"),
            "CN IDE client_id unevidenced: omit the param, never guess a value"
        );

        let bare = build_ide_device_login_url_for_variant(
            &params,
            "n",
            "c",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            None,
        )
        .expect("bare cn ide login url");
        let bare_parsed = Url::parse(&bare).expect("parse bare cn ide login url");
        assert_eq!(bare_parsed.path(), "/device/selectAccounts");
        assert!(!bare_parsed.query_pairs().any(|(key, _)| key == "client_id"));
        assert!(!bare_parsed
            .query_pairs()
            .any(|(key, _)| key == "machine_id"));
        assert!(bare_parsed
            .query_pairs()
            .any(|(key, value)| key == "redirect_uri" && value == QODER_IDE_REDIRECT_URI));
        assert!(bare_parsed
            .query_pairs()
            .any(|(key, value)| key == "sourceType" && value == "IDE"));
    }

    #[test]
    fn qoder_cn_ide_variant_params_passthrough() {
        let cn_ide = resolve_qoder_variant_params("qoder_cn_ide").expect("cn ide params");
        assert_eq!(cn_ide.login_mode, QoderVariantLoginMode::IdeDirect);
        assert_eq!(cn_ide.login_base_url, QODER_CN_LOGIN_BASE_URL);
        assert_eq!(cn_ide.openapi_base_url, QODER_CN_OPENAPI_BASE_URL);
        assert_eq!(cn_ide.client_id, None);
        assert_eq!(cn_ide.vendor_channel, Some(QODER_CN_IDE_CHANNEL));
        assert_eq!(cn_ide.vendor_channel, Some("DedicatedQoderCn"));
        assert_eq!(cn_ide.protocol_marker, Some(QODER_CN_IDE_PROTOCOL_MARKER));
        assert_eq!(cn_ide.protocol_marker, Some("qodercn_2_0"));
        assert!(!cn_ide.is_app_line);

        let intl = resolve_qoder_variant_params("qoder").expect("qoder params");
        assert_eq!(intl.vendor_channel, None);
        assert_eq!(intl.protocol_marker, None);
        assert_eq!(intl.client_id, None);
    }

    #[test]
    fn qoder_cn_ide_poll_quad_parse() {
        let happy = r#"{"token":"dt-TEST","user_id":"user-TEST","refresh_token":"drt-TEST","expires_at":"2026-10-24T00:00:00Z","refresh_token_expires_at":"2027-09-24T00:00:00Z"}"#;
        let ready = parse_device_token_poll_response(happy)
            .expect("happy fixture parses")
            .expect("happy fixture is ready");
        assert_eq!(ready.token.as_deref(), Some("dt-TEST"));
        assert_eq!(ready.user_id.as_deref(), Some("user-TEST"));
        assert_eq!(ready.refresh_token.as_deref(), Some("drt-TEST"));
        assert!(ready.expires_at.is_some());
        assert!(ready.refresh_token_expires_at.is_some());

        let pending = r#"{"user_id":null,"token":null}"#;
        assert!(parse_device_token_poll_response(pending)
            .expect("pending fixture parses")
            .is_none());

        assert!(parse_device_token_poll_response("not-json{{{").is_err());
    }

    #[test]
    fn qoder_intl_app_sign_in_url_shape_no_biz_variant() {
        let params = resolve_qoder_variant_params("qoder_app").expect("intl app params");
        assert_eq!(params.login_mode, QoderVariantLoginMode::AppSignIn);
        assert_eq!(params.login_base_url, DEFAULT_LOGIN_BASE_URL);
        assert_eq!(params.openapi_base_url, DEFAULT_OPENAPI_BASE_URL);
        assert_eq!(params.client_id, Some(QODER_APP_SHARED_CLIENT_ID));
        assert_eq!(params.sign_in_biz_variant, None);
        assert_eq!(params.vendor_channel, None);
        assert!(params.is_app_line);

        let url = build_app_sign_in_login_url(
            &params,
            "intl-nonce-1",
            "intl-challenge-1",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            Some("intl-machine-1"),
        )
        .expect("intl app login url");
        let parsed = Url::parse(&url).expect("parse intl app login url");
        assert_eq!(parsed.host_str(), Some("qoder.com"));
        assert_eq!(parsed.path(), QODER_APP_SIGN_IN_PATH);
        let outer = parsed
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(
            !outer.iter().any(|(key, _)| key == "biz_variant"),
            "intl sign-in must not carry biz_variant (evidence: omitted)"
        );
        let callback = outer
            .iter()
            .find(|(key, _)| key == "oauth_callback")
            .map(|(_, value)| value.clone())
            .expect("oauth_callback present");
        let inner = Url::parse(&callback).expect("parse inner selectAccounts");
        assert_eq!(inner.host_str(), Some("qoder.com"));
        assert_eq!(inner.path(), "/device/selectAccounts");
        let inner_query = inner
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(inner_query.contains(&("nonce".to_string(), "intl-nonce-1".to_string())));
        assert!(inner_query.contains(&(
            "challenge".to_string(),
            "intl-challenge-1".to_string()
        )));
        assert!(inner_query.contains(&(
            "challenge_method".to_string(),
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD.to_string()
        )));
        assert!(inner_query.contains(&(
            "client_id".to_string(),
            QODER_APP_SHARED_CLIENT_ID.to_string()
        )));
        assert!(inner_query.contains(&(
            "machine_id".to_string(),
            "intl-machine-1".to_string()
        )));
        assert!(!inner_query.iter().any(|(key, _)| key == "redirect_uri"));
        assert!(!inner_query.iter().any(|(key, _)| key == "biz_variant"));
    }

    #[test]
    fn qoder_intl_app_poll_recorded_fixture_parses_device_set() {
        let happy = r#"{"token":"dt-SYNTH-INTL-001","user_id":"user-SYNTH-INTL-001","refresh_token":"drt-SYNTH-INTL-001","expires_at":"2026-10-24T00:00:00Z","refresh_token_expires_at":"2027-09-24T00:00:00Z","expires_in":2592000,"refresh_token_expires_in":31536000,"id":"dev-SYNTH-001","nonce":"n-SYNTH-001","code_challenge":"c-SYNTH-001","code_challenge_method":"S256"}"#;
        let ready = parse_device_token_poll_response(happy)
            .expect("happy fixture parses")
            .expect("happy fixture is ready");
        assert_eq!(ready.token.as_deref(), Some("dt-SYNTH-INTL-001"));
        assert_eq!(ready.user_id.as_deref(), Some("user-SYNTH-INTL-001"));
        assert_eq!(
            ready.refresh_token.as_deref(),
            Some("drt-SYNTH-INTL-001")
        );
        assert!(ready.expires_at.is_some());
        assert!(ready.refresh_token_expires_at.is_some());

        let raw = build_initial_user_info_raw(&ready, None);
        assert_eq!(
            raw.get("token").and_then(|value| value.as_str()),
            Some("dt-SYNTH-INTL-001")
        );
        assert_eq!(
            raw.get("refreshToken").and_then(|value| value.as_str()),
            Some("drt-SYNTH-INTL-001")
        );
        let expire_ms = raw
            .get("expireTime")
            .and_then(|value| value.as_str())
            .and_then(|text| text.parse::<i64>().ok())
            .expect("expireTime is millis string");
        assert!(expire_ms > 1_000_000_000_000);
    }

    #[test]
    fn qoder_intl_app_poll_status_classes_wait_terminate() {
        assert_eq!(
            classify_poll_http_status(200),
            QoderPollClass::Authorized
        );
        assert_eq!(classify_poll_http_status(404), QoderPollClass::Waiting);
        assert_eq!(
            classify_poll_http_status(401),
            QoderPollClass::NeedsRelogin
        );
        assert_eq!(
            classify_poll_http_status(403),
            QoderPollClass::NeedsRelogin
        );
        assert_eq!(classify_poll_http_status(500), QoderPollClass::Retryable);
        assert_eq!(classify_poll_http_status(429), QoderPollClass::Retryable);
    }

    #[test]
    fn qoder_intl_app_jobtoken_recorded_fixture_parses() {
        let body: Value = serde_json::from_str(
            r#"{"token":"jt-SYNTH-INTL-001","refresh_token":"jrt-SYNTH-INTL-001","expires_in":86400000,"expires_at":"2026-09-25T00:00:00Z","refresh_token_expires_at":"2026-09-26T00:00:00Z","created_at":"2026-09-24T00:00:00Z"}"#,
        )
        .expect("job fixture json");
        let bundle = parse_job_token_body(&body).expect("job fixture parses");
        assert_eq!(bundle.token, "jt-SYNTH-INTL-001");
        assert_eq!(
            bundle.refresh_token.as_deref(),
            Some("jrt-SYNTH-INTL-001")
        );
        assert_eq!(bundle.expires_in_ms.as_deref(), Some("86400000"));

        assert!(parse_job_token_body(&serde_json::json!({
            "refresh_token": "jrt-SYNTH-ORPHAN"
        }))
        .is_err());
    }

    #[test]
    fn qoder_intl_app_exchange_failure_preserves_device_session() {
        let device = parse_device_token_poll_response(
            r#"{"token":"dt-SYNTH-INTL-002","user_id":"user-SYNTH-INTL-002","refresh_token":"drt-SYNTH-INTL-002","expires_at":"2026-10-24T00:00:00Z","refresh_token_expires_at":"2027-09-24T00:00:00Z"}"#,
        )
        .expect("device fixture parses")
        .expect("device fixture is ready");
        let job = parse_job_token_body(&serde_json::json!({
            "token": "jt-SYNTH-INTL-002",
            "refresh_token": "jrt-SYNTH-INTL-002",
            "expires_in": 86400000
        }))
        .expect("job fixture parses");

        let with_job = build_app_login_user_info_raw(&device, Some(&job), None);
        assert_eq!(
            with_job.get("token").and_then(|value| value.as_str()),
            Some("dt-SYNTH-INTL-002")
        );
        assert_eq!(
            with_job.get("job_token").and_then(|value| value.as_str()),
            Some("jt-SYNTH-INTL-002")
        );
        assert_eq!(
            with_job
                .get("job_refresh_token")
                .and_then(|value| value.as_str()),
            Some("jrt-SYNTH-INTL-002")
        );

        let device_only = build_app_login_user_info_raw(&device, None, None);
        assert_eq!(
            device_only.get("token").and_then(|value| value.as_str()),
            Some("dt-SYNTH-INTL-002")
        );
        assert_eq!(
            device_only
                .get("refreshToken")
                .and_then(|value| value.as_str()),
            Some("drt-SYNTH-INTL-002")
        );
        assert!(device_only.get("job_token").is_none());
    }

    #[test]
    fn qoder_intl_app_dual_refresh_recorded_fixtures_parse() {
        let device_body: Value = serde_json::from_str(
            r#"{"device_token":"dt-SYNTH-INTL-003","refresh_token":"drt-SYNTH-INTL-003","token_type":"Bearer","expires_at":"2026-10-24T00:00:00Z","refresh_token_expires_at":"2027-09-24T00:00:00Z","created_at":"2026-09-24T00:00:00Z"}"#,
        )
        .expect("device refresh fixture json");
        let refreshed_device =
            parse_device_refresh_body(&device_body).expect("device refresh parses");
        assert_eq!(refreshed_device.token, "dt-SYNTH-INTL-003");
        assert_eq!(
            refreshed_device.refresh_token.as_deref(),
            Some("drt-SYNTH-INTL-003")
        );
        assert!(refreshed_device.expires_at.is_some());

        let job_body: Value = serde_json::from_str(
            r#"{"token":"jt-SYNTH-INTL-003","refresh_token":"jrt-SYNTH-INTL-003","expires_in":86400000}"#,
        )
        .expect("job refresh fixture json");
        let refreshed_job = parse_job_refresh_body(&job_body).expect("job refresh parses");
        assert_eq!(refreshed_job.token, "jt-SYNTH-INTL-003");
        assert_eq!(
            refreshed_job.refresh_token.as_deref(),
            Some("jrt-SYNTH-INTL-003")
        );

        assert!(is_refresh_token_invalid_status(400));
        assert!(is_refresh_token_invalid_status(401));
        assert!(!is_refresh_token_invalid_status(403));
        assert!(!is_refresh_token_invalid_status(404));
        assert!(!is_refresh_token_invalid_status(500));
    }

    fn cn_app_quad_fixture() -> &'static str {
        r#"{"id":"01a0d218-fake0001-fake-fake-000000000001","token":"dt-fakebody000000000000000001","user_id":"01a0d20d-fake0002-fake-fake-000000000002","code_challenge":"fakechallenge43chars000000000000000000000","code_challenge_method":"S256","nonce":"36a6c4a1-fake0003-fake-fake-000000000003","refresh_token_id":"f3a0d218-fake0004-fake-fake-000000000004","refresh_token":"drt-fakebody00000000000000001","created_at":"2026-09-24T06:26:23Z","updated_at":"2026-09-24T06:26:23Z","expires_at":"2026-10-24T06:26:23Z"}"#
    }

    fn cn_app_job_fixture() -> Value {
        serde_json::from_str(
            r#"{"token":"jt-fakebody000000000000000001","created_at":"2026-09-24T06:26:24Z","expires_at":"2026-09-25T06:26:24Z","expires_in":86400000,"refresh_token":"jrt-fakebody0000000000000001","refresh_token_expires_at":"2026-09-26T06:26:24Z","refresh_token_expires_in":172800000}"#,
        )
        .expect("cn job fixture json")
    }

    #[test]
    fn qoder_cn_app_oauth_sign_in_url_shape() {
        let params = resolve_qoder_variant_params("qoder_cn_app").expect("cn app params");
        assert_eq!(params.login_mode, QoderVariantLoginMode::AppSignIn);
        assert_eq!(params.login_base_url, QODER_CN_LOGIN_BASE_URL);
        assert_eq!(params.openapi_base_url, QODER_CN_OPENAPI_BASE_URL);
        assert_eq!(params.client_id, Some(QODER_APP_SHARED_CLIENT_ID));
        assert_eq!(params.sign_in_biz_variant, Some("qoder"));
        assert_eq!(params.vendor_channel, Some("qoder-cn"));
        assert!(params.is_app_line);

        let url = build_app_sign_in_login_url(
            &params,
            "cn-nonce-36-fake-0001-aaaaaaaaaaaa",
            "cn-challenge-fake-43-aaaaaaaaaaaaaaaaaaaaaaaaaaa",
            QODER_DEVICE_LOGIN_CHALLENGE_METHOD,
            Some("cn-machine-1"),
        )
        .expect("cn app login url");
        let parsed = Url::parse(&url).expect("parse cn app login url");
        assert_eq!(parsed.host_str(), Some("qoder.cn"));
        assert_eq!(parsed.path(), "/users/sign-in");
        let outer = parsed
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(outer.contains(&("biz_variant".to_string(), "qoder".to_string())));
        assert!(!outer.iter().any(|(key, _)| key == "redirect_uri"));
        assert!(!outer.iter().any(|(key, _)| key == "client_id"));
        let callback = outer
            .iter()
            .find(|(key, _)| key == "oauth_callback")
            .map(|(_, value)| value.clone())
            .expect("oauth_callback present");
        assert!(callback.contains("selectAccounts"));
        let inner = Url::parse(&callback).expect("parse inner selectAccounts");
        assert_eq!(inner.host_str(), Some("qoder.cn"));
        assert_eq!(inner.path(), "/device/selectAccounts");
        let inner_query = inner
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();
        assert!(inner_query.contains(&(
            "client_id".to_string(),
            "732aef47-9cf2-46a2-95fe-4cebb5d0d1fa".to_string()
        )));
        assert!(!inner_query.iter().any(|(key, _)| key == "redirect_uri"));
        for key in ["nonce", "challenge", "challenge_method", "machine_id"] {
            assert!(
                inner_query.iter().any(|(k, _)| k == key),
                "inner url missing {key}"
            );
        }
    }

    #[test]
    fn qoder_cn_app_oauth_device_quad_parse_and_expiry() {
        let quad = parse_device_token_poll_response(cn_app_quad_fixture())
            .expect("quad fixture parses")
            .expect("quad fixture is ready");
        for (field, value) in [
            ("id", quad.id.as_deref()),
            ("token", quad.token.as_deref()),
            ("user_id", quad.user_id.as_deref()),
            ("code_challenge", quad.code_challenge.as_deref()),
            ("code_challenge_method", quad.code_challenge_method.as_deref()),
            ("nonce", quad.nonce.as_deref()),
            ("refresh_token_id", quad.refresh_token_id.as_deref()),
            ("refresh_token", quad.refresh_token.as_deref()),
            ("created_at", quad.created_at.as_deref()),
            ("updated_at", quad.updated_at.as_deref()),
            ("expires_at", quad.expires_at.as_deref()),
        ] {
            assert!(value.is_some(), "quad field {field} must parse");
        }
        validate_cn_app_device_quad(&quad).expect("synthetic quad validates");
        let days = cn_app_quad_validity_days(&quad).expect("quad duration parses");
        assert!(
            (29.0..=31.0).contains(&days),
            "device validity must be ~30d, got {days}"
        );

        let pending = parse_device_token_poll_response(r#"{"user_id":null,"token":null}"#)
            .expect("pending parses");
        assert!(pending.is_none(), "pending poll must stay waiting");

        let mut bad_prefix = parse_device_token_poll_response(cn_app_quad_fixture())
            .expect("parses")
            .expect("ready");
        bad_prefix.token = Some("at-fakebody000000000000000001".to_string());
        assert!(validate_cn_app_device_quad(&bad_prefix).is_err());

        let mut bad_method = parse_device_token_poll_response(cn_app_quad_fixture())
            .expect("parses")
            .expect("ready");
        bad_method.code_challenge_method = Some("plain".to_string());
        assert!(validate_cn_app_device_quad(&bad_method).is_err());
        assert!(parse_device_token_poll_response("not-json{{{").is_err());
    }

    #[test]
    fn qoder_cn_app_oauth_job_token_parse_and_24h() {
        let body = cn_app_job_fixture();
        let bundle = parse_job_token_body(&body).expect("job fixture parses");
        assert!(bundle.token.starts_with("jt-"));
        assert!(bundle
            .refresh_token
            .as_deref()
            .is_some_and(|value| value.starts_with("jrt-")));
        assert_eq!(bundle.expires_in_ms.as_deref(), Some("86400000"));
        validate_cn_app_job_token_body(&body).expect("24h job validates");

        let wrong_window =
            serde_json::json!({"token": "jt-fake000000000000000000000001", "expires_in": 3600000});
        assert!(validate_cn_app_job_token_body(&wrong_window).is_err());
        let missing_token = serde_json::json!({"refresh_token": "jrt-fake00000000000000001"});
        assert!(parse_job_token_body(&missing_token).is_err());
        assert!(validate_cn_app_job_token_body(&missing_token).is_err());
    }

    #[test]
    fn qoder_cn_app_oauth_poll_and_refresh_status_branches() {
        assert_eq!(
            classify_poll_http_status(200),
            QoderPollClass::Authorized
        );
        assert_eq!(classify_poll_http_status(404), QoderPollClass::Waiting);
        assert_eq!(
            classify_poll_http_status(401),
            QoderPollClass::NeedsRelogin
        );
        assert_eq!(
            classify_poll_http_status(403),
            QoderPollClass::NeedsRelogin
        );
        assert_eq!(classify_poll_http_status(500), QoderPollClass::Retryable);

        assert!(is_refresh_token_invalid_status(400));
        assert!(is_refresh_token_invalid_status(401));
        assert!(!is_refresh_token_invalid_status(403));
        assert!(!is_refresh_token_invalid_status(500));

        assert!(qoder_error_requires_relogin(
            "Qoder App token 刷新被拒绝 (/api/v1/deviceToken/refresh: status=401)，refresh token 已失效，请重新登录"
        ));
        assert!(!qoder_error_requires_relogin(
            "刷新 Qoder App token 失败 (/api/v1/deviceToken/refresh): status=500, body_len=12"
        ));
    }

    #[test]
    fn qoder_cn_app_oauth_exchange_failure_preserves_device() {
        let device = parse_device_token_poll_response(cn_app_quad_fixture())
            .expect("device parses")
            .expect("device ready");
        let job = parse_job_token_body(&cn_app_job_fixture()).expect("job parses");

        let with_job = build_app_login_user_info_raw(&device, Some(&job), None);
        assert!(with_job
            .get("token")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("dt-")));
        assert!(with_job
            .get("job_token")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("jt-")));
        assert!(with_job
            .get("job_refresh_token")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("jrt-")));
        assert_eq!(
            with_job
                .get("job_token_expires_in")
                .and_then(|value| value.as_str()),
            Some("86400000")
        );

        let device_only = build_app_login_user_info_raw(&device, None, None);
        assert!(device_only
            .get("token")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("dt-")));
        assert!(device_only
            .get("refreshToken")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.starts_with("drt-")));
        assert!(device_only.get("job_token").is_none());
        assert!(device_only.get("job_refresh_token").is_none());
        let expire_ms = device_only
            .get("expireTime")
            .and_then(|value| value.as_str())
            .and_then(|text| text.parse::<i64>().ok())
            .expect("expireTime is millis string");
        assert!(expire_ms > 1_000_000_000_000);
    }

    #[test]
    fn qoder_cn_app_oauth_dual_refresh_bodies_parse_and_apply() {
        let device_body: Value = serde_json::from_str(
            r#"{"device_token":"dt-fakebody000000000000000009","refresh_token":"drt-fakebody00000000000000009","token_type":"Bearer","expires_at":"2026-10-24T08:50:31Z","refresh_token_expires_at":"2027-09-19T08:50:31Z","created_at":"2026-09-24T08:50:31Z"}"#,
        )
        .expect("device refresh fixture json");
        let refreshed_device =
            parse_device_refresh_body(&device_body).expect("device refresh parses");
        assert!(refreshed_device.token.starts_with("dt-"));
        assert!(refreshed_device
            .refresh_token
            .as_deref()
            .is_some_and(|value| value.starts_with("drt-")));

        let job_body: Value = serde_json::from_str(
            r#"{"token":"jt-fakebody000000000000000009","refresh_token":"jrt-fakebody00000000000000009","expires_in":86400000}"#,
        )
        .expect("job refresh fixture json");
        let refreshed_job = parse_job_refresh_body(&job_body).expect("job refresh parses");
        assert!(refreshed_job.token.starts_with("jt-"));

        assert!(parse_device_refresh_body(&serde_json::json!({"token_type": "Bearer"})).is_err());
        assert!(parse_job_refresh_body(&serde_json::json!({"expires_in": 86400000})).is_err());

        let mut user_info =
            build_app_login_user_info_raw(
                &parse_device_token_poll_response(cn_app_quad_fixture())
                    .expect("parses")
                    .expect("ready"),
                None,
                None,
            );
        apply_refreshed_device_token(&mut user_info, &refreshed_device);
        assert_eq!(
            user_info.get("token").and_then(|value| value.as_str()),
            Some("dt-fakebody000000000000000009")
        );
        assert_eq!(
            user_info
                .get("refreshToken")
                .and_then(|value| value.as_str()),
            Some("drt-fakebody00000000000000009")
        );
        apply_refreshed_job_token(&mut user_info, &refreshed_job);
        assert_eq!(
            user_info
                .get("job_token")
                .and_then(|value| value.as_str()),
            Some("jt-fakebody000000000000000009")
        );

        let (device_drt, job_jrt) = extract_cn_app_stored_refresh_tokens(&user_info);
        assert!(device_drt.is_some_and(|value| value.starts_with("drt-")));
        assert!(job_jrt.is_some_and(|value| value.starts_with("jrt-")));
        let (no_device, no_job) =
            extract_cn_app_stored_refresh_tokens(&serde_json::json!({"token": "dt-x"}));
        assert!(no_device.is_none());
        assert!(no_job.is_none());
    }

    #[test]
    fn qoder_cn_app_oauth_verifier_charset_lengths() {
        let cn_app = resolve_qoder_variant_params("qoder_cn_app").expect("cn app params");
        let app_verifier = generate_verifier_for_variant(&cn_app);
        assert_eq!(app_verifier.len(), 64);
        assert!(
            app_verifier
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || "-._~".contains(ch)),
            "app verifier must be PKCE unreserved"
        );
        let ide = resolve_qoder_variant_params("qoder").expect("qoder params");
        let ide_verifier = generate_verifier_for_variant(&ide);
        assert_eq!(ide_verifier.len(), 43);
        let challenge = generate_pkce_challenge(&app_verifier);
        assert_eq!(challenge.len(), 43);

        assert_eq!(
            mask_token_for_log("dt-fakebody000000000000000001"),
            "dt-fake…0001 len=29"
        );
        assert_eq!(mask_token_for_log("short"), "***");
    }

    fn t7_frozen_account_fixture() -> crate::models::qoder::QoderAccount {
        crate::models::qoder::QoderAccount {
            shared_refresh_token: None,
            client_auth: HashMap::new(),
            legacy_ids: Vec::new(),
            id: "qoder-t7-frozen-001".to_string(),
            variant: None,
            email: "frozen@example.invalid".to_string(),
            user_id: Some("019c56-SYNTH-FROZEN-001".to_string()),
            display_name: Some("Frozen User".to_string()),
            plan_type: Some("personal_standard".to_string()),
            credits_used: Some(100.0),
            credits_total: Some(200.0),
            credits_remaining: Some(100.0),
            credits_usage_percent: Some(50.0),
            quota_query_last_error: None,
            quota_query_last_error_at: None,
            usage_updated_at: Some(1790230239000),
            tags: None,
            auth_user_info_raw: Some(serde_json::json!({
                "id": "019c56-SYNTH-FROZEN-001",
                "token": "dt-SYNTH-FROZEN-001",
                "securityOauthToken": "dt-SYNTH-FROZEN-001",
                "email": "frozen@example.invalid",
                "name": "Frozen User"
            })),
            auth_user_plan_raw: Some(serde_json::json!({"plan": "personal_standard"})),
            auth_credit_usage_raw: Some(serde_json::json!({
                "displayMode": "qoder",
                "qoderUsage": {
                    "userId": "019c56-SYNTH-FROZEN-001",
                    "userType": "personal_standard",
                    "usageType": "credits",
                    "totalUsagePercentage": 0.5,
                    "isQuotaExceeded": false,
                    "expiresAt": 253402214400000_i64,
                    "userQuota": {"total": 0, "used": 0, "remaining": 0, "percentage": 0, "unit": "credits"},
                    "addOnQuota": {"total": 200, "used": 100, "remaining": 100, "percentage": 0.5, "unit": "credits"}
                }
            })),
            reward_claim_status: None,
            reward_window_end_at: None,
            reward_status_updated_at: None,
            web_session_cookie: None,
            web_quota_raw: None,
            web_quota_updated_at: None,
            created_at: 1790230239000,
            last_used: 1790230239000,
        }
    }

    const FROZEN_ACCOUNT_JSON: &str = r#"{
  "id": "qoder-t7-frozen-001",
  "email": "frozen@example.invalid",
  "user_id": "019c56-SYNTH-FROZEN-001",
  "display_name": "Frozen User",
  "plan_type": "personal_standard",
  "credits_used": 100.0,
  "credits_total": 200.0,
  "credits_remaining": 100.0,
  "credits_usage_percent": 50.0,
  "usage_updated_at": 1790230239000,
  "auth_user_info_raw": {
    "email": "frozen@example.invalid",
    "id": "019c56-SYNTH-FROZEN-001",
    "name": "Frozen User",
    "securityOauthToken": "dt-SYNTH-FROZEN-001",
    "token": "dt-SYNTH-FROZEN-001"
  },
  "auth_user_plan_raw": {
    "plan": "personal_standard"
  },
  "auth_credit_usage_raw": {
    "displayMode": "qoder",
    "qoderUsage": {
      "addOnQuota": {
        "percentage": 0.5,
        "remaining": 100,
        "total": 200,
        "unit": "credits",
        "used": 100
      },
      "expiresAt": 253402214400000,
      "isQuotaExceeded": false,
      "totalUsagePercentage": 0.5,
      "usageType": "credits",
      "userId": "019c56-SYNTH-FROZEN-001",
      "userQuota": {
        "percentage": 0,
        "remaining": 0,
        "total": 0,
        "unit": "credits",
        "used": 0
      },
      "userType": "personal_standard"
    }
  },
  "created_at": 1790230239000,
  "last_used": 1790230239000
}"#;

    #[test]
    fn qoder_ide_quota_frozen_account_json() {
        let pretty = serde_json::to_string_pretty(&t7_frozen_account_fixture())
            .expect("serialize frozen account");
        assert_eq!(pretty, FROZEN_ACCOUNT_JSON);
    }

    fn t7_sash_intl_fixture() -> Value {
        serde_json::json!({
            "displayMode": "qoder",
            "qoderUsage": {
                "userId": "019c56-SYNTH-FROZEN-INTL",
                "userType": "personal_standard",
                "usageType": "credits",
                "totalUsagePercentage": 0.5,
                "isQuotaExceeded": false,
                "expiresAt": 253402214400000_i64,
                "upgradeUrl": "https://qoder.com/pricing?client=qoder",
                "userQuota": {"total": 0, "used": 0, "remaining": 0, "percentage": 0, "unit": "credits"},
                "addOnQuota": {"total": 200, "used": 100, "remaining": 100, "percentage": 0.5, "unit": "credits"},
                "isPlanQuotaProrated": false
            }
        })
    }

    fn t7_sash_cn_fixture() -> Value {
        serde_json::json!({
            "displayMode": "qoder",
            "qoderUsage": {
                "userId": "01a0ba-SYNTH-FROZEN-CN",
                "userType": "personal_professional_trial",
                "usageType": "credits",
                "totalUsagePercentage": 0.01,
                "isQuotaExceeded": false,
                "expiresAt": 1791041092084_i64,
                "userQuota": {"total": 300, "used": 6, "remaining": 294, "percentage": 0.03, "unit": "credits"},
                "addOnQuota": {"total": 500, "used": 0, "remaining": 500, "percentage": 0, "unit": "credits"}
            }
        })
    }

    #[test]
    fn app_usage_with_dedicated_packages_does_not_require_legacy_summary_fields() {
        let body = serde_json::json!({"displayMode": "qoder", "qoderUsage": {
            "userType": "personal_standard",
            "userQuota": {"total": 300, "used": 20},
            "addOnQuota": {"total": 100, "used": 0},
            "dedicatedResourcePackages": [{"id": "fixture-package", "total": 60, "used": 10}]
        }});
        assert!(validate_sash_usage_schema(&body).is_ok());
        let mut invalid = body.clone();
        invalid["qoderUsage"]["userQuota"]["used"] = serde_json::json!(-1);
        assert!(validate_sash_usage_schema(&invalid).is_err());
        invalid = body;
        invalid["qoderUsage"]["dedicatedResourcePackages"] = serde_json::json!({});
        assert!(validate_sash_usage_schema(&invalid).is_err());
    }

    #[test]
    fn qoder_ide_sash_usage_recorded_fixture_parses() {
        for body in [t7_sash_intl_fixture(), t7_sash_cn_fixture()] {
            validate_sash_usage_schema(&body).expect("live-proven sash shape parses");
            let usage = body.get("qoderUsage").expect("qoderUsage present");
            for bucket in ["userQuota", "addOnQuota"] {
                let node = usage.get(bucket).expect("quota bucket present");
                for field in ["total", "used", "remaining"] {
                    assert!(
                        node.get(field).is_some_and(|value| value.is_number()),
                        "sash field qoderUsage.{bucket}.{field} must parse"
                    );
                }
            }
            assert!(usage.get("isQuotaExceeded").is_some());
            assert!(usage.get("expiresAt").is_some());
        }

        let mut with_unknown = t7_sash_intl_fixture();
        with_unknown
            .as_object_mut()
            .expect("sash body is object")
            .insert(
                "futureUnknownTopLevel".to_string(),
                serde_json::json!({"x": 1}),
            );
        with_unknown
            .get_mut("qoderUsage")
            .and_then(|value| value.as_object_mut())
            .expect("qoderUsage is object")
            .insert(
                "futureUnknownNested".to_string(),
                serde_json::json!([1, 2, 3]),
            );
        validate_sash_usage_schema(&with_unknown).expect("unknown extra fields are ignored");

        assert!(validate_sash_usage_schema(&serde_json::json!({"displayMode": "qoder"})).is_err());
        assert!(validate_sash_usage_schema(
            &serde_json::json!({"qoderUsage": {"isQuotaExceeded": false, "expiresAt": 1}})
        )
        .is_err());
        let mut missing_used = t7_sash_cn_fixture();
        missing_used
            .get_mut("qoderUsage")
            .and_then(|value| value.get_mut("userQuota"))
            .and_then(|value| value.as_object_mut())
            .expect("userQuota is object")
            .remove("used");
        assert!(validate_sash_usage_schema(&missing_used).is_err());
    }

    fn t7_read_mock_request_head(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.windows(4).any(|w| w == b"\r\n\r\n") || raw.len() > 8192 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    fn t7_mock_response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            status,
            body.len(),
            body
        )
    }

    #[test]
    fn qoder_ide_sash_fallback_on_500_uses_legacy() {
        use std::io::Write;
        let legacy_body = r#"{"credits":{"total":200,"used":100,"remaining":100}}"#;
        let legacy_owned = legacy_body.to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock openapi");
        let addr = listener.local_addr().expect("mock addr");
        let server = std::thread::spawn(move || {
            let mut heads = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept mock conn");
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("set read timeout");
                heads.push(t7_read_mock_request_head(&mut stream));
                let is_sash = heads
                    .last()
                    .is_some_and(|head| head.contains(QODER_SASH_USAGE_PATH));
                let response = if is_sash {
                    t7_mock_response("500 Internal Server Error", r#"{"error":"boom"}"#)
                } else {
                    t7_mock_response("200 OK", &legacy_owned)
                };
                stream
                    .write_all(response.as_bytes())
                    .expect("write mock response");
            }
            heads
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let (result, params) = rt.block_on(async {
            let params = resolve_qoder_variant_params(QODER_VARIANT_QODER).expect("qoder params");
            let client = build_reqwest_client().expect("test client");
            let base = format!("http://{}", addr);
            let out =
                fetch_qoder_credit_usage(&client, &params, &base, "dt-SYNTH-FROZEN-001", None).await;
            (out, params)
        });
        let heads = server.join().expect("mock server joins");
        assert_eq!(heads.len(), 2);

        let body = result.expect("sash 500 must fall back to legacy");
        assert_eq!(
            body,
            serde_json::from_str::<Value>(legacy_body).expect("legacy fixture json")
        );

        let sash_head = heads
            .iter()
            .find(|head| head.contains(QODER_SASH_USAGE_PATH))
            .expect("sash primary was requested");
        let sash_lower = sash_head.to_ascii_lowercase();
        assert!(sash_lower.contains("get /sash/api/v2/me/usage"));
        assert!(sash_lower.contains("authorization: bearer dt-synth-frozen-001"));
        assert!(sash_lower.contains("cosy-clienttype: 10"));
        assert!(sash_lower.contains("user-agent: qoder"));

        let legacy_head = heads
            .iter()
            .find(|head| head.contains(CREDIT_USAGE_PATH))
            .expect("legacy fallback was requested");
        let legacy_lower = legacy_head.to_ascii_lowercase();
        assert!(legacy_lower.contains("get /api/v2/quota/usage"));
        assert!(legacy_lower.contains("cosy-clienttype: 0"));
        assert!(legacy_lower.contains("authorization: bearer dt-synth-frozen-001"));
        assert_eq!(params.openapi_base_url, DEFAULT_OPENAPI_BASE_URL);
    }

    #[test]
    fn qoder_t8_mask_token_char_boundary_safe() {
        assert_eq!(
            mask_token_for_log("abcdefgQUIJ你好世界"),
            "abcdefg…你好世界 len=15"
        );
        assert_eq!(
            mask_token_for_log("🔑🔑abcdefg1234567890"),
            "🔑🔑abcde…7890 len=19"
        );
        assert_eq!(mask_token_for_log("123456789012"), "***");
        assert_eq!(mask_token_for_log("1234567890123"), "1234567…0123 len=13");
        assert_eq!(mask_token_for_log("drt-🔑"), "***");
        assert_eq!(mask_token_for_log(""), "***");
    }

    #[test]
    fn qoder_t8_sash_quota_reuses_t7_canonical_leg() {
        // 复用既有 sash 主链路：合法 `qoderUsage` 形状通过校验，垃圾数据不通过。
        validate_sash_usage_schema(&serde_json::json!({
            "qoderUsage": {
                "userQuota": {"total": 300, "used": 6, "remaining": 294},
                "addOnQuota": {"total": 500, "used": 0, "remaining": 500},
                "isQuotaExceeded": false,
                "expiresAt": 253402214400000_i64,
            }
        }))
        .expect("recorded sash shape validates");
        assert!(validate_sash_usage_schema(&serde_json::json!({"expiresAt": 1})).is_err());
        assert!(validate_sash_usage_schema(&serde_json::json!([1, 2])).is_err());
        // 共享常量：sash 路径唯一定义。
        assert_eq!(QODER_SASH_USAGE_PATH, "/sash/api/v2/me/usage");
    }

    #[test]
    fn qoder_t8_sash_quota_per_variant_hosts() {
        for key in [
            QODER_VARIANT_QODER_APP,
            QODER_VARIANT_QODER_CN_IDE,
            QODER_VARIANT_QODER_CN_APP,
        ] {
            let params = resolve_qoder_variant_params(key).expect("variant params");
            let url = format!("{}{}", params.openapi_base_url, QODER_SASH_USAGE_PATH);
            assert!(url.ends_with(QODER_SASH_USAGE_PATH));
            let headers = build_qoder_app_usage_headers("dt-SYNTH-USAGE");
            assert_eq!(headers["cosy-clienttype"], "10");
            assert_eq!(
                headers
                    .get("user-agent")
                    .and_then(|value| value.to_str().ok()),
                Some(QODER_APP_USAGE_USER_AGENT)
            );
            assert_eq!(
                headers.get("authorization").map(|value| value.to_str().ok()),
                Some(Some("Bearer dt-SYNTH-USAGE"))
            );
        }
        let app_params =
            resolve_qoder_variant_params(QODER_VARIANT_QODER_APP).expect("app params");
        let cn_params =
            resolve_qoder_variant_params(QODER_VARIANT_QODER_CN_APP).expect("cn app params");
        let intl = format!("{}{}", app_params.openapi_base_url, QODER_SASH_USAGE_PATH);
        let cn = format!("{}{}", cn_params.openapi_base_url, QODER_SASH_USAGE_PATH);
        assert!(intl.starts_with("https://openapi.qoder.sh"));
        assert!(cn.starts_with("https://openapi.qoder.com.cn"));
        assert_ne!(intl, cn);
    }

    #[test]
    fn qoder_t8_refresh_dispatch_guards() {
        for key in [
            QODER_VARIANT_QODER_APP,
            QODER_VARIANT_QODER_CN_IDE,
            QODER_VARIANT_QODER_CN_APP,
        ] {
            check_variant_refresh_route(key, false).expect("device line routes");
            assert!(variant_supports_device_refresh(key));
        }
        for key in [QODER_VARIANT_QODER_APP, QODER_VARIANT_QODER_CN_APP] {
            check_variant_refresh_route(key, true).expect("app job line routes");
            assert!(variant_supports_job_line(key));
        }
        check_variant_refresh_route(QODER_VARIANT_QODER, false).expect("international IDE shares device RT");
        assert!(variant_supports_device_refresh(QODER_VARIANT_QODER));
        assert!(check_variant_refresh_route(QODER_VARIANT_QODER, true).is_err());
        assert!(!variant_supports_job_line(QODER_VARIANT_QODER));
        let ide_job = check_variant_refresh_route(QODER_VARIANT_QODER_CN_IDE, true)
            .expect_err("ide has no job line");
        assert!(ide_job.contains("IDE"));
        assert!(check_variant_refresh_route("qoder_eu", false).is_err());
        assert!(check_variant_refresh_route("qoder_eu", true).is_err());

        let strict_device = serde_json::json!({"refreshToken": "drt-SYNTH-USAGE-001"});
        assert!(extract_variant_device_refresh_token(
            &strict_device,
            QODER_VARIANT_QODER_CN_APP
        )
        .is_some());
        let odd_device = serde_json::json!({"refreshToken": "opaque-ide-refresh-001"});
        assert!(extract_variant_device_refresh_token(
            &odd_device,
            QODER_VARIANT_QODER_CN_APP
        )
        .is_none());
        assert!(extract_variant_device_refresh_token(
            &odd_device,
            QODER_VARIANT_QODER_CN_IDE
        )
        .is_some());
        assert!(extract_variant_device_refresh_token(
            &odd_device,
            QODER_VARIANT_QODER_APP
        )
        .is_some());
        let strict_job = serde_json::json!({"job_refresh_token": "jrt-SYNTH-USAGE-001"});
        assert!(extract_variant_job_refresh_token(
            &strict_job,
            QODER_VARIANT_QODER_CN_APP
        )
        .is_some());
        assert!(extract_variant_job_refresh_token(
            &strict_job,
            QODER_VARIANT_QODER_APP
        )
        .is_some());
        let empty = serde_json::json!({"token": "dt-x"});
        assert!(extract_variant_device_refresh_token(
            &empty,
            QODER_VARIANT_QODER_CN_IDE
        )
        .is_none());
        assert!(
            extract_variant_job_refresh_token(&empty, QODER_VARIANT_QODER_APP).is_none()
        );
    }

    #[test]
    fn qoder_t8_refresh_invalid_marks_relogin_never_silent() {
        assert!(is_refresh_token_invalid_status(400));
        assert!(is_refresh_token_invalid_status(401));
        for path in [QODER_APP_DEVICE_REFRESH_PATH, QODER_APP_JOB_REFRESH_PATH] {
            for status in [400, 401] {
                let err = format!(
                    "Qoder App token 刷新被拒绝 ({path}: status={status})，refresh token 已失效，请重新登录"
                );
                assert!(
                    qoder_error_requires_relogin(&err),
                    "line {path} status {status} must mark relogin"
                );
            }
            let transient =
                format!("刷新 Qoder App token 失败 ({path}): status=500, body_len=12");
            assert!(!qoder_error_requires_relogin(&transient));
        }
    }

    #[test]
    fn qoder_cn_app_oauth_variant_account_route() {
        for key in ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"] {
            let kind =
                crate::modules::qoder_account::check_qoder_variant_account_route(key)
                    .expect("known variant routes");
            assert_eq!(kind.provider_key(), key);
        }
        let err = crate::modules::qoder_account::check_qoder_variant_account_route("qoder_eu")
            .expect_err("unknown variant must not route");
        assert!(err.contains("qoder_eu"));
        let upsert_err = crate::modules::qoder_account::upsert_account_from_snapshot_for_variant(
            "qoder_eu",
            serde_json::json!({"token": "dt-fake"}),
            None,
            None,
        )
        .expect_err("unknown variant must not upsert");
        assert!(upsert_err.contains("qoder_eu"));
    }

    #[test]
    fn qoder_variant_product_base_paths_use_variant_custom_path() {
        let custom = "/tmp/cockpit-custom-qoder-app";
        let custom_path = PathBuf::from(custom);

        for kind in [
            QoderVariantKind::Qoder,
            QoderVariantKind::QoderApp,
            QoderVariantKind::QoderCnIde,
            QoderVariantKind::QoderCnApp,
        ] {
            let paths = build_variant_product_base_paths(kind, custom);
            assert_eq!(paths.first(), Some(&custom_path));
            #[cfg(target_os = "macos")]
            for candidate in qoder_platform_paths::macos_exec_candidates(kind) {
                assert!(
                    paths.contains(&candidate),
                    "table candidate missing for {kind:?}: {candidate:?}"
                );
            }
        }

        let blank = build_variant_product_base_paths(QoderVariantKind::QoderApp, "   ");
        assert!(!blank.iter().any(|p| p == &custom_path));
    }

    #[test]
    fn qoder_security_mobile_captured_from_user_info() {
        let device: QoderDeviceTokenPollResult = serde_json::from_value(serde_json::json!({
            "token": "dt-SYNTH",
            "user_id": "u-SYNTH"
        }))
        .expect("device fixture");
        let response = serde_json::json!({
            "name": "nick",
            "email": "nick@example.com",
            "security_mobile": "13800001111"
        });
        let raw = build_initial_user_info_raw(&device, Some(&response));
        assert_eq!(raw.get("security_mobile"), Some(&Value::String("13800001111".into())));

        let app_raw = build_app_login_user_info_raw(&device, None, Some(&response));
        assert_eq!(
            app_raw.get("security_mobile"),
            Some(&Value::String("13800001111".into()))
        );
    }

    #[test]
    fn qoder_security_mobile_merge_is_key_scoped_and_idempotent() {
        let mut user_info = serde_json::json!({ "id": "u1", "token": "dt-x" });
        let response = serde_json::json!({ "security_mobile": "13800001111", "email": "e@x" });
        assert!(merge_security_mobile(&mut user_info, &response));
        assert_eq!(user_info.get("security_mobile"), Some(&Value::String("13800001111".into())));
        assert_eq!(user_info.get("id"), Some(&Value::String("u1".into())));
        assert_eq!(user_info.get("token"), Some(&Value::String("dt-x".into())));
        assert!(user_info.get("email").is_none());
        assert!(!user_info_missing_security_mobile(&user_info));

        assert!(!merge_security_mobile(
            &mut user_info,
            &serde_json::json!({ "security_mobile": "   " })
        ));
        assert!(!merge_security_mobile(
            &mut user_info,
            &serde_json::json!({ "security_mobile": 12345 })
        ));
    }

    #[test]
    fn qoder_security_mobile_missing_detection() {
        assert!(user_info_missing_security_mobile(&serde_json::json!({ "id": "u1" })));
        assert!(user_info_missing_security_mobile(
            &serde_json::json!({ "security_mobile": "  " })
        ));
        assert!(user_info_missing_security_mobile(
            &serde_json::json!({ "security_mobile": 7 })
        ));
        assert!(!user_info_missing_security_mobile(
            &serde_json::json!({ "security_mobile": "13800001111" })
        ));
    }

    #[test]
    fn qoder_claim_headers_match_contract() {
        let headers = build_qoder_claim_headers(
            QoderVariantKind::Qoder,
            "https://openapi.qoder.sh",
            "dt-SYNTH-TOKEN-123",
            None,
        );
        assert_eq!(
            headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer dt-SYNTH-TOKEN-123")
        );
        assert_eq!(
            headers.get("cosy-clienttype").and_then(|v| v.to_str().ok()),
            Some("10")
        );
        assert_eq!(
            headers.get("origin").and_then(|v| v.to_str().ok()),
            Some("https://openapi.qoder.sh/growth-page/activity-iframe")
        );
        assert_eq!(
            headers.get("referer").and_then(|v| v.to_str().ok()),
            Some("https://openapi.qoder.sh/growth-page/activity-iframe")
        );
    }
}
