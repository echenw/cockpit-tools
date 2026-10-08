use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::models::qoder::{QoderAccount, QoderAccountIndex};
use crate::modules::qoder_variant::{all_qoder_variant_kinds, QoderVariantKind};
use crate::modules::{account, logger};

const ACCOUNTS_INDEX_FILE: &str = "qoder_accounts.json";
const ACCOUNTS_DIR: &str = "qoder_accounts";

const QODER_QUOTA_ALERT_COOLDOWN_SECONDS: i64 = 10 * 60;

static QODER_QUOTA_ALERT_LAST_SENT: std::sync::LazyLock<Mutex<HashMap<String, i64>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const QODER_SECRET_USER_INFO_KEY: &str = "secret://aicoding.auth.userInfo";
const QODER_SECRET_USER_PLAN_KEY: &str = "secret://aicoding.auth.userPlan";
const QODER_SECRET_CREDIT_USAGE_KEY: &str = "secret://aicoding.auth.creditUsage";
const QODER_APP_AUTH_FILE: &str = "auth.v1.dat";

// Qoder CN IDE (com.aliyun.lingma.ide) 的 ApplicationAuthService._restoreFromStorage 会把
// 缺少 IDE 管理 `login_source` 的 state.vscdb 会话判为 legacy 并清空（客户端 renderer.log 实证：
// "Clearing legacy auth session without IDE-managed login_source"）。客户端真实登录写入的
// login_source 为 LV.QoderCn="qodercn"（uct→login_version="2.0"）；CN OAuth 快照不含该字段，
// 故注入前补齐。默认 qoder 路径不经过此处，语义不变。
const QODER_CN_IDE_LOGIN_SOURCE: &str = "qodercn";
const QODER_CN_IDE_LOGIN_VERSION: &str = "2.0";

// App 变体切号写回门控：开启后按 backup→write→re-read 流程写入并校验。
// 如需回退，改回 false 即恢复门控。
pub const QODER_APP_WRITE_BACK_ENABLED: bool = true;

static QODER_ACCOUNT_INDEX_LOCK: std::sync::LazyLock<Mutex<()>> =
    std::sync::LazyLock::new(|| Mutex::new(()));

#[cfg(test)]
thread_local! {
    static ACCOUNT_DETAIL_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Debug, Clone, Default)]
struct QoderSnapshot {
    // 归一化后的变体键：`None` 等价默认 `qoder` 变体。
    variant: Option<String>,
    user_info_raw: Option<Value>,
    user_plan_raw: Option<Value>,
    credit_usage_raw: Option<Value>,
}

#[derive(Debug, Clone)]
struct NumericCandidate {
    path: String,
    value: f64,
}

fn now_ts() -> i64 {
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

fn normalize_email(value: Option<&str>) -> Option<String> {
    normalize_non_empty(value).map(|v| v.to_lowercase())
}

/// 存储侧归一化：默认 `qoder` 变体不写 `variant` 字段，其余变体写 provider key。
fn stored_variant_key(kind: QoderVariantKind) -> Option<String> {
    if kind == QoderVariantKind::Qoder {
        None
    } else {
        Some(kind.provider_key().to_string())
    }
}

/// 账号变体字段的唯一权威解析：`None`/`qoder` → 默认变体，未知值报错。
pub(crate) fn account_variant_kind(account: &QoderAccount) -> Result<QoderVariantKind, String> {
    QoderVariantKind::parse(account.variant.as_deref())
        .map_err(|err| format!("Qoder 账号变体字段无效: {}", err))
}

/// Account identity is shared inside one region; client sessions remain independent.
pub(crate) fn account_supports_variant(account: &QoderAccount, kind: QoderVariantKind) -> bool {
    account_variant_kind(account).is_ok_and(|source| source.site() == kind.site())
}

fn without_device_rt(mut raw: Value) -> Value {
    if let Some(object) = raw.as_object_mut() { object.remove("refreshToken"); }
    raw
}

pub(crate) fn has_client_auth(account: &QoderAccount, kind: QoderVariantKind) -> bool {
    account_variant_kind(account).ok() == Some(kind)
        || account.client_auth.contains_key(kind.provider_key())
}

/// Ephemeral client view. Only the account Owner stores/updates the shared RT.
pub(crate) fn account_for_variant(
    account: &QoderAccount,
    kind: QoderVariantKind,
) -> Result<QoderAccount, String> {
    if !account_supports_variant(account, kind) {
        return Err("Qoder 国内与国际账号不能互通".to_string());
    }
    let mut view = account.clone();
    if account_variant_kind(account)? != kind {
        view.auth_user_info_raw = Some(if let Some(raw) = account.client_auth.get(kind.provider_key()) {
            raw.clone()
        } else {
            // This view is only input to credential preparation. Never inject it until
            // the target client has acquired its own token and login metadata.
            let source = account.auth_user_info_raw.as_ref().ok_or("Qoder 账号缺少认证资料")?;
            let mut raw = source.clone();
            if let Some(user) = source.get("user").and_then(Value::as_object) {
                let object = raw.as_object_mut().ok_or("Qoder 认证资料格式无效")?;
                for (key, value) in user { object.insert(key.clone(), value.clone()); }
                if let Some(phone) = user.get("phone") { object.insert("security_mobile".into(), phone.clone()); }
                object.remove("user");
                object.remove("schemaVersion");
                for (iso, milliseconds) in [("expiresAt", "expireTime"), ("refreshTokenExpiresAt", "refreshTokenExpireTime")] {
                    if let Some(value) = source.get(iso).and_then(Value::as_str)
                        .and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok()) {
                        object.insert(milliseconds.into(), Value::String(value.timestamp_millis().to_string()));
                    }
                }
            }
            if let Some(object) = raw.as_object_mut() {
                for key in ["job_token", "job_refresh_token", "job_expires_at", "job_expires_in", "job_token_expires_in"] {
                    object.remove(key);
                }
            }
            raw
        });
    }
    view.variant = stored_variant_key(kind);
    // Legacy records have not yet passed through the regional migration.
    let rt = account.shared_refresh_token.clone().or_else(|| account.auth_user_info_raw.as_ref()
        .and_then(|raw| raw.get("refreshToken")).and_then(Value::as_str).map(str::to_string));
    if let (Some(raw), Some(rt)) = (view.auth_user_info_raw.as_mut().and_then(Value::as_object_mut), rt) {
        raw.insert("refreshToken".into(), Value::String(rt));
        if let Some(source) = account.auth_user_info_raw.as_ref() {
            let expiry = source.get("refreshTokenExpireTime").and_then(Value::as_str)
                .and_then(|value| value.parse::<i64>().ok())
                .or_else(|| source.get("refreshTokenExpiresAt").and_then(Value::as_str)
                    .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.timestamp_millis()));
            if let Some(expiry) = expiry {
                raw.insert("refreshTokenExpireTime".into(), Value::String(expiry.to_string()));
                if let Some(time) = chrono::DateTime::from_timestamp_millis(expiry) {
                    raw.insert("refreshTokenExpiresAt".into(), Value::String(time.to_rfc3339()));
                }
            }
        }
    }
    Ok(view)
}

fn normalize_regional_credentials(account: &mut QoderAccount) -> Result<(), String> {
    let source = account_variant_kind(account)?;
    account.legacy_ids = account.legacy_ids.iter().map(|id| normalize_account_id(id))
        .collect::<Result<Vec<_>, _>>()?;
    account.legacy_ids.retain(|id| id != &account.id);
    account.legacy_ids.sort();
    account.legacy_ids.dedup();
    let source_uid = account.auth_user_info_raw.as_ref().and_then(|raw| {
        raw.get("user").and_then(|user| user.get("id")).or_else(|| raw.get("id"))
    }).and_then(Value::as_str).and_then(|id| normalize_non_empty(Some(id)));
    if let (Some(saved), Some(raw)) = (&account.user_id, &source_uid) {
        if saved != raw { return Err("Qoder 账号资料身份不一致，拒绝保存".into()); }
    }
    if account.user_id.is_none() { account.user_id = source_uid; }
    let uid = account.user_id.as_deref();
    for (variant, raw) in &account.client_auth {
        let kind = QoderVariantKind::parse(Some(variant))?;
        if kind.site() != source.site() { return Err("Qoder 客户端凭据跨地区，拒绝保存".into()); }
        let raw_uid = raw.get("user").and_then(|user| user.get("id"))
            .or_else(|| raw.get("id")).and_then(Value::as_str);
        if uid.is_some() && raw_uid.is_some() && uid != raw_uid {
            return Err("Qoder 客户端凭据身份不一致，拒绝保存".into());
        }
    }
    if let Some(rt) = account.auth_user_info_raw.as_ref()
        .and_then(|raw| raw.get("refreshToken")).and_then(Value::as_str)
        .filter(|rt| !rt.trim().is_empty()) {
        account.shared_refresh_token = Some(rt.to_string());
    }
    account.client_auth.remove(source.provider_key());
    for raw in account.client_auth.values_mut() { *raw = without_device_rt(raw.take()); }
    Ok(())
}

enum RegionalMergeMode {
    Update,
    Migration,
}

fn merge_regional_record(
    mut incoming: QoderAccount,
    existing: &QoderAccount,
    mode: RegionalMergeMode,
) -> Result<QoderAccount, String> {
    let source = account_variant_kind(&incoming)?;
    let merging_duplicates = incoming.id != existing.id;
    // Migration can revisit the canonical ID after merging another legacy record.
    // Ordinary same-ID updates must still be able to clear tags and cached data.
    let preserve_metadata = merging_duplicates || matches!(mode, RegionalMergeMode::Migration);
    if !account_supports_variant(existing, source) {
        return Err("Qoder 账号 ID 已属于其他地区，拒绝覆盖".into());
    }
    if let (Some(left), Some(right)) = (&existing.user_id, &incoming.user_id) {
        if left != right { return Err("Qoder 账号 ID 已属于其他用户，拒绝覆盖".into()); }
    }
    let mut clients = existing.client_auth.clone();
    if let Some(raw) = &existing.auth_user_info_raw {
        clients.insert(account_variant_kind(existing)?.provider_key().to_string(), without_device_rt(raw.clone()));
    }
    clients.extend(incoming.client_auth.clone());
    incoming.client_auth = clients;
    if incoming.auth_user_info_raw.is_none() {
        incoming.auth_user_info_raw = existing.auth_user_info_raw.clone();
        incoming.variant = existing.variant.clone();
    }
    incoming.shared_refresh_token = incoming.shared_refresh_token.or_else(|| existing.shared_refresh_token.clone());
    incoming.user_id = incoming.user_id.or_else(|| existing.user_id.clone());
    if account_email_is_sentinel(&incoming.email) { incoming.email = existing.email.clone(); }
    if let Some(phone) = existing.security_mobile_for_display() {
        if incoming.security_mobile_for_display().is_none() {
            if let Some(raw) = incoming.auth_user_info_raw.as_mut().and_then(Value::as_object_mut) {
                raw.insert("security_mobile".into(), Value::String(phone.to_string()));
            }
        }
    }
    incoming.display_name = incoming.display_name.or_else(|| existing.display_name.clone());
    incoming.plan_type = incoming.plan_type.or_else(|| existing.plan_type.clone());
    incoming.web_session_cookie = incoming.web_session_cookie.or_else(|| existing.web_session_cookie.clone());
    if preserve_metadata && incoming.web_quota_updated_at < existing.web_quota_updated_at {
        incoming.web_quota_raw = existing.web_quota_raw.clone();
        incoming.web_quota_updated_at = existing.web_quota_updated_at;
    }
    if preserve_metadata && incoming.usage_updated_at < existing.usage_updated_at {
        incoming.auth_credit_usage_raw = existing.auth_credit_usage_raw.clone();
        incoming.auth_user_plan_raw = existing.auth_user_plan_raw.clone();
        incoming.plan_type = existing.plan_type.clone();
        incoming.credits_used = existing.credits_used;
        incoming.credits_total = existing.credits_total;
        incoming.credits_remaining = existing.credits_remaining;
        incoming.credits_usage_percent = existing.credits_usage_percent;
        incoming.usage_updated_at = existing.usage_updated_at;
    }
    if preserve_metadata && incoming.reward_status_updated_at < existing.reward_status_updated_at {
        incoming.reward_claim_status = existing.reward_claim_status.clone();
        incoming.reward_window_end_at = existing.reward_window_end_at;
        incoming.reward_status_updated_at = existing.reward_status_updated_at;
    }
    if preserve_metadata {
        incoming.tags = normalize_tags(existing.tags.iter().flatten().chain(incoming.tags.iter().flatten()).cloned().collect());
    }
    if merging_duplicates { incoming.legacy_ids.push(incoming.id.clone()); }
    incoming.legacy_ids.extend(existing.legacy_ids.clone());
    incoming.legacy_ids.sort(); incoming.legacy_ids.dedup();
    incoming.id = existing.id.clone();
    incoming.created_at = incoming.created_at.min(existing.created_at);
    incoming.last_used = incoming.last_used.max(existing.last_used);
    normalize_regional_credentials(&mut incoming)?;
    Ok(incoming)
}

/// CN 账号无真实邮箱，后端写哨兵 `unknown@qoder.local`（保持冻结）；空串同样视为哨兵。
pub fn account_email_is_sentinel(email: &str) -> bool {
    let trimmed = email.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown@qoder.local")
}

/// 原生展示面（托盘 / macOS 菜单卡片）读取的绑定手机号；仅非空字符串算命中，不做任何掩码。
pub fn security_mobile_of(account: &QoderAccount) -> Option<String> {
    account.security_mobile_for_display().map(str::to_string)
}

fn sanitize_account_id_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

fn generate_account_id(
    snapshot: &QoderSnapshot,
    user_id: Option<&str>,
) -> String {
    // 地区前缀隔离国内与国际账号，同地区 App / IDE 使用同一身份 ID。
    let prefix = if QoderVariantKind::parse(snapshot.variant.as_deref()).is_ok_and(|kind| kind.is_cn()) {
        "qoder_cn"
    } else { "qoder" };
    if let Some(uid) = normalize_non_empty(user_id) {
        let cleaned = sanitize_account_id_component(&uid);
        if !cleaned.is_empty() {
            return format!("{}_uid_{}", prefix, cleaned);
        }
    }

    // Without an official UID, retain distinct credential snapshots rather than
    // combining unrelated accounts through a nickname, email or missing-email sentinel.
    let basis = format!(
        "{}|{}|{}",
        snapshot
            .user_info_raw
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        snapshot
            .user_plan_raw
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        snapshot
            .credit_usage_raw
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    let digest = md5::compute(basis.as_bytes());
    format!("{}_{:x}", prefix, digest)
}

fn get_data_dir() -> Result<PathBuf, String> {
    account::get_data_dir()
}

fn get_accounts_dir() -> Result<PathBuf, String> {
    let base = get_data_dir()?;
    let dir = base.join(ACCOUNTS_DIR);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("创建 Qoder 账号目录失败: {}", e))?;
    }
    Ok(dir)
}

fn get_accounts_index_path() -> Result<PathBuf, String> {
    Ok(get_data_dir()?.join(ACCOUNTS_INDEX_FILE))
}

pub fn accounts_index_path_string() -> Result<String, String> {
    Ok(get_accounts_index_path()?.to_string_lossy().to_string())
}

fn normalize_account_id(account_id: &str) -> Result<String, String> {
    let trimmed = account_id.trim();
    if trimmed.is_empty() {
        return Err("账号 ID 不能为空".to_string());
    }

    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err("账号 ID 非法，包含路径字符".to_string());
    }

    let valid = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.');
    if !valid {
        return Err("账号 ID 非法，仅允许字母/数字/._-".to_string());
    }

    Ok(trimmed.to_string())
}

fn resolve_account_file_path(account_id: &str) -> Result<PathBuf, String> {
    let normalized = normalize_account_id(account_id)?;
    Ok(get_accounts_dir()?.join(format!("{}.json", normalized)))
}

fn load_account_file(account_id: &str) -> Option<QoderAccount> {
    #[cfg(test)]
    ACCOUNT_DETAIL_READS.with(|reads| reads.set(reads.get() + 1));
    let account_path = resolve_account_file_path(account_id).ok()?;
    if !account_path.exists() {
        return None;
    }
    let content = fs::read_to_string(&account_path).ok()?;
    match crate::modules::secure_account_storage::deserialize_account_file::<QoderAccount>(
        &account_path,
        &content,
    ) {
        Ok((mut account, needs_rotation)) => {
            if needs_rotation {
                let account_for_rewrite = account.clone();
                crate::modules::deferred_account_rewrite::schedule_account_rewrite_if_unchanged(
                    "qoder",
                    account_for_rewrite.id.clone(),
                    account_path.clone(),
                    content.as_bytes(),
                    move || {
                        crate::modules::secure_account_storage::serialize_account_file(
                            "qoder",
                            &account_for_rewrite,
                        )
                    },
                );
            }
            if let (Some(raw), Some(rt)) = (account.auth_user_info_raw.as_mut().and_then(Value::as_object_mut), account.shared_refresh_token.as_ref()) {
                raw.insert("refreshToken".into(), Value::String(rt.clone()));
            }
            Some(account)
        }
        Err(_) => None,
    }
}

/// Resolve old instance/current-account references without maintaining duplicate accounts.
pub fn load_account(account_id: &str) -> Option<QoderAccount> {
    let normalized = normalize_account_id(account_id).ok()?;
    let index_path = get_accounts_index_path().ok()?;
    if let Ok(content) = fs::read_to_string(index_path) {
        if let Ok(index) = serde_json::from_str::<QoderAccountIndex>(&content) {
            // Canonical IDs do not need legacy-reference resolution. Keep alias
            // lookup ahead of orphan files only for IDs absent from the index.
            if index.accounts.iter().any(|summary| summary.id == normalized) {
                return load_account_file(&normalized);
            }
            for summary in &index.accounts {
                if let Some(account) = load_account_file(&summary.id) {
                    if account.legacy_ids.contains(&normalized) { return Some(account); }
                }
            }
        }
    }
    load_account_file(&normalized)
}

fn save_account_file(account: &QoderAccount) -> Result<(), String> {
    let path = resolve_account_file_path(account.id.as_str())?;
    let mut stored = account.clone();
    normalize_regional_credentials(&mut stored)?;
    if let Some(raw) = stored.auth_user_info_raw.take() { stored.auth_user_info_raw = Some(without_device_rt(raw)); }
    let content = crate::modules::secure_account_storage::serialize_account_file("qoder", &stored)?;
    crate::modules::atomic_write::write_string_atomic(&path, &content)
        .map_err(|e| format!("保存账号失败: {}", e))
}

fn delete_account_file(account_id: &str) -> Result<(), String> {
    let path = resolve_account_file_path(account_id)?;
    if path.exists() {
        crate::modules::atomic_write::remove_file_locked(&path)
            .map_err(|e| format!("删除账号文件失败: {}", e))?;
    }
    Ok(())
}

fn load_account_index() -> QoderAccountIndex {
    let path = match get_accounts_index_path() {
        Ok(p) => p,
        Err(_) => return QoderAccountIndex::new(),
    };
    if !path.exists() {
        return repair_account_index_from_details("索引文件不存在")
            .unwrap_or_else(QoderAccountIndex::new);
    }
    match fs::read_to_string(&path) {
        Ok(content) if content.trim().is_empty() => {
            repair_account_index_from_details("索引文件为空").unwrap_or_else(QoderAccountIndex::new)
        }
        Ok(content) => match crate::modules::atomic_write::parse_json_with_auto_restore::<
            QoderAccountIndex,
        >(&path, &content)
        {
            Ok(index) if !index.accounts.is_empty() => index,
            Ok(_) => repair_account_index_from_details("索引账号列表为空")
                .unwrap_or_else(QoderAccountIndex::new),
            Err(err) => {
                logger::log_warn(&format!(
                    "[Qoder Account] 账号索引解析失败，尝试按详情文件自动修复: path={}, error={}",
                    path.display(),
                    err
                ));
                repair_account_index_from_details("索引文件损坏")
                    .unwrap_or_else(QoderAccountIndex::new)
            }
        },
        Err(_) => QoderAccountIndex::new(),
    }
}

fn load_account_index_checked() -> Result<QoderAccountIndex, String> {
    let path = get_accounts_index_path()?;
    if !path.exists() {
        if let Some(index) = repair_account_index_from_details("索引文件不存在") {
            return Ok(index);
        }
        return Ok(QoderAccountIndex::new());
    }

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) => {
            if let Some(index) = repair_account_index_from_details("索引文件读取失败") {
                return Ok(index);
            }
            return Err(format!("读取账号索引失败: {}", err));
        }
    };

    if content.trim().is_empty() {
        if let Some(index) = repair_account_index_from_details("索引文件为空") {
            return Ok(index);
        }
        return Ok(QoderAccountIndex::new());
    }

    match crate::modules::atomic_write::parse_json_with_auto_restore::<QoderAccountIndex>(
        &path, &content,
    ) {
        Ok(mut index) if !index.accounts.is_empty() => {
            // A deleted detail is authoritative even if the process stopped before
            // publishing its index. Unreadable existing details must still fail migration.
            let previous_len = index.accounts.len();
            let mut retained = Vec::new();
            for summary in index.accounts {
                let path = resolve_account_file_path(&summary.id)?;
                match fs::metadata(path) {
                    Ok(_) => retained.push(summary),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {},
                    Err(err) => return Err(format!("读取 Qoder 账号详情元数据失败: {err}")),
                }
            }
            index.accounts = retained;
            if index.accounts.len() != previous_len { save_account_index(&index)?; }
            Ok(index)
        },
        Ok(index) => {
            if let Some(repaired) = repair_account_index_from_details("索引账号列表为空") {
                return Ok(repaired);
            }
            Ok(index)
        }
        Err(err) => {
            if let Some(index) = repair_account_index_from_details("索引文件损坏") {
                return Ok(index);
            }
            Err(crate::error::file_corrupted_error(
                ACCOUNTS_INDEX_FILE,
                &path.to_string_lossy(),
                &err.to_string(),
            ))
        }
    }
}

fn save_account_index(index: &QoderAccountIndex) -> Result<(), String> {
    let path = get_accounts_index_path()?;
    let content =
        serde_json::to_string_pretty(index).map_err(|e| format!("序列化账号索引失败: {}", e))?;
    crate::modules::atomic_write::write_string_atomic(&path, &content)
        .map_err(|e| format!("写入账号索引失败: {}", e))
}

fn repair_account_index_from_details(reason: &str) -> Option<QoderAccountIndex> {
    let index_path = get_accounts_index_path().ok()?;
    let accounts_dir = get_accounts_dir().ok()?;
    let mut accounts = crate::modules::account_index_repair::load_accounts_from_details(
        &accounts_dir,
        |account_id| load_account_file(account_id),
    )
    .ok()?;

    if accounts.is_empty() { return None; }
    let retired: HashSet<String> = accounts.iter().flat_map(|account| account.legacy_ids.clone()).collect();
    accounts.retain(|account| !retired.contains(&account.id));

    crate::modules::account_index_repair::sort_accounts_by_recency(
        &mut accounts,
        |account| account.last_used,
        |account| account.created_at,
        |account| account.id.as_str(),
    );

    let mut index = QoderAccountIndex::new();
    index.accounts = accounts.iter().map(|account| account.summary()).collect();

    let backup_path = crate::modules::account_index_repair::backup_existing_index(&index_path)
        .unwrap_or_else(|err| {
            logger::log_warn(&format!(
                "[Qoder Account] 自动修复前备份索引失败，继续尝试重建: path={}, error={}",
                index_path.display(),
                err
            ));
            None
        });

    if let Err(err) = save_account_index(&index) {
        logger::log_warn(&format!(
            "[Qoder Account] 自动修复索引保存失败，将以内存结果继续运行: reason={}, recovered_accounts={}, error={}",
            reason,
            index.accounts.len(),
            err
        ));
    }

    logger::log_warn(&format!(
        "[Qoder Account] 检测到账号索引异常，已根据详情文件自动重建: reason={}, recovered_accounts={}, backup_path={}",
        reason,
        index.accounts.len(),
        backup_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    ));

    Some(index)
}

fn refresh_summary(index: &mut QoderAccountIndex, account: &QoderAccount) {
    if let Some(summary) = index.accounts.iter_mut().find(|item| item.id == account.id) {
        *summary = account.summary();
        return;
    }
    index.accounts.push(account.summary());
}

pub fn upsert_account_record(account: QoderAccount) -> Result<QoderAccount, String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|_| "获取 Qoder 账号锁失败".to_string())?;
    save_account_record_locked(account)
}

// 调用方必须持有 QODER_ACCOUNT_INDEX_LOCK；读改写操作在读取之前就要获取该锁。
fn save_account_record_locked(mut account: QoderAccount) -> Result<QoderAccount, String> {
    normalize_regional_credentials(&mut account)?;
    let mut index = merge_legacy_accounts_locked(load_account_index_checked()?)?;
    let accounts = list_accounts_from_index(&index);
    for alias in &account.legacy_ids {
        if let Some(owner) = load_account(alias) {
            if owner.id != account.id && (!account_supports_variant(&owner, account_variant_kind(&account)?)
                || account.user_id.is_none() || account.user_id != owner.user_id) {
                return Err("Qoder 历史账号 ID 已属于其他账号，拒绝导入".into());
            }
        }
    }
    let existing = load_account(&account.id).or_else(|| accounts.iter().find(|existing| {
        account_supports_variant(existing, account_variant_kind(&account).unwrap_or(QoderVariantKind::Qoder))
            && account.user_id.as_ref().is_some_and(|uid| existing.user_id.as_ref() == Some(uid))
    }).cloned());
    if let Some(existing) = existing {
        account = merge_regional_record(account, &existing, RegionalMergeMode::Update)?;
    }
    normalize_regional_credentials(&mut account)?;
    save_account_file(&account)?;
    refresh_summary(&mut index, &account);
    save_account_index(&index)?;
    Ok(account)
}

/// Forward migration: write the canonical account first, then publish one index.
/// Originals remain encrypted in a private backup; old IDs resolve through legacy_ids.
/// A crash before index publication is safe to replay from the remaining originals.
fn merge_legacy_accounts_locked(mut index: QoderAccountIndex) -> Result<QoderAccountIndex, String> {
    let mut groups: HashMap<(String, Option<String>, Option<String>), Vec<QoderAccount>> = HashMap::new();
    for summary in &index.accounts {
        let mut account = load_account_file(&summary.id)
            .ok_or_else(|| format!("Qoder 账号详情无法读取，合并已中止: {}", summary.id))?;
        if account.user_id.is_none() {
            account.user_id = account.auth_user_info_raw.as_ref().and_then(|raw| raw.get("user")
                .and_then(|user| user.get("id")).or_else(|| raw.get("id")))
                .and_then(Value::as_str).and_then(|id| normalize_non_empty(Some(id)));
        }
        let kind = account_variant_kind(&account)?;
        let uid = normalize_non_empty(account.user_id.as_deref());
        let unidentified = uid.is_none().then(|| account.id.clone());
        groups.entry((kind.site().as_str().to_string(), uid, unidentified)).or_default().push(account);
    }
    let needs_migration = groups.values().any(|group| group.len() > 1
        || group.iter().any(|account| account.shared_refresh_token.is_none()
            && account.auth_user_info_raw.as_ref().and_then(|raw| raw.get("refreshToken"))
                .and_then(Value::as_str).is_some_and(|rt| !rt.trim().is_empty())));
    if !needs_migration { return Ok(index); }
    let backup = get_data_dir()?.join("qoder-regional-backups").join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&backup).map_err(|e| format!("创建 Qoder 合并备份失败: {e}"))?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    for group in groups.values() {
        for account in group {
            let content = crate::modules::secure_account_storage::serialize_account_file("qoder", account)?;
            crate::modules::atomic_write::write_string_atomic(&backup.join(format!("{}.json", account.id)), &content)?;
        }
    }
    let original_index = serde_json::to_string_pretty(&index).map_err(|e| e.to_string())?;
    crate::modules::atomic_write::write_string_atomic(&backup.join(ACCOUNTS_INDEX_FILE), &original_index)?;
    let mut canonical = Vec::new();
    let mut retired = Vec::new();
    for mut group in groups.into_values() {
        // Stable original ID keeps existing bindings valid; newer credentials win.
        group.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.id.cmp(&b.id)));
        let original = group[0].clone();
        group.sort_by(|a, b| a.last_used.cmp(&b.last_used).then(a.id.cmp(&b.id)));
        let mut merged = original.clone();
        for account in group {
            let old_id = account.id.clone();
            merged = merge_regional_record(account, &merged, RegionalMergeMode::Migration)?;
            if old_id != merged.id {
                merged.legacy_ids.push(old_id.clone());
                retired.push(old_id);
            }
        }
        merged.legacy_ids.sort(); merged.legacy_ids.dedup();
        save_account_file(&merged)?;
        canonical.push(merged.summary());
    }
    canonical.sort_by(|a, b| a.id.cmp(&b.id));
    index.accounts = canonical;
    index.version = "2.0".into();
    save_account_index(&index)?;
    for id in retired { delete_account_file(&id)?; }
    Ok(index)
}

fn update_account_metadata(
    account_id: &str,
    update: impl FnOnce(&mut QoderAccount),
) -> Result<Option<QoderAccount>, String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|_| "获取 Qoder 账号锁失败".to_string())?;
    // Read the canonical record before applying the edit; a pre-migration snapshot
    // would otherwise overwrite merged credentials and metadata when saved.
    merge_legacy_accounts_locked(load_account_index_checked()?)?;
    let Some(mut account) = load_account(account_id) else {
        return Ok(None);
    };
    update(&mut account);
    save_account_record_locked(account).map(Some)
}

fn update_last_used(account_id: &str) -> Result<QoderAccount, String> {
    update_account_metadata(account_id, |account| account.last_used = now_ts())?
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))
}

/// 在账号锁内读取最新记录，只写活动字段；查询传入请求前的快照以拒绝过期响应。
/// 领取结果不传快照，但同样保留最新凭证和配额，并向调用方传播保存错误。
pub fn update_reward_status(
    account_id: &str,
    claim_status: Option<String>,
    window_end_at: Option<i64>,
    expected: Option<&QoderAccount>,
) -> Result<QoderAccount, String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|_| "获取 Qoder 账号锁失败".to_string())?;
    let mut index = load_account_index();
    let mut account = load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    if let Some(expected) = expected {
        if account.id != expected.id
            || account.reward_claim_status != expected.reward_claim_status
            || account.reward_window_end_at != expected.reward_window_end_at
            || account.reward_status_updated_at != expected.reward_status_updated_at
        {
            // 比较与保存持有同一把锁，其他领取/查询不能在两者之间插入写入。
            return Ok(account);
        }
    }
    account.reward_claim_status = claim_status;
    account.reward_window_end_at = window_end_at;
    account.reward_status_updated_at = Some(now_ts());
    save_account_file(&account)?;
    refresh_summary(&mut index, &account);
    save_account_index(&index)?;
    Ok(account)
}

pub fn update_quota_query_error(
    account_id: &str,
    message: Option<String>,
) -> Result<Option<QoderAccount>, String> {
    update_account_metadata(account_id, |account| {
        account.quota_query_last_error = message;
        account.quota_query_last_error_at = account
            .quota_query_last_error
            .as_ref()
            .map(|_| chrono::Utc::now().timestamp_millis());
    })
}

/// 只更新用量与已确认的套餐投影，不把请求开始时的凭证快照写回账号库。
pub(crate) fn update_account_usage(
    account_id: &str,
    usage: Value,
    user_plan: Option<Value>,
) -> Result<QoderAccount, String> {
    update_account_metadata(account_id, |account| {
        let snapshot = QoderSnapshot {
            credit_usage_raw: Some(usage.clone()),
            user_plan_raw: user_plan.clone(),
            ..Default::default()
        };
        let (used, total, remaining, percent) = extract_snapshot_credits(&snapshot);
        account.auth_credit_usage_raw = Some(usage);
        if let Some(plan_type) = extract_snapshot_plan_type(&snapshot) {
            account.plan_type = Some(plan_type);
            // 最新用量已确认档位时，不能继续保留优先级更高的旧套餐响应。
            account.auth_user_plan_raw = user_plan.filter(|plan| plan_type_from_user_plan(plan).is_some());
        }
        account.credits_used = used;
        account.credits_total = total;
        account.credits_remaining = remaining;
        account.credits_usage_percent = percent;
        account.usage_updated_at = Some(now_ts());
        // 网页额度是独立缓存；正常用量查询成功后失效，随后可用已验证的网页会话重拉。
        account.web_quota_raw = None;
        account.web_quota_updated_at = None;
        account.quota_query_last_error = None;
        account.quota_query_last_error_at = None;
    })?
    .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))
}

/// Caller must verify the website's user ID while holding the account refresh lock.
pub(crate) fn update_verified_web_session(account_id: &str, cookie: String) -> Result<QoderAccount, String> {
    update_account_metadata(account_id, |account| {
        account.web_session_cookie = Some(cookie);
    })?.ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))
}

pub fn update_account_web_quota(
    account_id: &str,
    web_quota: Value,
    cookie: Option<String>,
) -> Result<QoderAccount, String> {
    update_account_metadata(account_id, |account| {
        account.web_quota_raw = Some(web_quota);
        account.web_quota_updated_at = Some(now_ts());
        if let Some(c) = cookie {
            account.web_session_cookie = Some(c);
        }
    })?
    .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))
}

fn list_accounts_from_index(index: &QoderAccountIndex) -> Vec<QoderAccount> {
    let mut accounts = Vec::new();
    for summary in &index.accounts {
        // The index already contains canonical IDs after regional migration.
        // Calling the public alias resolver here would scan the whole list again.
        if let Some(account) = load_account_file(&summary.id) {
            accounts.push(account);
        }
    }
    accounts.sort_by(|a, b| b.last_used.cmp(&a.last_used));
    accounts
}

pub fn list_accounts() -> Vec<QoderAccount> {
    match list_accounts_checked() {
        Ok(accounts) => accounts,
        Err(err) => { logger::log_warn(&format!("[Qoder Account] 读取地区账号失败: {err}")); Vec::new() }
    }
}

pub fn list_accounts_checked() -> Result<Vec<QoderAccount>, String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK.lock().map_err(|_| "获取 Qoder 账号锁失败")?;
    let index = merge_legacy_accounts_locked(load_account_index_checked()?)?;
    Ok(list_accounts_from_index(&index))
}

pub fn remove_account(account_id: &str) -> Result<(), String> {
    remove_accounts(&[account_id.to_string()])
}

pub fn remove_accounts(account_ids: &[String]) -> Result<(), String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK.lock().map_err(|_| "获取 Qoder 账号锁失败")?;
    let mut index = merge_legacy_accounts_locked(load_account_index_checked()?)?;
    let mut target = HashSet::new();
    let mut files = HashSet::new();
    for id in account_ids {
        if let Some(account) = load_account(id) {
            target.insert(account.id.clone());
            files.extend(account.legacy_ids);
        }
    }
    // Retired aliases go first; the canonical detail retains their ownership until
    // cleanup finishes. Index reads prune a missing canonical detail after interruption.
    for id in &files { delete_account_file(id)?; }
    for id in &target { delete_account_file(id)?; }
    index.accounts.retain(|item| !target.contains(&item.id));
    save_account_index(&index)
}

fn parse_json_or_string(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

fn walk_value<'a>(value: &'a Value, path: &str, visit: &mut dyn FnMut(&str, &'a Value)) {
    visit(path, value);
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{}.{}", path, key)
                };
                walk_value(child, &child_path, visit);
            }
        }
        Value::Array(list) => {
            for (idx, child) in list.iter().enumerate() {
                let child_path = if path.is_empty() {
                    format!("[{}]", idx)
                } else {
                    format!("{}[{}]", path, idx)
                };
                walk_value(child, &child_path, visit);
            }
        }
        _ => {}
    }
}

fn path_last_segment(path: &str) -> &str {
    let mut last = path;
    if let Some(idx) = last.rfind('.') {
        last = &last[idx + 1..];
    }
    if let Some(idx) = last.rfind('[') {
        last = &last[..idx];
    }
    last
}

fn find_string_by_exact_keys(value: &Value, keys: &[&str]) -> Option<String> {
    let key_set: HashSet<String> = keys.iter().map(|k| k.to_ascii_lowercase()).collect();
    let mut found: Option<String> = None;
    walk_value(value, "", &mut |path, current| {
        if found.is_some() {
            return;
        }
        let Some(text) = current.as_str() else {
            return;
        };
        let Some(normalized) = normalize_non_empty(Some(text)) else {
            return;
        };
        let last = path_last_segment(path).to_ascii_lowercase();
        if key_set.contains(last.as_str()) {
            found = Some(normalized);
        }
    });
    found
}

fn find_string_by_path_keywords(value: &Value, includes: &[&str]) -> Option<String> {
    let mut found: Option<String> = None;
    walk_value(value, "", &mut |path, current| {
        if found.is_some() {
            return;
        }
        let Some(text) = current.as_str() else {
            return;
        };
        let Some(normalized) = normalize_non_empty(Some(text)) else {
            return;
        };
        let path_lower = path.to_ascii_lowercase();
        if includes
            .iter()
            .all(|keyword| path_lower.contains(&keyword.to_ascii_lowercase()))
        {
            found = Some(normalized);
        }
    });
    found
}

fn find_first_email(value: &Value) -> Option<String> {
    let mut found: Option<String> = None;
    walk_value(value, "", &mut |_path, current| {
        if found.is_some() {
            return;
        }
        let Some(text) = current.as_str() else {
            return;
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.contains('@') && trimmed.contains('.') {
            found = Some(trimmed.to_lowercase());
        }
    });
    found
}

fn collect_numeric_candidates(value: &Value, base_path: &str, output: &mut Vec<NumericCandidate>) {
    walk_value(value, base_path, &mut |path, current| {
        let num = match current {
            Value::Number(n) => n.as_f64(),
            Value::String(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    trimmed.parse::<f64>().ok()
                }
            }
            _ => None,
        };
        let Some(raw) = num else {
            return;
        };
        if !raw.is_finite() || raw.abs() > 1_000_000_000_000.0 {
            return;
        }
        output.push(NumericCandidate {
            path: path.to_ascii_lowercase(),
            value: raw,
        });
    });
}

fn pick_numeric_candidate(
    candidates: &[NumericCandidate],
    includes: &[&str],
    excludes: &[&str],
) -> Option<f64> {
    for candidate in candidates {
        if includes
            .iter()
            .all(|item| candidate.path.contains(&item.to_ascii_lowercase()))
            && excludes
                .iter()
                .all(|item| !candidate.path.contains(&item.to_ascii_lowercase()))
        {
            return Some(candidate.value);
        }
    }
    None
}

fn clamp_percent(value: f64) -> f64 {
    if value.is_nan() {
        return 0.0;
    }
    value.clamp(0.0, 100.0)
}

fn extract_snapshot_email(snapshot: &QoderSnapshot) -> Option<String> {
    let candidates = [
        snapshot.user_info_raw.as_ref(),
        snapshot.user_plan_raw.as_ref(),
        snapshot.credit_usage_raw.as_ref(),
    ];
    for value in candidates.into_iter().flatten() {
        if let Some(email) = find_string_by_exact_keys(value, &["email", "mail"]) {
            return Some(email.to_lowercase());
        }
        if let Some(email) = find_first_email(value) {
            return Some(email);
        }
    }
    None
}

fn extract_snapshot_user_id(snapshot: &QoderSnapshot) -> Option<String> {
    let raw = snapshot.user_info_raw.as_ref()?;
    // Only authentication identity fields are authoritative. Plan/package IDs
    // and nested organization IDs cannot identify a regional account.
    for object in [raw.get("user"), Some(raw)].into_iter().flatten() {
        for key in ["id", "uid", "user_id", "userid", "userId", "account_id", "accountId"] {
            if let Some(uid) = object.get(key).and_then(Value::as_str)
                .and_then(|value| normalize_non_empty(Some(value))) {
                return Some(uid);
            }
        }
    }
    None
}

fn extract_snapshot_display_name(snapshot: &QoderSnapshot) -> Option<String> {
    let Some(value) = snapshot.user_info_raw.as_ref() else {
        return None;
    };
    find_string_by_exact_keys(
        value,
        &[
            "name",
            "nickname",
            "display_name",
            "displayName",
            "username",
        ],
    )
}

/// 供套餐查询复用账号 Owner 的档位解析，避免把身份昵称当成套餐。
pub(crate) fn plan_type_from_user_plan(user_plan: &Value) -> Option<String> {
    extract_snapshot_plan_type(&QoderSnapshot {
        user_plan_raw: Some(user_plan.clone()),
        ..Default::default()
    })
}

fn extract_snapshot_plan_type(snapshot: &QoderSnapshot) -> Option<String> {
    if let Some(value) = snapshot.user_plan_raw.as_ref() {
        if let Some(plan) = find_string_by_exact_keys(
            value,
            &[
                "plan_tier_name",
                "planTierName",
                "plan_name",
                "planName",
                "plan",
                "plan_type",
                "planType",
                "tier",
                "tier_name",
                "tierName",
                "package",
                "package_name",
                "packageName",
            ],
        ) {
            return Some(plan);
        }
        for key in ["plan", "package"] {
            if let Some(name) = normalize_non_empty(value.get(key)
                .and_then(|item| item.get("name"))
                .and_then(Value::as_str)) {
                return Some(name);
            }
        }
    }

    if let Some(value) = snapshot.credit_usage_raw.as_ref() {
        let usage = value.get("qoderUsage").unwrap_or(value);
        if let Some(plan) = find_string_by_exact_keys(
            usage,
            &["plan_tier_name", "planTierName", "tier_name", "tierName", "plan_name", "planName"],
        ) {
            return Some(plan);
        }
        // Sash 的具体枚举可确认档位；enterprise/personal 仅是类别，保留细分套餐。
        for key in ["userType", "user_type"] {
            if let Some(plan) = normalize_non_empty(usage.get(key).and_then(Value::as_str)) {
                if matches!(
                    plan.to_ascii_lowercase().as_str(),
                    "personal_standard" | "personal_professional_trial" | "personal_professional"
                    | "personal_professional_plus" | "personal_ultra" | "teams"
                    | "enterprise_standard" | "enterprise_professional"
                ) {
                    return Some(plan);
                }
            }
        }
    }

    if let Some(value) = snapshot.user_info_raw.as_ref() {
        if let Some(plan) =
            find_string_by_exact_keys(value, &["userTag", "user_tag", "plan_tier_name"])
        {
            return Some(plan);
        }
    }

    if let Some(value) = snapshot.credit_usage_raw.as_ref() {
        if let Some(plan) = find_string_by_path_keywords(value, &["plan"]) {
            return Some(plan);
        }
    }

    None
}

fn extract_snapshot_credits(
    snapshot: &QoderSnapshot,
) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    let mut candidates = Vec::new();
    if let Some(value) = snapshot.credit_usage_raw.as_ref() {
        collect_numeric_candidates(value, "usage", &mut candidates);
    }
    if let Some(value) = snapshot.user_plan_raw.as_ref() {
        collect_numeric_candidates(value, "plan", &mut candidates);
    }

    let mut used = pick_numeric_candidate(
        &candidates,
        &["used"],
        &["percent", "rate", "ratio", "remaining", "remain", "left"],
    )
    .or_else(|| {
        pick_numeric_candidate(
            &candidates,
            &["consum"],
            &["percent", "rate", "ratio", "remaining", "remain", "left"],
        )
    });

    let mut remaining =
        pick_numeric_candidate(&candidates, &["remaining"], &["percent", "rate", "ratio"])
            .or_else(|| {
                pick_numeric_candidate(&candidates, &["remain"], &["percent", "rate", "ratio"])
            })
            .or_else(|| {
                pick_numeric_candidate(&candidates, &["left"], &["percent", "rate", "ratio"])
            })
            .or_else(|| {
                pick_numeric_candidate(&candidates, &["available"], &["percent", "rate", "ratio"])
            });

    let mut total = pick_numeric_candidate(
        &candidates,
        &["total"],
        &[
            "percent",
            "rate",
            "ratio",
            "remaining",
            "remain",
            "left",
            "used",
            "consum",
        ],
    )
    .or_else(|| {
        pick_numeric_candidate(
            &candidates,
            &["quota"],
            &[
                "percent",
                "rate",
                "ratio",
                "remaining",
                "remain",
                "left",
                "used",
                "consum",
            ],
        )
    })
    .or_else(|| {
        pick_numeric_candidate(
            &candidates,
            &["limit"],
            &[
                "percent",
                "rate",
                "ratio",
                "remaining",
                "remain",
                "left",
                "used",
                "consum",
            ],
        )
    });

    if total.is_none() {
        if let (Some(u), Some(r)) = (used, remaining) {
            total = Some(u + r);
        }
    }

    if remaining.is_none() {
        if let (Some(t), Some(u)) = (total, used) {
            remaining = Some((t - u).max(0.0));
        }
    }

    if used.is_none() {
        if let (Some(t), Some(r)) = (total, remaining) {
            used = Some((t - r).max(0.0));
        }
    }

    let mut usage_percent =
        pick_numeric_candidate(&candidates, &["percent"], &["remaining", "remain", "left"]);

    if usage_percent.is_none() {
        usage_percent = pick_numeric_candidate(&candidates, &["ratio"], &[]);
    }

    if let Some(pct) = usage_percent {
        let normalized = if pct <= 1.0 { pct * 100.0 } else { pct };
        usage_percent = Some(clamp_percent(normalized));
    } else if let (Some(u), Some(t)) = (used, total) {
        if t > 0.0 {
            usage_percent = Some(clamp_percent((u / t) * 100.0));
        }
    }

    (used, total, remaining, usage_percent)
}

fn snapshot_has_any_data(snapshot: &QoderSnapshot) -> bool {
    snapshot.user_info_raw.is_some()
        || snapshot.user_plan_raw.is_some()
        || snapshot.credit_usage_raw.is_some()
}

fn same_identity(
    account: &QoderAccount,
    user_id: Option<&str>,
    generated_id: &str,
) -> bool {
    match (normalize_non_empty(account.user_id.as_deref()), normalize_non_empty(user_id)) {
        (Some(left), Some(right)) => left == right,
        (None, None) => account.id == generated_id || account.legacy_ids.iter().any(|id| id == generated_id),
        _ => false,
    }
}

fn normalize_tags(tags: Vec<String>) -> Option<Vec<String>> {
    let mut set = HashSet::new();
    let mut result = Vec::new();
    for raw in tags {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = trimmed.to_string();
        let lower = normalized.to_lowercase();
        if set.insert(lower) {
            result.push(normalized);
        }
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn snapshot_to_account(snapshot: QoderSnapshot, existing: Option<&QoderAccount>) -> QoderAccount {
    let now = now_ts();
    let email = extract_snapshot_email(&snapshot)
        .or_else(|| existing.and_then(|item| normalize_email(Some(item.email.as_str()))))
        .unwrap_or_else(|| "unknown@qoder.local".to_string());
    let user_id = extract_snapshot_user_id(&snapshot)
        .or_else(|| existing.and_then(|item| item.user_id.clone()));
    let generated_id = generate_account_id(&snapshot, user_id.as_deref());
    let display_name = extract_snapshot_display_name(&snapshot)
        .or_else(|| existing.and_then(|item| item.display_name.clone()));
    let plan_type = extract_snapshot_plan_type(&snapshot)
        .or_else(|| existing.and_then(|item| item.plan_type.clone()));
    let usage_confirms_plan = extract_snapshot_plan_type(&QoderSnapshot {
        credit_usage_raw: snapshot.credit_usage_raw.clone(),
        ..Default::default()
    })
    .is_some();
    let usage_refreshed = snapshot.credit_usage_raw.is_some();
    let (credits_used, credits_total, credits_remaining, credits_usage_percent) =
        extract_snapshot_credits(&snapshot);

    QoderAccount {
        shared_refresh_token: None,
        client_auth: HashMap::new(),
        legacy_ids: Vec::new(),
        id: existing.map(|item| item.id.clone()).unwrap_or(generated_id),
        variant: snapshot.variant.clone(),
        email,
        user_id,
        display_name,
        plan_type,
        credits_used: credits_used.or_else(|| existing.and_then(|item| item.credits_used)),
        credits_total: credits_total.or_else(|| existing.and_then(|item| item.credits_total)),
        credits_remaining: credits_remaining
            .or_else(|| existing.and_then(|item| item.credits_remaining)),
        credits_usage_percent: credits_usage_percent
            .or_else(|| existing.and_then(|item| item.credits_usage_percent)),
        quota_query_last_error: if snapshot.credit_usage_raw.is_some() {
            None
        } else {
            existing.and_then(|item| item.quota_query_last_error.clone())
        },
        quota_query_last_error_at: if snapshot.credit_usage_raw.is_some() {
            None
        } else {
            existing.and_then(|item| item.quota_query_last_error_at)
        },
        usage_updated_at: if snapshot.credit_usage_raw.is_some() {
            Some(now)
        } else {
            existing.and_then(|item| item.usage_updated_at)
        },
        tags: existing.and_then(|item| item.tags.clone()),
        reward_claim_status: existing.and_then(|item| item.reward_claim_status.clone()),
        reward_window_end_at: existing.and_then(|item| item.reward_window_end_at),
        reward_status_updated_at: existing.and_then(|item| item.reward_status_updated_at),
        auth_user_info_raw: snapshot
            .user_info_raw
            .or_else(|| existing.and_then(|item| item.auth_user_info_raw.clone())),
        auth_user_plan_raw: snapshot
            .user_plan_raw
            .or_else(|| {
                if usage_confirms_plan {
                    None
                } else {
                    existing.and_then(|item| item.auth_user_plan_raw.clone())
                }
            }),
        auth_credit_usage_raw: snapshot
            .credit_usage_raw
            .or_else(|| existing.and_then(|item| item.auth_credit_usage_raw.clone())),
        web_session_cookie: existing.and_then(|item| item.web_session_cookie.clone()),
        web_quota_raw: if usage_refreshed {
            None
        } else {
            existing.and_then(|item| item.web_quota_raw.clone())
        },
        web_quota_updated_at: if usage_refreshed {
            None
        } else {
            existing.and_then(|item| item.web_quota_updated_at)
        },
        created_at: existing.map(|item| item.created_at).unwrap_or(now),
        last_used: now,
    }
}

fn find_existing_account_for_snapshot(
    snapshot: &QoderSnapshot,
    accounts: &[QoderAccount],
) -> Option<QoderAccount> {
    let user_id = extract_snapshot_user_id(snapshot);
    let generated_id = generate_account_id(snapshot, user_id.as_deref());
    accounts
        .iter()
        .find(|item| {
            QoderVariantKind::parse(snapshot.variant.as_deref())
                .map(|kind| account_supports_variant(item, kind))
                .unwrap_or(false)
                && same_identity(item, user_id.as_deref(), &generated_id)
        })
        .cloned()
}

fn read_qoder_secret_json_with_mode(
    db_path: &Path,
    db_key: &str,
    cn: bool,
) -> Result<Option<Value>, String> {
    let raw = if cn {
        crate::modules::vscode_inject::read_qoder_cn_secret_storage_value_by_db_path(db_path, db_key)?
    } else {
        crate::modules::vscode_inject::read_qoder_secret_storage_value_by_db_path(db_path, db_key)?
    };
    Ok(raw.map(|text| parse_json_or_string(text.as_str())))
}

fn read_snapshot_from_state_db_path_with_mode(
    db_path: &Path,
    cn: bool,
) -> Result<Option<QoderSnapshot>, String> {
    if !db_path.exists() {
        return Ok(None);
    }

    let snapshot = QoderSnapshot {
        variant: None,
        user_info_raw: read_qoder_secret_json_with_mode(db_path, QODER_SECRET_USER_INFO_KEY, cn)?,
        user_plan_raw: read_qoder_secret_json_with_mode(db_path, QODER_SECRET_USER_PLAN_KEY, cn)?,
        credit_usage_raw: read_qoder_secret_json_with_mode(
            db_path,
            QODER_SECRET_CREDIT_USAGE_KEY,
            cn,
        )?,
    };

    if snapshot_has_any_data(&snapshot) {
        Ok(Some(snapshot))
    } else {
        Ok(None)
    }
}

fn read_snapshot_from_state_db_path(db_path: &Path) -> Result<Option<QoderSnapshot>, String> {
    read_snapshot_from_state_db_path_with_mode(db_path, false)
}

fn merge_snapshot(snapshot: QoderSnapshot) -> Result<QoderAccount, String> {
    let _lock = QODER_ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|_| "获取 Qoder 账号锁失败".to_string())?;
    let index = merge_legacy_accounts_locked(load_account_index_checked()?)?;
    let accounts = list_accounts_from_index(&index);
    let existing = find_existing_account_for_snapshot(&snapshot, &accounts);
    let account = snapshot_to_account(snapshot, existing.as_ref());
    save_account_record_locked(account)
}

pub fn upsert_account_from_snapshot(
    user_info_raw: Value,
    user_plan_raw: Option<Value>,
    credit_usage_raw: Option<Value>,
) -> Result<QoderAccount, String> {
    merge_snapshot(QoderSnapshot {
        variant: None,
        user_info_raw: Some(user_info_raw),
        user_plan_raw,
        credit_usage_raw,
    })
}

pub(crate) fn check_qoder_variant_account_route(
    variant_key: &str,
) -> Result<QoderVariantKind, String> {
    QoderVariantKind::parse(Some(variant_key))
}

pub fn upsert_account_from_snapshot_for_variant(
    variant_key: &str,
    user_info_raw: Value,
    user_plan_raw: Option<Value>,
    credit_usage_raw: Option<Value>,
) -> Result<QoderAccount, String> {
    let kind = check_qoder_variant_account_route(variant_key)?;
    logger::log_info(&format!(
        "[Qoder Account] 变体入库路由: variant={} display={}",
        kind.provider_key(),
        kind.display_name(),
    ));
    // 按地区与官方用户 ID 合并；variant 仅记录当前凭据来源。
    merge_snapshot(QoderSnapshot {
        variant: stored_variant_key(kind),
        user_info_raw: Some(user_info_raw),
        user_plan_raw,
        credit_usage_raw,
    })
}

pub fn mark_account_needs_relogin(
    account_id: &str,
    reason: impl Into<String>,
) -> Result<QoderAccount, String> {
    let reason = reason.into();
    let tagged = if reason.contains("请重新登录") {
        reason
    } else {
        format!("{}，请重新登录", reason)
    };
    update_quota_query_error(account_id, Some(tagged))?.ok_or_else(|| {
        format!("Qoder 账号不存在，无法标记重登态: {}", account_id)
    })
}

pub fn get_default_qoder_state_db_path() -> Option<PathBuf> {
    let data_root = crate::modules::qoder_instance::get_default_qoder_user_data_dir().ok()?;
    Some(
        data_root
            .join("User")
            .join("globalStorage")
            .join("state.vscdb"),
    )
}

fn resolve_state_db_path_for_user_data_dir(user_data_dir: &str) -> PathBuf {
    PathBuf::from(user_data_dir)
        .join("User")
        .join("globalStorage")
        .join("state.vscdb")
}

pub fn ensure_state_db_path_for_user_data_dir(user_data_dir: &str) -> Result<PathBuf, String> {
    ensure_state_db_path_for_user_data_dir_with_fallback(
        user_data_dir,
        get_default_qoder_state_db_path(),
    )
}

/// 按变体解析默认 state.vscdb 路径，作为实例新库的复制回退源。
fn variant_default_state_db_path(kind: QoderVariantKind) -> Option<PathBuf> {
    let data_root =
        crate::modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind).ok()?;
    Some(
        data_root
            .join("User")
            .join("globalStorage")
            .join("state.vscdb"),
    )
}

fn ensure_state_db_path_for_user_data_dir_with_fallback(
    user_data_dir: &str,
    fallback_db: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let root = PathBuf::from(user_data_dir);
    let candidates = vec![
        root.join("User").join("globalStorage").join("state.vscdb"),
        root.join("globalStorage").join("state.vscdb"),
        root.join("state.vscdb"),
    ];

    if let Some(existing) = candidates.iter().find(|path| path.exists()) {
        return Ok(existing.clone());
    }

    let preferred = resolve_state_db_path_for_user_data_dir(user_data_dir);
    if let Some(parent) = preferred.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("创建 Qoder globalStorage 目录失败: {}", e))?;
    }

    if let Some(default_db) = fallback_db {
        if default_db.exists() && default_db != preferred {
            if let Err(err) = fs::copy(&default_db, &preferred) {
                logger::log_warn(&format!(
                    "[Qoder Inject] 复制默认 state.vscdb 失败，改为写入新库: from={}, to={}, error={}",
                    default_db.to_string_lossy(),
                    preferred.to_string_lossy(),
                    err
                ));
            }
        }
    }

    Ok(preferred)
}

fn ensure_default_state_db_path() -> Result<PathBuf, String> {
    let data_root = crate::modules::qoder_instance::get_default_qoder_user_data_dir()?;
    ensure_state_db_path_for_user_data_dir(&data_root.to_string_lossy())
}

/// 只读地定位已存在的 state.vscdb；不存在即视为「无账号」，绝不创建/复制（区别于注入路径）。
fn resolve_existing_state_db_path_for_user_data_dir(user_data_dir: &str) -> Option<PathBuf> {
    let root = PathBuf::from(user_data_dir);
    [
        root.join("User").join("globalStorage").join("state.vscdb"),
        root.join("globalStorage").join("state.vscdb"),
        root.join("state.vscdb"),
    ]
    .into_iter()
    .find(|path| path.exists())
}

/// 定位 App 变体的 `auth.v1.dat` 及其 userData（safeStorage data_root 候选来源）。
fn resolve_qoder_app_auth_path(kind: QoderVariantKind) -> Result<(PathBuf, PathBuf), String> {
    let params = crate::modules::qoder_oauth::resolve_qoder_variant_params(kind.provider_key())?;
    let user_data = crate::modules::qoder_oauth::qoder_user_data_dir_for_variant(&params)?;
    let auth_path = user_data.join(QODER_APP_AUTH_FILE);
    Ok((auth_path, user_data))
}

/// App `auth.v1.dat` 的唯一解密+JSON+凭证探测路径（本地只读导入与写回读回校验共用）。
/// 实测 schema：`{schemaVersion, token, refreshToken, expiresAt, refreshTokenExpiresAt, user}`。
/// 未知/损坏格式或缺少 token/refreshToken 一律拒绝，绝不猜格式。
fn decode_qoder_app_auth_value(
    auth_path: &Path,
    user_data: &Path,
    kind: QoderVariantKind,
) -> Result<Value, String> {
    let bytes = fs::read(auth_path).map_err(|e| {
        format!(
            "读取 Qoder App auth.v1.dat 失败: variant={}, path={}, error={}",
            kind.provider_key(),
            auth_path.display(),
            e
        )
    })?;
    let plaintext = crate::modules::vscode_inject::decrypt_qoder_app_auth_payload(
        &bytes,
        Some(user_data),
        kind == QoderVariantKind::QoderCnApp,
    )
    .map_err(|err| {
        format!(
            "Qoder App auth.v1.dat 格式探测失败（未知/损坏格式不猜）: variant={}, path={}, error={}",
            kind.provider_key(),
            auth_path.display(),
            err
        )
    })?;
    let value: Value = serde_json::from_slice(&plaintext).map_err(|e| {
        format!(
            "Qoder App auth.v1.dat 解密后非 JSON: variant={}, path={}, error={}",
            kind.provider_key(),
            auth_path.display(),
            e
        )
    })?;
    let has_credential = value
        .get("refreshToken")
        .map(|item| !item.is_null())
        .unwrap_or(false)
        || value
            .get("token")
            .map(|item| !item.is_null())
            .unwrap_or(false);
    if !has_credential {
        return Err(format!(
            "Qoder App auth.v1.dat 缺少 token/refreshToken，未知格式拒绝处理: variant={}, path={}",
            kind.provider_key(),
            auth_path.display()
        ));
    }
    Ok(value)
}

/// App 变体（`qoder_app`/`qoder_cn_app`）本地只读导入：读 `<userData>/auth.v1.dat`，
/// safeStorage(v10) 解密为该 schema 后整份作为账号原始凭证保存（与 IDE 变体保存
/// `secret://aicoding.auth.userInfo` 原文同构）。
fn read_qoder_app_snapshot(kind: QoderVariantKind) -> Result<Option<QoderSnapshot>, String> {
    if !kind.is_app() {
        return Err(format!(
            "内部错误: read_qoder_app_snapshot 仅服务 App 变体，收到 {}",
            kind.provider_key()
        ));
    }
    let (auth_path, user_data) = resolve_qoder_app_auth_path(kind)?;
    if !auth_path.exists() {
        return Ok(None);
    }
    let value = decode_qoder_app_auth_value(&auth_path, &user_data, kind)?;
    logger::log_info(&format!(
        "[Qoder Account] App 本地只读导入读取成功: variant={}, path={}",
        kind.provider_key(),
        auth_path.display()
    ));
    Ok(Some(QoderSnapshot {
        variant: stored_variant_key(kind),
        user_info_raw: Some(value),
        user_plan_raw: None,
        credit_usage_raw: None,
    }))
}

/// 官方登录只读探测：显式目录不允许回退默认库，也不把套餐缓存当成登录凭据。
pub(crate) struct OfficialLoginCandidate {
    snapshot: QoderSnapshot,
}

impl OfficialLoginCandidate {
    pub fn account_id(&self) -> String {
        // Existing records can have IDs from an earlier email-based import.
        // Use the same identity resolution as merge_snapshot when choosing the refresh lock.
        find_existing_account_for_snapshot(&self.snapshot, &list_accounts())
            .map(|account| account.id)
            .unwrap_or_else(|| snapshot_to_account(self.snapshot.clone(), None).id)
    }

    pub fn refresh_lock_key(&self) -> String {
        if let (Ok(kind), Some(uid)) = (QoderVariantKind::parse(self.snapshot.variant.as_deref()), extract_snapshot_user_id(&self.snapshot)) {
            return format!("qoder-account:{}:{}", kind.site().as_str(), uid);
        }
        self.account_id()
    }

    pub fn import(self) -> Result<QoderAccount, String> {
        merge_snapshot(self.snapshot)
    }
}

pub(crate) fn read_official_login_candidate(
    kind: QoderVariantKind,
    user_data: &Path,
) -> Result<Option<OfficialLoginCandidate>, String> {
    let snapshot = if kind.is_app() {
        let path = user_data.join(QODER_APP_AUTH_FILE);
        if !path.try_exists().map_err(|error| format!("检查官方登录凭据失败: {error}"))? {
            return Ok(None);
        }
        let raw = decode_qoder_app_auth_value(&path, user_data, kind)?;
        QoderSnapshot {
            variant: stored_variant_key(kind),
            user_info_raw: Some(raw),
            user_plan_raw: None,
            credit_usage_raw: None,
        }
    } else {
        let Some(db) = resolve_existing_state_db_path_for_user_data_dir(&user_data.to_string_lossy()) else {
            return Ok(None);
        };
        // 登录探测仅读认证载荷，套餐/额度的写入不作为完成依据。
        let raw = read_qoder_secret_json_with_mode(&db, QODER_SECRET_USER_INFO_KEY, kind.is_cn())?;
        QoderSnapshot {
            variant: stored_variant_key(kind),
            user_info_raw: raw,
            user_plan_raw: None,
            credit_usage_raw: None,
        }
    };
    if snapshot.user_info_raw.is_none() { return Ok(None); }
    let account = snapshot_to_account(snapshot.clone(), None);
    if crate::modules::qoder_oauth::extract_access_token_from_account(&account).is_none() {
        return Err("官方认证载荷缺少有效 token，继续等待客户端完成写入".to_string());
    }
    let identity = if kind.is_app() {
        snapshot.user_info_raw.as_ref()
            .and_then(|raw| raw.get("user"))
            .and_then(|user| user.get("id"))
            .and_then(Value::as_str)
            .and_then(|id| normalize_non_empty(Some(id)))
    } else {
        extract_snapshot_user_id(&snapshot)
    };
    identity.ok_or_else(|| "官方认证载荷缺少账号身份，继续等待客户端完成写入".to_string())?;
    Ok(Some(OfficialLoginCandidate { snapshot }))
}

fn app_session_matches_account(snapshot: &QoderSnapshot, account: &QoderAccount) -> bool {
    if !QoderVariantKind::parse(snapshot.variant.as_deref()).is_ok_and(|kind| kind.is_app() && account_supports_variant(account, kind)) {
        return false;
    }
    // App 的 user.id 是权威身份；不要用邮箱兜底把另一账号的凭证借过来。
    let local_id = snapshot.user_info_raw.as_ref()
        .and_then(|raw| raw.get("user"))
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str);
    match (local_id, account.user_id.as_deref()) {
        (Some(local), Some(saved)) => !local.is_empty() && local == saved,
        _ => false,
    }
}

#[cfg(test)]
mod official_login_tests {
    use super::*;

    #[test]
    fn missing_login_profile_stays_missing_for_every_variant() {
        let dir = std::env::temp_dir().join(format!("qoder-login-missing-{}", uuid::Uuid::new_v4()));
        for kind in all_qoder_variant_kinds() {
            assert!(read_official_login_candidate(kind, &dir).unwrap().is_none());
            assert!(!dir.exists(), "login observation must not create or seed a profile");
        }
    }

    #[test]
    fn quota_cache_without_credentials_does_not_complete_ide_login() {
        for kind in [QoderVariantKind::Qoder, QoderVariantKind::QoderCnIde] {
            let dir = std::env::temp_dir().join(format!("qoder-login-quota-{}", uuid::Uuid::new_v4()));
            let storage = dir.join("User").join("globalStorage");
            fs::create_dir_all(&storage).unwrap();
            let db = storage.join("state.vscdb");
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute("CREATE TABLE ItemTable (key TEXT PRIMARY KEY, value TEXT)", []).unwrap();
            conn.execute(
                "INSERT INTO ItemTable (key, value) VALUES (?1, ?2)",
                [QODER_SECRET_CREDIT_USAGE_KEY, r#"{"remaining":100}"#],
            ).unwrap();
            assert!(read_official_login_candidate(kind, &dir).unwrap().is_none());
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM ItemTable", [], |row| row.get(0)).unwrap();
            assert_eq!(count, 1, "observation must not copy default credentials into this database");
            drop(conn);
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

/// 本机 App 会话由官方客户端续期。读取其最新凭证仅供本次请求，不写文件/账号库。
/// 即使认证文件暂时消失，记忆中的当前账号也不能由后台接管续期。
pub(crate) fn app_owned_session(account: &QoderAccount) -> Result<Option<QoderAccount>, String> {
    let kind = account_variant_kind(account)?;
    if !kind.is_app() {
        return Ok(None);
    }
    // auth.v1.dat 在客户端退出后仍留在磁盘上；只有主进程运行时才由官方客户端续期。
    let data_dir = crate::modules::process::qoder_variant_default_user_data_dir(kind)
        .ok_or_else(|| "无法确定 Qoder App 默认数据目录，拒绝后台续期".to_string())?;
    if crate::modules::process::resolve_qoder_pid_for_variant(kind, None, Some(&data_dir)).is_none() {
        return Ok(None);
    }
    let current = crate::modules::provider_current_state::get_current_account_id(kind.provider_key())?;
    match read_qoder_app_snapshot(kind) {
        Ok(snapshot) => Ok(select_app_owned_session(account, snapshot, current.as_deref())),
        Err(err) if current.as_deref() == Some(account.id.as_str()) => {
            // 当前账号的 auth 文件可能正由官方客户端原子替换。此时只能保守地使用
            // 账号库快照查询，禁止把它当作离线账号去兑换 refresh token。
            logger::log_warn(&format!(
                "[Qoder Account] 当前 App 会话读取失败，保持官方会话所有权: variant={}, account_id={}, error={}",
                kind.provider_key(),
                account.id,
                err
            ));
            Ok(Some(account.clone()))
        }
        Err(err) => Err(err),
    }
}

fn select_app_owned_session(
    account: &QoderAccount,
    snapshot: Option<QoderSnapshot>,
    current_id: Option<&str>,
) -> Option<QoderAccount> {
    if let Some(snapshot) = snapshot {
        if app_session_matches_account(&snapshot, account) {
            let mut session = account.clone();
            session.auth_user_info_raw = snapshot.user_info_raw;
            return Some(session);
        }
    }
    (current_id == Some(account.id.as_str())).then(|| account.clone())
}

/// 调用方须先关闭 App。保留官方最后一次续期的凭证，供以后切回该账号。
pub(crate) fn save_closed_app_session(kind: QoderVariantKind) -> Result<(), String> {
    if let Some(snapshot) = read_qoder_app_snapshot(kind)? {
        save_closed_app_snapshot(snapshot)?;
    }
    Ok(())
}

fn save_closed_app_snapshot(mut snapshot: QoderSnapshot) -> Result<QoderAccount, String> {
    let auth = snapshot.user_info_raw.clone()
        .ok_or_else(|| "Qoder App 关闭后的会话缺少认证载荷".to_string())?;
    let has_user_id = auth.get("user")
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .is_some_and(|id| !id.trim().is_empty());
    if !has_user_id {
        return Err("Qoder App 关闭后的会话缺少用户 ID，拒绝保存".to_string());
    }
    // auth 文件中的 user 是身份资料，不是套餐；已有账号只更新官方最终凭证。
    snapshot.user_plan_raw = None;
    let _lock = QODER_ACCOUNT_INDEX_LOCK
        .lock()
        .map_err(|_| "获取 Qoder 账号锁失败".to_string())?;
    let index = merge_legacy_accounts_locked(load_account_index_checked()?)?;
    let accounts = list_accounts_from_index(&index);
    let account = if let Some(mut existing) = accounts
        .into_iter()
        .find(|account| app_session_matches_account(&snapshot, account))
    {
        existing = account_for_variant(&existing, QoderVariantKind::parse(snapshot.variant.as_deref())?)?;
        existing.auth_user_info_raw = Some(auth);
        existing
    } else {
        // 若本地导入尚未记录这个官方账号，仍需建档，避免切走后丢失最后的登录态。
        snapshot_to_account(snapshot, None)
    };
    save_account_record_locked(account)
}

/// Prepare the official App's own sign-in screen after its process has stopped.
/// The caller holds the variant session lock, the previous account's refresh lock
/// (when present), and the official-login cancellation boundary.
pub(crate) fn prepare_closed_app_official_login(
    kind: QoderVariantKind,
    candidate: Option<OfficialLoginCandidate>,
) -> Result<(), String> {
    if !kind.is_app() {
        return Err("只有 Qoder App 需要准备官方客户端登录态".to_string());
    }
    if !QODER_APP_WRITE_BACK_ENABLED {
        return Err("Qoder App 登录态写入已禁用，无法准备客户端登录页".to_string());
    }
    let (auth_path, user_data) = resolve_qoder_app_auth_path(kind)?;
    let ensure_stopped = || {
        if crate::modules::process::resolve_qoder_pid_for_variant(
            kind, None, Some(&user_data.to_string_lossy()),
        ).is_some() {
            Err("Qoder App 仍在运行，拒绝修改登录态".to_string())
        } else {
            Ok(())
        }
    };
    ensure_stopped()?;
    if let Some(candidate) = candidate {
        if candidate.snapshot.variant != stored_variant_key(kind) {
            return Err("旧账号与本次官方客户端版本不匹配，登录已中止".to_string());
        }
        let original = fs::read(&auth_path).map_err(|e| format!("读取旧登录态失败: {e}"))?;
        let auth = decode_qoder_app_auth_value(&auth_path, &user_data, kind)?;
        if candidate.snapshot.user_info_raw.as_ref() != Some(&auth) {
            return Err("旧登录态已变化，登录已中止，请重试".to_string());
        }
        // Preserve the client's last credentials and existing quota metadata before sign-out.
        save_closed_app_snapshot(candidate.snapshot)?;
        let backup = auth_path.with_extension(format!(
            "dat.cockpit-login-{}.bak", uuid::Uuid::new_v4().simple(),
        ));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&backup)
            .map_err(|e| format!("备份旧登录态失败，登录已中止: {e}"))?;
        {
            use std::io::Write;
            file.write_all(&original).and_then(|_| file.sync_all())
                .map_err(|e| format!("保存旧登录态备份失败，登录已中止: {e}"))?;
        }
        ensure_stopped()?;
        let expected_hash = Sha256::digest(&original).into();
        if !crate::modules::atomic_write::remove_file_if_hash_matches(&auth_path, expected_hash)? {
            return Err("旧登录态已变化，未退出账号；登录已中止，请重试".to_string());
        }
    } else if auth_path.try_exists().map_err(|e| format!("检查登录态失败: {e}"))? {
        return Err("登录态存在但无法确认账号，拒绝清空".to_string());
    }
    crate::modules::provider_current_state::set_current_account_id(kind.provider_key(), None)
        .map_err(|e| format!("客户端登录态已退出，旧账号已保存，但当前账号状态更新失败: {e}"))
}

fn read_local_snapshot_for_variant(kind: QoderVariantKind) -> Result<Option<QoderSnapshot>, String> {
    match kind {
        QoderVariantKind::Qoder => {
            read_snapshot_from_state_db_path(&ensure_default_state_db_path()?)
        }
        QoderVariantKind::QoderCnIde => {
            let params =
                crate::modules::qoder_oauth::resolve_qoder_variant_params(kind.provider_key())?;
            let user_data = crate::modules::qoder_oauth::qoder_user_data_dir_for_variant(&params)?;
            let Some(db_path) =
                resolve_existing_state_db_path_for_user_data_dir(&user_data.to_string_lossy())
            else {
                return Ok(None);
            };
            let Some(mut snapshot) = read_snapshot_from_state_db_path_with_mode(&db_path, true)?
            else {
                return Ok(None);
            };
            snapshot.variant = stored_variant_key(kind);
            Ok(Some(snapshot))
        }
        QoderVariantKind::QoderApp | QoderVariantKind::QoderCnApp => {
            read_qoder_app_snapshot(kind)
        }
    }
}

fn import_local_snapshot(
    kind: QoderVariantKind,
    mut read_snapshot: impl FnMut() -> Result<Option<QoderSnapshot>, String>,
) -> Result<Option<QoderAccount>, String> {
    // Match switching and official login: client session -> regional account -> storage.
    // Callers run this blocking operation off the UI and async worker threads.
    let session_lock = crate::modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.blocking_lock();
    let Some(snapshot) = read_snapshot()? else {
        return Ok(None);
    };
    let lock_key = OfficialLoginCandidate { snapshot }.refresh_lock_key();
    let account_lock = crate::modules::qoder_oauth::account_refresh_lock(&lock_key)?;
    let _account_guard = account_lock.blocking_lock();
    // The native client can change its session while the account lock is pending.
    // Re-read after draining an older credential update; never commit the earlier probe.
    let Some(snapshot) = read_snapshot()? else {
        return Ok(None);
    };
    let candidate = OfficialLoginCandidate { snapshot };
    if candidate.refresh_lock_key() != lock_key {
        return Err("本地 Qoder 登录账号已变化，未导入旧快照，请重试".to_string());
    }
    let account = candidate.import()?;
    crate::modules::provider_current_state::set_current_account_id(
        kind.provider_key(),
        Some(&account.id),
    )?;
    logger::log_info(&format!(
        "[Qoder Account] 变体本地导入成功: variant={}, id={}",
        kind.provider_key(),
        account.id
    ));
    Ok(Some(account))
}

/// Read native credentials and publish the current account under the same locks as switching.
/// Must run on a blocking thread, because the session/account locks may wait on network work.
pub fn import_from_local_for_variant(variant_key: &str) -> Result<Option<QoderAccount>, String> {
    let kind = check_qoder_variant_account_route(variant_key)?;
    import_local_snapshot(kind, || read_local_snapshot_for_variant(kind))
}

/// 默认 IDE 的监听身份仅来自 userInfo，保持原有字段优先级和大小写。
fn local_ide_identity_from_user_info(user_info: &str) -> (Option<String>, Option<String>) {
    let parsed = parse_json_or_string(user_info);
    let email = parsed
        .get("email")
        .and_then(Value::as_str)
        .map(str::to_string);
    let user_id = parsed
        .get("id")
        .or_else(|| parsed.get("userId"))
        .and_then(Value::as_str)
        .map(str::to_string);
    (email, user_id)
}

/// 变体感知的只读身份探针：默认 IDE 仅读 userInfo，其余变体复用账号快照读取路径。
/// 不入库、不写回；不让默认 IDE 的身份检测依赖套餐和额度数据。
/// 返回 `(email, user_id)`（均可能为 `None`，由调用方组合去重键）；无本地登录数据返回 `Ok(None)`。
/// 仅供 auto_local_import 本机变更监听使用；未知变体和读取错误向调用方返回。
pub fn peek_local_identity_for_variant(
    variant_key: &str,
) -> Result<Option<(Option<String>, Option<String>)>, String> {
    let kind = check_qoder_variant_account_route(variant_key)?;
    let snapshot = match kind {
        QoderVariantKind::Qoder => {
            let Some(db_path) = get_default_qoder_state_db_path().filter(|path| path.exists()) else {
                return Ok(None);
            };
            let user_info =
                crate::modules::vscode_inject::read_qoder_secret_storage_value_by_db_path(
                    &db_path,
                    QODER_SECRET_USER_INFO_KEY,
                )?;
            return Ok(user_info.map(|raw| local_ide_identity_from_user_info(&raw)));
        }
        QoderVariantKind::QoderCnIde => {
            let params =
                crate::modules::qoder_oauth::resolve_qoder_variant_params(kind.provider_key())?;
            let user_data = crate::modules::qoder_oauth::qoder_user_data_dir_for_variant(&params)?;
            match resolve_existing_state_db_path_for_user_data_dir(&user_data.to_string_lossy()) {
                Some(db_path) => read_snapshot_from_state_db_path_with_mode(&db_path, true)?,
                None => None,
            }
        }
        QoderVariantKind::QoderApp | QoderVariantKind::QoderCnApp => {
            read_qoder_app_snapshot(kind)?
        }
    };
    Ok(snapshot.map(|snap| (extract_snapshot_email(&snap), extract_snapshot_user_id(&snap))))
}

pub(crate) fn resolve_current_account_id(accounts: &[QoderAccount]) -> Option<String> {
    resolve_current_account_id_for_variant(accounts, QoderVariantKind::Qoder)
}

pub(crate) fn resolve_current_account_id_for_variant(
    accounts: &[QoderAccount],
    variant: QoderVariantKind,
) -> Option<String> {
    crate::modules::provider_current_state::resolve_existing_current_account_id(
        variant.provider_key(),
        accounts.iter().filter(|account| account_supports_variant(account, variant)).map(|account| account.id.as_str()),
    )
}

fn serialize_raw_or_fallback(raw: &Option<Value>, fallback: Value) -> Result<String, String> {
    let value = raw.clone().unwrap_or(fallback);
    serde_json::to_string(&value).map_err(|e| format!("序列化 Qoder 注入数据失败: {}", e))
}

fn build_qoder_inject_payloads(
    account: &QoderAccount,
    cn: bool,
) -> Result<(String, String, String), String> {
    let user_info_json = serialize_raw_or_fallback(
        &account.auth_user_info_raw,
        build_user_info_fallback(account),
    )?;
    let user_plan_json = serialize_raw_or_fallback(
        &account.auth_user_plan_raw,
        build_user_plan_fallback(account),
    )?;
    let (user_info_json, user_plan_json) = if cn {
        (
            ensure_qoder_cn_ide_login_source(user_info_json)?,
            ensure_qoder_cn_ide_login_version(user_plan_json)?,
        )
    } else {
        (user_info_json, user_plan_json)
    };
    let credit_usage_json = serialize_raw_or_fallback(
        &account.auth_credit_usage_raw,
        build_credit_usage_fallback(account),
    )?;
    Ok((user_info_json, user_plan_json, credit_usage_json))
}

fn ensure_qoder_cn_ide_login_source(json: String) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(&json)
        .map_err(|e| format!("解析 Qoder CN IDE 注入载荷失败: {}", e))?;
    if let Value::Object(map) = &mut value {
        map.entry("login_source".to_string())
            .or_insert_with(|| Value::String(QODER_CN_IDE_LOGIN_SOURCE.to_string()));
    }
    serde_json::to_string(&value).map_err(|e| format!("序列化 Qoder CN IDE 注入载荷失败: {}", e))
}

fn ensure_qoder_cn_ide_login_version(json: String) -> Result<String, String> {
    let mut value: Value = serde_json::from_str(&json)
        .map_err(|e| format!("解析 Qoder CN IDE 计划载荷失败: {}", e))?;
    if let Value::Object(map) = &mut value {
        map.entry("login_source".to_string())
            .or_insert_with(|| Value::String(QODER_CN_IDE_LOGIN_SOURCE.to_string()));
        map.entry("login_version".to_string())
            .or_insert_with(|| Value::String(QODER_CN_IDE_LOGIN_VERSION.to_string()));
    }
    serde_json::to_string(&value).map_err(|e| format!("序列化 Qoder CN IDE 计划载荷失败: {}", e))
}

fn build_user_info_fallback(account: &QoderAccount) -> Value {
    serde_json::json!({
        "id": account.user_id.clone().unwrap_or_default(),
        "email": account.email,
        "name": account.display_name.clone().unwrap_or_default(),
    })
}

fn build_user_plan_fallback(account: &QoderAccount) -> Value {
    serde_json::json!({
        "plan": account.plan_type.clone().unwrap_or_default(),
        "tier": account.plan_type.clone().unwrap_or_default(),
    })
}

fn build_credit_usage_fallback(account: &QoderAccount) -> Value {
    serde_json::json!({
        "used": account.credits_used,
        "total": account.credits_total,
        "remaining": account.credits_remaining,
        "usagePercent": account.credits_usage_percent,
    })
}

fn verify_state_db_key_exists(db_path: &Path, db_key: &str) -> Result<(), String> {
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| format!("注入校验失败，无法打开 state.vscdb: {}", e))?;

    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM ItemTable WHERE key = ?1",
            [db_key],
            |row| row.get(0),
        )
        .ok();

    match value {
        Some(stored) if !stored.trim().is_empty() => Ok(()),
        _ => Err(format!(
            "注入校验失败，未在 state.vscdb 找到 key: db={}, key={}",
            db_path.to_string_lossy(),
            db_key
        )),
    }
}

fn verify_injected_account_matches_with_mode(
    db_path: &Path,
    account: &QoderAccount,
    cn: bool,
) -> Result<(), String> {
    let snapshot = read_snapshot_from_state_db_path_with_mode(db_path, cn)?.ok_or_else(|| {
        format!(
            "注入校验失败，未读取到 state.vscdb 快照: {}",
            db_path.display()
        )
    })?;
    let effective_user_id = extract_snapshot_user_id(&snapshot);
    let effective_email = extract_snapshot_email(&snapshot);
    let generated_id = generate_account_id(
        &snapshot,
        effective_user_id.as_deref(),
    );

    if same_identity(
        account,
        effective_user_id.as_deref(),
        &generated_id,
    ) {
        return Ok(());
    }

    Err(format!(
        "注入校验失败，落盘账号与目标账号不一致: db={}, target_id={}, target_email={}, actual_user_id={:?}, actual_email={:?}",
        db_path.display(),
        account.id,
        account.email,
        effective_user_id,
        effective_email
    ))
}

pub fn inject_to_qoder(account_id: &str) -> Result<(), String> {
    let db_path = ensure_default_state_db_path()?;
    inject_to_qoder_at_path(&db_path, account_id)
}

pub fn inject_to_qoder_for_user_data_dir(
    user_data_dir: &str,
    account_id: &str,
) -> Result<(), String> {
    let db_path = ensure_state_db_path_for_user_data_dir(user_data_dir)?;
    inject_to_qoder_at_path(&db_path, account_id)
}

pub fn inject_to_qoder_at_path(db_path: &Path, account_id: &str) -> Result<(), String> {
    inject_ide_account_at_path(db_path, account_id, false, false)
}

fn backup_state_db(db_path: &Path) -> Result<Option<PathBuf>, String> {
    if !db_path.exists() {
        return Ok(None);
    }
    let backup = db_path.with_extension("vscdb.cockpit-bak");
    fs::copy(db_path, &backup).map_err(|e| {
        format!(
            "备份 state.vscdb 失败，拒绝写入: db={}, backup={}, error={}",
            db_path.display(),
            backup.display(),
            e
        )
    })?;
    logger::log_info(&format!(
        "[Qoder Inject] state.vscdb 已备份: db={}, backup={}",
        db_path.display(),
        backup.display()
    ));
    Ok(Some(backup))
}

fn probe_qoder_cn_state_db_format(db_path: &Path) -> Result<(), String> {
    if !db_path.exists() {
        return Ok(());
    }
    match crate::modules::vscode_inject::read_qoder_cn_secret_storage_value_by_db_path(
        db_path,
        QODER_SECRET_USER_INFO_KEY,
    ) {
        Ok(_) => Ok(()),
        Err(err) => Err(format!(
            "CN IDE state.vscdb 格式探测失败，未知/损坏格式拒绝写入并告警: db={}, error={}",
            db_path.display(),
            err
        )),
    }
}

fn inject_ide_account_at_path(
    db_path: &Path,
    account_id: &str,
    cn: bool,
    backup: bool,
) -> Result<(), String> {
    let saved = load_account(account_id).ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let kind = if cn { QoderVariantKind::QoderCnIde } else { QoderVariantKind::Qoder };
    if !has_client_auth(&saved, kind) { return Err("请先准备目标 IDE 登录凭据".into()); }
    let account = account_for_variant(&saved, kind)?;
    if cn {
        let user_info = account.auth_user_info_raw.as_ref()
            .ok_or_else(|| "Qoder CN IDE 缺少登录资料，拒绝写入".to_string())?;
        // 包含领取后回写等同步入口：轮换后待补齐的凭证不能热写进客户端。
        crate::modules::qoder_oauth::ensure_cn_ide_login_info_ready(user_info)?;
    }
    // 写前纪律：先备份（CN IDE 路径 backup=true），再探测格式；探测失败即拒写。
    let backup_path = if backup {
        backup_state_db(db_path)?
    } else {
        None
    };
    if cn {
        probe_qoder_cn_state_db_format(db_path)?;
    }
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("创建 Qoder state.vscdb 目录失败: {}", e))?;
    }

    let (user_info_json, user_plan_json, credit_usage_json) =
        build_qoder_inject_payloads(&account, cn)?;

    let write_secret = |db_key: &str, plaintext: &str| -> Result<(), String> {
        if cn {
            crate::modules::vscode_inject::inject_secret_to_state_db_for_qoder_cn(
                db_path, db_key, plaintext,
            )
        } else {
            crate::modules::vscode_inject::inject_secret_to_state_db_for_qoder(
                db_path, db_key, plaintext,
            )
        }
    };
    let write_result = (|| -> Result<(), String> {
        write_secret(QODER_SECRET_USER_INFO_KEY, &user_info_json)?;
        write_secret(QODER_SECRET_USER_PLAN_KEY, &user_plan_json)?;
        write_secret(QODER_SECRET_CREDIT_USAGE_KEY, &credit_usage_json)?;

        verify_state_db_key_exists(db_path, QODER_SECRET_USER_INFO_KEY)?;
        verify_state_db_key_exists(db_path, QODER_SECRET_USER_PLAN_KEY)?;
        verify_state_db_key_exists(db_path, QODER_SECRET_CREDIT_USAGE_KEY)?;
        verify_injected_account_matches_with_mode(db_path, &account, cn)?;
        Ok(())
    })();

    if let Err(err) = write_result {
        if let Some(backup) = backup_path.as_ref() {
            let variant = if cn { "qoder_cn_ide" } else { "qoder" };
            match fs::copy(backup, db_path) {
                Ok(_) => logger::log_warn(&format!(
                    "[Qoder Inject] round-trip 读回校验失败，已回滚 state.vscdb 备份: variant={}, db={}, backup={}, error={}",
                    variant,
                    db_path.display(),
                    backup.display(),
                    err
                )),
                Err(rollback_err) => logger::log_warn(&format!(
                    "[Qoder Inject] round-trip 读回校验失败且回滚备份失败，请人工恢复: variant={}, db={}, backup={}, error={}, rollback_error={}",
                    variant,
                    db_path.display(),
                    backup.display(),
                    err,
                    rollback_err
                )),
            }
        }
        return Err(err);
    }

    update_last_used(account_id)
        .map_err(|err| format!("Qoder 登录态已写入，但账号元数据更新失败: {}", err))?;

    logger::log_info(&format!(
        "[Qoder Inject] 注入成功: variant={}, account_id={}, email={}, db={}",
        if cn { "qoder_cn_ide" } else { "qoder" },
        account.id,
        account.email,
        db_path.to_string_lossy()
    ));
    Ok(())
}

pub fn inject_to_qoder_cn_ide(account_id: &str) -> Result<(), String> {
    let params = crate::modules::qoder_oauth::resolve_qoder_variant_params(
        QoderVariantKind::QoderCnIde.provider_key(),
    )?;
    let user_data = crate::modules::qoder_oauth::qoder_user_data_dir_for_variant(&params)?;
    let db_path = resolve_existing_state_db_path_for_user_data_dir(&user_data.to_string_lossy())
        .unwrap_or_else(|| resolve_state_db_path_for_user_data_dir(&user_data.to_string_lossy()));
    inject_ide_account_at_path(&db_path, account_id, true, true)
}

fn app_raw_string<'a>(raw: &'a Value, key: &str) -> Option<&'a str> {
    raw.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn ms_string_to_iso(value: Option<&Value>) -> Option<String> {
    let millis = value?.as_str()?.trim().parse::<i64>().ok()?;
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// 构造写回 App 的 auth 载荷：
/// - 账号原始载荷若已是 App 同构（`schemaVersion`/`token`/`refreshToken`/`user`），原文复用；
/// - 否则仅沿用现有文件的 schemaVersion，凭证和用户身份都从目标账号重建，
///   避免切号时继承上一账号的姓名、邮箱或手机号。
fn build_qoder_app_auth_payload(
    template: Option<&Value>,
    account: &QoderAccount,
) -> Result<Value, String> {
    let raw = account
        .auth_user_info_raw
        .as_ref()
        .ok_or_else(|| format!("App 账号缺少 auth 原始载荷，拒绝写回: {}", account.id))?;
    let is_app_shaped = raw.get("schemaVersion").is_some()
        && raw.get("token").is_some()
        && raw.get("refreshToken").is_some()
        && raw.get("user").map(Value::is_object).unwrap_or(false);
    if is_app_shaped {
        return Ok(raw.clone());
    }

    let token = app_raw_string(raw, "token")
        .ok_or_else(|| format!("App 账号缺少 token，拒绝写回: {}", account.id))?;
    let refresh_token = app_raw_string(raw, "refreshToken")
        .ok_or_else(|| format!("App 账号缺少 refreshToken，拒绝写回: {}", account.id))?;

    let mut payload = serde_json::Map::new();
    let schema_version = raw
        .get("schemaVersion")
        .or_else(|| template.and_then(|value| value.get("schemaVersion")))
        .filter(|value| value.is_number())
        .cloned()
        .unwrap_or_else(|| Value::from(1));
    payload.insert("schemaVersion".to_string(), schema_version);
    payload.insert("token".to_string(), Value::String(token.to_string()));
    payload.insert(
        "refreshToken".to_string(),
        Value::String(refresh_token.to_string()),
    );
    if let Some(iso) = ms_string_to_iso(raw.get("expireTime"))
        .or_else(|| app_raw_string(raw, "expiresAt").map(str::to_string))
    {
        payload.insert("expiresAt".to_string(), Value::String(iso));
    }
    if let Some(iso) = ms_string_to_iso(raw.get("refreshTokenExpireTime"))
        .or_else(|| app_raw_string(raw, "refreshTokenExpiresAt").map(str::to_string))
    {
        payload.insert("refreshTokenExpiresAt".to_string(), Value::String(iso));
    }

    let mut user = serde_json::Map::new();
    let raw_user = raw.get("user");
    for key in ["id", "name", "email", "avatarUrl", "phone"] {
        if let Some(text) = raw_user
            .and_then(|value| app_raw_string(value, key))
            .or_else(|| app_raw_string(raw, key))
        {
            user.insert(key.to_string(), Value::String(text.to_string()));
        }
    }
    if !user.contains_key("phone") {
        if let Some(phone) = app_raw_string(raw, "security_mobile") {
            user.insert("phone".to_string(), Value::String(phone.to_string()));
        }
    }
    if !user.contains_key("id") {
        if let Some(uid) = normalize_non_empty(account.user_id.as_deref()) {
            user.insert("id".to_string(), Value::String(uid));
        }
    }
    if !user.contains_key("id") {
        return Err(format!("App 账号缺少用户 ID，拒绝写回: {}", account.id));
    }
    if !user.contains_key("name") {
        if let Some(name) = normalize_non_empty(account.display_name.as_deref()) {
            user.insert("name".to_string(), Value::String(name));
        }
    }
    if !user.contains_key("email") && !account_email_is_sentinel(&account.email) {
        user.insert("email".to_string(), Value::String(account.email.clone()));
    }
    payload.insert("user".to_string(), Value::Object(user));
    Ok(Value::Object(payload))
}

fn backup_qoder_app_auth(auth_path: &Path) -> Result<Option<PathBuf>, String> {
    if !auth_path.exists() {
        return Ok(None);
    }
    let backup = auth_path.with_extension("dat.cockpit-bak");
    fs::copy(auth_path, &backup).map_err(|e| {
        format!(
            "备份 Qoder App auth.v1.dat 失败，拒绝写入: path={}, backup={}, error={}",
            auth_path.display(),
            backup.display(),
            e
        )
    })?;
    logger::log_info(&format!(
        "[Qoder Inject] App auth.v1.dat 已备份: path={}, backup={}",
        auth_path.display(),
        backup.display()
    ));
    Ok(Some(backup))
}

/// App 写回核心：格式探测（已有文件必须先能解密解析）→ 备份 → 写 → 立即读回+解密+比对；
/// 读回失败时恢复已有文件的备份，或按内容校验移除本次新建的文件。
fn write_qoder_app_auth(kind: QoderVariantKind, account: &QoderAccount) -> Result<(), String> {
    let (auth_path, user_data) = resolve_qoder_app_auth_path(kind)?;
    let template = if auth_path.exists() {
        Some(decode_qoder_app_auth_value(&auth_path, &user_data, kind)?)
    } else {
        logger::log_warn(&format!(
            "[Qoder Inject] App 变体无现有 auth.v1.dat，将按标准格式新建: variant={}, path={}",
            kind.provider_key(),
            auth_path.display()
        ));
        None
    };
    let payload = build_qoder_app_auth_payload(template.as_ref(), account)?;
    let plaintext = serde_json::to_vec(&payload)
        .map_err(|e| format!("序列化 Qoder App auth 载荷失败: {}", e))?;
    let encrypted = crate::modules::vscode_inject::encrypt_qoder_app_auth_payload(
        &plaintext,
        Some(user_data.as_path()),
        kind == QoderVariantKind::QoderCnApp,
    )
    .map_err(|err| {
        format!(
            "Qoder App auth.v1.dat 加密失败: variant={}, path={}, error={}",
            kind.provider_key(),
            auth_path.display(),
            err
        )
    })?;

    let backup_path = backup_qoder_app_auth(&auth_path)?;
    let mut wrote_auth = false;
    let write_result = (|| -> Result<(), String> {
        // 先确保父目录存在（App 未登录过时 userData 可能缺 auth 文件但目录通常已在）。
        if let Some(parent) = auth_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("创建 Qoder App userData 目录失败: {}", e))?;
        }
        crate::modules::atomic_write::write_bytes_atomic(&auth_path, &encrypted)?;
        wrote_auth = true;
        let reread = decode_qoder_app_auth_value(&auth_path, &user_data, kind)?;
        if reread != payload {
            return Err(format!(
                "App 写回读回校验失败，落盘载荷与目标账号不一致: variant={}, account_id={}, path={}",
                kind.provider_key(),
                account.id,
                auth_path.display()
            ));
        }
        Ok(())
    })();

    if let Err(err) = write_result {
        if let Some(backup) = backup_path.as_ref() {
            match fs::copy(backup, &auth_path) {
                Ok(_) => logger::log_warn(&format!(
                    "[Qoder Inject] App round-trip 校验失败，已回滚 auth.v1.dat 备份: variant={}, path={}, backup={}, error={}",
                    kind.provider_key(),
                    auth_path.display(),
                    backup.display(),
                    err
                )),
                Err(rollback_err) => logger::log_warn(&format!(
                    "[Qoder Inject] App round-trip 校验失败且回滚备份失败，请人工恢复: variant={}, path={}, backup={}, error={}, rollback_error={}",
                    kind.provider_key(),
                    auth_path.display(),
                    backup.display(),
                    err,
                    rollback_err
                )),
            }
        } else if wrote_auth {
            let expected_hash = Sha256::digest(&encrypted).into();
            match crate::modules::atomic_write::remove_file_if_hash_matches(
                &auth_path,
                expected_hash,
            ) {
                Ok(true) => logger::log_warn(&format!(
                    "[Qoder Inject] App round-trip 校验失败，已移除本次新建的 auth.v1.dat: variant={}, path={}, error={}",
                    kind.provider_key(),
                    auth_path.display(),
                    err
                )),
                Ok(false) => {
                    return Err(format!(
                        "{}；本次新建的 auth.v1.dat 不存在或内容已变化，无法确认回滚结果: path={}",
                        err,
                        auth_path.display()
                    ));
                }
                Err(rollback_err) => {
                    return Err(format!(
                        "{}；移除本次新建的 auth.v1.dat 失败: path={}, rollback_error={}",
                        err,
                        auth_path.display(),
                        rollback_err
                    ));
                }
            }
        }
        return Err(err);
    }

    logger::log_info(&format!(
        "[Qoder Inject] App 写回成功（backup→write→re-read）: variant={}, account_id={}, email={}, path={}",
        kind.provider_key(),
        account.id,
        account.email,
        auth_path.display()
    ));
    Ok(())
}

/// App 系（`qoder_app`/`qoder_cn_app`）切号写回入口。门控检查在 `inject_to_qoder_for_variant`。
pub fn inject_to_qoder_app(kind: QoderVariantKind, account_id: &str) -> Result<(), String> {
    if !kind.is_app() {
        return Err(format!(
            "内部错误: inject_to_qoder_app 仅服务 App 变体，收到 {}",
            kind.provider_key()
        ));
    }
    let saved = load_account(account_id).ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    if !has_client_auth(&saved, kind) { return Err("请先准备目标 App 登录凭据".into()); }
    let account = account_for_variant(&saved, kind)?;
    write_qoder_app_auth(kind, &account)?;
    update_last_used(account_id)
        .map_err(|err| format!("Qoder App 登录态已写入，但账号元数据更新失败: {}", err))?;
    Ok(())
}

pub fn inject_to_qoder_for_variant(variant_key: &str, account_id: &str) -> Result<(), String> {
    let kind = check_qoder_variant_account_route(variant_key)?;
    match kind {
        QoderVariantKind::Qoder => inject_to_qoder(account_id),
        QoderVariantKind::QoderCnIde => inject_to_qoder_cn_ide(account_id),
        QoderVariantKind::QoderApp | QoderVariantKind::QoderCnApp => {
            if !QODER_APP_WRITE_BACK_ENABLED {
                return Err(format!(
                    "Qoder 变体 {} 的 App 写回为门控关闭（QODER_APP_WRITE_BACK_ENABLED={}）：需先在测试机完成 backup→write→re-read round-trip 实证（auth.v1.dat）才可启用，当前仅支持只读导入",
                    variant_key, QODER_APP_WRITE_BACK_ENABLED
                ));
            }
            inject_to_qoder_app(kind, account_id)
        }
    }
}

/// 多开实例启动前注入：按变体与显式 user_data_dir 写入目标账号登录态（仅 IDE 系）。
pub fn inject_to_qoder_for_variant_user_data_dir(
    kind: QoderVariantKind,
    user_data_dir: &str,
    account_id: &str,
) -> Result<(), String> {
    if !kind.supports_instances() {
        return Err(format!(
            "{} 客户端不支持应用多开（官方单实例机制），无法按实例目录注入登录态",
            kind.display_name()
        ));
    }

    // 必须在创建实例目录或复制登录库之前校验，不能把其他变体的凭证注入当前实例。
    let account = load_account(account_id)
        .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))?;
    let account_kind = account_variant_kind(&account)?;
    if account_kind.site() != kind.site() {
        return Err(format!(
            "实例变体与绑定账号不一致: instance={}, account={}",
            kind.provider_key(),
            account_kind.provider_key()
        ));
    }
    let fallback = variant_default_state_db_path(kind);
    let db_path = ensure_state_db_path_for_user_data_dir_with_fallback(user_data_dir, fallback)?;
    inject_ide_account_at_path(&db_path, account_id, kind.is_cn(), kind.is_cn())
}

pub fn update_account_tags(account_id: &str, tags: Vec<String>) -> Result<QoderAccount, String> {
    update_account_metadata(account_id, |account| {
        account.tags = normalize_tags(tags);
        account.last_used = now_ts();
    })?
    .ok_or_else(|| format!("Qoder 账号不存在: {}", account_id))
}

fn normalize_imported_account(mut account: QoderAccount) -> Result<QoderAccount, String> {
    let now = now_ts();
    // 完整账号遵守存储契约：历史备份和国际 IDE 导出省略 variant，仍属于 qoder。
    // 只有下方原始凭证分支才使用导入页面提供的变体。
    let variant = QoderVariantKind::parse(account.variant.as_deref())
        .map_err(|err| format!("导入账号变体无效: {}", err))?;
    account.variant = stored_variant_key(variant);
    account.id = sanitize_account_id_component(account.id.trim());
    if account.id.is_empty() {
        let snapshot = QoderSnapshot {
            variant: account.variant.clone(),
            user_info_raw: account.auth_user_info_raw.clone(),
            user_plan_raw: account.auth_user_plan_raw.clone(),
            credit_usage_raw: account.auth_credit_usage_raw.clone(),
        };
        account.id = generate_account_id(
            &snapshot,
            account.user_id.as_deref(),
        );
    }
    account.email = normalize_email(Some(account.email.as_str()))
        .unwrap_or_else(|| "unknown@qoder.local".to_string());
    account.user_id = normalize_non_empty(account.user_id.as_deref());
    account.display_name = normalize_non_empty(account.display_name.as_deref());
    account.plan_type = normalize_non_empty(account.plan_type.as_deref());
    account.tags = normalize_tags(account.tags.unwrap_or_default());
    account.quota_query_last_error = normalize_non_empty(account.quota_query_last_error.as_deref());
    if account.created_at <= 0 {
        account.created_at = now;
    }
    if account.last_used <= 0 {
        account.last_used = now;
    }
    if account.credits_usage_percent.is_none() {
        if let (Some(used), Some(total)) = (account.credits_used, account.credits_total) {
            if total > 0.0 {
                account.credits_usage_percent = Some(clamp_percent((used / total) * 100.0));
            }
        }
    }
    Ok(account)
}

fn parse_import_item(
    item: &Value,
    default_variant: QoderVariantKind,
) -> Result<QoderAccount, String> {
    if let Ok(account) = serde_json::from_value::<QoderAccount>(item.clone()) {
        return normalize_imported_account(account);
    }

    let Some(obj) = item.as_object() else {
        return Err("Qoder 导入数据格式无效".to_string());
    };

    let variant = match obj.get("variant") {
        None | Some(Value::Null) => default_variant,
        Some(Value::String(raw)) => QoderVariantKind::parse(Some(raw))
            .map_err(|err| format!("导入账号变体无效: {}", err))?,
        Some(_) => return Err("导入账号变体必须是字符串或 null".to_string()),
    };
    let snapshot = QoderSnapshot {
        variant: stored_variant_key(variant),
        user_info_raw: obj
            .get("auth_user_info_raw")
            .or_else(|| obj.get("userInfo"))
            .cloned(),
        user_plan_raw: obj
            .get("auth_user_plan_raw")
            .or_else(|| obj.get("userPlan"))
            .cloned(),
        credit_usage_raw: obj
            .get("auth_credit_usage_raw")
            .or_else(|| obj.get("creditUsage"))
            .cloned(),
    };

    if !snapshot_has_any_data(&snapshot) {
        return Err("Qoder 导入项缺少账号字段".to_string());
    }

    Ok(snapshot_to_account(snapshot, None))
}

pub fn import_from_json(json_content: &str) -> Result<Vec<QoderAccount>, String> {
    import_from_json_for_variant(json_content, QoderVariantKind::Qoder.provider_key())
}

pub fn import_from_json_for_variant(
    json_content: &str,
    variant_key: &str,
) -> Result<Vec<QoderAccount>, String> {
    let default_variant = QoderVariantKind::parse(Some(variant_key))?;
    let parsed: Value =
        serde_json::from_str(json_content).map_err(|e| format!("JSON 解析失败: {}", e))?;
    let items: Vec<Value> = match parsed {
        Value::Array(list) => list,
        Value::Object(map) => {
            if let Some(Value::Array(list)) = map.get("accounts") {
                list.clone()
            } else {
                vec![Value::Object(map)]
            }
        }
        _ => return Err("仅支持对象或数组格式的 Qoder JSON".to_string()),
    };

    if items.is_empty() {
        return Ok(Vec::new());
    }

    let mut imported = Vec::new();
    for item in items {
        let account = parse_import_item(&item, default_variant)?;
        let saved = upsert_account_record(account)?;
        imported.push(saved);
    }

    Ok(imported)
}

pub fn export_accounts(
    account_ids: &[String],
    include_credentials: bool,
) -> Result<String, String> {
    let accounts = list_accounts();
    let selected: Vec<QoderAccount> = if account_ids.is_empty() {
        accounts
    } else {
        let target: HashSet<String> = account_ids
            .iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect();
        accounts
            .into_iter()
            .filter(|item| target.contains(&item.id))
            .collect()
    };

    let selected = if include_credentials {
        selected
    } else {
        selected
            .into_iter()
            .map(QoderAccount::without_credentials)
            .collect()
    };
    serde_json::to_string_pretty(&selected).map_err(|e| format!("序列化导出 JSON 失败: {}", e))
}

fn normalize_quota_alert_threshold(raw: i32) -> i32 {
    raw.clamp(0, 100)
}

fn build_quota_alert_cooldown_key(account_id: &str, threshold: i32) -> String {
    format!("qoder:{}:{}", account_id, threshold)
}

fn should_emit_quota_alert(cooldown_key: &str, now: i64) -> bool {
    let Ok(mut state) = QODER_QUOTA_ALERT_LAST_SENT.lock() else {
        return true;
    };

    if let Some(last_sent) = state.get(cooldown_key) {
        if now - *last_sent < QODER_QUOTA_ALERT_COOLDOWN_SECONDS {
            return false;
        }
    }

    state.insert(cooldown_key.to_string(), now);
    true
}

fn clear_quota_alert_cooldown(account_id: &str, threshold: i32) {
    if let Ok(mut state) = QODER_QUOTA_ALERT_LAST_SENT.lock() {
        state.remove(&build_quota_alert_cooldown_key(account_id, threshold));
    }
}

/// `credits_usage_percent` 是已用百分比（0-100）；预警口径与同族平台一致取「剩余百分比」。
pub(crate) fn remaining_quota_percent(account: &QoderAccount) -> Option<i32> {
    let used = account.credits_usage_percent?;
    if !used.is_finite() {
        return None;
    }
    let remaining = 100.0 - used.clamp(0.0, 100.0);
    Some(remaining.round().clamp(0.0, 100.0) as i32)
}

pub(crate) fn extract_quota_metrics(account: &QoderAccount) -> Vec<(String, i32)> {
    remaining_quota_percent(account)
        .map(|percent| vec![("Credits".to_string(), percent)])
        .unwrap_or_default()
}

fn filter_low_quota_models(metrics: &[(String, i32)], threshold: i32) -> Vec<(String, i32)> {
    metrics
        .iter()
        .filter(|(_, percent)| *percent <= threshold)
        .cloned()
        .collect()
}

fn average_quota_percentage(metrics: &[(String, i32)]) -> f64 {
    if metrics.is_empty() {
        return 0.0;
    }
    let sum: i32 = metrics.iter().map(|(_, percent)| *percent).sum();
    sum as f64 / metrics.len() as f64
}

fn pick_quota_alert_recommendation<'a>(
    accounts: &'a [QoderAccount],
    current_id: &str,
    kind: QoderVariantKind,
) -> Option<&'a QoderAccount> {
    let mut candidates: Vec<&QoderAccount> = accounts
        .iter()
        .filter(|account| account.id != current_id)
        .filter(|account| account_supports_variant(account, kind))
        .filter(|account| !extract_quota_metrics(account).is_empty())
        .collect();

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by(|left, right| {
        let avg_left = average_quota_percentage(&extract_quota_metrics(left));
        let avg_right = average_quota_percentage(&extract_quota_metrics(right));
        avg_right
            .partial_cmp(&avg_left)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.last_used.cmp(&left.last_used))
    });

    candidates.into_iter().next()
}

/// Qoder 配额预警：阈值口径 = 剩余百分比（`credits_usage_percent` 取反），与同族平台（cursor/kiro/zed）
/// 一致。变体感知：逐一检查 4 个客户端各自的「当前账号」（后端当前账号映射为权威），每个变体独立
/// 去重/冷却，命中即派发 `quota:alert`（platform=对应变体键）。纯阈值逻辑，无网络；通知由
/// `account::dispatch_quota_alert` 统一出口。
pub fn run_quota_alert_if_needed() -> Result<(), String> {
    let config = crate::modules::config::get_user_config();
    if !config.qoder_quota_alert_enabled {
        return Ok(());
    }

    let threshold = normalize_quota_alert_threshold(config.qoder_quota_alert_threshold);
    let accounts = list_accounts();
    let now = now_ts();

    for kind in all_qoder_variant_kinds() {
        let current_id = match resolve_current_account_id_for_variant(&accounts, kind) {
            Some(id) => id,
            None => continue,
        };
        let Some(current) = accounts.iter().find(|account| account.id == current_id) else {
            continue;
        };

        let metrics = extract_quota_metrics(current);
        let low_models = filter_low_quota_models(&metrics, threshold);
        if low_models.is_empty() {
            clear_quota_alert_cooldown(&current_id, threshold);
            continue;
        }

        let cooldown_key = build_quota_alert_cooldown_key(&current_id, threshold);
        if !should_emit_quota_alert(&cooldown_key, now) {
            continue;
        }

        let recommendation = pick_quota_alert_recommendation(&accounts, &current_id, kind);
        let lowest_percentage = low_models
            .iter()
            .map(|(_, percent)| *percent)
            .min()
            .unwrap_or(0);
        crate::modules::account::dispatch_quota_alert(&crate::modules::account::QuotaAlertPayload {
            platform: kind.provider_key().to_string(),
            current_account_id: current_id,
            current_email: current.email.clone(),
            threshold,
            threshold_display: None,
            lowest_percentage,
            low_models: low_models.into_iter().map(|(name, _)| name).collect(),
            recommended_account_id: recommendation.map(|account| account.id.clone()),
            recommended_email: recommendation.map(|account| account.email.clone()),
            triggered_at: now,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_name_is_not_inferred_as_plan_type() {
        let snapshot = QoderSnapshot {
            variant: stored_variant_key(QoderVariantKind::QoderApp),
            user_info_raw: Some(serde_json::json!({"user": {"id": "user-a", "name": "Sample User"}})),
            user_plan_raw: Some(serde_json::json!({"id": "user-a", "name": "Sample User"})),
            ..Default::default()
        };
        assert_eq!(extract_snapshot_plan_type(&snapshot), None);

        let mut actual_plan = snapshot;
        actual_plan.user_plan_raw = Some(serde_json::json!({"plan": {"name": "PRO"}}));
        assert_eq!(extract_snapshot_plan_type(&actual_plan).as_deref(), Some("PRO"));
        actual_plan.user_plan_raw = Some(serde_json::json!({"planName": "Enterprise VPC"}));
        assert_eq!(
            extract_snapshot_plan_type(&actual_plan).as_deref(),
            Some("Enterprise VPC")
        );
    }

    #[test]
    fn app_session_uses_official_credentials_without_adopting_another_identity() {
        for kind in [QoderVariantKind::QoderApp, QoderVariantKind::QoderCnApp] {
            let mut account = variant_test_account("active", Some(kind.provider_key()));
            account.user_id = Some("user-a".to_string());
            account.auth_user_info_raw = Some(serde_json::json!({"token": "saved-token"}));
            let mut snapshot = QoderSnapshot {
                variant: stored_variant_key(kind),
                user_info_raw: Some(serde_json::json!({
                    "schemaVersion": 1,
                    "token": "official-token",
                    "refreshToken": "official-refresh",
                    "user": {"id": "user-a", "email": account.email}
                })),
                ..Default::default()
            };
            // 外部登录尚未被 watcher 记录，也必须保护实际本机会话。
            let session = select_app_owned_session(&account, Some(snapshot.clone()), None).unwrap();
            assert_eq!(session.auth_user_info_raw.as_ref().unwrap()["token"], "official-token");
            assert_eq!(account.auth_user_info_raw.as_ref().unwrap()["token"], "saved-token");

            let mut ide_source = account.clone();
            ide_source.variant = stored_variant_key(if kind.is_cn() { QoderVariantKind::QoderCnIde } else { QoderVariantKind::Qoder });
            assert!(select_app_owned_session(&ide_source, Some(snapshot.clone()), None).is_some());

            // 文件暂时消失不能把当前会话当作离线账号，继而轮换其 refresh token。
            assert!(select_app_owned_session(&account, None, Some("active")).is_some());
            assert!(select_app_owned_session(&account, None, Some("other")).is_none());

            snapshot.user_info_raw.as_mut().unwrap()["user"]["id"] = Value::from("user-b");
            assert!(select_app_owned_session(&account, Some(snapshot.clone()), None).is_none());
            let remembered = select_app_owned_session(&account, Some(snapshot.clone()), Some("active")).unwrap();
            assert_eq!(remembered.auth_user_info_raw, account.auth_user_info_raw);

            snapshot.user_info_raw.as_mut().unwrap()["user"]["id"] = Value::from("user-a");
            snapshot.variant = Some("qoder_cn_ide".to_string());
            assert!(select_app_owned_session(&account, Some(snapshot), None).is_none());
        }
    }

    #[test]
    fn saving_closed_app_session_changes_only_existing_credentials() {
        let _lock = crate::modules::test_support::env_lock().lock().expect("lock env");
        let _guard = DataDirGuard::new("save-closed-app-session");
        let mut account = variant_test_account("active", Some("qoder_app"));
        account.user_id = Some("user-a".to_string());
        account.email = "user-a@example.invalid".to_string();
        account.auth_user_info_raw = Some(serde_json::json!({"token": "saved-token"}));
        account.auth_user_plan_raw = Some(serde_json::json!({"plan": "PRO"}));
        account.auth_credit_usage_raw = Some(serde_json::json!({"userQuota": {"total": 200}}));
        account.plan_type = Some("PRO".to_string());
        account.last_used = 42;
        let mut other = variant_test_account("other", Some("qoder_app"));
        other.user_id = Some("user-b".to_string());
        other.email = account.email.clone();
        other.auth_user_info_raw = Some(serde_json::json!({"token": "other-token"}));
        upsert_account_record(other.clone()).unwrap();
        upsert_account_record(account.clone()).unwrap();

        let saved = save_closed_app_snapshot(QoderSnapshot {
            variant: stored_variant_key(QoderVariantKind::QoderApp),
            user_info_raw: Some(serde_json::json!({
                "token": "official-token",
                "refreshToken": "official-refresh",
                "user": {"id": "user-a", "email": account.email.clone(), "name": "display name"}
            })),
            user_plan_raw: Some(serde_json::json!({"name": "display name"})),
            ..Default::default()
        }).unwrap();

        assert_eq!(saved.id, account.id);
        assert_eq!(saved.auth_user_info_raw.as_ref().unwrap()["token"], "official-token");
        assert_eq!(saved.auth_user_plan_raw, account.auth_user_plan_raw);
        assert_eq!(saved.auth_credit_usage_raw, account.auth_credit_usage_raw);
        assert_eq!(saved.plan_type, account.plan_type);
        assert_eq!(saved.last_used, account.last_used);
        assert_eq!(load_account(&other.id).unwrap().auth_user_info_raw, other.auth_user_info_raw);
        assert_eq!(list_accounts().len(), 2);
    }

    #[test]
    fn usage_and_plan_update_preserves_latest_credentials_and_reward_state() {
        let _lock = crate::modules::test_support::env_lock().lock().expect("lock env");
        let _guard = DataDirGuard::new("usage-preserves-app-session");
        let mut latest = variant_test_account("active", Some("qoder_app"));
        latest.auth_user_info_raw = Some(serde_json::json!({"token": "newer-session"}));
        latest.reward_claim_status = Some("CLAIMED".to_string());
        latest.tags = Some(vec!["keep".to_string()]);
        upsert_account_record(latest.clone()).unwrap();
        let updated = update_account_usage("active", serde_json::json!({
            "userQuota": {"total": 200, "used": 40, "remaining": 160}
        }), Some(serde_json::json!({
            "userType": "enterprise",
            "planTierName": "Enterprise VPC"
        }))).unwrap();
        assert_eq!(updated.auth_user_info_raw, latest.auth_user_info_raw);
        assert_eq!(updated.reward_claim_status, latest.reward_claim_status);
        assert_eq!(updated.tags, latest.tags);
        assert_eq!(updated.credits_remaining, Some(160.0));
        assert_eq!(updated.plan_type.as_deref(), Some("Enterprise VPC"));
        assert_eq!(updated.auth_user_plan_raw.as_ref().unwrap()["userType"], "enterprise");
        assert_eq!(updated.last_used, latest.last_used);
        assert!(updated.usage_updated_at.is_some());

        let unchanged_plan = update_account_usage("active", serde_json::json!({
            "userQuota": {"total": 200, "used": 40, "remaining": 160}
        }), Some(serde_json::json!({"name": "account nickname"}))).unwrap();
        assert_eq!(unchanged_plan.plan_type, updated.plan_type);
        assert_eq!(unchanged_plan.auth_user_plan_raw, updated.auth_user_plan_raw);
    }

    #[test]
    fn refreshed_app_usage_replaces_stale_plan_and_invalidates_web_cache() {
        let _lock = crate::modules::test_support::env_lock().lock().expect("lock env");
        let _guard = DataDirGuard::new("app-plan-and-web-cache");
        let mut account = variant_test_account("active", Some("qoder_app"));
        account.plan_type = Some("Free".to_string());
        account.auth_user_plan_raw = Some(serde_json::json!({"planTierName": "Free"}));
        account.auth_user_info_raw = Some(serde_json::json!({"userTag": "FREE", "token": "synthetic-token"}));
        account.web_quota_raw = Some(serde_json::json!({"account_quota": {"limit_value": 300, "used_value": 10}}));
        account.web_quota_updated_at = Some(1);
        account.usage_updated_at = Some(2);
        account.web_session_cookie = Some("session=synthetic-cookie".to_string());
        upsert_account_record(account.clone()).unwrap();

        let updated = update_account_usage("active", serde_json::json!({
            "qoderUsage": {"userType": "personal_professional", "userQuota": {"total": 300, "used": 50, "remaining": 250}}
        }), None).unwrap();
        assert_eq!(updated.plan_type.as_deref(), Some("personal_professional"));
        assert_eq!(updated.auth_user_plan_raw, None);
        assert_eq!(updated.auth_user_info_raw, account.auth_user_info_raw);
        assert_eq!(updated.web_quota_raw, None);
        assert_eq!(updated.web_quota_updated_at, None);
        assert_eq!(updated.web_session_cookie, account.web_session_cookie);

        let from_snapshot = snapshot_to_account(QoderSnapshot {
            variant: Some("qoder_app".to_string()),
            user_info_raw: account.auth_user_info_raw.clone(),
            credit_usage_raw: updated.auth_credit_usage_raw.clone(),
            ..Default::default()
        }, Some(&account));
        assert_eq!(from_snapshot.plan_type.as_deref(), Some("personal_professional"));
        assert_eq!(from_snapshot.auth_user_plan_raw, None);
        assert_eq!(from_snapshot.web_quota_raw, None);

        // 查询失败不提供新用量；保留缓存和原更新时间，而不是伪装成刷新成功。
        let no_new_usage = snapshot_to_account(QoderSnapshot {
            variant: Some("qoder_app".to_string()),
            ..Default::default()
        }, Some(&account));
        assert_eq!(no_new_usage.web_quota_raw, account.web_quota_raw);
        assert_eq!(no_new_usage.web_quota_updated_at, account.web_quota_updated_at);
        assert_eq!(no_new_usage.usage_updated_at, account.usage_updated_at);
    }

    #[test]
    fn generic_enterprise_usage_preserves_confirmed_enterprise_tier() {
        let _lock = crate::modules::test_support::env_lock().lock().expect("lock env");
        let _guard = DataDirGuard::new("app-preserves-enterprise-tier");
        let mut account = variant_test_account("active", Some("qoder_app"));
        account.plan_type = Some("Enterprise VPC".to_string());
        account.auth_user_plan_raw = Some(serde_json::json!({"planTierName": "Enterprise VPC"}));
        upsert_account_record(account.clone()).unwrap();
        let updated = update_account_usage("active", serde_json::json!({"userType": "enterprise"}), None).unwrap();
        assert_eq!(updated.plan_type, account.plan_type);
        assert_eq!(updated.auth_user_plan_raw, account.auth_user_plan_raw);
    }

    #[test]
    fn quota_snapshot_preserves_raw_storage_and_projects_safe_ipc_data() {
        let expected = serde_json::json!({
            "userQuota": {"total": 200, "used": 40, "remaining": 160, "percentage": 20},
            "addOnQuota": {"total": 500, "used": 100, "remaining": 400, "percentage": 20},
            "expiresAt": 1791041092084_i64,
            "totalUsagePercentage": 20,
            "isQuotaExceeded": false
        });
        let mut usage = expected.clone();
        usage["token"] = serde_json::json!("synthetic-secret-root");
        usage["userQuota"]["refreshToken"] = serde_json::json!("synthetic-secret-bucket");
        let wrapped = serde_json::json!({
            "displayMode": "qoder",
            "qoderUsage": usage.clone(),
            "token": "synthetic-secret-envelope"
        });

        for kind in all_qoder_variant_kinds() {
            // Both the Sash envelope and existing flat local/legacy payloads are supported.
            for raw in [&wrapped, &usage] {
                let account = snapshot_to_account(
                    QoderSnapshot {
                        variant: stored_variant_key(kind),
                        user_info_raw: Some(serde_json::json!({
                            "id": "quota-projection-user",
                            "email": "quota@example.invalid"
                        })),
                        credit_usage_raw: Some(raw.clone()),
                        ..Default::default()
                    },
                    None,
                );
                // Exercise the persisted account format without touching a user's files.
                let stored: QoderAccount = serde_json::from_str(
                    &serde_json::to_string(&account).expect("serialize stored account"),
                )
                .expect("read stored account");
                assert_eq!(stored.auth_credit_usage_raw.as_ref(), Some(raw));
                // Native menus/report consumers read this same unwrapped root.
                assert_eq!(stored.credit_usage(), Some(&usage));

                let visible = stored.clone().for_ipc();
                assert_eq!(visible.auth_credit_usage_raw.as_ref(), Some(&expected));
                assert_eq!(account_variant_kind(&visible).unwrap(), kind);
                assert!(!serde_json::to_string(&visible)
                    .unwrap()
                    .contains("synthetic-secret"));
                assert_eq!(stored.auth_credit_usage_raw.as_ref(), Some(raw));
                assert_eq!(
                    visible.for_ipc().auth_credit_usage_raw,
                    Some(expected.clone())
                );
            }
        }
    }

    #[test]
    fn local_ide_identity_preserves_watcher_field_semantics() {
        assert_eq!(
            local_ide_identity_from_user_info(r#"{"email":"a@example.com","id":"uid-1"}"#),
            (Some("a@example.com".to_string()), Some("uid-1".to_string()))
        );
        assert_eq!(
            local_ide_identity_from_user_info(r#"{"email":"b@example.com","userId":"uid-2"}"#),
            (Some("b@example.com".to_string()), Some("uid-2".to_string()))
        );
        assert_eq!(
            local_ide_identity_from_user_info(r#"{"id":"uid-3"}"#),
            (None, Some("uid-3".to_string()))
        );
        assert_eq!(local_ide_identity_from_user_info("not-json"), (None, None));
        assert_eq!(
            local_ide_identity_from_user_info(r#"{"name":"x"}"#),
            (None, None)
        );
    }

    #[test]
    fn app_variant_write_back_enabled_after_proven_roundtrip() {
        assert!(
            QODER_APP_WRITE_BACK_ENABLED,
            "App write-back must be enabled after the proven round-trip"
        );
        for key in ["qoder_app", "qoder_cn_app"] {
            let err = inject_to_qoder_for_variant(key, "account-not-loaded")
                .expect_err("missing account must still be rejected");
            assert!(
                err.contains("Qoder 账号不存在"),
                "dispatch must reach the App write path for {key}: {err}"
            );
            assert!(
                !err.contains("QODER_APP_WRITE_BACK_ENABLED"),
                "gate error must be gone for {key}: {err}"
            );
        }
    }

    #[test]
    fn unknown_variant_routes_are_rejected() {
        let inject_err =
            inject_to_qoder_for_variant("qoder_eu", "x").expect_err("unknown variant rejected");
        assert!(inject_err.contains("不支持的 Qoder 变体"), "{inject_err}");

        let import_err =
            import_from_local_for_variant("qoder_eu").expect_err("unknown variant rejected");
        assert!(import_err.contains("不支持的 Qoder 变体"), "{import_err}");
    }

    #[test]
    fn app_snapshot_reader_rejects_non_app_kind() {
        let err = read_qoder_app_snapshot(QoderVariantKind::Qoder)
            .expect_err("non-app kind must not use the app reader");
        assert!(err.contains("仅服务 App 变体"), "{err}");
    }

    /// 真机 round-trip 校验（显式 `--ignored` 运行，会写真实 App auth.v1.dat 后还原）：
    /// `COCKPIT_TOOLS_TEST_DATA_DIR="$HOME/.antigravity_cockpit" cargo test --lib \
    ///   app_writeback_roundtrip_on_machine -- --ignored --nocapture`
    #[test]
    #[ignore = "on-machine round-trip: writes the real auth.v1.dat then restores it"]
    fn app_writeback_roundtrip_on_machine() {
        let kind = QoderVariantKind::QoderCnApp;
        let account = list_accounts()
            .into_iter()
            .find(|item| account_supports_variant(item, kind) && has_client_auth(item, kind))
            .map(|item| account_for_variant(&item, kind).expect("prepare App credential view"))
            .expect("a real CN account with App credentials must exist");
        let (auth_path, _) = resolve_qoder_app_auth_path(kind).expect("resolve app auth path");
        let original = fs::read(&auth_path).expect("read original auth.v1.dat");
        let backup_path = auth_path.with_extension("dat.cockpit-bak");
        println!(
            "[app-writeback] variant={} account_id={} email={}",
            kind.provider_key(),
            account.id,
            account.email
        );
        println!(
            "[app-writeback] auth_path={} before_len={}",
            auth_path.display(),
            original.len()
        );

        let outcome = inject_to_qoder_app(kind, &account.id);

        match &outcome {
            Ok(()) => {
                let after = fs::read(&auth_path).expect("read written auth.v1.dat");
                println!(
                    "[app-writeback] RESULT=PASS after_len={} backup_exists={} backup_path={}",
                    after.len(),
                    backup_path.exists(),
                    backup_path.display()
                );
            }
            Err(err) => println!("[app-writeback] RESULT=FAIL error={err}"),
        }

        fs::write(&auth_path, &original).expect("restore original auth.v1.dat");
        println!("[app-writeback] restored_original=true");
        outcome.expect("app write-back round-trip must succeed");
    }

    #[test]
    fn missing_state_db_dir_is_read_only_none() {
        let missing = std::env::temp_dir().join("qoder-t9-absent-user-data-dir-019c5662");
        assert!(resolve_existing_state_db_path_for_user_data_dir(&missing.to_string_lossy()).is_none());
    }

    fn cn_ide_test_account() -> QoderAccount {
        QoderAccount {
            shared_refresh_token: None,
            client_auth: HashMap::new(),
            legacy_ids: Vec::new(),
            id: "qoder_cn_ide_uid_test".to_string(),
            variant: Some("qoder_cn_ide".to_string()),
            email: "user@qoder.local".to_string(),
            user_id: Some("01a0d20d-b287-7f02-9a3c-6a4ced5e5b8a".to_string()),
            display_name: Some("tester".to_string()),
            plan_type: None,
            credits_used: None,
            credits_total: None,
            credits_remaining: None,
            credits_usage_percent: None,
            quota_query_last_error: None,
            quota_query_last_error_at: None,
            usage_updated_at: None,
            tags: None,
            auth_user_info_raw: Some(serde_json::json!({
                "id": "01a0d20d-b287-7f02-9a3c-6a4ced5e5b8a",
                "status": 2,
                "whitelist": 3,
                "token": "dt-test"
            })),
            auth_user_plan_raw: Some(
                serde_json::json!({"plan_tier_name": "Pro", "user_type": "personal"}),
            ),
            auth_credit_usage_raw: Some(serde_json::json!({"displayMode": "qoder"})),
            reward_claim_status: None,
            reward_window_end_at: None,
            reward_status_updated_at: None,
            web_session_cookie: None,
            web_quota_raw: None,
            web_quota_updated_at: None,
            created_at: 1,
            last_used: 1,
        }
    }

    #[test]
    fn cn_ide_inject_adds_ide_managed_login_source() {
        let account = cn_ide_test_account();
        let (user_info, user_plan, _usage) = build_qoder_inject_payloads(&account, true).unwrap();
        let user_info: Value = serde_json::from_str(&user_info).unwrap();
        let user_plan: Value = serde_json::from_str(&user_plan).unwrap();

        assert_eq!(user_info["login_source"], "qodercn");
        assert_eq!(user_plan["login_source"], "qodercn");
        assert_eq!(user_plan["login_version"], "2.0");
        assert_eq!(user_info["id"], "01a0d20d-b287-7f02-9a3c-6a4ced5e5b8a");
        assert_eq!(user_info["status"], 2);
    }

    #[test]
    fn default_qoder_inject_payload_is_verbatim() {
        let account = cn_ide_test_account();
        let (user_info, user_plan, usage) = build_qoder_inject_payloads(&account, false).unwrap();

        assert_eq!(
            user_info,
            serde_json::to_string(account.auth_user_info_raw.as_ref().unwrap()).unwrap()
        );
        assert_eq!(
            user_plan,
            serde_json::to_string(account.auth_user_plan_raw.as_ref().unwrap()).unwrap()
        );
        assert_eq!(
            usage,
            serde_json::to_string(account.auth_credit_usage_raw.as_ref().unwrap()).unwrap()
        );
        let user_info: Value = serde_json::from_str(&user_info).unwrap();
        assert!(user_info.get("login_source").is_none());
    }

    #[test]
    fn cn_ide_inject_preserves_existing_login_source() {
        let mut account = cn_ide_test_account();
        account.auth_user_info_raw =
            Some(serde_json::json!({"id": "x", "login_source": "dedicated_qodercn"}));
        account.auth_user_plan_raw =
            Some(serde_json::json!({"login_source": "dedicated_qodercn", "login_version": "2.0"}));
        let (user_info, user_plan, _usage) = build_qoder_inject_payloads(&account, true).unwrap();
        let user_info: Value = serde_json::from_str(&user_info).unwrap();
        let user_plan: Value = serde_json::from_str(&user_plan).unwrap();

        assert_eq!(user_info["login_source"], "dedicated_qodercn");
        assert_eq!(user_plan["login_source"], "dedicated_qodercn");
        assert_eq!(user_plan["login_version"], "2.0");
    }

    struct DataDirGuard {
        dir: PathBuf,
        previous_data_dir: Option<String>,
    }

    impl DataDirGuard {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "cockpit-qoder-variant-current-{}-{}",
                name,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create temp data dir");
            let previous_data_dir = std::env::var("COCKPIT_TOOLS_DATA_DIR").ok();
            std::env::set_var("COCKPIT_TOOLS_DATA_DIR", &dir);
            Self {
                dir,
                previous_data_dir,
            }
        }
    }

    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            match self.previous_data_dir.as_ref() {
                Some(value) => std::env::set_var("COCKPIT_TOOLS_DATA_DIR", value),
                None => std::env::remove_var("COCKPIT_TOOLS_DATA_DIR"),
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn variant_test_account(id: &str, variant: Option<&str>) -> QoderAccount {
        QoderAccount {
            shared_refresh_token: None,
            client_auth: HashMap::new(),
            legacy_ids: Vec::new(),
            id: id.to_string(),
            variant: variant.map(|value| value.to_string()),
            email: format!("{id}@qoder.local"),
            user_id: None,
            display_name: None,
            plan_type: None,
            credits_used: None,
            credits_total: None,
            credits_remaining: None,
            credits_usage_percent: None,
            quota_query_last_error: None,
            quota_query_last_error_at: None,
            usage_updated_at: None,
            tags: None,
            auth_user_info_raw: None,
            auth_user_plan_raw: None,
            auth_credit_usage_raw: None,
            reward_claim_status: None,
            reward_window_end_at: None,
            reward_status_updated_at: None,
            web_session_cookie: None,
            web_quota_raw: None,
            web_quota_updated_at: None,
            created_at: 1,
            last_used: 1,
        }
    }

    #[test]
    fn json_import_rejects_id_owned_by_another_variant_without_overwriting() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("import-cross-variant-id");

        let mut original = variant_test_account("shared-id", None);
        original.auth_user_info_raw = Some(serde_json::json!({"token": "original"}));
        upsert_account_record(original.clone()).expect("save original account");

        let mut incoming = variant_test_account("shared-id", Some("qoder_cn_app"));
        incoming.auth_user_info_raw = Some(serde_json::json!({"token": "incoming"}));
        let json = serde_json::to_string(&incoming).expect("serialize imported account");
        let error = import_from_json(&json).expect_err("cross-variant ID must be rejected");

        assert!(error.contains("ID 已属于其他地区"), "{error}");
        let saved = load_account("shared-id").expect("original account remains");
        assert_eq!(saved.auth_user_info_raw, original.auth_user_info_raw);
        assert_eq!(saved.variant, original.variant);
        assert_eq!(list_accounts().len(), 1);
    }

    #[test]
    fn exported_default_account_keeps_variant_on_every_import_page() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("import-default-variant");

        let mut incoming = variant_test_account("qoder_uid_exported", None);
        incoming.auth_user_info_raw = Some(serde_json::json!({"token": "incoming"}));
        upsert_account_record(incoming.clone()).expect("save default IDE account");
        let json = export_accounts(&[incoming.id.clone()], true).expect("export account");
        let value: Value = serde_json::from_str(&json).expect("export JSON");
        assert!(value[0].get("variant").is_none());

        for kind in all_qoder_variant_kinds() {
            // 模拟新环境：没有同 ID 记录帮忙阻止变体被改写。
            remove_account(&incoming.id).expect("remove existing record");
            let imported = import_from_json_for_variant(&json, kind.provider_key())
                .expect("restore full account backup");
            assert_eq!(imported.len(), 1);
            assert_eq!(imported[0].variant, None);
            let saved = load_account(&incoming.id).expect("restored account");
            assert_eq!(saved.variant, None);
            assert_eq!(saved.auth_user_info_raw, incoming.auth_user_info_raw);
        }
    }

    #[test]
    fn raw_credentials_without_variant_use_requested_variant() {
        let raw = serde_json::json!({
            "userInfo": {"id": "raw-user", "token": "incoming"}
        });
        for kind in all_qoder_variant_kinds() {
            let account = parse_import_item(&raw, kind).expect("import raw credentials");
            assert_eq!(account_variant_kind(&account).unwrap(), kind);
            assert!(account.id.starts_with(if kind.is_cn() { "qoder_cn_uid_" } else { "qoder_uid_" }));
        }
    }

    #[test]
    fn json_import_rejects_non_string_variant() {
        let json = serde_json::json!({
            "id": "bad-variant",
            "email": "bad@example.com",
            "variant": 123,
            "auth_user_info_raw": {"token": "should-not-import"}
        })
        .to_string();

        let error = import_from_json_for_variant(&json, "qoder_cn_app")
            .expect_err("non-string variant must be rejected");
        assert!(error.contains("必须是字符串或 null"), "{error}");
    }

    #[test]
    fn export_without_credentials_redacts_raw_auth_payloads() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("export-redacts-credentials");

        let mut account = variant_test_account("redacted-account", None);
        account.auth_user_info_raw = Some(serde_json::json!({"token": "secret"}));
        account.auth_user_plan_raw = Some(serde_json::json!({"plan": "pro"}));
        upsert_account_record(account).expect("save account");

        let exported = export_accounts(&[], false).expect("export metadata");
        let value: Value = serde_json::from_str(&exported).expect("export JSON");
        assert!(value[0].get("auth_user_info_raw").is_none());
        assert!(value[0].get("auth_user_plan_raw").is_none());
        assert!(value[0].get("auth_credit_usage_raw").is_none());
    }

    #[test]
    fn export_with_credentials_preserves_auth_tokens_and_payloads() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("export-preserves-credentials");

        let mut account = variant_test_account("credentialed-account", None);
        account.auth_user_info_raw = Some(serde_json::json!({
            "token": "secret-token",
            "refreshToken": "secret-refresh-token"
        }));
        account.auth_user_plan_raw = Some(serde_json::json!({"plan": "pro"}));
        account.auth_credit_usage_raw = Some(serde_json::json!({"credits": 100}));
        upsert_account_record(account).expect("save account");

        let exported = export_accounts(&[], true).expect("export credentials");
        let value: Value = serde_json::from_str(&exported).expect("export JSON");
        assert_eq!(
            value[0]["auth_user_info_raw"]["refreshToken"].as_str(),
            Some("secret-refresh-token")
        );
        assert_eq!(
            value[0]["auth_user_info_raw"]["token"].as_str(),
            Some("secret-token")
        );
        assert_eq!(value[0]["auth_user_plan_raw"]["plan"].as_str(), Some("pro"));
        assert_eq!(value[0]["auth_credit_usage_raw"]["credits"].as_i64(), Some(100));
    }

    #[test]
    fn app_auth_payload_does_not_inherit_previous_accounts_identity() {
        let template = serde_json::json!({
            "schemaVersion": 1,
            "token": "old-token",
            "refreshToken": "old-refresh",
            "expiresAt": "old-expiry",
            "user": {
                "id": "old-user",
                "name": "Old Name",
                "email": "old@example.com",
                "phone": "old-phone",
                "avatarUrl": "old-avatar"
            }
        });
        let mut target = variant_test_account("target", Some("qoder_cn_app"));
        target.email = "unknown@qoder.local".to_string();
        target.user_id = Some("target-user".to_string());
        target.display_name = Some("Target Name".to_string());
        target.auth_user_info_raw = Some(serde_json::json!({
            "token": "target-token",
            "refreshToken": "target-refresh"
        }));

        let payload = build_qoder_app_auth_payload(Some(&template), &target)
            .expect("build target app auth payload");
        assert_eq!(payload["schemaVersion"], 1);
        assert_eq!(payload["token"], "target-token");
        assert_eq!(payload["refreshToken"], "target-refresh");
        assert_eq!(payload["user"]["id"], "target-user");
        assert_eq!(payload["user"]["name"], "Target Name");
        for key in ["email", "phone", "avatarUrl"] {
            assert!(payload["user"].get(key).is_none(), "stale user field: {key}");
        }
        assert!(payload.get("expiresAt").is_none());
    }

    #[test]
    fn resolve_current_account_id_is_isolated_per_variant() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("variant-isolation");

        let accounts = vec![
            variant_test_account("acct-default", None),
            variant_test_account("acct-cn-app", Some("qoder_cn_app")),
        ];
        crate::modules::provider_current_state::set_current_account_id(
            "qoder",
            Some("acct-default"),
        )
        .expect("set default current");
        crate::modules::provider_current_state::set_current_account_id(
            "qoder_cn_app",
            Some("acct-cn-app"),
        )
        .expect("set cn app current");

        assert_eq!(
            resolve_current_account_id(&accounts),
            Some("acct-default".to_string())
        );
        assert_eq!(
            resolve_current_account_id_for_variant(&accounts, QoderVariantKind::QoderCnApp),
            Some("acct-cn-app".to_string())
        );
        assert_eq!(
            resolve_current_account_id_for_variant(&accounts, QoderVariantKind::QoderCnIde),
            None
        );
    }

    #[test]
    fn qoder_quota_alert_remaining_percent_inverts_usage() {
        let mut account = variant_test_account("acct-usage", None);
        account.credits_usage_percent = Some(90.0);
        assert_eq!(remaining_quota_percent(&account), Some(10));
        account.credits_usage_percent = Some(0.0);
        assert_eq!(remaining_quota_percent(&account), Some(100));
        account.credits_usage_percent = Some(150.0);
        assert_eq!(remaining_quota_percent(&account), Some(0));
        account.credits_usage_percent = None;
        assert_eq!(remaining_quota_percent(&account), None);
    }

    #[test]
    fn qoder_quota_alert_filters_models_at_or_below_threshold() {
        let metrics = vec![("Credits".to_string(), 10), ("Other".to_string(), 50)];
        assert_eq!(
            filter_low_quota_models(&metrics, 20),
            vec![("Credits".to_string(), 10)]
        );
        assert!(filter_low_quota_models(&metrics, 5).is_empty());
    }

    #[test]
    fn qoder_quota_alert_threshold_clamps_and_key_is_stable() {
        assert_eq!(normalize_quota_alert_threshold(-5), 0);
        assert_eq!(normalize_quota_alert_threshold(150), 100);
        assert_eq!(build_quota_alert_cooldown_key("acct", 20), "qoder:acct:20");
    }

    #[test]
    fn qoder_quota_alert_recommends_same_region_highest_remaining() {
        let mut low = variant_test_account("low", None);
        low.credits_usage_percent = Some(90.0);
        let mut high = variant_test_account("high", None);
        high.credits_usage_percent = Some(10.0);
        let mut other_variant = variant_test_account("other", Some("qoder_app"));
        other_variant.credits_usage_percent = Some(0.0);
        let accounts = vec![low, high, other_variant];

        let recommendation =
            pick_quota_alert_recommendation(&accounts, "low", QoderVariantKind::Qoder)
                .expect("same-variant candidate");
        assert_eq!(recommendation.id, "other");
    }

    #[test]
    fn qoder_account_email_sentinel_detection() {
        assert!(account_email_is_sentinel(""));
        assert!(account_email_is_sentinel("   "));
        assert!(account_email_is_sentinel("unknown@qoder.local"));
        assert!(account_email_is_sentinel("Unknown@Qoder.Local"));
        assert!(!account_email_is_sentinel("nick@example.com"));
    }

    #[test]
    fn qoder_account_security_mobile_extractor() {
        let mut with = variant_test_account("u1", Some("qoder_cn_ide"));
        with.email = "unknown@qoder.local".to_string();
        with.auth_user_info_raw = Some(serde_json::json!({ "security_mobile": " 13800001111 " }));
        assert_eq!(security_mobile_of(&with).as_deref(), Some("13800001111"));

        for variant in ["qoder_app", "qoder_cn_app"] {
            let mut app = variant_test_account("app-phone", Some(variant));
            app.auth_user_info_raw = Some(serde_json::json!({
                "user": {"phone": " 13800001111 "}
            }));
            assert_eq!(security_mobile_of(&app).as_deref(), Some("13800001111"));
        }

        let mut blank = variant_test_account("u2", Some("qoder_cn_ide"));
        blank.auth_user_info_raw = Some(serde_json::json!({ "security_mobile": "   " }));
        assert!(security_mobile_of(&blank).is_none());

        let absent = variant_test_account("u3", None);
        assert!(security_mobile_of(&absent).is_none());
    }

    #[test]
    fn regional_authorization_updates_one_account_and_preserves_other_client_at() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-authorization");
        for (ide, app) in [("qoder", "qoder_app"), ("qoder_cn_ide", "qoder_cn_app")] {
            let first = upsert_account_from_snapshot_for_variant(ide, serde_json::json!({
                "id": "regional-user", "token": "ide-at-fixture", "refreshToken": "first-rt-fixture"
            }), None, None).unwrap();
            update_account_tags(&first.id, vec!["keep-tag".into()]).unwrap();
            let second = upsert_account_from_snapshot_for_variant(app, serde_json::json!({
                "schemaVersion": 1, "user": {"id": "regional-user", "phone": "fixture-phone"},
                "token": "app-at-fixture", "refreshToken": "second-rt-fixture"
            }), None, None).unwrap();
            assert_eq!(first.id, second.id);
            assert_eq!(second.tags.as_deref(), Some(&["keep-tag".to_string()][..]));
            let ide_view = account_for_variant(&second, QoderVariantKind::parse(Some(ide)).unwrap()).unwrap();
            assert_eq!(ide_view.auth_user_info_raw.as_ref().unwrap()["token"], "ide-at-fixture");
            assert_eq!(ide_view.auth_user_info_raw.as_ref().unwrap()["refreshToken"], "second-rt-fixture");
            let stored_path = resolve_account_file_path(&second.id).unwrap();
            let content = fs::read_to_string(&stored_path).unwrap();
            let (stored, _) = crate::modules::secure_account_storage::deserialize_account_file::<QoderAccount>(&stored_path, &content).unwrap();
            assert_eq!(stored.shared_refresh_token.as_deref(), Some("second-rt-fixture"));
            assert!(stored.auth_user_info_raw.as_ref().unwrap().get("refreshToken").is_none());
            assert!(stored.client_auth.values().all(|raw| raw.get("refreshToken").is_none()));
            let public = serde_json::to_string(&second.clone().for_ipc()).unwrap();
            assert!(!public.contains("at-fixture") && !public.contains("rt-fixture"));
            update_account_tags(&second.id, vec![]).unwrap();
            assert!(load_account(&second.id).unwrap().tags.is_none(), "metadata removals must survive merging");
        }
        let accounts = list_accounts_checked().unwrap();
        assert_eq!(accounts.len(), 2, "same UID in different regions must remain separate");
        assert_ne!(accounts[0].id, accounts[1].id);
        assert!(account_for_variant(&accounts[0], if account_variant_kind(&accounts[0]).unwrap().is_cn() {
            QoderVariantKind::Qoder
        } else { QoderVariantKind::QoderCnIde }).is_err());
    }

    #[test]
    fn canonical_account_reads_and_listing_do_not_scan_other_details() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-linear-reads");
        let mut index = QoderAccountIndex::new();
        for number in 0..8 {
            let account = variant_test_account(&format!("canonical-{number}"), None);
            save_account_file(&account).unwrap();
            index.accounts.push(account.summary());
        }
        save_account_index(&index).unwrap();
        ACCOUNT_DETAIL_READS.with(|reads| reads.set(0));
        assert_eq!(load_account("canonical-3").unwrap().id, "canonical-3");
        ACCOUNT_DETAIL_READS.with(|reads| assert_eq!(reads.get(), 1,
            "a canonical reference must not decrypt unrelated accounts"));
        ACCOUNT_DETAIL_READS.with(|reads| reads.set(0));
        assert_eq!(list_accounts_from_index(&index).len(), 8);
        ACCOUNT_DETAIL_READS.with(|reads| assert_eq!(reads.get(), 8,
            "listing must read each indexed detail only once"));
    }

    #[test]
    fn regional_migration_preserves_credentials_aliases_and_replays_without_duplication() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-migration");
        let mut ide = variant_test_account("legacy-ide", Some("qoder_cn_ide"));
        ide.user_id = Some("migration-user".into()); ide.created_at = 1; ide.last_used = 2;
        ide.auth_user_info_raw = Some(serde_json::json!({"id": "migration-user", "token": "old-ide-at-fixture", "refreshToken": "old-rt-fixture"}));
        let mut app = ide.clone(); app.id = "legacy-app".into(); app.variant = Some("qoder_cn_app".into());
        app.created_at = 2; app.last_used = 3;
        app.auth_user_info_raw = Some(serde_json::json!({"user": {"id": "migration-user"}, "schemaVersion": 1, "token": "new-app-at-fixture", "refreshToken": "new-rt-fixture"}));
        for account in [&ide, &app] {
            let content = crate::modules::secure_account_storage::serialize_account_file("qoder", account).unwrap();
            crate::modules::atomic_write::write_string_atomic(&resolve_account_file_path(&account.id).unwrap(), &content).unwrap();
        }
        let mut index = QoderAccountIndex::new(); index.accounts = vec![ide.summary(), app.summary()];
        save_account_index(&index).unwrap();
        crate::modules::provider_current_state::set_current_account_id("qoder_cn_app", Some("legacy-app")).unwrap();
        let accounts = list_accounts_checked().unwrap();
        assert_eq!(accounts.len(), 1); assert_eq!(accounts[0].id, "legacy-ide");
        assert_eq!(load_account("legacy-app").unwrap().id, "legacy-ide");
        assert_eq!(resolve_current_account_id_for_variant(&accounts, QoderVariantKind::QoderCnApp).as_deref(), Some("legacy-ide"));
        assert_eq!(resolve_current_account_id_for_variant(&accounts, QoderVariantKind::QoderCnIde), None,
            "sharing an account must not switch the other running client");
        let old = crate::modules::qoder_oauth::account_refresh_lock("legacy-app").unwrap();
        let current = crate::modules::qoder_oauth::account_refresh_lock("legacy-ide").unwrap();
        assert!(std::sync::Arc::ptr_eq(&old, &current), "aliases must share the credential lock");
        let ide_view = account_for_variant(&accounts[0], QoderVariantKind::QoderCnIde).unwrap();
        assert_eq!(ide_view.auth_user_info_raw.as_ref().unwrap()["token"], "old-ide-at-fixture");
        assert_eq!(ide_view.auth_user_info_raw.as_ref().unwrap()["refreshToken"], "new-rt-fixture");
        assert_eq!(list_accounts_checked().unwrap().len(), 1);
        assert_eq!(fs::read_dir(get_data_dir().unwrap().join("qoder-regional-backups")).unwrap().count(), 1,
            "idempotent migration must not make another backup");
        // A retired detail left behind by interrupted cleanup must not reappear on index repair.
        let content = crate::modules::secure_account_storage::serialize_account_file("qoder", &app).unwrap();
        crate::modules::atomic_write::write_string_atomic(&resolve_account_file_path(&app.id).unwrap(), &content).unwrap();
        fs::remove_file(get_accounts_index_path().unwrap()).unwrap();
        assert_eq!(list_accounts_checked().unwrap().len(), 1);
        let exported = export_accounts(&["legacy-ide".into()], true).unwrap();
        remove_account("legacy-app").unwrap();
        assert!(list_accounts_checked().unwrap().is_empty());
        assert!(load_account("legacy-app").is_none());
        import_from_json_for_variant(&exported, "qoder_cn_ide").unwrap();
        assert_eq!(load_account("legacy-app").unwrap().id, "legacy-ide",
            "full backup restoration must preserve old instance references");
    }

    #[test]
    fn regional_migration_preserves_metadata_independently_of_last_used_order() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        for (canonical_last_used, first_edit_id) in [
            (10, None),
            (30, None),
            (10, Some("legacy-ide")),
            (30, Some("legacy-app")),
        ] {
            let _guard = DataDirGuard::new(&format!(
                "regional-metadata-{canonical_last_used}-{}", first_edit_id.unwrap_or("list")
            ));
            let mut ide = variant_test_account("legacy-ide", Some("qoder_cn_ide"));
            ide.user_id = Some("migration-user".into());
            ide.created_at = 1;
            ide.last_used = canonical_last_used;
            ide.auth_user_info_raw = Some(serde_json::json!({
                "id": "migration-user", "token": "ide-at-fixture", "refreshToken": "ide-rt-fixture"
            }));
            ide.tags = Some(vec!["ide-tag".into()]);
            ide.plan_type = Some("Free".into());
            ide.auth_user_plan_raw = Some(serde_json::json!({"planTierName": "Free"}));
            ide.auth_credit_usage_raw = Some(serde_json::json!({"userQuota": {"used": 1, "total": 100}}));
            ide.credits_used = Some(1.0);
            ide.credits_total = Some(100.0);
            ide.credits_remaining = Some(99.0);
            ide.credits_usage_percent = Some(1.0);
            ide.usage_updated_at = Some(10);
            ide.web_quota_raw = Some(serde_json::json!({"account_quota": {"limit_value": 100, "used_value": 1}}));
            ide.web_quota_updated_at = Some(10);
            ide.reward_claim_status = Some("UNCLAIMED".into());
            ide.reward_window_end_at = Some(100);
            ide.reward_status_updated_at = Some(10);

            let mut app = ide.clone();
            app.id = "legacy-app".into();
            app.variant = Some("qoder_cn_app".into());
            app.created_at = 2;
            app.last_used = 20;
            app.auth_user_info_raw = Some(serde_json::json!({
                "user": {"id": "migration-user"}, "schemaVersion": 1,
                "token": "app-at-fixture", "refreshToken": "app-rt-fixture"
            }));
            app.tags = Some(vec!["app-tag".into()]);
            app.plan_type = Some("Pro".into());
            app.auth_user_plan_raw = Some(serde_json::json!({"planTierName": "Pro"}));
            app.auth_credit_usage_raw = Some(serde_json::json!({"userQuota": {"used": 60, "total": 300}}));
            app.credits_used = Some(60.0);
            app.credits_total = Some(300.0);
            app.credits_remaining = Some(240.0);
            app.credits_usage_percent = Some(20.0);
            app.usage_updated_at = Some(20);
            app.web_quota_raw = Some(serde_json::json!({"account_quota": {"limit_value": 300, "used_value": 60}}));
            app.web_quota_updated_at = Some(20);
            app.reward_claim_status = Some("CLAIMED".into());
            app.reward_window_end_at = Some(200);
            app.reward_status_updated_at = Some(20);

            for account in [&ide, &app] {
                let content = crate::modules::secure_account_storage::serialize_account_file("qoder", account).unwrap();
                crate::modules::atomic_write::write_string_atomic(&resolve_account_file_path(&account.id).unwrap(), &content).unwrap();
            }
            let mut index = QoderAccountIndex::new();
            index.accounts = vec![ide.summary(), app.summary()];
            save_account_index(&index).unwrap();

            if let Some(id) = first_edit_id {
                update_account_tags(id, vec!["edited-tag".into()]).unwrap();
            }
            let accounts = list_accounts_checked().unwrap();
            assert_eq!(accounts.len(), 1);
            let merged = load_account("legacy-app").unwrap();
            assert_eq!(merged.id, "legacy-ide");
            let expected_tags = if first_edit_id.is_some() {
                vec!["edited-tag".to_string()]
            } else {
                vec!["ide-tag".to_string(), "app-tag".to_string()]
            };
            assert_eq!(merged.tags, Some(expected_tags));
            assert_eq!(merged.auth_credit_usage_raw, app.auth_credit_usage_raw);
            assert_eq!(merged.auth_user_plan_raw, app.auth_user_plan_raw);
            assert_eq!(merged.plan_type, app.plan_type);
            assert_eq!(merged.credits_used, Some(60.0));
            assert_eq!(merged.credits_total, Some(300.0));
            assert_eq!(merged.credits_remaining, Some(240.0));
            assert_eq!(merged.credits_usage_percent, Some(20.0));
            assert_eq!(merged.usage_updated_at, Some(20));
            assert_eq!(merged.web_quota_raw, app.web_quota_raw);
            assert_eq!(merged.web_quota_updated_at, Some(20));
            assert_eq!(merged.reward_claim_status.as_deref(), Some("CLAIMED"));
            assert_eq!(merged.reward_window_end_at, Some(200));
            assert_eq!(merged.reward_status_updated_at, Some(20));
            let expected_rt = if canonical_last_used > app.last_used { "ide-rt-fixture" } else { "app-rt-fixture" };
            assert_eq!(merged.shared_refresh_token.as_deref(), Some(expected_rt));
            for (kind, expected_at) in [
                (QoderVariantKind::QoderCnIde, "ide-at-fixture"),
                (QoderVariantKind::QoderCnApp, "app-at-fixture"),
            ] {
                let view = account_for_variant(&merged, kind).unwrap();
                let raw = view.auth_user_info_raw.as_ref().unwrap();
                assert_eq!(raw["token"], expected_at);
                assert_eq!(raw["refreshToken"], expected_rt);
            }

            // Normal updates after migration must not restore explicitly cleared metadata.
            update_account_tags("legacy-app", vec![]).unwrap();
            update_account_usage("legacy-ide", serde_json::json!({
                "userQuota": {"used": 90, "total": 300, "remaining": 210}
            }), None).unwrap();
            let updated = load_account("legacy-ide").unwrap();
            assert!(updated.tags.is_none());
            assert!(updated.web_quota_raw.is_none());
            assert!(updated.web_quota_updated_at.is_none());
            assert_eq!(updated.credits_used, Some(90.0));
            assert_eq!(updated.reward_claim_status, merged.reward_claim_status);
            assert_eq!(updated.client_auth, merged.client_auth);
            assert_eq!(updated.shared_refresh_token, merged.shared_refresh_token);
        }
    }

    #[test]
    fn regional_import_without_official_identity_does_not_merge_by_plan_or_email() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-unknown-identity");
        for token in ["first-at-fixture", "second-at-fixture"] {
            let raw = serde_json::json!({
                "userInfo": {"token": token, "email": "shared@example.invalid", "organization": {"id": "org-fixture"}},
                "userPlan": {"id": "same-plan-fixture"}
            });
            let imported = import_from_json_for_variant(&raw.to_string(), "qoder_app").unwrap();
            assert!(imported[0].user_id.is_none());
        }
        assert_eq!(list_accounts_checked().unwrap().len(), 2);
        upsert_account_from_snapshot_for_variant("qoder", serde_json::json!({
            "id": "official-user", "email": "shared@example.invalid", "token": "known-at-fixture"
        }), None, None).unwrap();
        assert_eq!(list_accounts_checked().unwrap().len(), 3);
    }

    #[test]
    fn regional_deletion_recovers_after_details_removed_before_index_publication() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-delete-interrupted");
        let account = upsert_account_from_snapshot_for_variant("qoder_app", serde_json::json!({
            "id": "deleted-user", "token": "at-fixture", "refreshToken": "rt-fixture"
        }), None, None).unwrap();
        delete_account_file(&account.id).unwrap();
        assert!(list_accounts_checked().unwrap().is_empty());
        assert!(load_account_index_checked().unwrap().accounts.is_empty());
        assert!(load_account(&account.id).is_none());
    }

    #[test]
    fn regional_accounts_never_merge_known_different_ids_or_unknown_sentinel_emails() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("regional-identity-boundary");
        for uid in ["one", "two"] {
            upsert_account_from_snapshot_for_variant("qoder_app", serde_json::json!({
                "id": uid, "email": "same@example.invalid", "token": "at-fixture", "refreshToken": "rt-fixture"
            }), None, None).unwrap();
        }
        assert_eq!(list_accounts_checked().unwrap().len(), 2);
        let mut impostor = load_account("qoder_uid_two").unwrap();
        impostor.legacy_ids.push("qoder_uid_one".into());
        assert!(upsert_account_record(impostor).is_err(), "aliases cannot take over another identity");
        let mut first = variant_test_account("unknown-one", None);
        first.email = "unknown@qoder.local".into();
        let mut second = first.clone(); second.id = "unknown-two".into(); second.variant = Some("qoder_app".into());
        upsert_account_record(first).unwrap(); upsert_account_record(second).unwrap();
        assert_eq!(list_accounts_checked().unwrap().len(), 4);
    }

    #[test]
    fn local_import_reloads_credentials_under_switch_and_account_locks() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("local-import-locks");
        for kind in all_qoder_variant_kinds() {
            let initial = QoderSnapshot {
                variant: stored_variant_key(kind),
                user_info_raw: Some(serde_json::json!({
                    "id": "local-import-fixture-user", "token": "old-at-fixture",
                    "refreshToken": "old-rt-fixture"
                })),
                ..Default::default()
            };
            let mut latest = initial.clone();
            latest.user_info_raw.as_mut().unwrap()["token"] = Value::String("latest-at-fixture".into());
            latest.user_info_raw.as_mut().unwrap()["refreshToken"] =
                Value::String("latest-rt-fixture".into());
            let account_key = OfficialLoginCandidate {
                snapshot: initial.clone(),
            }
            .refresh_lock_key();
            let mut reads = 0;
            let imported = import_local_snapshot(kind, || {
                reads += 1;
                let session_lock = crate::modules::qoder_oauth::client_session_lock(kind).unwrap();
                assert!(
                    session_lock.try_lock().is_err(),
                    "the client session must stay locked from the first read through commit"
                );
                if reads == 2 {
                    let account_lock =
                        crate::modules::qoder_oauth::account_refresh_lock(&account_key).unwrap();
                    assert!(
                        account_lock.try_lock().is_err(),
                        "the second read must drain older credential updates"
                    );
                    Ok(Some(latest.clone()))
                } else {
                    Ok(Some(initial.clone()))
                }
            })
            .unwrap()
            .unwrap();
            assert_eq!(reads, 2);
            let stored = load_account(&imported.id).unwrap();
            assert_eq!(
                stored.auth_user_info_raw.as_ref().unwrap()["token"],
                "latest-at-fixture"
            );
            assert_eq!(
                stored.shared_refresh_token.as_deref(),
                Some("latest-rt-fixture")
            );
            assert_eq!(
                crate::modules::provider_current_state::get_current_account_id(kind.provider_key())
                    .unwrap()
                    .as_deref(),
                Some(imported.id.as_str())
            );
        }
    }

    #[test]
    fn local_import_does_not_commit_when_native_identity_changes_before_the_locked_read() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("local-import-identity-change");
        for kind in all_qoder_variant_kinds() {
            let current = upsert_account_from_snapshot_for_variant(
                kind.provider_key(),
                serde_json::json!({
                    "id": "kept-fixture-user", "token": "kept-at-fixture", "refreshToken": "kept-rt-fixture"
                }),
                None,
                None,
            )
            .unwrap();
            crate::modules::provider_current_state::set_current_account_id(
                kind.provider_key(),
                Some(&current.id),
            )
            .unwrap();
            let mut reads = 0;
            let result = import_local_snapshot(kind, || {
                reads += 1;
                Ok(Some(QoderSnapshot {
                    variant: stored_variant_key(kind),
                    user_info_raw: Some(serde_json::json!({
                        "id": if reads == 1 { "probed-fixture-user" } else { "changed-fixture-user" },
                        "token": "native-at-fixture", "refreshToken": "native-rt-fixture"
                    })),
                    ..Default::default()
                }))
            });
            assert!(result.unwrap_err().contains("登录账号已变化"));
            assert_eq!(reads, 2);
            assert!(list_accounts_checked()
                .unwrap()
                .iter()
                .all(|account| account.user_id.as_deref() == Some("kept-fixture-user")));
            assert_eq!(
                crate::modules::provider_current_state::get_current_account_id(kind.provider_key())
                    .unwrap()
                    .as_deref(),
                Some(current.id.as_str())
            );
            assert_eq!(
                load_account(&current.id)
                    .unwrap()
                    .shared_refresh_token
                    .as_deref(),
                Some("kept-rt-fixture")
            );
        }
    }
}
