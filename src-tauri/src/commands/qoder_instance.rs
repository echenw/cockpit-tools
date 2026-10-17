use std::path::Path;

use crate::models::InstanceProfileView;
use crate::modules;
use crate::modules::qoder_variant::QoderVariantKind;

const DEFAULT_INSTANCE_ID: &str = "__default__";

/// 解析并校验变体：实例管理仅服务 IDE 系（App 系客户端受官方单实例机制限制）。
fn parse_variant(variant_key: Option<String>) -> Result<QoderVariantKind, String> {
    let kind = QoderVariantKind::parse(variant_key.as_deref())?;
    if !kind.supports_instances() {
        return Err(format!(
            "{} 客户端不支持应用多开（官方单实例机制），实例管理仅服务 Qoder IDE 与 Qoder CN IDE",
            kind.display_name()
        ));
    }
    Ok(kind)
}

fn is_profile_initialized(user_data_dir: &str) -> bool {
    let path = Path::new(user_data_dir);
    if !path.exists() {
        return false;
    }
    match std::fs::read_dir(path) {
        Ok(mut iter) => iter.next().is_some(),
        Err(_) => false,
    }
}

// Instance views may use a best-effort PID. Mutating operations must obtain
// a reliable process snapshot through close_instances before writing any state.
fn resolve_running_pid(
    kind: QoderVariantKind,
    last_pid: Option<u32>,
    user_data_dir: Option<&str>,
) -> Option<u32> {
    modules::process::resolve_qoder_pid_for_variant(kind, last_pid, user_data_dir)
}

fn close_instances(
    kind: QoderVariantKind,
    user_data_dirs: &[String],
    timeout_secs: u64,
) -> Result<(), String> {
    // Both IDE variants must propagate probe errors before account/profile writes.
    modules::process::close_qoder_variant_instances(kind, user_data_dirs, timeout_secs)
}

fn inject_bound_account_for_instance_start(
    kind: QoderVariantKind,
    user_data_dir: &str,
    bind_account_id: Option<&str>,
) -> Result<(), String> {
    let bind_id = bind_account_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(bind_id) = bind_id else {
        return Ok(());
    };

    let account = modules::qoder_account::load_account(bind_id)
        .ok_or_else(|| format!("绑定账号不存在: {}", bind_id))?;
    modules::logger::log_info(&format!(
        "[Qoder Instance] 实例启动检测到绑定账号，准备注入: variant={}, bind_account_id={}, email={}, user_data_dir={}",
        kind.provider_key(),
        bind_id,
        account.email,
        user_data_dir
    ));

    modules::qoder_account::inject_to_qoder_for_variant_user_data_dir(kind, user_data_dir, bind_id)?;
    Ok(())
}

async fn prepare_bound_account_for_instance_start(
    kind: QoderVariantKind,
    bind_account_id: Option<&str>,
) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>, String> {
    let bind_id = bind_account_id
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(bind_id) = bind_id {
        return modules::qoder_oauth::prepare_account_for_launch(kind, bind_id)
            .await.map(Some);
    }
    Ok(None)
}

async fn reconcile_stopped_instance(kind: QoderVariantKind, instance: &crate::models::InstanceProfile) -> Result<(), String> {
    // 从未启动的复制配置不属于实例续期；已有交接记录仍由账号 Owner 查找。
    let legacy_bound = instance.last_launched_at.and(instance.bind_account_id.as_deref());
    modules::qoder_account::reconcile_ide_instance_session(kind, &instance.user_data_dir, legacy_bound).await
}

fn ensure_launch_path(kind: QoderVariantKind) -> Result<(), String> {
    modules::process::ensure_qoder_variant_launch_path(kind)
}

fn start_instance_with_args(
    kind: QoderVariantKind,
    user_data_dir: &str,
    extra_args: &[String],
) -> Result<u32, String> {
    modules::process::start_qoder_variant_with_args_with_new_window(
        kind,
        user_data_dir,
        extra_args,
        true,
    )
}

fn start_default_instance_with_args(
    kind: QoderVariantKind,
    extra_args: &[String],
) -> Result<u32, String> {
    modules::process::start_qoder_variant_default_with_args_with_new_window(kind, extra_args, true)
}

#[tauri::command]
pub async fn qoder_get_instance_defaults(
    variant_key: Option<String>,
) -> Result<modules::instance::InstanceDefaults, String> {
    let kind = parse_variant(variant_key)?;
    modules::qoder_instance::get_instance_defaults_for_variant(kind)
}

#[tauri::command]
pub async fn qoder_list_instances(
    variant_key: Option<String>,
) -> Result<Vec<InstanceProfileView>, String> {
    let kind = parse_variant(variant_key)?;
    let store = modules::qoder_instance::load_instance_store_for_variant(kind)?;
    let default_dir = modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind)?;
    let default_dir_str = default_dir.to_string_lossy().to_string();

    let default_settings = store.default_settings.clone();

    let mut result: Vec<InstanceProfileView> = store
        .instances
        .into_iter()
        .map(|instance| {
            let running_pid =
                resolve_running_pid(kind, instance.last_pid, Some(&instance.user_data_dir));
            let running = running_pid.is_some();
            let initialized = is_profile_initialized(&instance.user_data_dir);
            let mut view = InstanceProfileView::from_profile(instance, running, initialized);
            view.last_pid = running_pid;
            view
        })
        .collect();

    let default_pid = resolve_running_pid(kind, default_settings.last_pid, None);
    result.push(InstanceProfileView {
        id: DEFAULT_INSTANCE_ID.to_string(),
        name: String::new(),
        user_data_dir: default_dir_str,
        working_dir: None,
        extra_args: default_settings.extra_args.clone(),
        bind_account_id: default_settings.bind_account_id.clone(),
        created_at: 0,
        last_launched_at: None,
        last_pid: default_pid,
        running: default_pid.is_some(),
        initialized: is_profile_initialized(&default_dir.to_string_lossy()),
        is_default: true,
        follow_local_account: false,
    });

    Ok(result)
}

#[tauri::command]
pub async fn qoder_create_instance(
    variant_key: Option<String>,
    name: String,
    user_data_dir: String,
    extra_args: Option<String>,
    bind_account_id: Option<String>,
    copy_source_instance_id: Option<String>,
    init_mode: Option<String>,
) -> Result<InstanceProfileView, String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;
    let instance = modules::qoder_instance::create_instance_for_variant(
        kind,
        modules::qoder_instance::CreateInstanceParams {
            working_dir: None,
            name,
            user_data_dir,
            extra_args: extra_args.unwrap_or_default(),
            bind_account_id,
            copy_source_instance_id,
            init_mode,
        },
    )?;

    let initialized = is_profile_initialized(&instance.user_data_dir);
    Ok(InstanceProfileView::from_profile(
        instance,
        false,
        initialized,
    ))
}

#[tauri::command]
pub async fn qoder_update_instance(
    variant_key: Option<String>,
    instance_id: String,
    name: Option<String>,
    extra_args: Option<String>,
    bind_account_id: Option<Option<String>>,
    follow_local_account: Option<bool>,
) -> Result<InstanceProfileView, String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;

    if instance_id == DEFAULT_INSTANCE_ID {
        let default_dir =
            modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind)?;
        let default_dir_str = default_dir.to_string_lossy().to_string();
        let updated = modules::qoder_instance::update_default_settings_for_variant(
            kind,
            bind_account_id,
            extra_args,
            follow_local_account,
        )?;
        let running_pid = resolve_running_pid(kind, updated.last_pid, None);
        return Ok(InstanceProfileView {
            id: DEFAULT_INSTANCE_ID.to_string(),
            name: String::new(),
            user_data_dir: default_dir_str,
            working_dir: None,
            extra_args: updated.extra_args,
            bind_account_id: updated.bind_account_id,
            created_at: 0,
            last_launched_at: None,
            last_pid: running_pid,
            running: running_pid.is_some(),
            initialized: is_profile_initialized(&default_dir.to_string_lossy()),
            is_default: true,
            follow_local_account: false,
        });
    }

    let instance = modules::qoder_instance::update_instance_for_variant(
        kind,
        modules::qoder_instance::UpdateInstanceParams {
            working_dir: None,
            instance_id,
            name,
            extra_args,
            bind_account_id,
        },
    )?;

    let running_pid = resolve_running_pid(kind, instance.last_pid, Some(&instance.user_data_dir));
    let running = running_pid.is_some();
    let initialized = is_profile_initialized(&instance.user_data_dir);
    let mut view = InstanceProfileView::from_profile(instance, running, initialized);
    view.last_pid = running_pid;
    Ok(view)
}

#[tauri::command]
pub async fn qoder_delete_instance(
    variant_key: Option<String>,
    instance_id: String,
) -> Result<(), String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;
    if instance_id == DEFAULT_INSTANCE_ID {
        return Err("默认实例不可删除".to_string());
    }
    let instance = modules::qoder_instance::load_instance_store_for_variant(kind)?.instances
        .into_iter().find(|instance| instance.id == instance_id).ok_or("实例不存在")?;
    reconcile_stopped_instance(kind, &instance).await?;
    modules::qoder_instance::delete_instance_for_variant(kind, &instance_id)
}

#[tauri::command]
pub async fn qoder_start_instance(
    variant_key: Option<String>,
    instance_id: String,
) -> Result<InstanceProfileView, String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;
    ensure_launch_path(kind)?;

    if instance_id == DEFAULT_INSTANCE_ID {
        let default_dir =
            modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind)?;
        let default_dir_str = default_dir.to_string_lossy().to_string();
        let default_settings =
            modules::qoder_instance::load_default_settings_for_variant(kind)?;

        // Never terminate a PID based on an optional/best-effort probe before
        // the checked close has verified its executable and user-data-dir.
        close_instances(kind, &[default_dir_str.clone()], 20)?;
        modules::qoder_account::reconcile_default_ide_session(kind).await?;
        let _account_guard = prepare_bound_account_for_instance_start(
            kind, default_settings.bind_account_id.as_deref(),
        ).await?;
        let _ = modules::qoder_instance::update_default_pid_for_variant(kind, None)?;

        inject_bound_account_for_instance_start(
            kind,
            &default_dir_str,
            default_settings.bind_account_id.as_deref(),
        )?;
        if let Some(bind_id) = default_settings.bind_account_id.as_deref().map(str::trim).filter(|id| !id.is_empty()) {
            let account = modules::qoder_account::load_account(bind_id).ok_or("绑定账号不存在")?;
            modules::provider_current_state::set_current_account_id(kind.provider_key(), Some(&account.id))?;
        }

        let extra_args = modules::process::parse_extra_args(&default_settings.extra_args);
        let pid = start_default_instance_with_args(kind, &extra_args)?;
        let _ = modules::qoder_instance::update_default_pid_for_variant(kind, Some(pid))?;
        let running_pid = resolve_running_pid(kind, Some(pid), None);

        return Ok(InstanceProfileView {
            id: DEFAULT_INSTANCE_ID.to_string(),
            name: String::new(),
            user_data_dir: default_dir_str,
            working_dir: None,
            extra_args: default_settings.extra_args,
            bind_account_id: default_settings.bind_account_id,
            created_at: 0,
            last_launched_at: None,
            last_pid: running_pid,
            running: running_pid.is_some(),
            initialized: is_profile_initialized(&default_dir.to_string_lossy()),
            is_default: true,
            follow_local_account: false,
        });
    }

    let store = modules::qoder_instance::load_instance_store_for_variant(kind)?;
    let instance = store
        .instances
        .into_iter()
        .find(|item| item.id == instance_id)
        .ok_or("实例不存在")?;

    modules::qoder_instance::validate_instance_directory_for_variant(
        kind, Some(&instance.id), &instance.user_data_dir,
    )?;
    // This checked close protects the bound-account injection below.
    close_instances(kind, &[instance.user_data_dir.clone()], 20)?;
    reconcile_stopped_instance(kind, &instance).await?;
    let _account_guard = prepare_bound_account_for_instance_start(
        kind, instance.bind_account_id.as_deref(),
    ).await?;
    modules::qoder_instance::validate_instance_directory_for_variant(
        kind, Some(&instance.id), &instance.user_data_dir,
    )?;
    let _ = modules::qoder_instance::update_instance_pid_for_variant(kind, &instance.id, None)?;

    inject_bound_account_for_instance_start(
        kind,
        &instance.user_data_dir,
        instance.bind_account_id.as_deref(),
    )?;

    let extra_args = modules::process::parse_extra_args(&instance.extra_args);
    let pid = start_instance_with_args(kind, &instance.user_data_dir, &extra_args)?;

    let updated =
        modules::qoder_instance::update_instance_after_start_for_variant(kind, &instance.id, pid)?;
    let running_pid = resolve_running_pid(kind, Some(pid), Some(&updated.user_data_dir));
    let initialized = is_profile_initialized(&updated.user_data_dir);
    let mut view = InstanceProfileView::from_profile(updated, running_pid.is_some(), initialized);
    view.last_pid = running_pid;
    Ok(view)
}

#[tauri::command]
pub async fn qoder_stop_instance(
    variant_key: Option<String>,
    instance_id: String,
) -> Result<InstanceProfileView, String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;

    if instance_id == DEFAULT_INSTANCE_ID {
        let default_dir =
            modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind)?;
        let default_dir_str = default_dir.to_string_lossy().to_string();
        let default_settings =
            modules::qoder_instance::load_default_settings_for_variant(kind)?;
        close_instances(kind, &[default_dir_str.clone()], 20)?;
        modules::qoder_account::reconcile_default_ide_session(kind).await?;
        let _ = modules::qoder_instance::update_default_pid_for_variant(kind, None)?;
        return Ok(InstanceProfileView {
            id: DEFAULT_INSTANCE_ID.to_string(),
            name: String::new(),
            user_data_dir: default_dir_str,
            working_dir: None,
            extra_args: default_settings.extra_args,
            bind_account_id: default_settings.bind_account_id,
            created_at: 0,
            last_launched_at: None,
            last_pid: None,
            running: false,
            initialized: is_profile_initialized(&default_dir.to_string_lossy()),
            is_default: true,
            follow_local_account: false,
        });
    }

    let store = modules::qoder_instance::load_instance_store_for_variant(kind)?;
    let instance = store
        .instances
        .into_iter()
        .find(|item| item.id == instance_id)
        .ok_or("实例不存在")?;

    modules::qoder_instance::validate_instance_directory_for_variant(
        kind, Some(&instance.id), &instance.user_data_dir,
    )?;
    close_instances(kind, &[instance.user_data_dir.clone()], 20)?;
    reconcile_stopped_instance(kind, &instance).await?;
    let updated =
        modules::qoder_instance::update_instance_pid_for_variant(kind, &instance.id, None)?;
    let initialized = is_profile_initialized(&updated.user_data_dir);
    Ok(InstanceProfileView::from_profile(
        updated,
        false,
        initialized,
    ))
}

#[tauri::command]
pub async fn qoder_open_instance_window(
    variant_key: Option<String>,
    instance_id: String,
) -> Result<(), String> {
    let kind = parse_variant(variant_key)?;

    if instance_id == DEFAULT_INSTANCE_ID {
        let default_settings =
            modules::qoder_instance::load_default_settings_for_variant(kind)?;
        let pid = resolve_running_pid(kind, default_settings.last_pid, None)
            .ok_or("默认实例未运行")?;
        modules::process::focus_process_pid(pid).map_err(|err| {
            format!(
                "定位 {} 默认实例窗口失败: {}",
                kind.display_name(),
                err
            )
        })?;
        return Ok(());
    }

    let store = modules::qoder_instance::load_instance_store_for_variant(kind)?;
    let instance = store
        .instances
        .into_iter()
        .find(|item| item.id == instance_id)
        .ok_or("实例不存在")?;
    let pid = resolve_running_pid(kind, instance.last_pid, Some(&instance.user_data_dir))
        .ok_or("实例未运行")?;

    modules::process::focus_process_pid(pid).map_err(|err| {
        format!(
            "定位 {} 实例窗口失败: instance_id={}, err={}",
            kind.display_name(),
            instance.id,
            err
        )
    })?;
    Ok(())
}

#[tauri::command]
pub async fn qoder_close_all_instances(variant_key: Option<String>) -> Result<(), String> {
    let kind = parse_variant(variant_key)?;
    let session_lock = modules::qoder_oauth::client_session_lock(kind)?;
    let _session_guard = session_lock.lock().await;
    let store = modules::qoder_instance::load_instance_store_for_variant(kind)?;
    let default_dir = modules::qoder_instance::get_default_qoder_user_data_dir_for_variant(kind)?;
    let mut target_dirs: Vec<String> = Vec::new();
    target_dirs.push(default_dir.to_string_lossy().to_string());
    for instance in &store.instances {
        let dir = instance.user_data_dir.trim();
        if !dir.is_empty() {
            target_dirs.push(dir.to_string());
        }
    }

    close_instances(kind, &target_dirs, 20)?;
    modules::qoder_account::reconcile_default_ide_session(kind).await?;
    for instance in &store.instances { reconcile_stopped_instance(kind, instance).await?; }
    let _ = modules::qoder_instance::clear_all_pids_for_variant(kind);
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    #[tokio::test]
    async fn qoder_stop_and_delete_wait_for_the_same_session_boundary_as_start() {
        let _env = modules::test_support::env_lock().lock().unwrap();
        let directory = std::env::temp_dir().join(format!("qoder-lifecycle-{}", uuid::Uuid::new_v4()));
        struct Restore { previous: Option<String>, directory: std::path::PathBuf }
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.previous {
                    Some(value) => std::env::set_var("COCKPIT_TOOLS_DATA_DIR", value),
                    None => std::env::remove_var("COCKPIT_TOOLS_DATA_DIR"),
                }
                let _ = std::fs::remove_dir_all(&self.directory);
            }
        }
        let _restore = Restore { previous: std::env::var("COCKPIT_TOOLS_DATA_DIR").ok(), directory: directory.clone() };
        std::env::set_var("COCKPIT_TOOLS_DATA_DIR", &directory);
        for kind in [QoderVariantKind::Qoder, QoderVariantKind::QoderCnIde] {
            // Hold the boundary used by start across its preparation/launch.
            let lock = modules::qoder_oauth::client_session_lock(kind).unwrap();
            let held = lock.lock().await;
            let mut stop = Box::pin(qoder_stop_instance(Some(kind.provider_key().into()), "missing-fixture".into()));
            let mut delete = Box::pin(qoder_delete_instance(Some(kind.provider_key().into()), "missing-fixture".into()));
            poll_fn(|cx| {
                assert!(stop.as_mut().poll(cx).is_pending());
                assert!(delete.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            }).await;
            drop(held);
            // Missing IDs avoid touching any actual client or process; both
            // commands must proceed to the registry check after the lock releases.
            assert!(stop.await.unwrap_err().contains("实例不存在"));
            assert!(delete.await.unwrap_err().contains("实例不存在"));
        }
    }
}
