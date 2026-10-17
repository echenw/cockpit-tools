use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use crate::models::{DefaultInstanceSettings, InstanceProfile, InstanceStore};
use crate::modules;
use crate::modules::instance::InstanceDefaults;
use crate::modules::instance_store;
use crate::modules::qoder_variant::QoderVariantKind;

pub use crate::modules::instance_store::{CreateInstanceParams, UpdateInstanceParams};

static QODER_INSTANCE_STORE_LOCK: std::sync::LazyLock<Mutex<()>> =
    std::sync::LazyLock::new(|| Mutex::new(()));

const QODER_INSTANCES_FILE: &str = "qoder_instances.json";

fn instances_file_for_variant(kind: QoderVariantKind) -> &'static str {
    match kind {
        QoderVariantKind::Qoder => QODER_INSTANCES_FILE,
        QoderVariantKind::QoderCnIde => "qoder_cn_ide_instances.json",
        // App 系不支持实例管理（官方单实例限制），入口 ensure_variant_supports_instances 已拦截。
        QoderVariantKind::QoderApp => "qoder_app_instances.json",
        QoderVariantKind::QoderCnApp => "qoder_cn_app_instances.json",
    }
}

fn ensure_variant_supports_instances(kind: QoderVariantKind) -> Result<(), String> {
    if kind.supports_instances() {
        return Ok(());
    }
    Err(format!(
        "{} 客户端不支持应用多开（官方单实例机制），实例管理仅服务 Qoder IDE 与 Qoder CN IDE",
        kind.display_name()
    ))
}

fn instances_path_for_variant(kind: QoderVariantKind) -> Result<PathBuf, String> {
    ensure_variant_supports_instances(kind)?;
    let data_dir = modules::account::get_data_dir()?;
    Ok(data_dir.join(instances_file_for_variant(kind)))
}

pub fn load_instance_store_for_variant(kind: QoderVariantKind) -> Result<InstanceStore, String> {
    let path = instances_path_for_variant(kind)?;
    instance_store::load_instance_store(&path, instances_file_for_variant(kind))
}

pub fn save_instance_store_for_variant(
    kind: QoderVariantKind,
    store: &InstanceStore,
) -> Result<(), String> {
    let path = instances_path_for_variant(kind)?;
    instance_store::save_instance_store(&path, instances_file_for_variant(kind), store)
}

pub fn load_default_settings_for_variant(
    kind: QoderVariantKind,
) -> Result<DefaultInstanceSettings, String> {
    let store = load_instance_store_for_variant(kind)?;
    Ok(store.default_settings)
}

pub fn update_default_settings_for_variant(
    kind: QoderVariantKind,
    bind_account_id: Option<Option<String>>,
    extra_args: Option<String>,
    follow_local_account: Option<bool>,
) -> Result<DefaultInstanceSettings, String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    let settings = &mut store.default_settings;

    // Qoder 实例不支持“跟随当前账号”，直接忽略 follow_local_account。
    if follow_local_account == Some(true) {
        settings.follow_local_account = false;
    }

    if let Some(bind) = bind_account_id {
        settings.bind_account_id = bind;
        settings.follow_local_account = false;
    }

    if let Some(args) = extra_args {
        settings.extra_args = args.trim().to_string();
    }

    let updated = settings.clone();
    save_instance_store_for_variant(kind, &store)?;
    Ok(updated)
}

pub fn get_default_qoder_user_data_dir() -> Result<PathBuf, String> {
    get_default_qoder_user_data_dir_for_variant(QoderVariantKind::Qoder)
}

pub fn get_default_qoder_user_data_dir_for_variant(kind: QoderVariantKind) -> Result<PathBuf, String> {
    use crate::modules::qoder_platform_paths as qpp;
    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().ok_or("无法获取用户主目录")?;
        return Ok(qpp::macos_data_dir_with_home(kind, &home));
    }

    #[cfg(target_os = "windows")]
    {
        return qpp::windows_data_dir(kind);
    }

    #[cfg(target_os = "linux")]
    {
        return qpp::linux_data_dir(kind);
    }

    #[allow(unreachable_code)]
    Err("Qoder 应用多开仅支持 macOS、Windows 和 Linux".to_string())
}

pub fn get_default_instances_root_dir_for_variant(kind: QoderVariantKind) -> Result<PathBuf, String> {
    ensure_variant_supports_instances(kind)?;
    crate::modules::data_paths::managed_instances_root_dir(kind.provider_key())
}

pub fn get_instance_defaults_for_variant(kind: QoderVariantKind) -> Result<InstanceDefaults, String> {
    let root_dir = get_default_instances_root_dir_for_variant(kind)?;
    let default_user_data_dir = get_default_qoder_user_data_dir_for_variant(kind)?;
    Ok(InstanceDefaults {
        root_dir: root_dir.to_string_lossy().to_string(),
        default_user_data_dir: default_user_data_dir.to_string_lossy().to_string(),
    })
}

// Resolve every existing component, including symlinks, before comparing paths.
// Nonexistent suffixes are allowed for a newly created instance.
pub(crate) fn normalized_instance_directory(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() { path.to_path_buf() } else {
        std::env::current_dir().map_err(|e| format!("解析实例目录失败: {e}"))?.join(path)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => continue,
            Component::ParentDir => { resolved.pop(); }
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            component => {
                resolved.push(component.as_os_str());
                match fs::symlink_metadata(&resolved) {
                    Ok(_) => resolved = fs::canonicalize(&resolved)
                        .map_err(|e| format!("解析实例目录别名失败: {e}"))?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                    Err(e) => return Err(format!("检查实例目录失败: {e}")),
                }
            }
        }
    }
    #[cfg(windows)]
    { resolved = PathBuf::from(resolved.to_string_lossy().to_lowercase()); }
    Ok(resolved)
}

fn ensure_separate_directories(candidate: &Path, other: &Path) -> Result<(), String> {
    let candidate = normalized_instance_directory(candidate)?;
    let other = normalized_instance_directory(other)?;
    if candidate.starts_with(&other) || other.starts_with(&candidate) {
        return Err("实例目录不得与默认客户端或其他实例目录重合、互相嵌套或指向同一目录".into());
    }
    Ok(())
}

pub(crate) fn validate_instance_directory_for_variant(
    kind: QoderVariantKind,
    instance_id: Option<&str>,
    directory: &str,
) -> Result<(), String> {
    ensure_variant_supports_instances(kind)?;
    let candidate = Path::new(directory);
    for other_kind in crate::modules::qoder_variant::all_qoder_variant_kinds() {
        let default = get_default_qoder_user_data_dir_for_variant(other_kind)?;
        ensure_separate_directories(candidate, &default)?;
        if !other_kind.supports_instances() { continue; }
        for instance in load_instance_store_for_variant(other_kind)?.instances {
            if other_kind == kind && instance_id == Some(instance.id.as_str()) { continue; }
            ensure_separate_directories(candidate, Path::new(&instance.user_data_dir))?;
        }
    }
    Ok(())
}

pub fn create_instance_for_variant(
    kind: QoderVariantKind,
    params: CreateInstanceParams,
) -> Result<InstanceProfile, String> {
    let directory_preexisted = std::path::Path::new(params.user_data_dir.trim()).exists();
    let creation_mode = params.init_mode.clone().unwrap_or_else(|| "copy".to_string());
    let _creation_guard = crate::modules::instance_storage_cleanup::protect_instance_creation()?;
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;

    let name = instance_store::normalize_name(&params.name)?;
    let user_data_dir = params.user_data_dir.trim().to_string();
    if user_data_dir.is_empty() {
        return Err("实例目录不能为空".to_string());
    }

    instance_store::ensure_unique(&store, &name, &user_data_dir, None)?;
    validate_instance_directory_for_variant(kind, None, &user_data_dir)?;

    let user_dir_path = PathBuf::from(&user_data_dir);
    let init_mode = params
        .init_mode
        .as_deref()
        .unwrap_or("copy")
        .to_ascii_lowercase();
    let create_empty = init_mode == "empty";
    let use_existing_dir = init_mode == "existingdir" || init_mode == "existing_dir";

    if use_existing_dir {
        if !user_dir_path.exists() {
            let resolved = instance_store::display_path(&user_dir_path);
            return Err(format!("所选目录不存在: {}", resolved));
        }
        if !user_dir_path.is_dir() {
            return Err("所选路径不是目录".to_string());
        }
    } else if create_empty {
        if user_dir_path.exists() {
            let mut has_entries = false;
            if let Ok(mut iter) = fs::read_dir(&user_dir_path) {
                if iter.next().is_some() {
                    has_entries = true;
                }
            }
            if has_entries {
                let resolved_path = instance_store::display_path(&user_dir_path);
                return Err(format!("空白实例需要目标目录为空: {}", resolved_path));
            }
        }
        fs::create_dir_all(&user_dir_path).map_err(|e| format!("创建实例目录失败: {}", e))?;
    } else {
        let source_dir = match params.copy_source_instance_id.as_deref() {
            Some("__default__") | None => get_default_qoder_user_data_dir_for_variant(kind)?,
            Some(source_id) => {
                let source_instance = store
                    .instances
                    .iter()
                    .find(|item| item.id == source_id)
                    .ok_or("复制来源实例不存在")?;
                PathBuf::from(&source_instance.user_data_dir)
            }
        };

        if user_dir_path.exists() {
            let mut has_entries = false;
            if let Ok(mut iter) = fs::read_dir(&user_dir_path) {
                if iter.next().is_some() {
                    has_entries = true;
                }
            }
            if has_entries {
                let resolved_path = instance_store::display_path(&user_dir_path);
                modules::logger::log_info(&format!(
                    "[Qoder Instance] 复制来源实例需要空目录，但目标已存在: {}",
                    resolved_path
                ));
                return Err(format!("复制来源实例需要目标目录为空: {}", resolved_path));
            }
        }

        if !source_dir.exists() {
            return Err("未找到复制来源目录，请先确保来源实例已初始化".to_string());
        }

        instance_store::copy_dir_recursive(&source_dir, &user_dir_path)?;
    }

    let instance = InstanceProfile {
        id: Uuid::new_v4().to_string(),
        name,
        user_data_dir,
        working_dir: params.working_dir,
        extra_args: params.extra_args.trim().to_string(),
        bind_account_id: if create_empty {
            None
        } else {
            params.bind_account_id
        },
        model_routing: None,
        launch_mode: crate::models::InstanceLaunchMode::App,
        app_speed: crate::models::codex::CodexAppSpeed::Standard,
        created_at: Utc::now().timestamp_millis(),
        last_launched_at: None,
        last_pid: None,
    };

    crate::modules::instance_directory_ownership::record_creation(
        std::path::Path::new(&instance.user_data_dir), &instance.id, &creation_mode, directory_preexisted,
    )?;
    store.instances.push(instance.clone());
    save_instance_store_for_variant(kind, &store)?;
    Ok(instance)
}

pub fn update_instance_for_variant(
    kind: QoderVariantKind,
    params: UpdateInstanceParams,
) -> Result<InstanceProfile, String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    let index = store
        .instances
        .iter()
        .position(|instance| instance.id == params.instance_id)
        .ok_or("实例不存在")?;

    let current_id = store.instances[index].id.clone();
    let current_dir = store.instances[index].user_data_dir.clone();
    let next_name = params
        .name
        .as_ref()
        .map(|name| instance_store::normalize_name(name))
        .transpose()?;

    if let Some(ref normalized) = next_name {
        instance_store::ensure_unique(&store, normalized, &current_dir, Some(&current_id))?;
    }

    let instance = &mut store.instances[index];
    if let Some(normalized) = next_name {
        instance.name = normalized;
    }
    if let Some(ref extra_args) = params.extra_args {
        instance.extra_args = extra_args.trim().to_string();
    }
    if let Some(bind) = params.bind_account_id.clone() {
        instance.bind_account_id = bind;
    }

    let updated = instance.clone();
    save_instance_store_for_variant(kind, &store)?;
    Ok(updated)
}

pub fn delete_instance_for_variant(
    kind: QoderVariantKind,
    instance_id: &str,
) -> Result<(), String> {
    delete_instance_with_probe(kind, instance_id, |instance| {
        modules::process::resolve_qoder_instance_pid_for_deletion_checked(
            kind, instance.last_pid, &instance.user_data_dir,
        )
    })
}

fn delete_instance_with_probe(
    kind: QoderVariantKind,
    instance_id: &str,
    probe: impl FnOnce(&InstanceProfile) -> Result<Option<u32>, String>,
) -> Result<(), String> {
    let _creation_guard = crate::modules::instance_storage_cleanup::protect_instance_creation()?;
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    let index = store
        .instances
        .iter()
        .position(|instance| instance.id == instance_id)
        .ok_or("实例不存在")?;
    let user_data_dir = store.instances[index].user_data_dir.clone();
    // 调用方持有变体会话锁，串行启动/停止/删除；不能把探测错误当成已退出。
    if probe(&store.instances[index])?.is_some() {
        return Err("实例仍在运行，请先停止实例，再删除。".into());
    }

    if !user_data_dir.trim().is_empty() {
        let dir_path = PathBuf::from(&user_data_dir);
        modules::instance::delete_instance_directory(&dir_path)?;
    }

    store.instances.remove(index);
    save_instance_store_for_variant(kind, &store)?;
    Ok(())
}

pub fn update_instance_after_start_for_variant(
    kind: QoderVariantKind,
    instance_id: &str,
    pid: u32,
) -> Result<InstanceProfile, String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    let mut updated = None;
    for instance in &mut store.instances {
        if instance.id == instance_id {
            instance.last_launched_at = Some(Utc::now().timestamp_millis());
            instance.last_pid = Some(pid);
            updated = Some(instance.clone());
            break;
        }
    }
    let updated = updated.ok_or("实例不存在")?;
    save_instance_store_for_variant(kind, &store)?;
    Ok(updated)
}

pub fn update_instance_pid_for_variant(
    kind: QoderVariantKind,
    instance_id: &str,
    pid: Option<u32>,
) -> Result<InstanceProfile, String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    let mut updated = None;
    for instance in &mut store.instances {
        if instance.id == instance_id {
            instance.last_pid = pid;
            updated = Some(instance.clone());
            break;
        }
    }
    let updated = updated.ok_or("实例不存在")?;
    save_instance_store_for_variant(kind, &store)?;
    Ok(updated)
}

pub fn update_default_pid_for_variant(
    kind: QoderVariantKind,
    pid: Option<u32>,
) -> Result<DefaultInstanceSettings, String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    store.default_settings.last_pid = pid;
    let updated = store.default_settings.clone();
    save_instance_store_for_variant(kind, &store)?;
    Ok(updated)
}

pub fn clear_all_pids_for_variant(kind: QoderVariantKind) -> Result<(), String> {
    let _lock = QODER_INSTANCE_STORE_LOCK
        .lock()
        .map_err(|_| "无法获取实例锁")?;
    let mut store = load_instance_store_for_variant(kind)?;
    store.default_settings.last_pid = None;
    for instance in &mut store.instances {
        instance.last_pid = None;
    }
    save_instance_store_for_variant(kind, &store)?;
    Ok(())
}

#[cfg(test)]
mod directory_tests {
    use super::*;

    #[test]
    fn deleting_running_or_unreadable_qoder_instance_preserves_directory_and_registration() {
        let _env = crate::modules::test_support::env_lock().lock().unwrap();
        let base = std::env::temp_dir().join(format!("qoder-delete-{}", Uuid::new_v4()));
        struct Restore { previous: Option<String>, base: PathBuf }
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.previous {
                    Some(value) => std::env::set_var("COCKPIT_TOOLS_DATA_DIR", value),
                    None => std::env::remove_var("COCKPIT_TOOLS_DATA_DIR"),
                }
                let _ = fs::remove_dir_all(&self.base);
            }
        }
        let _restore = Restore { previous: std::env::var("COCKPIT_TOOLS_DATA_DIR").ok(), base: base.clone() };
        std::env::set_var("COCKPIT_TOOLS_DATA_DIR", &base);
        for kind in [QoderVariantKind::Qoder, QoderVariantKind::QoderCnIde] {
            let profile = get_default_instances_root_dir_for_variant(kind).unwrap().join("live-fixture");
            assert!(profile.starts_with(&base));
            let instance = create_instance_for_variant(kind, CreateInstanceParams {
                name: "live-fixture".into(), user_data_dir: profile.to_string_lossy().into_owned(),
                working_dir: None, extra_args: String::new(), bind_account_id: None,
                copy_source_instance_id: None, init_mode: Some("empty".into()),
            }).unwrap();
            fs::write(profile.join("kept-fixture.txt"), "kept").unwrap();
            assert!(delete_instance_with_probe(kind, &instance.id, |_| Ok(Some(42)))
                .unwrap_err().contains("仍在运行"));
            assert_eq!(fs::read_to_string(profile.join("kept-fixture.txt")).unwrap(), "kept");
            assert!(load_instance_store_for_variant(kind).unwrap().instances.iter().any(|item| item.id == instance.id));
            assert!(delete_instance_with_probe(kind, &instance.id, |_| Err("fixture process probe failed".into()))
                .unwrap_err().contains("probe failed"));
            assert!(profile.join("kept-fixture.txt").exists());
            assert!(load_instance_store_for_variant(kind).unwrap().instances.iter().any(|item| item.id == instance.id));
            // Remove only this fixture before the stopped case, avoiding the OS trash.
            fs::remove_dir_all(&profile).unwrap();
            delete_instance_with_probe(kind, &instance.id, |_| Ok(None)).unwrap();
            assert!(load_instance_store_for_variant(kind).unwrap().instances.is_empty());
        }
    }

    #[test]
    fn qoder_instance_directories_reject_defaults_nested_paths_and_aliases() {
        let _env = crate::modules::test_support::env_lock().lock().unwrap();
        let base = std::env::temp_dir().join(format!("qoder-directory-{}", Uuid::new_v4()));
        fs::create_dir_all(base.join("profile")).unwrap();
        let profile = base.join("profile");
        assert!(ensure_separate_directories(&profile, &profile).is_err());
        assert!(ensure_separate_directories(&profile.join("nested"), &profile).is_err());
        assert!(ensure_separate_directories(&base, &profile).is_err());
        assert!(ensure_separate_directories(&profile.join("..").join("profile"), &profile).is_err());
        assert!(ensure_separate_directories(&base.join("sibling"), &profile).is_ok());
        #[cfg(unix)] {
            let alias = base.join("alias");
            std::os::unix::fs::symlink(&profile, &alias).unwrap();
            assert!(ensure_separate_directories(&alias, &profile).is_err());
            assert!(ensure_separate_directories(&alias.join("new-child"), &profile).is_err());
        }
        // Creation and launch validation share this rule; use the real default path
        // without creating or touching the official client's directory.
        let previous = std::env::var("COCKPIT_TOOLS_DATA_DIR").ok();
        struct Restore(Option<String>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("COCKPIT_TOOLS_DATA_DIR", value),
                    None => std::env::remove_var("COCKPIT_TOOLS_DATA_DIR"),
                }
            }
        }
        let _restore = Restore(previous);
        std::env::set_var("COCKPIT_TOOLS_DATA_DIR", base.join("catalog"));
        for kind in [QoderVariantKind::Qoder, QoderVariantKind::QoderCnIde] {
            let default = get_default_qoder_user_data_dir_for_variant(kind).unwrap();
            let error = create_instance_for_variant(kind, CreateInstanceParams {
                name: "default-alias-fixture".into(), user_data_dir: default.to_string_lossy().into_owned(),
                working_dir: None, extra_args: String::new(), bind_account_id: None,
                copy_source_instance_id: None, init_mode: Some("existingDir".into()),
            }).unwrap_err();
            assert!(error.contains("实例目录不得"));
            assert!(validate_instance_directory_for_variant(kind, Some("invalid-registration"),
                &default.to_string_lossy()).is_err());
            assert!(load_instance_store_for_variant(kind).unwrap().instances.is_empty());
        }
        fs::remove_dir_all(base).unwrap();
    }
}
