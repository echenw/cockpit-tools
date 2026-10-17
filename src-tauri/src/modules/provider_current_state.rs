use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const PROVIDER_CURRENT_STATE_FILE: &str = "provider_current_accounts.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderCurrentState {
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    current_accounts: HashMap<String, String>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl ProviderCurrentState {
    fn new() -> Self {
        Self {
            version: default_version(),
            current_accounts: HashMap::new(),
        }
    }
}

fn normalize_platform(platform: &str) -> Result<&'static str, String> {
    match platform.trim() {
        "windsurf" => Ok("windsurf"),
        "kiro" => Ok("kiro"),
        "cursor" => Ok("cursor"),
        "grok" => Ok("grok"),
        "claude_desktop_account" => Ok("claude_desktop_account"),
        "claude_code_account" => Ok("claude_code_account"),
        "codebuddy" => Ok("codebuddy"),
        "codebuddy_cn" | "codebuddy-cn" => Ok("codebuddy_cn"),
        "qoder" => Ok("qoder"),
        "qoder_app" | "qoder-app" => Ok("qoder_app"),
        "qoder_cn_ide" | "qoder-cn-ide" => Ok("qoder_cn_ide"),
        "qoder_cn_app" | "qoder-cn-app" => Ok("qoder_cn_app"),
        "zcode" => Ok("zcode"),
        "trae" => Ok("trae"),
        "trae_solo" | "trae-solo" => Ok("trae_solo"),
        "trae_cn" | "trae-cn" => Ok("trae_cn"),
        "trae_solo_cn" | "trae-solo-cn" => Ok("trae_solo_cn"),
        "workbuddy" => Ok("workbuddy"),
        "github_copilot" | "github-copilot" | "ghcp" => Ok("github_copilot"),
        other => Err(format!("不支持的平台: {}", other)),
    }
}

fn get_state_path() -> Result<PathBuf, String> {
    Ok(crate::modules::account::get_data_dir()?.join(PROVIDER_CURRENT_STATE_FILE))
}

fn load_state() -> Result<ProviderCurrentState, String> {
    let path = get_state_path()?;
    if !path.exists() {
        return Ok(ProviderCurrentState::new());
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("读取当前账号映射失败: path={}, error={}", path.display(), e))?;
    if content.trim().is_empty() {
        return Ok(ProviderCurrentState::new());
    }

    parse_state_or_recover(&content)
}

fn parse_state_or_recover(content: &str) -> Result<ProviderCurrentState, String> {
    match serde_json::from_str(content) {
        Ok(state) => Ok(state),
        Err(_) => {
            // 旧读取只触发恢复检查；update_state 在文件锁内重读主文件。
            // 若并发写入已经修好主文件，直接保留并返回它，不再用备份覆盖。
            let mut recovered = ProviderCurrentState::new();
            update_state(|state| recovered = state.clone())?;
            Ok(recovered)
        }
    }
}

fn update_state(update: impl FnOnce(&mut ProviderCurrentState)) -> Result<(), String> {
    let path = get_state_path()?;
    crate::modules::atomic_write::update_string_atomic(&path, |content| {
        let mut state = match content.filter(|value| !value.trim().is_empty()) {
            Some(content) => match serde_json::from_str::<ProviderCurrentState>(content) {
                Ok(state) => state,
                Err(error) => {
                    // 已持有文件锁；仅读取备份参与本次合并，不能再次调用加锁恢复。
                    let backup = path.with_file_name(format!("{PROVIDER_CURRENT_STATE_FILE}.bak"));
                    let restored = fs::read_to_string(&backup)
                        .map_err(|e| format!("解析当前账号映射失败: {error}；读取备份失败: {e}"))?;
                    serde_json::from_str::<ProviderCurrentState>(&restored)
                        .map_err(|e| format!("解析当前账号映射失败: {error}；备份无效: {e}"))?
                }
            },
            None => ProviderCurrentState::new(),
        };
        update(&mut state);
        serde_json::to_string_pretty(&state)
            .map_err(|e| format!("序列化当前账号映射失败: {e}"))
    })
        .map_err(|e| format!("保存当前账号映射失败: path={}, error={}", path.display(), e))
}

pub fn get_current_account_id(platform: &str) -> Result<Option<String>, String> {
    let key = normalize_platform(platform)?;
    let state = load_state()?;
    let id = state.current_accounts.get(key).map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if matches!(key, "qoder" | "qoder_app" | "qoder_cn_ide" | "qoder_cn_app") {
        return Ok(id.map(|id| crate::modules::qoder_account::load_account(&id)
            .map(|account| account.id).unwrap_or(id)));
    }
    Ok(id)
}

pub fn resolve_existing_current_account_id<'a, I>(platform: &str, existing_ids: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let current_id = get_current_account_id(platform).ok().flatten()?;
    if existing_ids.into_iter().any(|id| id == current_id.as_str()) {
        Some(current_id)
    } else {
        let _ = clear_current_account_if_matches(platform, &current_id);
        None
    }
}

pub fn set_current_account_id(platform: &str, account_id: Option<&str>) -> Result<(), String> {
    let key = normalize_platform(platform)?;
    update_state(|state| {
        if let Some(id) = account_id.map(str::trim).filter(|value| !value.is_empty()) {
            state.current_accounts.insert(key.to_string(), id.to_string());
        } else {
            state.current_accounts.remove(key);
        }
    })
}

fn clear_current_account_if_matches(platform: &str, expected: &str) -> Result<(), String> {
    let key = normalize_platform(platform)?;
    update_state(|state| {
        let current = state.current_accounts.get(key).map(|id| id.trim().to_string());
        let current = if matches!(key, "qoder" | "qoder_app" | "qoder_cn_ide" | "qoder_cn_app") {
            current.map(|id| crate::modules::qoder_account::load_account(&id)
                .map(|account| account.id).unwrap_or(id))
        } else { current };
        if current.as_deref() == Some(expected) {
            state.current_accounts.remove(key);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_corrupt_read_cannot_restore_over_a_concurrent_current_account_update() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("qoder-current-stale-recovery");
        set_current_account_id("qoder", Some("kept-fixture")).unwrap();
        set_current_account_id("qoder_app", Some("previous-fixture")).unwrap();
        let path = get_state_path().unwrap();
        fs::write(&path, "{invalid").unwrap();
        let stale_read = fs::read_to_string(&path).unwrap();
        // The writer repairs from the backup and saves a newer current account.
        set_current_account_id("qoder_cn_ide", Some("new-current-fixture")).unwrap();
        let before = fs::read_to_string(&path).unwrap();
        // Resume the reader with its earlier corrupt observation, as in load_state.
        let state = parse_state_or_recover(&stale_read).unwrap();
        assert_eq!(state.current_accounts.get("qoder_cn_ide").map(String::as_str), Some("new-current-fixture"));
        assert_eq!(state.current_accounts.get("qoder").map(String::as_str), Some("kept-fixture"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&path).unwrap()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&before).unwrap());
        // Without a concurrent repair, a real corrupt read still recovers its backup.
        fs::write(&path, "{invalid-again").unwrap();
        assert_eq!(load_state().unwrap().current_accounts.get("qoder").map(String::as_str), Some("kept-fixture"));
    }

    #[test]
    fn concurrent_qoder_current_updates_keep_each_variant_and_stale_cleanup_keeps_new_value() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("qoder-concurrent-current");
        let variants = ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(variants.len()));
        let threads: Vec<_> = variants.into_iter().map(|variant| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut results = Vec::new();
                for revision in 0..16 {
                    barrier.wait();
                    results.push(set_current_account_id(variant, Some(&format!("fixture-{variant}-{revision}"))));
                    barrier.wait();
                }
                for result in results { result.unwrap(); }
            })
        }).collect();
        for thread in threads { thread.join().unwrap(); }
        for variant in variants {
            assert_eq!(get_current_account_id(variant).unwrap(), Some(format!("fixture-{variant}-15")));
        }
        let previous = get_current_account_id("qoder").unwrap().unwrap();
        set_current_account_id("qoder", Some("new-current-fixture")).unwrap();
        clear_current_account_if_matches("qoder", &previous).unwrap();
        assert_eq!(get_current_account_id("qoder").unwrap().as_deref(), Some("new-current-fixture"));
        assert_eq!(get_current_account_id("qoder_app").unwrap().as_deref(), Some("fixture-qoder_app-15"));
    }

    #[test]
    fn qoder_current_update_merges_valid_backup_when_main_file_is_corrupt() {
        let _lock = crate::modules::test_support::env_lock().lock().unwrap();
        let _guard = DataDirGuard::new("qoder-current-backup");
        set_current_account_id("qoder", Some("kept-fixture")).unwrap();
        set_current_account_id("qoder_app", Some("previous-fixture")).unwrap();
        fs::write(get_state_path().unwrap(), "{invalid").unwrap();
        set_current_account_id("qoder_cn_ide", Some("new-fixture")).unwrap();
        assert_eq!(get_current_account_id("qoder").unwrap().as_deref(), Some("kept-fixture"));
        assert_eq!(get_current_account_id("qoder_cn_ide").unwrap().as_deref(), Some("new-fixture"));
    }

    fn temp_data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cockpit-provider-current-{}-{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp data dir");
        dir
    }

    struct DataDirGuard {
        dir: PathBuf,
        previous_data_dir: Option<String>,
    }

    impl DataDirGuard {
        fn new(name: &str) -> Self {
            let dir = temp_data_dir(name);
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

    #[test]
    fn provider_current_state_normalizes_platform_aliases() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("aliases");

        set_current_account_id("github-copilot", Some("gh-account")).expect("set github alias");
        assert_eq!(
            get_current_account_id("github_copilot").expect("get github canonical"),
            Some("gh-account".to_string())
        );
        assert_eq!(
            get_current_account_id("ghcp").expect("get github short alias"),
            Some("gh-account".to_string())
        );

        set_current_account_id("codebuddy-cn", Some("cn-account")).expect("set cn alias");
        assert_eq!(
            get_current_account_id("codebuddy_cn").expect("get cn canonical"),
            Some("cn-account".to_string())
        );

        set_current_account_id("trae-solo", Some("solo-account")).expect("set trae solo alias");
        assert_eq!(
            get_current_account_id("trae_solo").expect("get trae solo canonical"),
            Some("solo-account".to_string())
        );

        set_current_account_id("trae-solo-cn", Some("solo-cn-account"))
            .expect("set trae solo cn alias");
        assert_eq!(
            get_current_account_id("trae_solo_cn").expect("get trae solo cn canonical"),
            Some("solo-cn-account".to_string())
        );

        set_current_account_id("grok", Some("grok-account")).expect("set grok current");
        assert_eq!(
            get_current_account_id("grok").expect("get grok canonical"),
            Some("grok-account".to_string())
        );
    }

    #[test]
    fn provider_current_state_clears_stale_current_account_id() {
        let _lock = crate::modules::test_support::env_lock()
            .lock()
            .expect("lock env");
        let _guard = DataDirGuard::new("stale");

        set_current_account_id("cursor", Some("stale-account")).expect("set cursor current");
        assert_eq!(
            resolve_existing_current_account_id("cursor", ["other-account"].iter().copied()),
            None
        );
        assert_eq!(
            get_current_account_id("cursor").expect("get cursor after stale cleanup"),
            None
        );

        set_current_account_id("cursor", Some("active-account")).expect("set active cursor");
        assert_eq!(
            resolve_existing_current_account_id(
                "cursor",
                ["other-account", "active-account"].iter().copied()
            ),
            Some("active-account".to_string())
        );
    }
}
