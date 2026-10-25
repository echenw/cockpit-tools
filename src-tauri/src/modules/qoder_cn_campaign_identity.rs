//! 国内活动设备身份：调用已安装的官方 CN runtime-info，不启动 App 或操作登录态。

use super::{QoderMachineInfo, CAMPAIGN_CLIENT_VERSION};
use crate::modules::qoder_variant::QoderVariantKind;
use crate::modules::{account, atomic_write, logger, process};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const BRIDGE_TIMEOUT: Duration = Duration::from_secs(25);
const MAX_BRIDGE_OUTPUT: u64 = 64 * 1024;
const MACHINE_ID_FILE: &str = "qoder_cn_campaign_machine_id.txt";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeIdentity {
    machine_token: String,
    machine_type: String,
    machine_code: String,
}

fn runtime_candidates(installation: &Path, platform: &str) -> Vec<PathBuf> {
    if platform == "macos" {
        let root = installation
            .ancestors()
            .find(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
            })
            .unwrap_or(installation);
        return vec![root.join("Contents/Resources/umid/runtime-info")];
    }
    let root = if installation.is_dir() {
        installation
    } else {
        installation.parent().unwrap_or(installation)
    };
    vec![root.join("resources/umid").join(if platform == "windows" {
        "runtime-info.exe"
    } else {
        "runtime-info"
    })]
}

fn runtime_executable() -> Result<PathBuf, String> {
    let installation = process::resolve_qoder_variant_launch_path(QoderVariantKind::QoderCnApp)
        .map_err(|_| "未找到 Qoder CN App 安装路径，无法加载官方设备身份工具".to_string())?;
    let installation = std::fs::canonicalize(installation)
        .map_err(|_| "无法读取 Qoder CN App 安装目录".to_string())?;
    runtime_candidates(&installation, std::env::consts::OS)
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "Qoder CN App 安装目录缺少 umid/runtime-info，请更新或重新安装官方 CN App".into()
        })
}

fn machine_id_at(path: &Path) -> Result<String, String> {
    let mut machine_id = String::new();
    atomic_write::update_string_atomic(path, |previous| {
        machine_id = match previous {
            Some(value) => Uuid::parse_str(value.trim())
                .map_err(|_| "Qoder CN 活动机器 ID 格式无效，请检查本地活动身份文件".to_string())?,
            None => Uuid::new_v4(),
        }
        .to_string();
        Ok(machine_id.clone())
    })?;
    Ok(machine_id)
}

fn machine_hostname(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Qoder CN 活动无法读取本机主机名".into());
    }
    // 请求头只接受 ASCII。保留普通主机名；其他名称使用稳定摘要，避免静默丢失此字段。
    if value.len() <= 96 && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Ok(value.into());
    }
    Ok(format!("qoder-{:x}", Sha256::digest(value.as_bytes()))[..30].to_string())
}

fn parse_identity(body: &[u8]) -> Result<NativeIdentity, String> {
    let mut identity: NativeIdentity = serde_json::from_slice(body)
        .map_err(|_| "Qoder CN 设备身份工具响应格式无效".to_string())?;
    for value in [
        &mut identity.machine_token,
        &mut identity.machine_type,
        &mut identity.machine_code,
    ] {
        *value = value.trim().to_string();
        if value.is_empty()
            || value.len() > 4096
            || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err("Qoder CN 设备身份工具返回了无效的设备标识".into());
        }
    }
    Ok(identity)
}

async fn run_bridge(
    executable: &Path,
    uid: &str,
    timeout: Duration,
) -> Result<NativeIdentity, String> {
    if uid.trim().is_empty() || uid.len() > 512 {
        return Err("Qoder CN 设备身份请求缺少有效用户 ID".into());
    }
    let mut command = tokio::process::Command::new(executable);
    command
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        command.arg("--account-stdin").stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000);
    let mut child = command
        .spawn()
        .map_err(|_| "无法启动 Qoder CN 设备身份工具".to_string())?;
    let task = async {
        if let Some(mut stdin) = child.stdin.take() {
            let account = serde_json::to_vec(&serde_json::json!({ "account": uid }))
                .map_err(|_| "无法准备 Qoder CN 设备身份请求".to_string())?;
            stdin
                .write_all(&account)
                .await
                .map_err(|_| "写入 Qoder CN 设备身份请求失败".to_string())?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|_| "写入 Qoder CN 设备身份请求失败".to_string())?;
        }
        let mut body = Vec::new();
        child
            .stdout
            .take()
            .ok_or("Qoder CN 设备身份工具输出不可用")?
            .take(MAX_BRIDGE_OUTPUT + 1)
            .read_to_end(&mut body)
            .await
            .map_err(|_| "读取 Qoder CN 设备身份失败".to_string())?;
        if body.len() as u64 > MAX_BRIDGE_OUTPUT {
            return Err("Qoder CN 设备身份响应超过大小限制".into());
        }
        let status = child
            .wait()
            .await
            .map_err(|_| "等待 Qoder CN 设备身份工具失败".to_string())?;
        if !status.success() {
            return Err("Qoder CN 设备身份工具运行失败".into());
        }
        parse_identity(&body)
    };
    tokio::time::timeout(timeout, task)
        .await
        .map_err(|_| "Qoder CN 设备身份获取超时".to_string())?
}

pub(super) fn machine_id() -> Result<String, String> {
    machine_id_at(&account::get_data_dir()?.join(MACHINE_ID_FILE))
}

pub(super) async fn acquire(uid: &str) -> QoderMachineInfo {
    let machine_id = machine_id();
    let native = async {
        let executable = runtime_executable()?;
        run_bridge(&executable, uid, BRIDGE_TIMEOUT).await
    }
    .await;
    build_machine_info(machine_id, native)
}

fn build_machine_info(
    machine_id: Result<String, String>,
    native: Result<NativeIdentity, String>,
) -> QoderMachineInfo {
    // 官方 CN 客户端允许设备身份失败后继续请求；保留可用字段，不把工具错误当活动结果。
    let mut info = QoderMachineInfo {
        token: String::new(),
        machine_type: None,
        machine_code: None,
        machine_id: match machine_id {
            Ok(id) => Some(id),
            Err(error) => {
                logger::log_warn(&format!(
                    "[Qoder CN Campaign] 机器 ID 不可用，继续查询服务端活动：{error}"
                ));
                None
            }
        },
        machine_hostname: sysinfo::System::host_name()
            .and_then(|hostname| machine_hostname(&hostname).ok()),
        machine_os: Some(super::super::build_cosy_machine_os()),
        cosy_version: Some(
            super::super::detect_qoder_product_version_for_variant(QoderVariantKind::QoderCnApp)
                .unwrap_or_else(|| CAMPAIGN_CLIENT_VERSION.into()),
        ),
    };
    match native {
        Ok(native) => {
            info.token = native.machine_token;
            info.machine_type = Some(native.machine_type);
            info.machine_code = Some(native.machine_code);
        }
        Err(error) => logger::log_warn(&format!(
            "[Qoder CN Campaign] 官方设备身份不可用，继续查询服务端活动：{error}"
        )),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureDir(PathBuf);
    impl FixtureDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("qoder-cn-identity-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        #[cfg(unix)]
        fn bridge(&self, body: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;
            let path = self.0.join("runtime-info");
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            path
        }
    }
    impl Drop for FixtureDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn packaged_runtime_paths_follow_the_selected_installation() {
        let fixture = FixtureDir::new();
        let bundle = fixture.0.join("Qoder CN.app");
        let expected = bundle.join("Contents/Resources/umid/runtime-info");
        assert_eq!(runtime_candidates(&bundle, "macos"), vec![expected.clone()]);
        assert_eq!(
            runtime_candidates(&bundle.join("Contents/MacOS/Qoder CN"), "macos"),
            vec![expected]
        );
        let windows = fixture.0.join("windows");
        std::fs::create_dir_all(&windows).unwrap();
        let expected = windows.join("resources/umid/runtime-info.exe");
        assert_eq!(
            runtime_candidates(&windows, "windows"),
            vec![expected.clone()]
        );
        assert_eq!(
            runtime_candidates(&windows.join("Qoder CN.exe"), "windows"),
            vec![expected]
        );
        let linux = fixture.0.join("linux");
        std::fs::create_dir_all(&linux).unwrap();
        assert_eq!(
            runtime_candidates(&linux.join("qoder-cn"), "linux"),
            vec![linux.join("resources/umid/runtime-info")]
        );
    }

    #[test]
    fn own_machine_id_is_stable_and_corruption_is_not_replaced() {
        let fixture = FixtureDir::new();
        let path = fixture.0.join(MACHINE_ID_FILE);
        let first = machine_id_at(&path).unwrap();
        assert_eq!(Uuid::parse_str(&first).unwrap().get_version_num(), 4);
        assert_eq!(machine_id_at(&path).unwrap(), first);
        std::fs::write(&path, "corrupt-fixture").unwrap();
        assert!(machine_id_at(&path).unwrap_err().contains("格式无效"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "corrupt-fixture");
    }

    #[test]
    fn incomplete_or_unsafe_native_identity_is_an_error() {
        for body in [
            r#"{}"#,
            r#"{"machineToken":"fixture"}"#,
            r#"{"machineToken":"","machineType":"fixture","machineCode":"fixture"}"#,
            r#"{"machineToken":"fixture\r\nX-Test: value","machineType":"fixture","machineCode":"fixture"}"#,
            "fixture-private-invalid-output",
        ] {
            let error = parse_identity(body.as_bytes())
                .err()
                .expect("invalid native output must fail");
            assert!(!error.contains("fixture-private-invalid-output"));
        }
        let identity = parse_identity(br#"{"machineToken":"fixture-token","machineType":"fixture-type","machineCode":"fixture-code"}"#).unwrap();
        assert_eq!(identity.machine_token, "fixture-token");
        assert_eq!(identity.machine_type, "fixture-type");
        assert_eq!(identity.machine_code, "fixture-code");
    }

    #[test]
    fn hostnames_always_form_a_stable_header_value() {
        for hostname in ["fixture-host", "我的 Mac", &"fixture-host".repeat(20)] {
            let normalized = machine_hostname(hostname).unwrap();
            assert_eq!(machine_hostname(hostname).unwrap(), normalized);
            assert!(normalized.len() <= 96);
            assert!(reqwest::header::HeaderValue::from_str(&normalized).is_ok());
        }
        assert_eq!(machine_hostname(" fixture-host ").unwrap(), "fixture-host");
        assert!(machine_hostname(" ").is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_bridge_uses_cn_environment_and_accounts_over_stdin() {
        let fixture = FixtureDir::new();
        let account_check = if cfg!(target_os = "macos") {
            "[ \"$#\" = 2 ] && [ \"$2\" = --account-stdin ] || exit 62\nIFS= read -r account\n[ \"$account\" = '{\"account\":\"fixture-cn-user\"}' ] || exit 63"
        } else {
            "[ \"$#\" = 1 ] || exit 62"
        };
        let executable = fixture.bridge(&format!(
            "[ \"$1\" = 0 ] || exit 61\n{account_check}\nprintf '%s' '{{\"machineToken\":\"fixture-token\",\"machineType\":\"fixture-type\",\"machineCode\":\"fixture-code\"}}'"
        ));
        let identity = run_bridge(&executable, "fixture-cn-user", BRIDGE_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(identity.machine_token, "fixture-token");
        assert_eq!(identity.machine_type, "fixture-type");
        assert_eq!(identity.machine_code, "fixture-code");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_oversized_and_timed_out_bridges_never_become_an_empty_identity() {
        let fixture = FixtureDir::new();
        let executable =
            fixture.bridge("echo fixture-private-output; echo fixture-private-error >&2; exit 7");
        let error = run_bridge(&executable, "fixture-cn-user", BRIDGE_TIMEOUT)
            .await
            .err()
            .unwrap();
        assert!(error.contains("运行失败"));
        assert!(!error.contains("fixture-private"));
        let executable = fixture.bridge("head -c 65537 /dev/zero");
        assert!(run_bridge(&executable, "fixture-cn-user", BRIDGE_TIMEOUT)
            .await
            .err()
            .unwrap()
            .contains("大小限制"));
        let executable = fixture.bridge("exec sleep 30");
        let started = std::time::Instant::now();
        assert!(
            run_bridge(&executable, "fixture-cn-user", Duration::from_millis(100))
                .await
                .err()
                .unwrap()
                .contains("超时")
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn missing_or_failed_cn_tool_keeps_campaign_requests_usable() {
        let fixture = FixtureDir::new();
        let id = machine_id_at(&fixture.0.join(MACHINE_ID_FILE)).unwrap();
        let failed = fixture.bridge("exit 7");
        for executable in [fixture.0.join("missing-runtime-info"), failed] {
            let native = run_bridge(&executable, "fixture-cn-user", BRIDGE_TIMEOUT).await;
            assert!(native.is_err());
            let info = build_machine_info(Ok(id.clone()), native);
            let headers =
                crate::modules::qoder_oauth::build_qoder_claim_headers("dt-fixture", &info);
            assert_eq!(headers["authorization"], "Bearer dt-fixture");
            assert_eq!(headers["cosy-clienttype"], "10");
            assert_eq!(headers["cosy-machineid"], id);
            assert!(headers.contains_key("cosy-version"));
            assert!(headers.contains_key("cosy-machineos"));
            for field in ["cosy-machinetoken", "cosy-machinetype", "cosy-machinecode"] {
                assert!(
                    !headers.contains_key(field),
                    "unavailable device data must be omitted"
                );
            }
        }
        assert_eq!(machine_id_at(&fixture.0.join(MACHINE_ID_FILE)).unwrap(), id);
    }

    #[test]
    fn corrupt_cn_machine_id_does_not_block_campaigns_or_overwrite_local_identity() {
        let fixture = FixtureDir::new();
        let path = fixture.0.join(MACHINE_ID_FILE);
        std::fs::write(&path, "corrupt-fixture").unwrap();
        let info = build_machine_info(machine_id_at(&path), Err("fixture tool unavailable".into()));
        let headers = crate::modules::qoder_oauth::build_qoder_claim_headers("dt-fixture", &info);
        assert_eq!(headers["cosy-clienttype"], "10");
        assert!(headers.contains_key("cosy-version"));
        assert!(headers.contains_key("cosy-machineos"));
        assert!(!headers.contains_key("cosy-machineid"));
        assert!(!headers.contains_key("cosy-machinetoken"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "corrupt-fixture");
    }

    #[tokio::test]
    async fn invalid_account_does_not_start_the_bridge() {
        for uid in [" ", &"x".repeat(513)] {
            let error = run_bridge(Path::new("missing-fixture-binary"), uid, BRIDGE_TIMEOUT)
                .await
                .err()
                .unwrap();
            assert!(error.contains("有效用户 ID"));
        }
    }
}
