// Qoder 四变体平台路径表：按变体给出安装目录、数据目录与可执行探测链。
// 未配置的条目留空可配（空表 → 描述性 Err，永不 panic、永不猜测硬编码）。

use std::path::{Path, PathBuf};

use crate::modules::qoder_variant::{all_qoder_variant_kinds, QoderVariantKind};

/// 单变体平台路径表。切片为空 = 该 OS 该类路径无可用配置，调用方必须返回描述性错误。
#[derive(Debug, Clone, Copy)]
pub struct QoderPlatformPaths {
    pub kind: QoderVariantKind,
    /// macOS 应用包名（/Applications 下）。
    pub macos_app_bundle: &'static str,
    pub macos_bundle_id: &'static str,
    /// Contents/MacOS 下主程序名（首选；Electron 为回退）。
    pub macos_app_binaries: &'static [&'static str],
    /// userData 叶名（Win/Linux 数据目录沿用同一叶）。
    pub data_leaf: &'static str,
    /// Windows 安装目录名（%LOCALAPPDATA%\Programs + %ProgramFiles% 下）。
    pub windows_dirs: &'static [&'static str],
    /// Windows 运行中的主进程文件名。
    pub windows_exes: &'static [&'static str],
    /// Windows 启动入口候选。App 变体使用安装器创建的 Launcher，IDE 变体直接使用主程序。
    pub windows_launch_exes: &'static [&'static str],
    /// Linux 安装探测（绝对路径表；`~` 前缀表示相对 $HOME，调用方展开）。
    pub linux_install_probes: &'static [&'static str],
}

pub fn qoder_platform_table(kind: QoderVariantKind) -> QoderPlatformPaths {
    match kind {
        QoderVariantKind::Qoder => QoderPlatformPaths {
            kind,
            // 当前 IDE 包名。
            macos_app_bundle: "Qoder IDE.app",
            macos_bundle_id: "com.qoder.ide",
            // 主程序首选 `Qoder`，其余为回退。
            macos_app_binaries: &["Qoder", "Qoder IDE", "Electron"],
            // 数据叶沿用旧槽位名。
            data_leaf: "Qoder",
            windows_dirs: &["Qoder IDE"],
            windows_exes: &["Qoder IDE.exe"],
            windows_launch_exes: &["Qoder IDE.exe"],
            linux_install_probes: &[
                // 官方包 `qoder-ide`。
                "/usr/share/qoder-ide/qoder-ide",
                // kebab 与 spaced 两种命名都探。
                "/usr/bin/qoder-ide",
                "/usr/local/bin/qoder-ide",
                "/opt/qoder-ide/qoder-ide",
                "/opt/Qoder IDE",
            ],
        },
        QoderVariantKind::QoderApp => QoderPlatformPaths {
            kind,
            // 官方 App 包。
            macos_app_bundle: "Qoder.app",
            macos_bundle_id: "com.qoder.app",
            macos_app_binaries: &["Qoder", "Electron"],
            // 数据叶为 bundle id 形。
            data_leaf: "com.qoder.app.stable",
            windows_dirs: &["Qoder"],
            windows_exes: &["Qoder.exe"],
            windows_launch_exes: &["Qoder Launcher.exe"],
            linux_install_probes: &[
                // kebab 与 spaced 两种命名都探。
                "/usr/bin/qoder",
                "/usr/local/bin/qoder",
                "/opt/qoder/qoder",
                "/opt/Qoder",
                "/usr/share/qoder",
            ],
        },
        QoderVariantKind::QoderCnIde => QoderPlatformPaths {
            kind,
            // 当前 CN IDE 包名。
            macos_app_bundle: "Qoder CN IDE.app",
            macos_bundle_id: "com.aliyun.lingma.ide",
            // 主程序 `Qoder CN`，Electron 为备用入口。
            macos_app_binaries: &["Qoder CN", "Electron"],
            data_leaf: "QoderCN",
            windows_dirs: &["Qoder CN IDE"],
            windows_exes: &["Qoder CN IDE.exe"],
            windows_launch_exes: &["Qoder CN IDE.exe"],
            linux_install_probes: &[
                // 新包 `qoder-cn-ide`。
                "/usr/share/qoder-cn-ide/qoder-cn-ide",
                // kebab 与 spaced 两种命名都探。
                "/usr/bin/qoder-cn-ide",
                "/usr/local/bin/qoder-cn-ide",
                "/opt/qoder-cn-ide/qoder-cn-ide",
                "/opt/Qoder CN IDE",
            ],
        },
        QoderVariantKind::QoderCnApp => QoderPlatformPaths {
            kind,
            // 独立 App 包。
            macos_app_bundle: "Qoder CN.app",
            macos_bundle_id: "com.qodercn.app",
            macos_app_binaries: &["Qoder CN", "Electron"],
            data_leaf: "com.qodercn.app.stable",
            windows_dirs: &["Qoder CN"],
            windows_exes: &["Qoder CN.exe"],
            windows_launch_exes: &["Qoder CN Launcher.exe"],
            linux_install_probes: &[
                // CN App 当前包名 `qoder-cn`。
                "/usr/share/qoder-cn/qoder-cn",
                // kebab 与 spaced 两种命名都探。
                "/usr/bin/qoder-cn",
                "/usr/local/bin/qoder-cn",
                "/opt/qoder-cn/qoder-cn",
                "/opt/Qoder CN",
            ],
        },
    }
}

/// Windows 候选既要有该变体的程序名，也不能位于另一变体的安装目录。
pub fn windows_candidate_matches_variant(kind: QoderVariantKind, path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    let Some(file_name) = parts.last() else {
        return false;
    };
    let table = qoder_platform_table(kind);
    let expected_exe = table
        .windows_exes
        .iter()
        .chain(table.windows_launch_exes.iter())
        .any(|name| file_name.eq_ignore_ascii_case(name));
    if !expected_exe {
        return false;
    }
    !all_qoder_variant_kinds()
        .into_iter()
        .filter(|other| *other != kind)
        .any(|other| {
            qoder_platform_table(other).windows_dirs.iter().any(|dir| {
                parts[..parts.len() - 1]
                    .iter()
                    .any(|part| part.eq_ignore_ascii_case(dir))
            })
        })
}

/// Linux 自定义路径只接受该变体已知的程序名，并排除其他变体安装目录。
pub fn linux_candidate_matches_variant(kind: QoderVariantKind, path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let table = qoder_platform_table(kind);
    let matches_name = table.linux_install_probes.iter().any(|probe| {
        Path::new(probe)
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| file_name.eq_ignore_ascii_case(name))
    });
    if !matches_name {
        return false;
    }
    // 只排除已知安装目录；用户自行命名的父目录不能作为另一变体的证据。
    !all_qoder_variant_kinds()
        .into_iter()
        .filter(|other| *other != kind)
        .any(|other| {
            let other_table = qoder_platform_table(other);
            other_table.linux_install_probes.iter().any(|probe| {
                Path::new(probe)
                    .parent()
                    .is_some_and(|parent| {
                        parent.file_name().and_then(|name| name.to_str())
                            .is_some_and(|dir| dir.starts_with("qoder"))
                            && path.starts_with(parent)
                    })
            })
        })
}

fn empty_table_error(kind: QoderVariantKind, what: &str) -> String {
    format!(
        "Qoder 变体 {} 在{}缺少可配置的安装路径（empty-configurable）：请在设置中手动指定安装路径",
        kind.provider_key(),
        what
    )
}

/// macOS 可执行候选（/Applications 包 + Contents/MacOS 主程序链），纯函数。
pub fn macos_exec_candidates(kind: QoderVariantKind) -> Vec<PathBuf> {
    let table = qoder_platform_table(kind);
    let mut out = Vec::new();
    let root = PathBuf::from("/Applications").join(table.macos_app_bundle);
    out.push(root.clone());
    for binary in table.macos_app_binaries {
        out.push(root.join("Contents").join("MacOS").join(binary));
    }
    out
}

/// macOS userData 目录，纯函数（home 由调用方传入，便于单测）。
pub fn macos_data_dir_with_home(kind: QoderVariantKind, home: &Path) -> PathBuf {
    let table = qoder_platform_table(kind);
    home.join("Library/Application Support")
        .join(table.data_leaf)
}

/// Windows 安装候选：%LOCALAPPDATA%\Programs\{Dir}\{Exe} + %ProgramFiles%\{Dir}[\{Exe}]。
/// 纯函数（roots 由调用方传入；None = 环境变量缺失）。空表或双 root 缺失 → Err。
pub fn windows_install_candidates_with_roots(
    kind: QoderVariantKind,
    local_appdata: Option<&str>,
    program_files: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    let table = qoder_platform_table(kind);
    windows_candidates_for_table(
        &table,
        local_appdata,
        program_files,
        table.windows_exes,
    )
}

/// 表驱动的 Windows 安装候选解析（空表 → empty-configurable Err；单测可直传空表）。
pub fn windows_install_candidates_for_table(
    table: &QoderPlatformPaths,
    local_appdata: Option<&str>,
    program_files: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    windows_candidates_for_table(
        table,
        local_appdata,
        program_files,
        table.windows_exes,
    )
}

/// Windows 启动入口候选（App 变体使用 Launcher，IDE 变体使用主程序）。
pub fn windows_launch_candidates_with_roots(
    kind: QoderVariantKind,
    local_appdata: Option<&str>,
    program_files: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    let table = qoder_platform_table(kind);
    windows_candidates_for_table(
        &table,
        local_appdata,
        program_files,
        table.windows_launch_exes,
    )
}

fn windows_candidates_for_table(
    table: &QoderPlatformPaths,
    local_appdata: Option<&str>,
    program_files: Option<&str>,
    executables: &[&str],
) -> Result<Vec<PathBuf>, String> {
    let kind = table.kind;
    if table.windows_dirs.is_empty() || executables.is_empty() {
        return Err(empty_table_error(kind, " Windows 安装路径"));
    }
    let local = local_appdata.map(str::trim).filter(|v| !v.is_empty());
    let pf = program_files.map(str::trim).filter(|v| !v.is_empty());
    if local.is_none() && pf.is_none() {
        return Err(format!(
            "Qoder 变体 {} 缺少 LOCALAPPDATA/ProgramFiles 环境变量，无法解析 Windows 安装路径",
            kind.provider_key()
        ));
    }
    let mut out = Vec::new();
    if let Some(root) = local {
        for dir in table.windows_dirs {
            for exe in executables {
                out.push(PathBuf::from(root).join("Programs").join(dir).join(exe));
            }
            out.push(PathBuf::from(root).join("Programs").join(dir));
        }
    }
    if let Some(root) = pf {
        for dir in table.windows_dirs {
            for exe in executables {
                out.push(PathBuf::from(root).join(dir).join(exe));
            }
            out.push(PathBuf::from(root).join(dir));
        }
    }
    Ok(out)
}

/// Windows 数据目录：%APPDATA%\{leaf}（按变体参数化）。纯函数。
pub fn windows_data_dir_with_appdata(
    kind: QoderVariantKind,
    appdata: Option<&str>,
) -> Result<PathBuf, String> {
    let table = qoder_platform_table(kind);
    let root = appdata
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!(
                "Qoder 变体 {} 缺少 APPDATA 环境变量，无法解析 Windows 数据目录",
                kind.provider_key()
            )
        })?;
    Ok(PathBuf::from(root).join(table.data_leaf))
}

/// Linux 安装候选（`~` 前缀相对 $HOME 展开）。空表 → Err。纯函数。
pub fn linux_install_candidates_with_home(
    kind: QoderVariantKind,
    home: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    linux_install_candidates_for_table(&qoder_platform_table(kind), home)
}

/// 表驱动的 Linux 安装候选解析（空表 → empty-configurable Err；单测可直传空表）。
pub fn linux_install_candidates_for_table(
    table: &QoderPlatformPaths,
    home: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    let kind = table.kind;
    if table.linux_install_probes.is_empty() {
        return Err(empty_table_error(kind, " Linux 安装路径"));
    }
    let mut out = Vec::new();
    for probe in table.linux_install_probes {
        if let Some(rest) = probe.strip_prefix("~/") {
            if let Some(h) = home.map(str::trim).filter(|v| !v.is_empty()) {
                out.push(PathBuf::from(h).join(rest));
            }
            continue;
        }
        out.push(PathBuf::from(probe));
    }
    Ok(out)
}

/// Linux 数据目录：~/.config/{leaf}（绝非 .local/share，后者仅用于安装探测）。
/// 纯函数。
pub fn linux_data_dir_with_home(
    kind: QoderVariantKind,
    home: Option<&str>,
) -> Result<PathBuf, String> {
    let table = qoder_platform_table(kind);
    let h = home
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!(
                "Qoder 变体 {} 缺少 HOME，无法解析 Linux 数据目录",
                kind.provider_key()
            )
        })?;
    Ok(PathBuf::from(h).join(".config").join(table.data_leaf))
}

// ---- 运行期薄封装（读真实环境；单测走上方纯函数，跨 OS 可测） ----

pub fn windows_install_candidates(kind: QoderVariantKind) -> Result<Vec<PathBuf>, String> {
    windows_install_candidates_with_roots(
        kind,
        std::env::var("LOCALAPPDATA").ok().as_deref(),
        std::env::var("ProgramFiles").ok().as_deref(),
    )
}

pub fn windows_launch_candidates(kind: QoderVariantKind) -> Result<Vec<PathBuf>, String> {
    windows_launch_candidates_with_roots(
        kind,
        std::env::var("LOCALAPPDATA").ok().as_deref(),
        std::env::var("ProgramFiles").ok().as_deref(),
    )
}

pub fn windows_data_dir(kind: QoderVariantKind) -> Result<PathBuf, String> {
    windows_data_dir_with_appdata(kind, std::env::var("APPDATA").ok().as_deref())
}

pub fn linux_install_candidates(kind: QoderVariantKind) -> Result<Vec<PathBuf>, String> {
    let table = qoder_platform_table(kind);
    if table.linux_install_probes.is_empty() {
        return Err(empty_table_error(kind, " Linux 安装路径"));
    }
    let mut out = Vec::new();
    for probe in table.linux_install_probes {
        if let Some(rest) = probe.strip_prefix("~/") {
            if let Some(h) = dirs::home_dir() {
                out.push(h.join(rest));
            }
            continue;
        }
        out.push(PathBuf::from(probe));
    }
    Ok(out)
}

pub fn linux_data_dir(kind: QoderVariantKind) -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| {
        format!(
            "Qoder 变体 {} 缺少 HOME，无法解析 Linux 数据目录",
            kind.provider_key()
        )
    })?;
    Ok(home
        .join(".config")
        .join(qoder_platform_table(kind).data_leaf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::qoder_variant::QoderVariantKind;

    #[test]
    fn qoder_variant_custom_paths_reject_cross_variant_executables() {
        assert!(windows_candidate_matches_variant(
            QoderVariantKind::QoderApp,
            Path::new(r"C:\Apps\Qoder\Qoder Launcher.exe"),
        ));
        assert!(!windows_candidate_matches_variant(
            QoderVariantKind::QoderApp,
            Path::new(r"C:\Apps\Qoder CN IDE\Qoder Launcher.exe"),
        ));
        assert!(!windows_candidate_matches_variant(
            QoderVariantKind::QoderApp,
            Path::new(r"C:\Apps\Qoder CN\Qoder CN Launcher.exe"),
        ));
        assert!(linux_candidate_matches_variant(
            QoderVariantKind::QoderCnIde,
            Path::new("/custom/qoder-cn-ide"),
        ));
        assert!(linux_candidate_matches_variant(
            QoderVariantKind::Qoder,
            Path::new("/home/user/apps/qoder/qoder-ide"),
        ));
        assert!(!linux_candidate_matches_variant(
            QoderVariantKind::QoderApp,
            Path::new("/custom/qoder-cn-ide"),
        ));
        assert!(!linux_candidate_matches_variant(
            QoderVariantKind::QoderApp,
            Path::new("/opt/qoder-cn/qoder"),
        ));
    }

    fn all_kinds() -> [QoderVariantKind; 4] {
        [
            QoderVariantKind::Qoder,
            QoderVariantKind::QoderApp,
            QoderVariantKind::QoderCnIde,
            QoderVariantKind::QoderCnApp,
        ]
    }

    #[test]
    fn qoder_platform_table_parses_all_four_keys() {
        for key in ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"] {
            let kind = QoderVariantKind::parse(Some(key)).expect("parse variant key");
            let table = qoder_platform_table(kind);
            assert_eq!(table.kind, kind);
            assert!(!table.macos_app_bundle.is_empty());
            assert!(!table.macos_bundle_id.is_empty());
            assert!(!table.macos_app_binaries.is_empty());
            assert!(!table.data_leaf.is_empty());
            println!("platform table {key} -> bundle={}", table.macos_app_bundle);
        }
    }

    #[test]
    fn qoder_platform_macos_bundles_and_data_leaves() {
        let cases = [
            (QoderVariantKind::Qoder, "Qoder IDE.app", "Qoder"),
            (
                QoderVariantKind::QoderApp,
                "Qoder.app",
                "com.qoder.app.stable",
            ),
            (QoderVariantKind::QoderCnIde, "Qoder CN IDE.app", "QoderCN"),
            (
                QoderVariantKind::QoderCnApp,
                "Qoder CN.app",
                "com.qodercn.app.stable",
            ),
        ];
        for (kind, bundle, leaf) in cases {
            let table = qoder_platform_table(kind);
            assert_eq!(table.macos_app_bundle, bundle);
            assert_eq!(table.data_leaf, leaf);
            let cands = macos_exec_candidates(kind);
            assert!(cands.iter().any(|p| p.to_string_lossy().contains(bundle)));
            let home = Path::new("/Users/test");
            assert_eq!(
                macos_data_dir_with_home(kind, home),
                home.join("Library/Application Support").join(leaf)
            );
        }
    }

    #[test]
    fn qoder_platform_windows_candidates_per_variant() {
        let local = Some("C:\\Users\\u\\AppData\\Local");
        let pf = Some("C:\\Program Files");
        let cases = [
            (
                QoderVariantKind::Qoder,
                "Qoder IDE",
                "Qoder IDE.exe",
                "Qoder IDE.exe",
            ),
            (
                QoderVariantKind::QoderApp,
                "Qoder",
                "Qoder.exe",
                "Qoder Launcher.exe",
            ),
            (
                QoderVariantKind::QoderCnIde,
                "Qoder CN IDE",
                "Qoder CN IDE.exe",
                "Qoder CN IDE.exe",
            ),
            (
                QoderVariantKind::QoderCnApp,
                "Qoder CN",
                "Qoder CN.exe",
                "Qoder CN Launcher.exe",
            ),
        ];
        for (kind, dir, exe_new, launch_exe) in cases {
            let cands = windows_install_candidates_with_roots(kind, local, pf)
                .expect("windows candidates resolve");
            let first = cands
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("|");
            assert!(
                first.contains(dir) && first.contains(exe_new),
                "missing {dir}/{exe_new} in {first}"
            );
            assert!(
                windows_launch_candidates_with_roots(kind, local, pf)
                    .expect("windows launch candidates resolve")
                    .iter()
                    .any(|path| path.to_string_lossy().contains(launch_exe)),
                "missing launch executable {launch_exe}"
            );
            assert!(!qoder_platform_table(kind)
                .windows_exes
                .contains(&"Electron.exe"));
            // ProgramFiles 系（System 版）与 LOCALAPPDATA 系（User 版）双源。
            assert!(first.contains("Program Files"));
            let data = windows_data_dir_with_appdata(kind, Some("C:\\Users\\u\\AppData\\Roaming"))
                .expect("windows data dir");
            assert!(data
                .to_string_lossy()
                .contains(qoder_platform_table(kind).data_leaf));
        }
    }

    #[test]
    fn qoder_platform_linux_probes_kebab_and_spaced() {
        let cases = [
            (
                QoderVariantKind::Qoder,
                "/usr/share/qoder-ide/qoder-ide",
                "/opt/Qoder IDE",
            ),
            (QoderVariantKind::QoderApp, "/usr/bin/qoder", "/opt/Qoder"),
            (
                QoderVariantKind::QoderCnIde,
                "/usr/share/qoder-cn-ide/qoder-cn-ide",
                "/opt/Qoder CN IDE",
            ),
            (
                QoderVariantKind::QoderCnApp,
                "/usr/share/qoder-cn/qoder-cn",
                "/opt/Qoder CN",
            ),
        ];
        for (kind, stated_probe, spaced_probe) in cases {
            let cands = linux_install_candidates_with_home(kind, Some("/home/u"))
                .expect("linux candidates resolve");
            let joined = cands
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect::<Vec<_>>()
                .join("|");
            assert!(joined.contains(stated_probe), "missing {stated_probe}");
            // kebab 与 spaced 两种都探。
            assert!(joined.contains(spaced_probe), "missing {spaced_probe}");
            let data = linux_data_dir_with_home(kind, Some("/home/u")).expect("linux data dir");
            assert_eq!(
                data,
                PathBuf::from("/home/u")
                    .join(".config")
                    .join(qoder_platform_table(kind).data_leaf)
            );
            // 数据目录绝非 .local/share。
            assert!(!data.to_string_lossy().contains(".local/share"));
        }
    }

    #[test]
    fn qoder_platform_empty_configurable_errors_without_panic() {
        let empty = QoderPlatformPaths {
            kind: QoderVariantKind::QoderCnApp,
            macos_app_bundle: "Qoder CN.app",
            macos_bundle_id: "com.qodercn.app",
            macos_app_binaries: &[],
            data_leaf: "com.qodercn.app.stable",
            windows_dirs: &[],
            windows_exes: &[],
            windows_launch_exes: &[],
            linux_install_probes: &[],
        };
        // 空表走真实解析路径：含变体键 + empty-configurable + 非 panic。
        let win_err = windows_install_candidates_for_table(
            &empty,
            Some("C:\\Users\\u\\AppData\\Local"),
            Some("C:\\Program Files"),
        )
        .expect_err("empty windows table must error");
        assert!(win_err.contains("qoder_cn_app"));
        assert!(win_err.contains("empty-configurable"));
        let lin_err = linux_install_candidates_for_table(&empty, Some("/home/u"))
            .expect_err("empty linux table must error");
        assert!(lin_err.contains("qoder_cn_app"));
        assert!(lin_err.contains("empty-configurable"));
        // 环境缺失同样是描述性错误而非 panic。
        assert!(
            windows_install_candidates_with_roots(QoderVariantKind::Qoder, None, None)
                .expect_err("missing roots must error")
                .contains("LOCALAPPDATA")
        );
        assert!(windows_data_dir_with_appdata(QoderVariantKind::Qoder, None)
            .expect_err("missing APPDATA must error")
            .contains("APPDATA"));
        assert!(linux_data_dir_with_home(QoderVariantKind::Qoder, None)
            .expect_err("missing HOME must error")
            .contains("HOME"));
    }

    #[test]
    fn qoder_platform_home_quirk_expands_only_with_home() {
        // `~/.local/share/Qoder` 带 `~/` 前缀：有 HOME 才展开，无 HOME 则跳过（不报错）。
        let custom_table = QoderPlatformPaths {
            linux_install_probes: &["~/.local/share/Qoder", "/opt/qoder"],
            ..qoder_platform_table(QoderVariantKind::Qoder)
        };
        let with = linux_install_candidates_for_table(&custom_table, Some("/home/u"))
            .expect("resolve");
        assert!(with
            .iter()
            .any(|p| p == &PathBuf::from("/home/u/.local/share/Qoder")));
        let without =
            linux_install_candidates_for_table(&custom_table, None).expect("resolve");
        assert!(!without
            .iter()
            .any(|p| p.to_string_lossy().contains(".local")));
    }

    #[test]
    fn qoder_platform_all_variants_have_nonempty_tables() {
        // 当前四变体均有非空条目：锁定“无静默空表”；
        // 未来新增无可用配置的变体时应改为空表 + Err 覆盖。
        for kind in all_kinds() {
            let t = qoder_platform_table(kind);
            assert!(!t.windows_dirs.is_empty(), "{:?} windows_dirs", kind);
            assert!(!t.windows_exes.is_empty(), "{:?} windows_exes", kind);
            assert!(
                !t.windows_launch_exes.is_empty(),
                "{:?} windows_launch_exes",
                kind
            );
            assert!(!t.linux_install_probes.is_empty(), "{:?} probes", kind);
        }
    }
}
