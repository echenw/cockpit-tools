// Process 模块测试：平台路径、Codex 启动参数和进程清理行为。
// 保持测试模块位于原作用域，super 引用和 cfg 条件不变。
#[cfg(test)]
mod codex_native_probe_policy_tests {
    use super::{complete_native_codex_entries_or_probe, fresh_codex_entries_or_probe};

    #[test]
    fn complete_native_snapshot_including_no_client_avoids_powershell() {
        for entries in [vec![], vec![(10, None), (20, Some("managed".into()))]] {
            let actual = complete_native_codex_entries_or_probe(entries.clone(), true, || {
                panic!("a complete native snapshot must not start PowerShell")
            });
            assert_eq!(actual, entries);
        }
    }

    #[test]
    fn incomplete_snapshot_recovers_missing_instances_and_managed_identity() {
        let native = vec![(20, None)];
        let actual = complete_native_codex_entries_or_probe(native, false, || {
            vec![(10, None), (20, Some("managed".into()))]
        });
        assert_eq!(actual, vec![(10, None), (20, Some("managed".into()))]);
    }

    #[test]
    fn failed_fallback_keeps_readable_native_instances() {
        let native = vec![(20, Some("managed".into()))];
        let actual = complete_native_codex_entries_or_probe(native.clone(), false, Vec::new);
        assert_eq!(actual, native);
    }

    #[test]
    fn stopping_requires_fresh_identity_and_never_treats_probe_failure_as_exit() {
        let error = fresh_codex_entries_or_probe(vec![(20, None)], false, || None).unwrap_err();
        assert_eq!(error, "CODEX_PROCESS_PROBE_FAILED");
        let result = fresh_codex_entries_or_probe(Vec::new(), true, || {
            panic!("confirmed absence needs no fallback")
        })
        .unwrap();
        assert!(result.is_empty());
    }
}

#[cfg(all(test, target_os = "windows"))]
mod codex_local_probe_diagnostics {
    #[test]
    #[ignore = "read-only local diagnostic; set COCKPIT_CODEX_PROBE_EXPECTED_EXE explicitly"]
    fn native_snapshot_matches_local_powershell_without_launching_or_stopping_clients() {
        let expected = std::env::var("COCKPIT_CODEX_PROBE_EXPECTED_EXE")
            .expect("explicit local Codex executable path required");
        let started = std::time::Instant::now();
        let (native, complete) = super::collect_codex_process_snapshot_from_sysinfo(&expected);
        let native_ms = started.elapsed().as_millis();
        let ps_started = std::time::Instant::now();
        let fallback = super::collect_codex_process_entries_from_powershell(&expected);
        println!("native_ms={native_ms}, native_complete={complete}, native_count={}, powershell_ms={}, powershell_count={}",
            native.len(), ps_started.elapsed().as_millis(), fallback.len());
        let normalize = |entries: Vec<(u32, Option<String>)>| {
            entries
                .into_iter()
                .map(|(pid, dir)| (pid, dir.map(|dir| super::normalize_path_for_compare(&dir))))
                .collect::<Vec<_>>()
        };
        let native = normalize(native);
        let fallback = normalize(fallback);
        if complete {
            assert_eq!(
                native, fallback,
                "native identities must preserve default/managed ownership"
            );
        } else {
            for entry in native {
                assert!(fallback.contains(&entry));
            }
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_powershell_probe_regression_tests {
    use super::powershell_output_with_timeout;
    use std::time::{Duration, Instant};

    #[test]
    fn drains_stdout_and_stderr_larger_than_pipe_capacity() {
        // Real PowerShell and OS pipes: the old wait-before-read loop times out
        // on this output even though the script does not perform slow work.
        let output = powershell_output_with_timeout(
            &[
                "-Command",
                "[Console]::Out.Write(('o' * 200000)); [Console]::Error.Write(('e' * 200000))",
            ],
            Duration::from_secs(10),
        )
        .expect("large probe output must not deadlock");
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![b'o'; 200000]);
        assert_eq!(output.stderr, vec![b'e'; 200000]);
    }

    #[test]
    fn slow_probe_still_times_out() {
        let started = Instant::now();
        let error = powershell_output_with_timeout(
            &["-Command", "Start-Sleep -Seconds 30"],
            Duration::from_millis(500),
        )
        .expect_err("unresponsive probes must remain bounded");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn preserves_failed_probe_status_and_diagnostics() {
        let output = powershell_output_with_timeout(
            &[
                "-Command",
                "[Console]::Error.Write('probe failed'); exit 17",
            ],
            Duration::from_secs(10),
        )
        .expect("nonzero exit is a completed probe, not a spawn error");
        assert_eq!(output.status.code(), Some(17));
        assert_eq!(output.stderr, b"probe failed");
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_passive_exec_scan_tests {
    use super::{
        build_windows_exec_path_scan_script, parse_windows_exec_candidates, powershell_quote,
        WINDOWS_EXEC_CANDIDATE_FUNCTIONS,
    };
    use std::process::Command;

    fn run_scan_script(script: &str) -> std::process::Output {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", script]);
        command.creation_flags(super::CREATE_NO_WINDOW);
        crate::modules::process_timeout::output_with_timeout(
            &mut command,
            std::time::Duration::from_secs(10),
        )
        .expect("PowerShell scan must finish within its timeout")
    }

    #[test]
    fn stopped_wsl_shortcut_target_is_skipped_before_existence_check() {
        let script = format!(
            r#"$visited = @()
$global:wslQueries = 0

function Test-Path([string]$LiteralPath) {{
  $script:visited += "VISIT:$LiteralPath"
  return $true
}}
{WINDOWS_EXEC_CANDIDATE_FUNCTIONS}
function Get-RunningWslNames {{ $global:wslQueries++; return @{{ Success = $true; Names = @() }} }}
Emit-Candidate '\\wsl.localhost\Ubuntu-22.04\home\demo\Antigravity IDE.exe'
Emit-Candidate '\\WSL$\Ubuntu-22.04\Antigravity IDE.exe'
Emit-Candidate '\\?\UNC\wsl.localhost\Ubuntu-22.04\Antigravity IDE.exe'
Emit-Candidate '\\?\unc\WSL$\Ubuntu-22.04\Antigravity IDE.exe'
Emit-Candidate '\\wsl.localhost\Ubuntu-22.04\home\demo\Antigravity IDE.exe'
Emit-Candidate '  '
Emit-Candidate 'C:\Program Files\Antigravity IDE\Antigravity IDE.exe'
Emit-Candidate '\\server\share\Antigravity IDE.exe'
Emit-Candidate '\\wsl.localhost.example\share\Antigravity IDE.exe'
$visited
"WSL_QUERIES:$global:wslQueries"
"#
        );
        let output = run_scan_script(&script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let lines = String::from_utf8_lossy(&output.stdout);
        assert!(!lines.contains(r"VISIT:\\wsl.localhost\"), "{lines}");
        assert!(!lines.contains(r"VISIT:\\WSL$"), "{lines}");
        assert!(!lines.contains(r"VISIT:\\?\"), "{lines}");
        assert!(lines.contains("VISIT:C:\\Program Files"), "{lines}");
        assert!(lines.contains(r"VISIT:\\server\share"), "{lines}");
        assert!(lines.contains(r"VISIT:\\wsl.localhost.example"), "{lines}");
        assert!(lines.contains("WSL_QUERIES:1"), "{lines}");
    }

    #[test]
    fn running_wsl_shortcut_target_is_checked() {
        let script = format!(
            r#"$global:wslQueries = 0
$script:visited = @()

function Test-Path([string]$LiteralPath) {{ $script:visited += "VISIT:$LiteralPath"; return $true }}
{WINDOWS_EXEC_CANDIDATE_FUNCTIONS}
function Get-RunningWslNames {{ $global:wslQueries++; return @{{ Success = $true; Names = @('Ubuntu-22.04') }} }}
Emit-Candidate '\\wsl.localhost\Ubuntu-22.04\Antigravity IDE.exe'
Emit-Candidate '\\WSL$\Other-Distro\Antigravity IDE.exe'
$visited
"WSL_QUERIES:$global:wslQueries"
"#
        );
        let output = run_scan_script(&script);
        assert!(output.status.success());
        let lines = String::from_utf8_lossy(&output.stdout);
        assert!(
            lines.contains(r"VISIT:\\wsl.localhost\Ubuntu-22.04"),
            "{lines}"
        );
        assert!(!lines.contains(r"VISIT:\\WSL$\Other-Distro"), "{lines}");
        assert!(lines.contains("WSL_QUERIES:1"), "{lines}");
    }

    #[test]
    fn failed_wsl_status_query_skips_target() {
        let script = format!(
            r#"
function Test-Path([string]$LiteralPath) {{ Write-Output "VISIT:$LiteralPath"; return $true }}
{WINDOWS_EXEC_CANDIDATE_FUNCTIONS}
function Get-RunningWslNames {{ $global:wslQueries++; return @{{ Success = $false; Names = @('Ubuntu-22.04') }} }}
Emit-Candidate '\\wsl.localhost\Ubuntu-22.04\Antigravity IDE.exe'
"#
        );
        let output = run_scan_script(&script);
        assert!(output.status.success());
        let lines = String::from_utf8_lossy(&output.stdout);
        assert!(!lines.contains("VISIT:"), "{lines}");
    }

    #[test]
    fn shortcut_scan_finishes_without_probing_wsl_target() {
        let scan = build_windows_exec_path_scan_script(
            &["cockpit-regression-ide.exe"],
            &["cockpit-regression-command-not-found"],
            &["cockpit-regression-protocol-not-found"],
            &["cockpit-regression-product-not-found"],
        );
        let root = std::env::temp_dir().join(format!(
            "cockpit-wsl-shortcut-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root_literal = powershell_quote(&root.to_string_lossy());
        let setup = format!(
            r#"$ErrorActionPreference = 'Stop'
$root = {root_literal}
$env:APPDATA = $root
$env:ProgramData = $root
$env:USERPROFILE = $root
$env:PUBLIC = $root
$desktop = Join-Path $root 'Desktop'
[void][System.IO.Directory]::CreateDirectory($desktop)
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $desktop 'wsl.lnk'))
$wslTarget = '\\wsl.localhost\cockpit-regression-missing\cockpit-regression-ide.exe'
$shortcut.TargetPath = $wslTarget
$shortcut.Save()
if (-not [System.IO.File]::Exists((Join-Path $desktop 'wsl.lnk'))) {{ throw 'WSL shortcut was not saved' }}
if ($shell.CreateShortcut((Join-Path $desktop 'wsl.lnk')).TargetPath -ne $wslTarget) {{ throw 'WSL shortcut target changed' }}

function Test-Path([string]$LiteralPath) {{
  Write-Host "VISIT:$LiteralPath"
  return $true
}}
"#
        );
        let stubbed_scan = scan.replace(
            "function Get-RunningWslNames {",
            "function Get-RunningWslNames { return @{ Success = $true; Names = @() };",
        );
        let script = format!("{setup}\n{stubbed_scan}");
        let output = run_scan_script(&script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("STAGE:END"), "{stdout}");
        assert!(!stdout.contains("VISIT:\\\\wsl.localhost"), "{stdout}");
        assert!(
            !stdout
                .lines()
                .any(|line| line.starts_with(r"\\wsl.localhost")),
            "{stdout}"
        );
        assert!(parse_windows_exec_candidates(
            "antigravity",
            &["cockpit-regression-ide.exe"],
            &[],
            output,
            &|_| true,
        )
        .is_none());

        let local_exe = root.join("cockpit-regression-ide.exe");
        std::fs::write(&local_exe, []).unwrap();
        let local_literal = powershell_quote(&local_exe.to_string_lossy());
        let add_local_shortcut = format!(
            r#"$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path {root_literal} 'Desktop\local.lnk'))
$shortcut.TargetPath = {local_literal}
$shortcut.Save()
"#
        );
        let added = run_scan_script(&add_local_shortcut);
        assert!(
            added.status.success(),
            "{}",
            String::from_utf8_lossy(&added.stderr)
        );
        let output = run_scan_script(&script);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let detected = parse_windows_exec_candidates(
            "antigravity",
            &["cockpit-regression-ide.exe"],
            &[],
            output,
            &|_| true,
        );
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(detected.as_deref(), Some(local_exe.as_path()));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod qoder_variant_probe_failure_tests {
    use super::parse_qoder_macos_process_snapshot;
    use crate::modules::qoder_variant::QoderVariantKind;

    #[test]
    fn failing_or_empty_ps_snapshot_is_not_client_exit() {
        let kind = QoderVariantKind::Qoder;
        let expected = "/Applications/Qoder IDE.app";
        let failure = std::process::Command::new("/usr/bin/false").output();
        assert!(parse_qoder_macos_process_snapshot(kind, expected, failure).is_err());
        let permission_denied = Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied, "injected ps denial",
        ));
        assert!(parse_qoder_macos_process_snapshot(kind, expected, permission_denied).is_err());
        let mut empty = std::process::Command::new("/usr/bin/true").output().unwrap();
        empty.stdout.clear();
        assert!(parse_qoder_macos_process_snapshot(kind, expected, Ok(empty)).is_err());
    }

    #[test]
    fn mac_snapshot_matches_only_the_expected_bundle_and_main_process() {
        let kind = QoderVariantKind::Qoder;
        let expected = "/Applications/Qoder IDE.app";
        let mut output = std::process::Command::new("/usr/bin/true").output().unwrap();
        output.stdout = concat!(
            "45 /Applications/Qoder IDE.app/Contents/MacOS/Qoder --user-data-dir=/tmp/managed\n",
            "46 /tmp/Qoder IDE.app/Contents/MacOS/Qoder --user-data-dir=/tmp/other\n",
            "47 /Applications/Qoder IDE.app/Contents/Frameworks/Qoder Helper.app/Contents/MacOS/Qoder Helper --type=renderer\n"
        ).as_bytes().to_vec();
        let entries = parse_qoder_macos_process_snapshot(kind, expected, Ok(output)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, 45);
        assert_eq!(entries[0].1.as_deref(), Some("/tmp/managed"));
    }
}

#[cfg(all(test, unix))]
mod qoder_linux_proc_probe_tests {
    use super::collect_qoder_process_entries_from_proc_root_checked;
    use std::{fs, os::unix::fs::symlink, path::PathBuf};

    fn root() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "qoder-proc-probe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn inaccessible_proc_root_aborts_instead_of_reporting_no_client() {
        let base = root();
        assert!(collect_qoder_process_entries_from_proc_root_checked(
            &base, "/usr/bin/qoder-ide"
        ).is_err());
    }

    #[test]
    fn unreadable_matching_cmdline_and_exe_abort_but_unrelated_processes_do_not() {
        let base = root();
        let candidate = base.join("101");
        let other = base.join("202");
        fs::create_dir_all(&candidate).unwrap();
        fs::create_dir_all(&other).unwrap();
        fs::write(candidate.join("comm"), b"qoder-ide\n").unwrap();
        fs::write(other.join("comm"), b"unrelated\n").unwrap();
        // The candidate's command line cannot be read. The unrelated
        // process also has no readable cmdline and must not block the probe.
        assert!(collect_qoder_process_entries_from_proc_root_checked(
            &base, "/usr/bin/qoder-ide"
        ).unwrap_err().contains("101"));
        fs::write(candidate.join("cmdline"), b"/usr/bin/qoder-ide\0--user-data-dir=/tmp/managed\0").unwrap();
        assert!(collect_qoder_process_entries_from_proc_root_checked(
            &base, "/usr/bin/qoder-ide"
        ).unwrap_err().contains("exe"));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn deleted_qoder_binary_is_not_mistaken_for_a_stopped_client() {
        let base = root();
        let pid_dir = base.join("505");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("comm"), b"qoder-ide\n").unwrap();
        symlink("/opt/qoder-ide (deleted)", pid_dir.join("exe")).unwrap();
        let error = collect_qoder_process_entries_from_proc_root_checked(
            &base, "/usr/bin/qoder-ide"
        ).unwrap_err();
        assert!(error.contains("505"), "{error}");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn readable_matching_process_is_scoped_to_the_correct_executable_and_profile() {
        let base = root();
        let pid_dir = base.join("303");
        fs::create_dir_all(&pid_dir).unwrap();
        let executable = base.join("qoder-ide");
        fs::write(&executable, b"fixture").unwrap();
        fs::write(pid_dir.join("comm"), b"qoder-ide\n").unwrap();
        let cmdline = format!("{}\0--user-data-dir=/tmp/qoder-managed\0", executable.display());
        fs::write(pid_dir.join("cmdline"), cmdline.as_bytes()).unwrap();
        symlink(&executable, pid_dir.join("exe")).unwrap();

        // Another Qoder variant with an unreadable cmdline is unrelated when
        // its kernel-reported executable differs from the selected client.
        let other_dir = base.join("404");
        fs::create_dir_all(&other_dir).unwrap();
        let other_exe = base.join("qoder-cn");
        fs::write(&other_exe, b"fixture").unwrap();
        fs::write(other_dir.join("comm"), b"qoder-cn\n").unwrap();
        symlink(&other_exe, other_dir.join("exe")).unwrap();

        let matches = collect_qoder_process_entries_from_proc_root_checked(&base, &executable.to_string_lossy()).unwrap();
        assert_eq!(matches, vec![(303, Some("/tmp/qoder-managed".to_string()))]);

        // A configured symlink must match its real executable (as /proc does).
        let launch_alias = base.join("qoder-ide-launcher");
        symlink(&executable, &launch_alias).unwrap();
        assert_eq!(
            collect_qoder_process_entries_from_proc_root_checked(&base, &launch_alias.to_string_lossy()).unwrap(),
            matches,
        );

        // A different known executable must not be accepted as this install.
        assert!(collect_qoder_process_entries_from_proc_root_checked(
            &base, "/usr/bin/another-qoder"
        ).unwrap().is_empty());
        fs::remove_dir_all(&base).unwrap();
    }
}

#[cfg(test)]
mod qoder_windows_probe_fail_closed_tests {
    use super::{merge_qoder_windows_process_probes, WindowsElectronProcessProbe};

    fn snapshot(
        entries: Vec<(u32, Option<String>)>,
        unresolved: Vec<u32>,
    ) -> WindowsElectronProcessProbe {
        WindowsElectronProcessProbe {
            entries,
            unresolved_pids: unresolved,
            needs_powershell: false,
        }
    }

    #[test]
    fn unreadable_profile_cannot_be_mistaken_for_default() {
        let native = snapshot(Vec::new(), vec![42]);
        let fallback = snapshot(Vec::new(), vec![42]);
        let err = merge_qoder_windows_process_probes(native, fallback).unwrap_err();
        assert!(err.contains("42"), "{err}");
    }

    #[test]
    fn complete_fallback_recovers_an_unknown_managed_profile() {
        let native = snapshot(Vec::new(), vec![42]);
        let fallback = snapshot(vec![(42, Some("d:/qoder/managed".into()))], Vec::new());
        let merged = merge_qoder_windows_process_probes(native, fallback).unwrap();
        assert_eq!(merged, vec![(42, Some("d:/qoder/managed".into()))]);
    }

    #[test]
    fn confirmed_default_process_stays_matchable_without_user_data_dir() {
        let native = snapshot(vec![(11, None)], Vec::new());
        let fallback = snapshot(Vec::new(), Vec::new());
        let merged = merge_qoder_windows_process_probes(native, fallback).unwrap();
        assert_eq!(merged, vec![(11, None)]);
    }

    #[test]
    fn unresolved_executable_path_must_not_disappear_from_a_successful_empty_probe() {
        let native = snapshot(Vec::new(), vec![73]);
        let fallback = snapshot(Vec::new(), Vec::new());
        assert!(merge_qoder_windows_process_probes(native, fallback).is_err());
    }

    #[test]
    fn verified_native_process_can_cover_a_powershell_profile_read_failure() {
        let native = snapshot(vec![(31, Some("c:/qoder/default".into()))], Vec::new());
        let fallback = snapshot(Vec::new(), vec![31]);
        assert_eq!(
            merge_qoder_windows_process_probes(native, fallback).unwrap(),
            vec![(31, Some("c:/qoder/default".into()))]
        );
    }
}

#[cfg(test)]
mod qoder_close_probe_fail_closed_tests {
    use super::close_managed_instances_common;

    #[test]
    fn failed_initial_process_probe_must_abort_before_shutdown() {
        let target = vec!["/tmp/qoder-fail-closed-profile".to_string()];
        let result = close_managed_instances_common(
            "Qoder Probe Test",
            "closing",
            "empty",
            "not running",
            "Qoder",
            "close failed",
            &target,
            1,
            || Err("process enumeration unavailable".to_string()),
            |_, _| panic!("must not select PIDs after probe failure"),
            |_| panic!("must not retry after initial probe failure"),
            None,
            None,
            None,
        );
        assert_eq!(result.unwrap_err(), "process enumeration unavailable");
    }
}

#[cfg(test)]
mod qoder_app_strict_profile_tests {
    use super::{build_user_data_dir_match_target, resolve_pid_from_entries_by_user_data_dir};

    #[test]
    fn explicit_default_profile_detects_app_when_default_fallback_is_disabled() {
        let default_dir = "/tmp/qoder-app-default";
        // 严格检测禁用隐式默认目录，因此旧的 None 调用无法找到正在运行的 App。
        assert!(build_user_data_dir_match_target(None, Some(default_dir.to_string()), false).is_none());
        let (target, allow_no_dir) = build_user_data_dir_match_target(
            Some(default_dir), Some(default_dir.to_string()), false,
        ).unwrap();
        assert_eq!(resolve_pid_from_entries_by_user_data_dir(
            None, &target, allow_no_dir, &[(123, None)],
        ), Some(123));
    }
}

#[cfg(test)]
mod legacy_platform_adapter_cleanup_tests {
    use super::{orphaned_legacy_platform_adapter_pid_from_ps_line, utf8_command_output_snippet};

    #[test]
    fn matches_orphaned_legacy_platform_adapter() {
        let line = " 1359     1 /Users/jieli/.antigravity_cockpit/platform-packages/codex/current/adapter/macos/cockpit-codex-adapter";
        assert_eq!(
            orphaned_legacy_platform_adapter_pid_from_ps_line(line, 99999),
            Some(1359)
        );
    }

    #[test]
    fn ignores_non_orphaned_or_current_processes() {
        let line = " 1359 1805 /Users/jieli/.antigravity_cockpit/platform-packages/codex/current/adapter/macos/cockpit-codex-adapter";
        assert_eq!(
            orphaned_legacy_platform_adapter_pid_from_ps_line(line, 99999),
            None
        );

        let current_line = " 1359 1 /Users/jieli/.antigravity_cockpit/platform-packages/codex/current/adapter/macos/cockpit-codex-adapter";
        assert_eq!(
            orphaned_legacy_platform_adapter_pid_from_ps_line(current_line, 1359),
            None
        );
    }

    #[test]
    fn ignores_current_sidecar_and_official_apps() {
        let sidecar =
            " 64680 1805 /Applications/Cockpit Tools.app/Contents/MacOS/cockpit-cliproxy --parent-pid 1805";
        assert_eq!(
            orphaned_legacy_platform_adapter_pid_from_ps_line(sidecar, 99999),
            None
        );

        let official_codex =
            " 9300 1 /Applications/Codex.app/Contents/Frameworks/Codex Framework.framework/Helpers/browser_crashpad_handler";
        assert_eq!(
            orphaned_legacy_platform_adapter_pid_from_ps_line(official_codex, 99999),
            None
        );
    }

    #[test]
    fn command_output_snippet_drops_non_utf8_bytes() {
        assert_eq!(utf8_command_output_snippet(&[0xb4, 0xed, 0xce, 0xf3]), None);
    }

    #[test]
    fn command_output_snippet_keeps_utf8_text() {
        assert_eq!(
            utf8_command_output_snippet("No such process\n".as_bytes()).as_deref(),
            Some("No such process")
        );
    }
}

#[cfg(test)]
mod managed_sidecar_port_cleanup_tests {
    use super::{
        command_line_parent_pid, managed_sidecar_command_matches,
        managed_sidecar_parent_allows_cleanup, normalized_process_argument,
    };
    use std::path::Path;

    #[test]
    fn parses_sidecar_parent_pid_forms() {
        assert_eq!(
            command_line_parent_pid("cockpit-cliproxy --parent-pid 1805"),
            Some(1805)
        );
        assert_eq!(
            command_line_parent_pid("cockpit-cliproxy --parent-pid=64680 --config x"),
            Some(64680)
        );
        assert_eq!(command_line_parent_pid("cockpit-cliproxy"), None);
    }

    #[test]
    fn requires_expected_sidecar_binary_and_config_path() {
        let config =
            Path::new("/Users/demo/.antigravity_cockpit/codex_local_access_sidecar/config.json");
        let command = "/Applications/Cockpit Tools.app/Contents/MacOS/cockpit-cliproxy --config /Users/demo/.antigravity_cockpit/codex_local_access_sidecar/config.json --parent-pid 1805";
        assert!(managed_sidecar_command_matches(
            command,
            "cockpit-cliproxy",
            config
        ));
        assert!(!managed_sidecar_command_matches(
            command,
            "cockpit-cliproxy",
            Path::new("/Users/demo/another/config.json")
        ));
        assert!(!managed_sidecar_command_matches(
            "python server.py --config /Users/demo/.antigravity_cockpit/codex_local_access_sidecar/config.json",
            "cockpit-cliproxy",
            config
        ));
    }

    #[test]
    fn normalizes_windows_process_arguments() {
        assert_eq!(
            normalized_process_argument(r#""C:\Program Files\Cockpit Tools\cockpit-cliproxy.exe""#),
            "c:/program files/cockpit tools/cockpit-cliproxy.exe"
        );
    }

    #[test]
    fn cleanup_rejects_live_siblings_and_detached_sidecars() {
        assert!(managed_sidecar_parent_allows_cleanup(
            Some(1805),
            1805,
            true
        ));
        assert!(managed_sidecar_parent_allows_cleanup(
            Some(1804),
            1805,
            false
        ));
        assert!(!managed_sidecar_parent_allows_cleanup(
            Some(1804),
            1805,
            true
        ));
        assert!(!managed_sidecar_parent_allows_cleanup(Some(0), 1805, false));
        assert!(!managed_sidecar_parent_allows_cleanup(None, 1805, false));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod qoder_macos_process_tests {
    use super::{
        is_qoder_variant_main_process_command_line, parse_qoder_macos_process_snapshot,
        resolve_qoder_pid_for_variant_from_entries,
    };
    use crate::modules::qoder_variant::QoderVariantKind;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn matches_current_qoder_ide_main_process() {
        assert!(is_qoder_variant_main_process_command_line(
            QoderVariantKind::Qoder,
            "/Applications/Qoder IDE.app/Contents/MacOS/Qoder"
        ));
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::Qoder,
            "/Applications/Qoder.app/Contents/MacOS/Qoder"
        ));
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::Qoder,
            "/Applications/Qoder IDE.app/Contents/Frameworks/Qoder Helper.app/Contents/MacOS/Qoder Helper --type=gpu-process --user-data-dir=/tmp/qoder"
        ));
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::Qoder,
            "/Applications/Qoder IDE.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler"
        ));
    }

    #[test]
    fn electron_main_process_resolves_only_the_target_ide_instance() {
        let kind = QoderVariantKind::Qoder;
        let snapshot = std::process::Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: concat!(
                "PID COMMAND\n",
                "41 /Applications/Qoder IDE.app/Contents/MacOS/Electron --user-data-dir=/tmp/qoder-instance\n",
                "42 /Applications/Qoder.app/Contents/MacOS/Electron --user-data-dir=/tmp/qoder-instance\n",
                "43 /Applications/Qoder IDE.app/Contents/Frameworks/Qoder Helper.app/Contents/MacOS/Qoder Helper --type=gpu-process --user-data-dir=/tmp/qoder-instance\n",
                "44 /Applications/Qoder IDE.app/Contents/MacOS/Electron --user-data-dir=/tmp/qoder-other\n",
            )
            .as_bytes()
            .to_vec(),
            stderr: Vec::new(),
        };
        let entries = parse_qoder_macos_process_snapshot(
            kind,
            "/Applications/Qoder IDE.app",
            Ok(snapshot),
        )
        .expect("parse IDE Electron main processes");

        assert_eq!(entries.len(), 2, "App and helper processes must be excluded");
        assert_eq!(
            resolve_qoder_pid_for_variant_from_entries(
                kind,
                None,
                Some("/tmp/qoder-instance"),
                &entries,
            ),
            Some(41),
            "the instance PID must belong to its own IDE user-data directory"
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod qoder_variant_launch_mapping_tests {
    use super::{is_qoder_variant_main_process_command_line, qoder_variant_client_bundle};
    use crate::modules::qoder_variant::QoderVariantKind;

    #[test]
    fn qoder_variant_client_bundle_mapping() {
        let cases = [
            (QoderVariantKind::QoderCnApp, "Qoder CN.app"),
            (QoderVariantKind::QoderApp, "Qoder.app"),
            (QoderVariantKind::QoderCnIde, "Qoder CN IDE.app"),
            (QoderVariantKind::Qoder, "Qoder IDE.app"),
        ];
        for (kind, bundle) in cases {
            assert_eq!(qoder_variant_client_bundle(kind), bundle, "{kind:?}");
            println!("qoder variant {:?} -> {}", kind, bundle);
        }
    }

    #[test]
    fn qoder_variant_main_process_matching_is_per_variant() {
        assert!(is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderCnApp,
            "/Applications/Qoder CN.app/Contents/MacOS/Qoder CN"
        ));
        assert!(is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderCnIde,
            "/Applications/Qoder CN IDE.app/Contents/MacOS/Qoder CN"
        ));
        assert!(is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderApp,
            "/Applications/Qoder.app/Contents/MacOS/Qoder"
        ));
        // 变体互不串台：CN App 匹配不到 intl App，反之亦然。
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderCnApp,
            "/Applications/Qoder.app/Contents/MacOS/Qoder"
        ));
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderApp,
            "/Applications/Qoder CN.app/Contents/MacOS/Qoder CN"
        ));
        // helper/crashpad 不算主进程。
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderCnApp,
            "/Applications/Qoder CN.app/Contents/Frameworks/Qoder CN Helper.app/Contents/MacOS/Qoder CN Helper --type=gpu-process"
        ));
        assert!(!is_qoder_variant_main_process_command_line(
            QoderVariantKind::QoderCnApp,
            "/Applications/Qoder CN.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler --database=/tmp"
        ));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod qoder_macos_launch_detection_tests {
    use super::{
        detect_qoder_exec_path, resolve_qoder_variant_custom_exec_path,
        resolve_qoder_variant_launch_path,
    };
    use crate::modules::qoder_platform_paths::macos_exec_candidates;
    use crate::modules::qoder_variant::QoderVariantKind;

    #[test]
    fn requires_current_ide_bundle_name_and_identity() {
        let root = std::env::temp_dir()
            .join(format!("qoder-bundle-{}", uuid::Uuid::new_v4()));
        for (bundle_name, bundle_id, accepted) in [
            ("Qoder.app", "com.qoder.app", false),
            ("Qoder.app", "com.qoder.ide", false),
            ("Qoder IDE.app", "com.qoder.app", false),
            ("Qoder IDE.app", "com.qoder.ide", true),
        ] {
            let bundle = root.join(bundle_name);
            let macos = bundle.join("Contents/MacOS");
            std::fs::create_dir_all(&macos).expect("fixture directory");
            std::fs::write(macos.join("Qoder"), b"").expect("fixture executable");
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>{}</string></dict></plist>"#,
                bundle_id
            );
            std::fs::write(bundle.join("Contents/Info.plist"), plist).expect("fixture plist");
            assert_eq!(
                resolve_qoder_variant_custom_exec_path(QoderVariantKind::Qoder, &bundle.to_string_lossy()),
                accepted.then(|| macos.join("Qoder")),
                "bundle name and identity must distinguish {bundle_name} with {bundle_id}"
            );
        }
        std::fs::remove_dir_all(root).expect("remove fixture");
    }

    fn position_of(needle: &str) -> usize {
        macos_exec_candidates(QoderVariantKind::Qoder)
            .iter()
            .position(|path| path.to_string_lossy().contains(needle))
            .unwrap_or_else(|| panic!("missing candidate {needle}"))
    }

    #[test]
    fn ide_bundle_candidates_exclude_app_bundle() {
        let _ide = position_of("Qoder IDE.app");
        assert!(macos_exec_candidates(QoderVariantKind::Qoder)
            .iter()
            .all(|path| !path.to_string_lossy().contains("/Qoder.app")));
        for required in [
            "/Applications/Qoder IDE.app/Contents/MacOS/Qoder",
            "/Applications/Qoder IDE.app/Contents/MacOS/Qoder IDE",
            "/Applications/Qoder IDE.app/Contents/MacOS/Electron",
            "/Applications/Qoder IDE.app",
        ] {
            assert!(
                macos_exec_candidates(QoderVariantKind::Qoder)
                    .iter()
                    .any(|path| path.to_string_lossy() == required),
                "missing IDE candidate {required}"
            );
        }
    }

    #[test]
    fn detection_prefers_ide_bundle_when_both_bundles_installed() {
        let ide_bundle = std::path::Path::new("/Applications/Qoder IDE.app");
        if !ide_bundle.exists() {
            return;
        }
        let detected = detect_qoder_exec_path().expect("detect qoder exec path");
        assert!(
            detected.to_string_lossy().contains("Qoder IDE.app"),
            "detected legacy app instead of IDE: {}",
            detected.display()
        );
        let resolved = resolve_qoder_variant_launch_path(QoderVariantKind::Qoder)
            .expect("resolve qoder launch path");
        assert!(
            resolved.to_string_lossy().contains("Qoder IDE.app"),
            "resolved legacy app instead of IDE: {}",
            resolved.display()
        );
        println!("qoder launch path = {}", resolved.display());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod codex_macos_launch_tests {
    use super::{
        is_codex_direct_app_server_command_line, is_codex_macos_main_process_command_line,
        select_codex_direct_app_server_descendants, CodexProcessTreeEntry,
    };

    #[test]
    fn matches_chatgpt_and_legacy_codex_main_processes() {
        assert!(is_codex_macos_main_process_command_line(
            "/applications/chatgpt.app/contents/macos/chatgpt"
        ));
        assert!(is_codex_macos_main_process_command_line(
            "/applications/codex.app/contents/macos/codex"
        ));
        assert!(!is_codex_macos_main_process_command_line(
            "/applications/chatgpt.app/contents/resources/codex app-server"
        ));
    }

    #[test]
    fn matches_only_bundled_direct_app_server_commands() {
        let executable = "/Applications/ChatGPT.app/Contents/Resources/codex";
        assert!(is_codex_direct_app_server_command_line(
            "/Applications/ChatGPT.app/Contents/Resources/codex app-server --analytics-default-enabled",
            executable,
        ));
        assert!(is_codex_direct_app_server_command_line(
            "\"/Applications/ChatGPT.app/Contents/Resources/codex\" app-server --listen stdio://",
            executable,
        ));
        assert!(!is_codex_direct_app_server_command_line(
            "/Applications/ChatGPT.app/Contents/Resources/codex app-server daemon",
            executable,
        ));
        assert!(!is_codex_direct_app_server_command_line(
            "/opt/homebrew/bin/codex app-server --analytics-default-enabled",
            executable,
        ));
        assert!(!is_codex_direct_app_server_command_line(
            "/Applications/ChatGPT.app/Contents/Resources/codex exec hello",
            executable,
        ));
    }

    #[test]
    fn selects_direct_app_server_only_from_target_main_process_tree() {
        let executable = "/Applications/ChatGPT.app/Contents/Resources/codex";
        let entries = vec![
            CodexProcessTreeEntry {
                pid: 100,
                parent_pid: 1,
                command_line: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT".to_string(),
            },
            CodexProcessTreeEntry {
                pid: 110,
                parent_pid: 100,
                command_line: "helper".to_string(),
            },
            CodexProcessTreeEntry {
                pid: 120,
                parent_pid: 110,
                command_line: format!("{} app-server --analytics-default-enabled", executable),
            },
            CodexProcessTreeEntry {
                pid: 200,
                parent_pid: 1,
                command_line: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT".to_string(),
            },
            CodexProcessTreeEntry {
                pid: 220,
                parent_pid: 200,
                command_line: format!("{} app-server --analytics-default-enabled", executable),
            },
        ];

        assert_eq!(
            select_codex_direct_app_server_descendants(&entries, &[100], executable),
            vec![120]
        );
    }
}

#[cfg(test)]
mod codex_launch_args_tests {
    use super::{
        build_codex_app_launch_args, codex_managed_store_launch_unsafe_error,
        CODEX_MANAGED_STORE_LAUNCH_UNSAFE_PREFIX,
    };

    #[test]
    fn keeps_user_launch_args_without_adding_remote_debugging() {
        assert!(build_codex_app_launch_args(&[]).is_empty());
        assert_eq!(
            build_codex_app_launch_args(&[
                " --remote-debugging-port=9333 ".to_string(),
                "".to_string(),
                " --disable-gpu ".to_string(),
            ]),
            vec![
                "--remote-debugging-port=9333".to_string(),
                "--disable-gpu".to_string(),
            ]
        );
    }

    #[test]
    fn managed_store_launch_error_is_machine_readable_and_keeps_causes() {
        let error = codex_managed_store_launch_unsafe_error(
            "denied",
            "fallback failed",
            "launch_path=C:\\Program Files\\WindowsApps\\OpenAI.Codex_1.0\\app\\ChatGPT.exe; launch_path_exists=true",
        );
        assert!(error.starts_with(CODEX_MANAGED_STORE_LAUNCH_UNSAFE_PREFIX));
        assert!(error.contains("direct_error=denied"));
        assert!(error.contains("powershell_error=fallback failed"));
        // 诊断信息要跟着错误一起回传，用户复制错误即可让支持侧看到实际路径。
        assert!(error.contains("launch_path="));
        assert!(error.contains("launch_path_exists=true"));
    }

    #[test]
    fn managed_store_launch_error_keeps_package_identity_cause_readable() {
        // 三层兜底（直启 / Start-Process / 包身份）都失败时，包身份原因也要留在
        // 错误里，否则用户复制出来的诊断看不到真正卡在哪一层。
        let error = codex_managed_store_launch_unsafe_error(
            "拒绝访问。 (os error 5)",
            "PowerShell 启动 Codex 失败",
            "package_identity_error=包身份启动失败: status=exit code: 1; launch_path_exists=true",
        );
        assert!(error.contains("package_identity_error="));
        assert!(error.contains("launch_path_exists=true"));
    }

    #[test]
    fn managed_store_launch_error_omits_empty_diagnostics() {
        let error = codex_managed_store_launch_unsafe_error("denied", "fallback failed", "  ");
        assert_eq!(
            error,
            "CODEX_MANAGED_STORE_LAUNCH_UNSAFE:direct_error=denied; powershell_error=fallback failed"
        );
    }
}

#[cfg(test)]
mod codex_linux_layout_tests {
    use super::{
        linux_codex_discovery_paths, select_codex_direct_app_server_descendants,
        CodexProcessTreeEntry,
    };
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn discovery_includes_official_linux_package_and_path_launchers() {
        let home = Path::new("/home/demo");
        let path = OsString::from("/custom/bin:/usr/bin");
        let candidates = linux_codex_discovery_paths(Some(home), Some(path.as_os_str()));
        assert!(candidates.contains(&PathBuf::from("/usr/bin/chatgpt")));
        assert!(candidates.contains(&PathBuf::from("/usr/lib/chatgpt/ChatGPT")));
        assert!(candidates.contains(&PathBuf::from("/home/demo/.local/bin/chatgpt")));
        assert!(candidates.contains(&PathBuf::from("/custom/bin/chatgpt")));
    }

    #[test]
    fn selects_linux_bundled_app_server_from_target_desktop_tree() {
        let executable = "/usr/lib/chatgpt/resources/codex";
        let entries = vec![
            CodexProcessTreeEntry {
                pid: 100,
                parent_pid: 1,
                command_line: "/usr/lib/chatgpt/ChatGPT".to_string(),
            },
            CodexProcessTreeEntry {
                pid: 120,
                parent_pid: 100,
                command_line: format!("{} app-server --analytics-default-enabled", executable),
            },
            CodexProcessTreeEntry {
                pid: 220,
                parent_pid: 200,
                command_line: format!("{} app-server --analytics-default-enabled", executable),
            },
        ];
        assert_eq!(
            select_codex_direct_app_server_descendants(&entries, &[100], executable),
            vec![120]
        );
    }
}

#[cfg(test)]
mod codex_path_migration_tests {
    use super::{
        is_codex_embedded_backend_executable, score_windows_candidate,
        should_migrate_legacy_codex_launch_path, should_probe_legacy_codex_launch_path,
    };
    use std::collections::HashSet;
    use std::path::Path;

    #[test]
    fn migrates_official_windows_store_codex_path_when_chatgpt_exists() {
        assert!(should_migrate_legacy_codex_launch_path(
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\Codex.exe"
            ),
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.ChatGPT_2.0.0.0_x64__8wekyb3d8bbwe\app\ChatGPT.exe"
            ),
        ));
    }

    #[test]
    fn keeps_legacy_path_when_chatgpt_is_not_detected() {
        assert!(!should_migrate_legacy_codex_launch_path(
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\Codex.exe"
            ),
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\Codex.exe"
            ),
        ));
    }

    #[test]
    fn does_not_replace_custom_codex_executable() {
        assert!(!should_migrate_legacy_codex_launch_path(
            Path::new(r"D:\Tools\Codex.exe"),
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.ChatGPT_2.0.0.0_x64__8wekyb3d8bbwe\app\ChatGPT.exe"
            ),
        ));
    }

    #[test]
    fn migrates_official_macos_codex_path_when_chatgpt_exists() {
        assert!(should_migrate_legacy_codex_launch_path(
            Path::new("/Applications/Codex.app"),
            Path::new("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"),
        ));
        assert!(should_migrate_legacy_codex_launch_path(
            Path::new("/Applications/Codex.app/Contents/MacOS/Codex"),
            Path::new("/Applications/ChatGPT.app"),
        ));
    }

    #[test]
    fn keeps_macos_legacy_path_when_chatgpt_is_not_detected() {
        assert!(!should_migrate_legacy_codex_launch_path(
            Path::new("/Applications/Codex.app"),
            Path::new("/Applications/Codex.app/Contents/MacOS/Codex"),
        ));
    }

    #[test]
    fn does_not_replace_custom_macos_codex_path() {
        assert!(!should_migrate_legacy_codex_launch_path(
            Path::new("/Users/test/Applications/Codex.app"),
            Path::new("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"),
        ));
    }

    #[test]
    fn only_probes_official_legacy_codex_paths_for_migration() {
        assert!(should_probe_legacy_codex_launch_path(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\Codex.exe"
        )));
        assert!(should_probe_legacy_codex_launch_path(Path::new(
            "/Applications/Codex.app"
        )));
        assert!(!should_probe_legacy_codex_launch_path(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.ChatGPT_2.0.0.0_x64__8wekyb3d8bbwe\app\ChatGPT.exe"
        )));
        assert!(!should_probe_legacy_codex_launch_path(Path::new(
            r"D:\Tools\Codex.exe"
        )));
        assert!(!should_probe_legacy_codex_launch_path(Path::new(
            "/Users/test/Applications/Codex.app"
        )));
    }

    #[test]
    fn scan_rejects_codex_keyword_helper_executables() {
        let exe_names = HashSet::from(["chatgpt.exe".to_string()]);
        let keywords = vec!["chatgpt".to_string()];

        assert!(score_windows_candidate(
            Path::new("C:/Tools/CodexHelper.exe"),
            &exe_names,
            &keywords,
        )
        .is_none());
        assert!(
            score_windows_candidate(Path::new("C:/Tools/ChatGPT.exe"), &exe_names, &keywords,)
                .is_some()
        );
    }

    #[test]
    fn scan_excludes_embedded_resources_backend() {
        assert!(is_codex_embedded_backend_executable(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9564.0_x64__2p2nqsd0c76g0\app\resources\codex.exe"
        )));
        assert!(!is_codex_embedded_backend_executable(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9564.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe"
        )));
        assert!(!is_codex_embedded_backend_executable(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__2p2nqsd0c76g0\app\Codex.exe"
        )));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::{
        running_app_candidate_matches, windows_app_launch_signature,
        windows_trae_candidate_matches_platform,
    };
    use crate::modules::trae_account::TraePlatformKind;
    use std::path::Path;

    #[test]
    fn windows_launch_signatures_cover_provider_apps() {
        for app in [
            "antigravity_ide",
            "cursor",
            "zed",
            "codebuddy",
            "codebuddy_cn",
            "qoder",
            "trae",
            "trae_solo",
            "trae_cn",
            "trae_solo_cn",
            "workbuddy",
            "windsurf",
            "kiro",
            "codex",
            "claude",
            "vscode",
        ] {
            let signature =
                windows_app_launch_signature(app).unwrap_or_else(|| panic!("missing {app}"));
            assert!(
                !signature.exe_names.is_empty(),
                "{app} must define executable names"
            );
            assert!(
                !signature.common_paths.is_empty(),
                "{app} must define common install paths"
            );
            assert!(
                !signature.display_keywords.is_empty(),
                "{app} must define display keywords"
            );
        }
    }

    #[test]
    fn antigravity_ide_signature_uses_ide_executable_only() {
        let signature = windows_app_launch_signature("antigravity_ide")
            .expect("antigravity ide signature must exist");
        assert!(signature
            .exe_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Antigravity IDE.exe")));
        assert!(!signature
            .exe_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Antigravity.exe")));
    }

    #[test]
    fn codex_signature_accepts_only_chatgpt_gui_executable() {
        let signature = windows_app_launch_signature("codex").expect("codex signature must exist");
        assert!(signature
            .exe_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("ChatGPT.exe")));
        assert!(!signature
            .exe_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case("Codex.exe")));
    }

    #[test]
    fn running_codex_match_accepts_main_executable_and_rejects_embedded_backend() {
        let signature = windows_app_launch_signature("codex").expect("codex signature must exist");
        assert!(running_app_candidate_matches(
            "codex",
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9564.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe"
            ),
            signature,
        ));
        assert!(!running_app_candidate_matches(
            "codex",
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9564.0_x64__2p2nqsd0c76g0\app\resources\codex.exe"
            ),
            signature,
        ));
        assert!(!running_app_candidate_matches(
            "codex",
            Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_26.707.9564.0_x64__2p2nqsd0c76g0\app\Codex.exe"
            ),
            signature,
        ));
    }

    #[test]
    fn running_claude_match_requires_claude_executable() {
        let signature =
            windows_app_launch_signature("claude").expect("claude signature must exist");
        assert!(running_app_candidate_matches(
            "claude",
            Path::new(r"C:\Program Files\WindowsApps\Claude_1.0.0\app\Claude.exe"),
            signature,
        ));
        assert!(!running_app_candidate_matches(
            "claude",
            Path::new(r"C:\Tools\Electron.exe"),
            signature,
        ));
    }

    #[test]
    fn trae_windows_scan_candidates_match_exact_platform_dirs() {
        let trae = Path::new(r"D:\Users\李杰\AppData\Local\Programs\Trae\Trae.exe");
        let trae_cn = Path::new(r"D:\Users\李杰\AppData\Local\Programs\Trae CN\Trae CN.exe");
        let solo_cn =
            Path::new(r"D:\Users\李杰\AppData\Local\Programs\TRAE SOLO CN\TRAE SOLO CN.exe");

        assert!(windows_trae_candidate_matches_platform(
            trae,
            TraePlatformKind::Trae
        ));
        assert!(!windows_trae_candidate_matches_platform(
            trae,
            TraePlatformKind::TraeCn
        ));
        assert!(windows_trae_candidate_matches_platform(
            trae_cn,
            TraePlatformKind::TraeCn
        ));
        assert!(!windows_trae_candidate_matches_platform(
            trae_cn,
            TraePlatformKind::Trae
        ));
        assert!(windows_trae_candidate_matches_platform(
            solo_cn,
            TraePlatformKind::TraeSoloCn
        ));
        assert!(!windows_trae_candidate_matches_platform(
            solo_cn,
            TraePlatformKind::TraeSolo
        ));
    }
}

#[cfg(test)]
mod codex_windows_default_instance_tests {
    use super::{
        codex_windows_process_snapshot_is_stale, filter_codex_windows_default_process_entries,
        is_codex_windows_default_process_dir, next_codex_default_start_candidate,
        normalize_path_for_compare,
    };
    use std::collections::HashSet;

    const DEFAULT_APP_DIR: &str = r"C:\Users\me\AppData\Roaming\Codex\web\Codex";
    const MANAGED_APP_DIR: &str =
        r"C:\Users\me\AppData\Roaming\.antigravity_cockpit\instances\codex-app-data\5184";

    #[test]
    fn ignores_last_pid_reused_by_an_unrelated_process() {
        assert!(codex_windows_process_snapshot_is_stale(Some((
            "notepad.exe",
            Some(r"C:\Windows\System32\notepad.exe"),
        ))));
        // PID 仍存在但路径不可读时，明确的非 ChatGPT 进程名也能证明历史 PID 已失效。
        assert!(codex_windows_process_snapshot_is_stale(Some((
            "explorer.exe",
            None
        ))));
    }

    #[test]
    fn ignores_last_pid_that_exited_between_probes() {
        assert!(codex_windows_process_snapshot_is_stale(None));
    }

    #[test]
    fn preserves_ownership_guard_for_chatgpt_and_unreadable_identity() {
        for process in [
            ("ChatGPT.exe", None),
            ("CHATGPT.EXE", Some("")),
            ("", None),
            (
                "",
                Some(r"C:\Program Files\WindowsApps\OpenAI.Codex_26.930_x64__test\app\ChatGPT.exe"),
            ),
            ("ChatGPT.exe", Some("C:/Apps/ChatGPT.exe")),
        ] {
            assert!(
                !codex_windows_process_snapshot_is_stale(Some(process)),
                "{process:?}"
            );
        }
    }

    #[test]
    fn classifies_default_processes_without_mixing_managed_instances() {
        let default_dirs = HashSet::from([normalize_path_for_compare(DEFAULT_APP_DIR)]);
        assert!(is_codex_windows_default_process_dir(None, &default_dirs));
        assert!(is_codex_windows_default_process_dir(
            Some(DEFAULT_APP_DIR),
            &default_dirs
        ));
        assert!(!is_codex_windows_default_process_dir(
            Some(MANAGED_APP_DIR),
            &default_dirs
        ));

        let entries = vec![(4584, None), (5184, Some(MANAGED_APP_DIR.to_string()))];
        let filtered = filter_codex_windows_default_process_entries(&entries, &default_dirs);
        assert_eq!(filtered, vec![(4584, None)]);
    }

    #[test]
    fn rejects_start_result_while_old_default_pid_is_still_present() {
        let before = HashSet::from([4584]);
        assert_eq!(
            next_codex_default_start_candidate(&[4584], &before, None, 0),
            (None, 0)
        );
        assert_eq!(
            next_codex_default_start_candidate(&[4584, 18500], &before, None, 0),
            (None, 0)
        );
        assert_eq!(
            next_codex_default_start_candidate(&[18500], &before, None, 0),
            (Some(18500), 1)
        );
    }

    #[test]
    fn requires_the_new_default_pid_to_remain_stable() {
        let before = HashSet::from([4584]);
        let (pid, streak) = next_codex_default_start_candidate(&[18500], &before, Some(18500), 1);
        assert_eq!((pid, streak), (Some(18500), 2));
        let (pid, streak) = next_codex_default_start_candidate(&[18500], &before, Some(18500), 2);
        assert_eq!((pid, streak), (Some(18500), 3));
        let (pid, streak) = next_codex_default_start_candidate(&[], &before, Some(18500), 3);
        assert_eq!((pid, streak), (None, 0));
        let (pid, streak) = next_codex_default_start_candidate(&[18500], &before, None, 0);
        assert_eq!((pid, streak), (Some(18500), 1));
    }
}

#[cfg(test)]
mod windows_codex_exe_match_tests {
    use super::{is_matching_codex_windows_exe, windowsapps_package_family};

    const OLD_STORE: &str = r"c:\program files\windowsapps\openai.codex_26.820.7780.0_x64__2p2nqsd0c76g0\app\chatgpt.exe";
    const NEW_STORE: &str = r"c:\program files\windowsapps\openai.codex_26.908.4834.0_x64__2p2nqsd0c76g0\app\chatgpt.exe";
    const OTHER_FAMILY: &str =
        r"c:\program files\windowsapps\openai.chatgpt_1.0.0.0_x64__2p2nqsd0c76g0\app\chatgpt.exe";

    #[test]
    fn windowsapps_family_is_parsed_from_package_directory() {
        assert_eq!(
            windowsapps_package_family(OLD_STORE).as_deref(),
            Some("openai.codex")
        );
        assert_eq!(
            windowsapps_package_family(
                r"C:/Program Files/WindowsApps/OpenAI.Codex_1.0_x64__abc/app/Codex.exe"
            )
            .as_deref(),
            Some("openai.codex")
        );
        assert!(windowsapps_package_family(r"c:\users\me\codex\codex.exe").is_none());
    }

    #[test]
    fn store_package_matches_across_version_directories() {
        // 商店更新后配置路径与运行中进程只差版本目录，必须仍然认作同一实例，
        // 否则会误判「客户端没启动 / 已关闭」，官方登录更会直接判定失败。
        assert!(is_matching_codex_windows_exe(NEW_STORE, OLD_STORE));
        assert!(is_matching_codex_windows_exe(OLD_STORE, NEW_STORE));
        assert!(is_matching_codex_windows_exe(NEW_STORE, NEW_STORE));
    }

    #[test]
    fn package_family_and_file_name_still_have_to_match() {
        // 不同包族：ChatGPT 桌面端与 Codex 是两个应用，不能混为一谈。
        assert!(!is_matching_codex_windows_exe(OTHER_FAMILY, OLD_STORE));
        // 同包族但不是同一个可执行文件（内置 codex.exe 不应当成主进程）。
        assert!(!is_matching_codex_windows_exe(
            r"c:\program files\windowsapps\openai.codex_26.908.4834.0_x64__2p2nqsd0c76g0\app\resources\codex.exe",
            NEW_STORE
        ));
    }

    #[test]
    fn non_store_paths_keep_strict_comparison() {
        let local = r"c:\users\me\appdata\local\programs\codex\codex.exe";
        let other = r"d:\elsewhere\codex\codex.exe";
        assert!(is_matching_codex_windows_exe(local, local));
        assert!(!is_matching_codex_windows_exe(other, local));
        // 一侧是商店路径、另一侧不是时不得放宽。
        assert!(!is_matching_codex_windows_exe(local, NEW_STORE));
        assert!(!is_matching_codex_windows_exe(NEW_STORE, local));
    }

    #[test]
    fn empty_paths_never_match() {
        assert!(!is_matching_codex_windows_exe("", NEW_STORE));
        assert!(!is_matching_codex_windows_exe(NEW_STORE, ""));
        assert!(!is_matching_codex_windows_exe("", ""));
    }
}

#[cfg(test)]
mod codex_package_identity_launch_tests {
    use super::{windowsapps_install_location_from_launch_path, windowsapps_package_family};
    use std::path::Path;

    #[test]
    fn derives_install_location_from_store_launch_path() {
        assert_eq!(
            windowsapps_install_location_from_launch_path(Path::new(
                r"C:\Program Files\WindowsApps\OpenAI.Codex_26.908.9136.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe"
            ))
            .as_deref(),
            Some(r"C:\Program Files\WindowsApps\OpenAI.Codex_26.908.9136.0_x64__2p2nqsd0c76g0")
        );
        // 非商店路径不能落到包身份分支上。
        assert!(windowsapps_install_location_from_launch_path(Path::new(
            r"C:\Users\me\AppData\Local\Programs\Codex\Codex.exe"
        ))
        .is_none());
    }

    #[test]
    fn install_location_round_trips_to_the_registered_package_family() {
        // 外层脚本按 InstallLocation 反查包，这里确认解析结果仍属同一包族。
        let install_location = windowsapps_install_location_from_launch_path(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_26.908.9136.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe",
        ))
        .expect("store path should resolve");
        let fake_exe = format!(r"{}\app\ChatGPT.exe", install_location);
        assert_eq!(
            windowsapps_package_family(&fake_exe).as_deref(),
            Some("openai.codex")
        );
    }
}

#[cfg(test)]
mod windows_launch_fallback_tests {
    use super::{is_windowsapps_launch_path, windows_powershell_executable_candidates};
    use std::path::{Path, PathBuf};

    #[test]
    fn powershell_candidates_prefer_path_then_system32_then_pwsh() {
        let candidates = windows_powershell_executable_candidates(Some(r"D:\Windows"));
        assert_eq!(candidates[0], PathBuf::from("powershell.exe"));
        assert_eq!(
            candidates[1],
            PathBuf::from(r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
        assert_eq!(candidates[2], PathBuf::from("pwsh.exe"));
    }

    #[test]
    fn powershell_candidates_keep_windows_default_root_fallback() {
        let candidates = windows_powershell_executable_candidates(None);
        assert_eq!(
            candidates[1],
            PathBuf::from(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        );
    }

    #[test]
    fn detects_windowsapps_launch_paths() {
        assert!(is_windowsapps_launch_path(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\ChatGPT.exe"
        )));
        assert!(is_windowsapps_launch_path(Path::new(
            r"C:/Program Files/WindowsApps/OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe/app/Codex.exe"
        )));
        assert!(!is_windowsapps_launch_path(Path::new(
            r"C:\Users\me\AppData\Local\Programs\Codex\Codex.exe"
        )));
    }
}

#[cfg(test)]
mod codex_store_gui_exe_tests {
    use super::{appx_manifest_gui_executable_from_text, is_chatgpt_store_gui_exe};
    use std::path::Path;

    /// 真实清单的精简版：`App` 是桌面端入口，`CodexCoreCommandRunner` 是另一个应用。
    const REAL_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Applications>
    <Application Id="App" Executable="app/ChatGPT.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="ChatGPT" />
    </Application>
    <Application Id="CodexCoreCommandRunner" Executable="app/resources/codex-command-runner.exe" EntryPoint="Windows.FullTrustApplication" />
  </Applications>
</Package>"#;

    #[test]
    fn picks_the_app_application_executable() {
        assert_eq!(
            appx_manifest_gui_executable_from_text(REAL_MANIFEST).as_deref(),
            Some("app/ChatGPT.exe")
        );
    }

    #[test]
    fn ignores_other_applications_and_missing_executable() {
        // Id 顺序对调也要命中 App，而不是第一个 Application 节点。
        let other_first = r#"<Application Id="CodexCoreCommandRunner" Executable="app/resources/codex-command-runner.exe" /><Application Id="App" Executable="app/ChatGPT.exe" />"#;
        assert_eq!(
            appx_manifest_gui_executable_from_text(other_first).as_deref(),
            Some("app/ChatGPT.exe")
        );
        assert_eq!(
            appx_manifest_gui_executable_from_text(r#"<Application Id="App" />"#),
            None
        );
        assert_eq!(appx_manifest_gui_executable_from_text("<Package />"), None);
        assert_eq!(appx_manifest_gui_executable_from_text(""), None);
    }

    #[test]
    fn only_accepts_the_chatgpt_gui_binary() {
        assert!(is_chatgpt_store_gui_exe(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\ChatGPT.exe"
        )));
        assert!(is_chatgpt_store_gui_exe(Path::new(
            r"E:\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\chatgpt.EXE"
        )));
        // 同包目录里的另外两个 exe 都不是桌面端入口。
        assert!(!is_chatgpt_store_gui_exe(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\Codex.exe"
        )));
        assert!(!is_chatgpt_store_gui_exe(Path::new(
            r"C:\Program Files\WindowsApps\OpenAI.Codex_1.0.0.0_x64__8wekyb3d8bbwe\app\resources\codex.exe"
        )));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolves_gui_exe_from_manifest_and_falls_back_to_convention() {
        use super::codex_store_gui_exe_in;

        let root =
            std::env::temp_dir().join(format!("cockpit-tools-codex-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // 1) 清单声明 app/ChatGPT.exe 且文件存在 → 采信清单
        let with_manifest = root.join("with-manifest");
        std::fs::create_dir_all(with_manifest.join("app")).expect("create app dir");
        std::fs::write(with_manifest.join("AppxManifest.xml"), REAL_MANIFEST)
            .expect("write manifest");
        std::fs::write(with_manifest.join("app").join("ChatGPT.exe"), b"stub").expect("write exe");
        assert_eq!(
            codex_store_gui_exe_in(&with_manifest),
            Some(with_manifest.join("app").join("ChatGPT.exe"))
        );

        // 2) 读不到清单 → 退回约定路径 app\ChatGPT.exe
        let no_manifest = root.join("no-manifest");
        std::fs::create_dir_all(no_manifest.join("app")).expect("create app dir");
        std::fs::write(no_manifest.join("app").join("ChatGPT.exe"), b"stub").expect("write exe");
        assert_eq!(
            codex_store_gui_exe_in(&no_manifest),
            Some(no_manifest.join("app").join("ChatGPT.exe"))
        );

        // 3) 只有 Codex.exe → 不再猜其它 exe
        let only_codex = root.join("only-codex");
        std::fs::create_dir_all(only_codex.join("app")).expect("create app dir");
        std::fs::write(only_codex.join("app").join("Codex.exe"), b"stub").expect("write exe");
        assert_eq!(codex_store_gui_exe_in(&only_codex), None);

        // 4) 清单指向非 ChatGPT.exe → 不接受
        let manifest_other = root.join("manifest-other");
        std::fs::create_dir_all(manifest_other.join("app")).expect("create app dir");
        std::fs::write(
            manifest_other.join("AppxManifest.xml"),
            br#"<Application Id="App" Executable="app/Codex.exe" />"#,
        )
        .expect("write manifest");
        std::fs::write(manifest_other.join("app").join("Codex.exe"), b"stub").expect("write exe");
        assert_eq!(codex_store_gui_exe_in(&manifest_other), None);

        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod passive_wsl_path_tests {
    use super::{running_wsl_output_contains_distro, wsl_unc_distro};
    #[test]
    fn wsl_unc_paths_identify_target_distro_without_accessing_it() {
        for path in [
            r"\\wsl.localhost\Ubuntu-22.04\Antigravity IDE.exe",
            r"\\WSL$\Ubuntu-22.04\Antigravity IDE.exe",
            r"\\?\UNC\wsl.localhost\Ubuntu-22.04\Antigravity IDE.exe",
            r"\\?\unc\WSL$\Ubuntu-22.04\Antigravity IDE.exe",
        ] {
            assert_eq!(
                wsl_unc_distro(path).as_deref(),
                Some("ubuntu-22.04"),
                "{path}"
            );
        }
        assert!(wsl_unc_distro(r"C:\Program Files\Antigravity IDE.exe").is_none());
        assert!(wsl_unc_distro(r"\\server\share\Antigravity IDE.exe").is_none());
        assert!(wsl_unc_distro(r"\\wsl.localhost.example\share\app.exe").is_none());
    }

    #[test]
    fn running_distro_status_requires_exact_name_in_utf16_output() {
        let bytes: Vec<u8> = "Ubuntu-22.04\0\r\nDebian\0\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(running_wsl_output_contains_distro(&bytes, "ubuntu-22.04"));
        assert!(running_wsl_output_contains_distro(&bytes, "Debian"));
        assert!(!running_wsl_output_contains_distro(&bytes, "Ubuntu"));
        assert!(!running_wsl_output_contains_distro(&bytes, ""));
        assert!(!running_wsl_output_contains_distro(
            &bytes[..bytes.len() - 1],
            "Debian"
        ));
    }
}

#[cfg(test)]
mod managed_proxy_env_tests {
    use super::build_managed_proxy_env_pairs;

    #[test]
    fn direct_launch_does_not_inject_a_bypass_list() {
        for enabled in [false, true] {
            assert!(build_managed_proxy_env_pairs(
                enabled,
                " ",
                "example.test",
                &[],
                "existing.test",
                "upper.test"
            )
            .is_empty());
        }
        assert!(build_managed_proxy_env_pairs(
            false,
            "http://localhost:8080",
            "",
            &[" ".into()],
            "",
            ""
        )
        .is_empty());
    }

    #[test]
    fn configured_and_inherited_proxies_keep_local_bypass_and_user_entries() {
        for managed in [false, true] {
            let inherited = if managed {
                vec![]
            } else {
                vec!["socks5://localhost:9999".into()]
            };
            let pairs = build_managed_proxy_env_pairs(
                managed,
                " http://localhost:8080 ",
                "configured.test",
                &inherited,
                "lower.test",
                "upper.test",
            );
            assert_eq!(pairs.len(), if managed { 8 } else { 2 });
            let bypass = &pairs.iter().find(|(key, _)| *key == "NO_PROXY").unwrap().1;
            for entry in [
                "localhost",
                "127.0.0.1",
                "configured.test",
                "lower.test",
                "upper.test",
            ] {
                assert!(
                    bypass.split(',').any(|value| value.trim() == entry),
                    "{bypass}"
                );
            }
            if managed {
                assert_eq!(pairs[0].1, "http://localhost:8080");
            }
        }
    }
}
