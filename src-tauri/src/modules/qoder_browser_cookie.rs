//! Read only Qoder's Chrome cookies. The WebView owner verifies the server-side
//! user ID before persisting any candidate. No credentials cross IPC or logs.

pub(crate) const CHROME_PERMISSION_DENIED_ERROR: &str = "macOS 拒绝读取 Chrome 数据（权限不足）。请允许当前运行的 Cockpit 访问 Chrome 数据后重试，或在该账号的网页会话中登录。";

#[cfg(target_os = "macos")]
mod macos {
    use aes::Aes128;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use pbkdf2::pbkdf2_hmac;
    use rusqlite::Connection;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use std::{fs, path::{Path, PathBuf}, time::Duration};

    struct Snapshot(PathBuf);

    impl Drop for Snapshot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn chrome_read_error(operation: &str, error: &std::io::Error) -> String {
        // EPERM is used by macOS privacy controls and is not consistently mapped
        // to PermissionDenied. Do not include cookie contents or private paths.
        if error.kind() == std::io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1) {
            super::CHROME_PERMISSION_DENIED_ERROR.to_string()
        } else {
            format!("{operation}（系统错误码：{}）", error.raw_os_error().map_or_else(|| "未知".to_string(), |code| code.to_string()))
        }
    }

    fn snapshot_database(path: &Path) -> Result<Snapshot, String> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        use std::io::Write;
        let directory = std::env::temp_dir().join(format!("cockpit-qoder-cookie-{}", uuid::Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&directory)
            .map_err(|_| "创建 Qoder Cookie 临时目录失败".to_string())?;
        let snapshot = Snapshot(directory);
        // Recover WAL/journal only on the private disposable copy. The original
        // Chrome database must never be opened in a mode that can create SHM.
        for suffix in ["", "-wal", "-journal"] {
            let mut source = path.as_os_str().to_os_string();
            source.push(suffix);
            let source = PathBuf::from(source);
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(error) if !suffix.is_empty() && error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(chrome_read_error("读取 Chrome Cookie 文件失败", &error)),
            };
            if !metadata.is_file() || metadata.len() > 128 * 1024 * 1024 {
                return Err("Chrome Cookie 文件类型或大小异常".to_string());
            }
            let bytes = fs::read(source).map_err(|error| chrome_read_error("读取 Chrome Cookie 文件失败", &error))?;
            let mut destination = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(snapshot.0.join(format!("Cookies{suffix}")))
                .map_err(|_| "创建 Cookie 临时副本失败".to_string())?;
            destination.write_all(&bytes).map_err(|_| "写入 Cookie 临时副本失败".to_string())?;
        }
        Ok(snapshot)
    }

    fn chrome_key() -> Result<[u8; 16], String> {
        let mut command = std::process::Command::new("/usr/bin/security");
        command.args(["find-generic-password", "-w", "-s", "Chrome Safe Storage"]);
        let output = crate::modules::process_timeout::output_with_timeout(&mut command, Duration::from_secs(20))
            .map_err(|_| "读取 Chrome Cookie 密钥失败".to_string())?;
        if !output.status.success() { return Err("无法读取 Chrome Cookie 密钥".to_string()); }
        let mut password = output.stdout;
        // security appends one newline; spaces in the password are significant.
        if password.last() == Some(&b'\n') { password.pop(); }
        if password.is_empty() { return Err("Chrome Cookie 密钥为空".to_string()); }
        let mut key = [0u8; 16];
        pbkdf2_hmac::<Sha1>(&password, b"saltysalt", 1003, &mut key);
        Ok(key)
    }

    fn decode_cookie(host: &str, version: i64, encrypted: &[u8], key: &[u8; 16]) -> Result<String, String> {
        if !encrypted.starts_with(b"v10") { return Err("不支持此 Chrome Cookie 加密格式".to_string()); }
        let mut bytes = encrypted[3..].to_vec();
        let plaintext = cbc::Decryptor::<Aes128>::new(key.into(), (&[b' '; 16]).into())
            .decrypt_padded_mut::<Pkcs7>(&mut bytes)
            .map_err(|_| "解密 Qoder Cookie 失败".to_string())?;
        let plaintext = if version >= 24 {
            let digest = Sha256::digest(host.as_bytes());
            if !plaintext.starts_with(&digest) { return Err("Qoder Cookie 域名校验失败".to_string()); }
            &plaintext[32..]
        } else { plaintext };
        String::from_utf8(plaintext.to_vec()).map_err(|_| "Qoder Cookie 格式无效".to_string())
    }

    fn read_profile(path: &Path, domain: &str, key: &mut Option<Result<[u8; 16], String>>) -> Result<Option<String>, String> {
        let snapshot = snapshot_database(path)?;
        let connection = Connection::open(snapshot.0.join("Cookies"))
            .map_err(|_| "打开 Cookie 临时副本失败".to_string())?;
        connection.busy_timeout(Duration::from_secs(2)).map_err(|_| "读取 Cookie 超时".to_string())?;
        // This schema read performs recovery on the copy before query_only.
        connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
            .map_err(|_| "恢复 Cookie 临时副本失败".to_string())?;
        connection.pragma_update(None, "query_only", true).map_err(|_| "设置 Cookie 只读查询失败".to_string())?;
        let version: i64 = connection.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'version'", [], |row| row.get(0))
            .map_err(|_| "读取 Chrome Cookie 版本失败".to_string())?;
        let now = (chrono::Utc::now().timestamp() + 11_644_473_600) * 1_000_000;
        let mut statement = connection.prepare(
            "SELECT host_key, name, value, encrypted_value FROM cookies
             WHERE host_key IN (?1, ?2) AND path IN ('/', '/api', '/api/')
             AND (expires_utc = 0 OR expires_utc > ?3) ORDER BY length(path) DESC, name LIMIT 128"
        ).map_err(|_| "查询 Qoder Cookie 失败".to_string())?;
        let rows = statement.query_map(rusqlite::params![domain, format!(".{domain}"), now], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?))
        }).map_err(|_| "查询 Qoder Cookie 失败".to_string())?;
        let mut pairs = Vec::new();
        for row in rows {
            let (host, name, value, encrypted) = row.map_err(|_| "读取 Qoder Cookie 失败".to_string())?;
            let value = if encrypted.is_empty() { value } else {
                if key.is_none() { *key = Some(chrome_key()); }
                let key = key.as_ref().ok_or("Chrome Cookie 密钥不可用")?
                    .as_ref().map_err(|error| error.clone())?;
                decode_cookie(&host, version, &encrypted, key)?
            };
            if super::valid_pair(&name, &value) { pairs.push(format!("{name}={value}")); }
        }
        Ok((!pairs.is_empty()).then(|| pairs.join("; ")))
    }

    pub(super) fn candidates(domain: &str) -> Result<Vec<String>, String> {
        let root = dirs::home_dir().ok_or("无法定位 Chrome 用户目录")?
            .join("Library/Application Support/Google/Chrome");
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(chrome_read_error("读取 Chrome Profile 列表失败", &error)),
        };
        let mut profiles = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| chrome_read_error("读取 Chrome Profile 失败", &error))?;
            let is_profile = {
                let name = entry.file_name().to_string_lossy().into_owned();
                name == "Default" || name.strip_prefix("Profile ").is_some_and(|index| index.parse::<u32>().is_ok())
            };
            if is_profile && entry.file_type().map_err(|error| chrome_read_error("读取 Chrome Profile 类型失败", &error))?.is_dir() {
                profiles.push(entry.path());
            }
        }
        profiles.sort();
        let mut result = Vec::new();
        let mut key = None;
        let mut last_error = None;
        for profile in profiles {
            let mut path = None;
            for candidate in [profile.join("Cookies"), profile.join("Network/Cookies")] {
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.is_file() => { path = Some(candidate); break; },
                    Ok(_) => {},
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                    Err(error) => last_error = Some(chrome_read_error("读取 Chrome Cookie 文件失败", &error)),
                }
            }
            let Some(path) = path else { continue; };
            match read_profile(&path, domain, &mut key) {
                Ok(Some(cookie)) => result.push(cookie),
                Ok(None) => {},
                Err(error) => last_error = Some(error),
            }
        }
        if result.is_empty() {
            if let Some(error) = last_error { return Err(error); }
        }
        Ok(result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use cbc::cipher::BlockEncryptMut;

        #[test]
        fn privacy_denial_is_actionable_and_not_reported_as_missing_cookie() {
            for code in [1, 13] {
                let message = chrome_read_error("读取 Chrome Profile 列表失败", &std::io::Error::from_raw_os_error(code));
                assert!(message.contains("macOS 拒绝读取 Chrome 数据"));
                assert!(message.contains("允许当前运行的 Cockpit"));
                assert!(!message.contains("未找到"));
            }
            assert!(chrome_read_error("读取失败", &std::io::Error::from_raw_os_error(5)).contains("系统错误码：5"));
        }

        #[test]
        fn chromium_v24_cookie_is_bound_to_its_original_domain() {
            let key = [7u8; 16];
            let mut plaintext = Sha256::digest(b".qoder.cn").to_vec();
            plaintext.extend_from_slice(b"synthetic-cookie");
            let size = plaintext.len();
            plaintext.resize(size + 16, 0);
            let ciphertext = cbc::Encryptor::<Aes128>::new((&key).into(), (&[b' '; 16]).into())
                .encrypt_padded_mut::<Pkcs7>(&mut plaintext, size).unwrap();
            let mut encrypted = b"v10".to_vec();
            encrypted.extend_from_slice(ciphertext);
            assert_eq!(decode_cookie(".qoder.cn", 24, &encrypted, &key).unwrap(), "synthetic-cookie");
            assert!(decode_cookie(".qoder.com", 24, &encrypted, &key).is_err());
        }

        #[test]
        fn snapshot_queries_only_unexpired_same_site_api_cookies() {
            let directory = std::env::temp_dir().join(format!("qoder-cookie-fixture-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            let guard = Snapshot(directory);
            let path = guard.0.join("Cookies");
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch("CREATE TABLE meta (key TEXT, value TEXT);
                INSERT INTO meta VALUES ('version', '24');
                CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER);
                INSERT INTO cookies VALUES ('.qoder.cn', 'session', 'fixture-cn', X'', '/', 0);
                INSERT INTO cookies VALUES ('.qoder.com', 'session', 'fixture-intl', X'', '/', 0);
                INSERT INTO cookies VALUES ('.example.invalid', 'private', 'unrelated-fixture', X'', '/', 0);
                INSERT INTO cookies VALUES ('.qoder.cn', 'expired', 'old', X'', '/', 1);
                INSERT INTO cookies VALUES ('.qoder.cn', 'login-only', 'login', X'', '/users', 0);").unwrap();
            drop(connection);
            assert_eq!(read_profile(&path, "qoder.cn", &mut None).unwrap().as_deref(), Some("session=fixture-cn"));
            assert_eq!(read_profile(&path, "qoder.com", &mut None).unwrap().as_deref(), Some("session=fixture-intl"));
            assert!(path.exists(), "the original Chrome database must remain intact");
            assert!(!guard.0.join("Cookies-shm").exists());
        }
    }
}

pub(crate) fn valid_pair(name: &str, value: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && !value.bytes().any(|b| b <= 0x20 || b >= 0x7f || b == b';')
}

pub(crate) fn candidates(is_cn: bool) -> Result<Vec<String>, String> {
    #[cfg(target_os = "macos")]
    { macos::candidates(if is_cn { "qoder.cn" } else { "qoder.com" }) }
    #[cfg(not(target_os = "macos"))]
    { let _ = is_cn; Ok(Vec::new()) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cookie_pairs_cannot_inject_headers_or_other_pairs() {
        assert!(super::valid_pair("session", "fixture-value"));
        assert!(!super::valid_pair("session", "value\r\nAuthorization: injected"));
        assert!(!super::valid_pair("session", "value; other=secret"));
        assert!(!super::valid_pair("bad=name", "value"));
    }
}
