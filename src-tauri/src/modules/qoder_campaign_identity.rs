//! Qoder OAuth Owner 的国际活动身份；协议与 cpa-workbuddy-plugin@806c61f/qoder-ai 对齐。
//! 身份按官方用户 ID 获取和缓存，查询与领取复用，不读取官方客户端的机器 ID 或登录文件。

use super::{normalize_non_empty, QoderMachineInfo, QoderVariantParams};
use crate::models::qoder::QoderAccount;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[path = "qoder_umid_codec.rs"]
mod codec;

const IDENTITY_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const UMID_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CACHED_IDENTITIES: usize = 256;
pub(super) const CAMPAIGN_CLIENT_VERSION: &str = "0.4.3";
// The reference protocol uses HTTP. Its fixed-key codec does not authenticate
// the server or protect transport integrity; a supported HTTPS endpoint is unconfirmed.
const UMID_ENDPOINT: &str = "http://us-pum.alibabachengdun.com/repPc.json?e=1000&pn=runtime-info-linux&os=8&sv=1.5.0&pv=NA&pt=1";
const UMID_USER_AGENT: &str = "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 SG/1.0.0";

struct CachedIdentity {
    acquired_at: Instant,
    info: QoderMachineInfo,
}

// 同一 Owner 串行取得身份，避免并发的首次查询与领取使用不同响应。
// 这里只缓存设备身份，AT/RT 始终由账号 Owner 管理。
static IDENTITIES: std::sync::LazyLock<tokio::sync::Mutex<HashMap<String, CachedIdentity>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(HashMap::new()));

#[derive(Deserialize)]
struct UmidResponse {
    ec: i64,
    dt: String,
}

fn identity_from_response(
    seed: &str,
    hostname: String,
    body: &[u8],
) -> Result<QoderMachineInfo, String> {
    let response: UmidResponse =
        serde_json::from_slice(body).map_err(|_| "Qoder UMID 服务响应格式无效".to_string())?;
    if response.ec != 200 || response.dt.is_empty() {
        return Err(format!(
            "Qoder UMID 服务未签发设备令牌 (ec={})",
            response.ec
        ));
    }
    let token = codec::decrypt_response(&response.dt)?;
    let (machine_type, machine_code) = codec::derive_codes(&token, 91, 0);
    Ok(QoderMachineInfo {
        token,
        machine_type: Some(machine_type),
        machine_code: Some(machine_code),
        machine_id: Some(codec::machine_id(seed)),
        machine_hostname: Some(hostname),
        machine_os: Some("x86_64_linux".into()),
        cosy_version: Some(CAMPAIGN_CLIENT_VERSION.into()),
    })
}

async fn acquire_identity(uid: &str) -> Result<QoderMachineInfo, String> {
    // 与参考实现的初始身份使用同一种稳定种子；不把 AT、RT 或本机硬件数据发给 UMID。
    let seed = format!("{}#0", uid);
    let packet = codec::build_request(&seed, chrono::Utc::now().timestamp_millis())?;
    let client = reqwest::Client::builder()
        .timeout(UMID_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "创建 Qoder UMID HTTP 客户端失败".to_string())?;
    let mut response = client
        .post(UMID_ENDPOINT)
        .header(reqwest::header::USER_AGENT, UMID_USER_AGENT)
        .header(reqwest::header::CONTENT_TYPE, "text/plain;charset=UTF-8")
        .body(packet.body)
        .send()
        .await
        .map_err(|error| format!("申请 Qoder UMID 设备身份失败：{}", error.without_url()))?;
    if !response.status().is_success() {
        return Err(format!(
            "Qoder UMID 服务请求失败 (HTTP {})",
            response.status()
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "读取 Qoder UMID 服务响应失败".to_string())?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err("Qoder UMID 服务响应超过大小限制".into());
        }
        body.extend_from_slice(&chunk);
    }
    identity_from_response(&seed, packet.hostname, &body)
}

pub(super) async fn resolve(
    params: &QoderVariantParams,
    account: &QoderAccount,
) -> Result<Option<QoderMachineInfo>, String> {
    // CN 活动保持其现有请求契约；本模块对齐 qoder-ai 国际活动协议。
    if params.kind.is_cn() {
        return Ok(None);
    }
    let uid = account
        .user_id
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)))
        .ok_or("Qoder 活动请求缺少已确认的用户 ID")?;
    let key = format!("{}:{}", params.site, uid);
    let mut cache = IDENTITIES.lock().await;
    cache.retain(|_, identity| identity.acquired_at.elapsed() < IDENTITY_TTL);
    if let Some(identity) = cache.get(&key) {
        return Ok(Some(identity.info.clone()));
    }
    let info = acquire_identity(&uid).await?;
    if cache.len() >= MAX_CACHED_IDENTITIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, value)| value.acquired_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        key,
        CachedIdentity {
            acquired_at: Instant::now(),
            info: info.clone(),
        },
    );
    Ok(Some(info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::qoder_oauth::resolve_qoder_variant_params;

    fn account(uid: Option<&str>) -> QoderAccount {
        serde_json::from_value(serde_json::json!({
            "id": "fixture-account", "email": "fixture@example.invalid",
            "variant": "qoder_app", "created_at": 0, "last_used": 0, "user_id": uid,
        }))
        .unwrap()
    }

    #[test]
    fn incomplete_or_rejected_issuance_does_not_create_an_identity() {
        for body in [
            r#"{}"#,
            r#"{"ec":200}"#,
            r#"{"ec":200,"dt":""}"#,
            r#"{"ec":403,"dt":"invalid"}"#,
            r#"{"ec":200,"dt":"invalid"}"#,
        ] {
            assert!(
                identity_from_response("fixture#0", "fixture-host".into(), body.as_bytes())
                    .is_err()
            );
        }
    }

    #[test]
    fn issued_identity_uses_the_references_account_seed_and_platform() {
        // 由独立 AES 实现为虚构 eeid 生成，不包含真实设备或账号凭据。
        let body = br#"{"ec":200,"dt":"AQWQ4eIMHDiURmmVA0awEeQpLa8k3G2kVCGu3TzzikBRBzOtZazWbMFmqK+EXXNTqg=="}"#;
        let first =
            identity_from_response("fixture-user-a#0", "fixture-host-a".into(), body).unwrap();
        let other =
            identity_from_response("fixture-user-b#0", "fixture-host-b".into(), body).unwrap();
        assert_eq!(first.token, "fixture-machine-token");
        assert_eq!(first.machine_os.as_deref(), Some("x86_64_linux"));
        assert_eq!(first.cosy_version.as_deref(), Some("0.4.3"));
        assert_eq!(first.machine_hostname.as_deref(), Some("fixture-host-a"));
        assert_eq!(
            first.machine_type.as_ref().map(|value| &value[8..10]),
            Some("91")
        );
        assert_eq!(
            first.machine_code.as_ref().map(|value| &value[8..10]),
            Some("00")
        );
        assert_ne!(first.machine_id, other.machine_id);
        assert_ne!(first.machine_hostname, other.machine_hostname);
    }

    #[tokio::test]
    async fn regional_clients_share_only_the_same_accounts_cached_identity() {
        let uid = format!("fixture-{}", uuid::Uuid::new_v4());
        let info = QoderMachineInfo {
            token: "fixture-machine-token".into(),
            machine_type: Some("fixture-machine-type".into()),
            machine_code: Some("fixture-machine-code".into()),
            machine_id: Some(codec::machine_id(&format!("{}#0", uid))),
            machine_hostname: Some("fixture-account-host".into()),
            machine_os: Some("x86_64_linux".into()),
            cosy_version: Some(CAMPAIGN_CLIENT_VERSION.into()),
        };
        let key = format!("intl:{}", uid);
        IDENTITIES.lock().await.insert(
            key.clone(),
            CachedIdentity {
                acquired_at: Instant::now(),
                info: info.clone(),
            },
        );
        for variant in ["qoder", "qoder_app"] {
            let params = resolve_qoder_variant_params(variant).unwrap();
            let resolved = resolve(&params, &account(Some(&uid)))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(resolved.machine_id, info.machine_id);
            assert_eq!(resolved.token, info.token);
            assert_eq!(resolved.machine_os.as_deref(), Some("x86_64_linux"));
        }
        IDENTITIES.lock().await.remove(&key);
    }

    #[tokio::test]
    async fn missing_uid_fails_before_network_and_cn_needs_no_umid() {
        let intl = resolve_qoder_variant_params("qoder_app").unwrap();
        assert!(resolve(&intl, &account(None))
            .await
            .unwrap_err()
            .contains("用户 ID"));
        for variant in ["qoder_cn_app", "qoder_cn_ide"] {
            let cn = resolve_qoder_variant_params(variant).unwrap();
            assert!(resolve(&cn, &account(None)).await.unwrap().is_none());
        }
    }
}
