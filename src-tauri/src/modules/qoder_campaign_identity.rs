//! Qoder OAuth Owner 的地区活动身份：国际版使用参考 UMID 协议，国内版使用官方 CN 桥接工具。
//! 身份按地区和用户 ID 缓存，查询与领取复用，不读取或改写官方客户端登录文件。

use super::{normalize_non_empty, QoderMachineInfo, QoderVariantParams};
use crate::models::qoder::QoderAccount;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[path = "qoder_cn_campaign_identity.rs"]
mod cn;
#[path = "qoder_umid_codec.rs"]
mod codec;

const IDENTITY_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const CN_IDENTITY_TTL: Duration = Duration::from_secs(60 * 60);
const UMID_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CACHED_IDENTITIES: usize = 256;
pub(super) const CAMPAIGN_CLIENT_VERSION: &str = "0.4.3";

pub(super) fn cn_machine_id() -> Result<String, String> {
    cn::machine_id()
}

// The reference protocol uses HTTP. Its fixed-key codec does not authenticate
// the server or protect transport integrity; a supported HTTPS endpoint is unconfirmed.
const UMID_ENDPOINT: &str = "http://us-pum.alibabachengdun.com/repPc.json?e=1000&pn=runtime-info-linux&os=8&sv=1.5.0&pv=NA&pt=1";
const UMID_USER_AGENT: &str = "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.2.3) Gecko/20100401 Firefox/3.6.3 SG/1.0.0";

struct CachedIdentity {
    acquired_at: Instant,
    ttl: Duration,
    info: QoderMachineInfo,
}

// 查询与领取由调用方的账号锁串行化；此锁只保护缓存读写，不跨工具或网络等待。
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
) -> Result<QoderMachineInfo, String> {
    resolve_with(params, account, |uid| async move {
        if params.kind.is_cn() {
            Ok(cn::acquire(&uid).await)
        } else {
            acquire_identity(&uid).await
        }
    })
    .await
}

async fn resolve_with<F, Fut>(
    params: &QoderVariantParams,
    account: &QoderAccount,
    acquire: F,
) -> Result<QoderMachineInfo, String>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<QoderMachineInfo, String>>,
{
    let uid = account
        .user_id
        .as_deref()
        .and_then(|value| normalize_non_empty(Some(value)))
        .ok_or("Qoder 活动请求缺少已确认的用户 ID")?;
    let key = format!("{}:{}", params.site, uid);
    {
        let mut cache = IDENTITIES.lock().await;
        cache.retain(|_, identity| identity.acquired_at.elapsed() < identity.ttl);
        if let Some(identity) = cache.get(&key) {
            return Ok(identity.info.clone());
        }
    }
    let info = acquire(uid).await?;
    // 官方 CN 工具是可选能力；失败时保留基础请求头，后续请求仍可重新尝试工具。
    if params.kind.is_cn() && info.token.is_empty() {
        return Ok(info);
    }
    let mut cache = IDENTITIES.lock().await;
    cache.retain(|_, identity| identity.acquired_at.elapsed() < identity.ttl);
    if let Some(identity) = cache.get(&key) {
        return Ok(identity.info.clone());
    }
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
            ttl: if params.kind.is_cn() {
                CN_IDENTITY_TTL
            } else {
                IDENTITY_TTL
            },
            info: info.clone(),
        },
    );
    Ok(info)
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

    #[tokio::test]
    async fn pending_cn_campaign_identity_does_not_block_a_cached_international_account() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let uid = format!("fixture-concurrent-{}", uuid::Uuid::new_v4());
        let target = account(Some(&uid));
        let cn_params = resolve_qoder_variant_params("qoder_cn_app").unwrap();
        let intl_params = resolve_qoder_variant_params("qoder_app").unwrap();
        let info = QoderMachineInfo {
            token: "fixture-intl-token".into(),
            machine_type: None,
            machine_code: None,
            machine_id: None,
            machine_hostname: None,
            machine_os: None,
            cosy_version: None,
        };
        let key = format!("intl:{uid}");
        IDENTITIES.lock().await.insert(
            key.clone(),
            CachedIdentity {
                acquired_at: Instant::now(),
                ttl: IDENTITY_TTL,
                info,
            },
        );
        let release = tokio::sync::Notify::new();
        let mut pending_cn = Box::pin(resolve_with(&cn_params, &target, |_| async {
            release.notified().await;
            Err("fixture CN SDK stopped".into())
        }));
        poll_fn(|cx| {
            assert!(pending_cn.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        let cached =
            tokio::time::timeout(Duration::from_secs(1), resolve(&intl_params, &target)).await;
        // Always release the controlled SDK before asserting, including on a regression.
        release.notify_one();
        assert!(pending_cn.await.is_err());
        IDENTITIES.lock().await.remove(&key);
        assert_eq!(
            cached
                .expect("pending CN SDK must not block an international cache hit")
                .unwrap()
                .token,
            "fixture-intl-token"
        );
    }

    #[tokio::test]
    async fn cn_campaigns_retry_optional_identity_while_international_errors_stay_errors() {
        let uid = format!("fixture-retry-{}", uuid::Uuid::new_v4());
        let target = account(Some(&uid));
        let cn = resolve_qoder_variant_params("qoder_cn_app").unwrap();
        let intl = resolve_qoder_variant_params("qoder_app").unwrap();
        let base = QoderMachineInfo {
            token: String::new(),
            machine_type: None,
            machine_code: None,
            machine_id: Some("fixture-stable-id".into()),
            machine_hostname: None,
            machine_os: Some("aarch64_darwin".into()),
            cosy_version: Some("0.4.3".into()),
        };
        let partial = resolve_with(&cn, &target, |_| async { Ok(base.clone()) })
            .await
            .unwrap();
        assert!(
            partial.token.is_empty(),
            "CN requests may continue without a native token"
        );
        let complete = QoderMachineInfo {
            token: "fixture-recovered-token".into(),
            ..base
        };
        let recovered = resolve_with(&cn, &target, |_| async { Ok(complete) })
            .await
            .unwrap();
        assert_eq!(
            recovered.token, "fixture-recovered-token",
            "optional failures must not be cached"
        );
        let ide = resolve_qoder_variant_params("qoder_cn_ide").unwrap();
        assert_eq!(
            resolve_with(&ide, &target, |_| async {
                panic!("query and claim must reuse the regional account identity");
            })
            .await
            .unwrap()
            .token,
            recovered.token
        );
        assert_eq!(
            resolve_with(&intl, &target, |_| async {
                Err("fixture UMID failure".into())
            })
            .await
            .unwrap_err(),
            "fixture UMID failure"
        );
        let mut cache = IDENTITIES.lock().await;
        assert!(!cache.contains_key(&format!("intl:{uid}")));
        cache.remove(&format!("cn:{uid}"));
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
                ttl: IDENTITY_TTL,
                info: info.clone(),
            },
        );
        for variant in ["qoder", "qoder_app"] {
            let params = resolve_qoder_variant_params(variant).unwrap();
            let resolved = resolve(&params, &account(Some(&uid))).await.unwrap();
            assert_eq!(resolved.machine_id, info.machine_id);
            assert_eq!(resolved.token, info.token);
            assert_eq!(resolved.machine_os.as_deref(), Some("x86_64_linux"));
        }
        IDENTITIES.lock().await.remove(&key);
    }

    #[tokio::test]
    async fn missing_uid_fails_before_external_identity_acquisition_in_every_region() {
        for variant in ["qoder", "qoder_app", "qoder_cn_app", "qoder_cn_ide"] {
            let params = resolve_qoder_variant_params(variant).unwrap();
            assert!(resolve(&params, &account(None))
                .await
                .unwrap_err()
                .contains("用户 ID"));
        }
    }

    #[tokio::test]
    async fn cn_clients_reuse_their_accounts_identity_without_using_the_international_cache() {
        let uid = format!("fixture-{}", uuid::Uuid::new_v4());
        let make_identity = |token: &str, os: &str| QoderMachineInfo {
            token: token.into(),
            machine_type: Some("fixture-type".into()),
            machine_code: Some("fixture-code".into()),
            machine_id: Some(uuid::Uuid::new_v4().to_string()),
            machine_hostname: Some("fixture-host".into()),
            machine_os: Some(os.into()),
            cosy_version: Some(CAMPAIGN_CLIENT_VERSION.into()),
        };
        for (site, token, os) in [
            ("cn", "fixture-cn-token", "aarch64_darwin"),
            ("intl", "fixture-intl-token", "x86_64_linux"),
        ] {
            IDENTITIES.lock().await.insert(
                format!("{site}:{uid}"),
                CachedIdentity {
                    acquired_at: Instant::now(),
                    ttl: CN_IDENTITY_TTL,
                    info: make_identity(token, os),
                },
            );
        }
        for variant in ["qoder_cn_app", "qoder_cn_ide", "qoder_app", "qoder"] {
            let params = resolve_qoder_variant_params(variant).unwrap();
            let identity = resolve(&params, &account(Some(&uid))).await.unwrap();
            assert_eq!(
                identity.token,
                if params.kind.is_cn() {
                    "fixture-cn-token"
                } else {
                    "fixture-intl-token"
                }
            );
            assert_eq!(
                identity.machine_os.as_deref(),
                Some(if params.kind.is_cn() {
                    "aarch64_darwin"
                } else {
                    "x86_64_linux"
                })
            );
        }
        let mut cache = IDENTITIES.lock().await;
        cache.remove(&format!("cn:{uid}"));
        cache.remove(&format!("intl:{uid}"));
    }
}
