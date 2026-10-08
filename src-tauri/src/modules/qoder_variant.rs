// Qoder 变体矩阵：四变体身份与站点 / 通道 / 显示名映射（结构对齐 TraePlatformKind）。
// 仅承载身份与显示名；端点 / 路径 / 凭证键参数由平台模块维护，不在此硬编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoderSite {
    Intl,
    Cn,
}

impl QoderSite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intl => "intl",
            Self::Cn => "cn",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoderChannel {
    Ide,
    App,
}

impl QoderChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ide => "ide",
            Self::App => "app",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QoderVariantKind {
    Qoder,
    QoderApp,
    QoderCnIde,
    QoderCnApp,
}

impl QoderVariantKind {
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let normalized = raw
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("qoder")
            .to_ascii_lowercase()
            .replace('-', "_");
        match normalized.as_str() {
            "qoder" => Ok(Self::Qoder),
            "qoder_app" => Ok(Self::QoderApp),
            "qoder_cn_ide" => Ok(Self::QoderCnIde),
            "qoder_cn_app" => Ok(Self::QoderCnApp),
            other => Err(format!("不支持的 Qoder 变体: {}", other)),
        }
    }

    pub fn provider_key(self) -> &'static str {
        match self {
            Self::Qoder => "qoder",
            Self::QoderApp => "qoder_app",
            Self::QoderCnIde => "qoder_cn_ide",
            Self::QoderCnApp => "qoder_cn_app",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::Qoder => "Qoder IDE",
            Self::QoderApp => "Qoder",
            Self::QoderCnIde => "Qoder CN IDE",
            Self::QoderCnApp => "Qoder CN",
        }
    }

    pub fn site(self) -> QoderSite {
        match self {
            Self::Qoder | Self::QoderApp => QoderSite::Intl,
            Self::QoderCnIde | Self::QoderCnApp => QoderSite::Cn,
        }
    }

    pub fn channel(self) -> QoderChannel {
        match self {
            Self::Qoder | Self::QoderCnIde => QoderChannel::Ide,
            Self::QoderApp | Self::QoderCnApp => QoderChannel::App,
        }
    }

    pub fn is_cn(self) -> bool {
        self.site() == QoderSite::Cn
    }

    pub fn is_app(self) -> bool {
        self.channel() == QoderChannel::App
    }

    /// 实例管理（应用多开）仅服务 IDE 系变体：App 系客户端受官方单实例机制限制，
    /// 无法同时运行多个登录态（`--user-data-dir` 与 e2e 旁路均被客户端显式封禁）。
    pub fn supports_instances(self) -> bool {
        !self.is_app()
    }
}

pub fn all_qoder_variant_kinds() -> [QoderVariantKind; 4] {
    [
        QoderVariantKind::Qoder,
        QoderVariantKind::QoderApp,
        QoderVariantKind::QoderCnIde,
        QoderVariantKind::QoderCnApp,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qoder_variant_matrix_qoder_intl_ide() {
        let kind = QoderVariantKind::parse(Some("qoder")).expect("parse qoder");
        assert_eq!(kind, QoderVariantKind::Qoder);
        assert_eq!(kind.provider_key(), "qoder");
        assert_eq!(kind.display_name(), "Qoder IDE");
        assert_eq!(kind.site(), QoderSite::Intl);
        assert_eq!(kind.channel(), QoderChannel::Ide);
        assert!(!kind.is_cn());
        assert!(!kind.is_app());
        println!(
            "matrix qoder -> display={} site={} channel={}",
            kind.display_name(),
            kind.site().as_str(),
            kind.channel().as_str()
        );
    }

    #[test]
    fn qoder_variant_matrix_qoder_app() {
        let kind = QoderVariantKind::parse(Some("qoder_app")).expect("parse qoder_app");
        assert_eq!(kind, QoderVariantKind::QoderApp);
        assert_eq!(kind.provider_key(), "qoder_app");
        assert_eq!(kind.display_name(), "Qoder");
        assert_eq!(kind.site(), QoderSite::Intl);
        assert_eq!(kind.channel(), QoderChannel::App);
        assert!(!kind.is_cn());
        assert!(kind.is_app());
        println!(
            "matrix qoder_app -> display={} site={} channel={}",
            kind.display_name(),
            kind.site().as_str(),
            kind.channel().as_str()
        );
    }

    #[test]
    fn qoder_variant_matrix_qoder_cn_ide() {
        let kind = QoderVariantKind::parse(Some("qoder_cn_ide")).expect("parse qoder_cn_ide");
        assert_eq!(kind, QoderVariantKind::QoderCnIde);
        assert_eq!(kind.provider_key(), "qoder_cn_ide");
        assert_eq!(kind.display_name(), "Qoder CN IDE");
        assert_eq!(kind.site(), QoderSite::Cn);
        assert_eq!(kind.channel(), QoderChannel::Ide);
        assert!(kind.is_cn());
        assert!(!kind.is_app());
        println!(
            "matrix qoder_cn_ide -> display={} site={} channel={}",
            kind.display_name(),
            kind.site().as_str(),
            kind.channel().as_str()
        );
    }

    #[test]
    fn qoder_variant_matrix_qoder_cn_app() {
        let kind = QoderVariantKind::parse(Some("qoder_cn_app")).expect("parse qoder_cn_app");
        assert_eq!(kind, QoderVariantKind::QoderCnApp);
        assert_eq!(kind.provider_key(), "qoder_cn_app");
        assert_eq!(kind.display_name(), "Qoder CN");
        assert_eq!(kind.site(), QoderSite::Cn);
        assert_eq!(kind.channel(), QoderChannel::App);
        assert!(kind.is_cn());
        assert!(kind.is_app());
        println!(
            "matrix qoder_cn_app -> display={} site={} channel={}",
            kind.display_name(),
            kind.site().as_str(),
            kind.channel().as_str()
        );
    }

    #[test]
    fn qoder_variant_matrix_rejects_unknown_key() {
        let error = QoderVariantKind::parse(Some("qoder_eu")).expect_err("unknown key must error");
        assert!(
            error.contains("不支持的 Qoder 变体"),
            "unexpected error message: {error}"
        );
        assert!(error.contains("qoder_eu"));
        // 连字符别名与默认空输入同样可解析（镜像 TraePlatformKind 行为）。
        assert_eq!(
            QoderVariantKind::parse(Some("qoder-cn-ide")).expect("hyphen alias"),
            QoderVariantKind::QoderCnIde
        );
        assert_eq!(
            QoderVariantKind::parse(None).expect("default key"),
            QoderVariantKind::Qoder
        );
        assert_eq!(all_qoder_variant_kinds().len(), 4);
        println!("matrix unknown key -> error={error}");
    }
}
