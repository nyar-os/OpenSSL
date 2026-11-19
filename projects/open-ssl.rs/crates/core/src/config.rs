//! 项目签发配置：把 provider、zone、directory 与联系人从命令行挪进配置文件。
//!
//! 配置文件是项目根的 `open-ssl.json`（非秘密，可随项目提交）。用户日常只需要记
//! 域名；旗标永远是显式覆盖，优先级固定为 旗标 > 配置 > 默认值（`manual` 交互式
//! 与 `staging`）。文件不存在就是“没有配置”，不是错误；文件存在但不合 `/v0` 合同
//! 则是明确失败，不静默忽略任何字段。

use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, Result, dns::credentials::ProjectRoot, state::DirectoryKind};

/// 本 crate 唯一接受的配置 schema。
pub const CONFIG_SCHEMA: &str = "open-ssl/config/v0";

/// 项目根的配置文件名。
const CONFIG_FILE: &str = "open-ssl.json";

/// 管理 Cloudflare zone 的方式，二选一。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ZoneSelection {
    /// 按 zone id 管理。
    #[serde(default)]
    pub id: Option<String>,
    /// 按 zone 名管理。
    #[serde(default)]
    pub name: Option<String>,
}

/// 一次签发在配置里的默认值，全部可缺省。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueConfig {
    /// 必须是 [`CONFIG_SCHEMA`]。
    pub schema: String,
    /// 默认 DNS provider id。
    #[serde(default)]
    pub dns_provider: Option<String>,
    /// 默认 ACME directory。
    #[serde(default)]
    pub kind: Option<DirectoryKind>,
    /// 默认 zone 管理方式。
    #[serde(default)]
    pub zone: Option<ZoneSelection>,
    /// 默认账户联系人。
    #[serde(default)]
    pub contact: Vec<String>,
}

impl IssueConfig {
    /// 该项目的配置文件位置。
    #[must_use]
    pub fn file(project: &ProjectRoot) -> PathBuf {
        project.as_path().join(CONFIG_FILE)
    }

    /// 读取项目配置；文件不存在返回 `Ok(None)`。
    ///
    /// 不是合法 JSON、schema 不符、含未知字段或 zone 同时给出 id 与 name 都按合同
    /// 明确失败，绝不静默降级成空配置。
    pub fn load(project: &ProjectRoot) -> Result<Option<Self>> {
        let file = Self::file(project);
        let text = match fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(Error::new(ErrorCode::Io, format!("项目配置文件 `{}` 无法读取：{error}", file.display())));
            }
        };
        let config: Self = serde_json::from_str(&text).map_err(|error| {
            Error::new(ErrorCode::Protocol, format!("项目配置文件 `{}` 不符合 `{CONFIG_SCHEMA}` 合同：{error}", file.display()))
        })?;
        config.validate(&file)?;
        Ok(Some(config))
    }

    fn validate(&self, file: &Path) -> Result<()> {
        if self.schema != CONFIG_SCHEMA {
            return Err(Error::new(ErrorCode::Protocol, format!("项目配置文件 `{}` 没有声明 `{CONFIG_SCHEMA}` schema", file.display())));
        }
        if let Some(provider) = &self.dns_provider {
            if provider.trim().is_empty() {
                return Err(Error::new(ErrorCode::Protocol, format!("项目配置文件 `{}` 的 `dnsProvider` 为空", file.display())));
            }
        }
        if let Some(zone) = &self.zone {
            let id_set = zone.id.as_deref().is_some_and(|value| !value.trim().is_empty());
            let name_set = zone.name.as_deref().is_some_and(|value| !value.trim().is_empty());
            if id_set && name_set {
                return Err(Error::new(ErrorCode::Protocol, format!("项目配置文件 `{}` 的 `zone` 同时给出了 `id` 与 `name`", file.display())));
            }
            for field in ["id", "name"] {
                let raw = if field == "id" { zone.id.as_deref() } else { zone.name.as_deref() };
                if raw.is_some_and(|value| value.trim().is_empty()) {
                    return Err(Error::new(
                        ErrorCode::Protocol,
                        format!("项目配置文件 `{}` 的 `zone.{field}` 是空字符串；填写实际值或删掉该字段", file.display()),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// 解析后的签发目标：旗标、配置与默认值合并后的唯一形状。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// 目标 ACME directory。
    pub kind: DirectoryKind,
    /// DNS provider id。
    pub dns_provider: String,
    /// Cloudflare zone id。
    pub zone_id: Option<String>,
    /// Cloudflare zone 名。
    pub zone_name: Option<String>,
    /// 账户联系人。
    pub contact: Vec<String>,
}

impl fmt::Display for ResolvedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} via {}", self.kind.as_str(), self.dns_provider)
    }
}
