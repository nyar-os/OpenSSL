//! 项目级 DNS 凭证：每个项目只读自己的一个文件。
//!
//! 唯一接受的来源是 `<projectRoot>/.secrets/open-ssl.json`，项目根始终由调用方显式给出。
//! 这里不做环境变量查找、不向父目录遍历、不读取共享或用户级秘密文件：没有秘密文件的项目
//! 直接失败，而不是悄悄借用另一个项目的 token。
//!
//! 文档形状是 `/v0` 合同：
//!
//! ```json
//! { "schema": "open-ssl/secrets/v0", "dns": { "cloudflare": { "apiToken": "..." } } }
//! ```
//!
//! token 不会出现在错误、调试输出或审计记录里。

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

use crate::errors::{Error, ErrorCode, Result};

/// 拒绝把自己渲染出来的凭证值。
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// 包装一个原始凭证值。
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 取出原始值，只供拼装那一个请求头的代码使用。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(<redacted>)")
    }
}

/// 项目秘密所在的目录，相对项目根。
const SECRETS_DIR: &str = ".secrets";
/// 本 crate 唯一读取的秘密文件名。
const SECRETS_FILE: &str = "open-ssl.json";
/// 项目私有状态目录，与输入凭证并列但分开。
const STATE_DIR: &str = "open-ssl";
/// 本 crate 唯一接受的秘密 schema。
pub const SECRETS_SCHEMA: &str = "open-ssl/secrets/v0";

/// 已规范化的项目根：所有秘密路径都由它派生。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRoot {
    path: PathBuf,
}

impl ProjectRoot {
    /// 把已存在的目录规范化为项目根。
    ///
    /// 路径不存在或无法解析属于 [`ErrorCode::Io`]，因为这是本进程无法使用的地址。
    /// 路径存在但不是目录属于 [`ErrorCode::InvalidArgument`]，因为参数形状不符合要求。
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let canonical =
            fs::canonicalize(path).map_err(|error| Error::new(ErrorCode::Io, format!("项目根目录 `{}` 无法解析：{error}", path.display())))?;
        if !canonical.is_dir() {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("项目根路径 `{}` 不是目录", canonical.display())));
        }
        Ok(Self { path: display_canonical(canonical) })
    }

    /// 精确使用当前工作目录作为项目根。
    ///
    /// 不向上搜索，因此在子目录中启动的进程把该子目录当成自己的项目。
    pub fn from_current_dir() -> Result<Self> {
        let directory = std::env::current_dir().map_err(|error| Error::new(ErrorCode::Io, format!("当前工作目录不可用：{error}")))?;
        Self::new(directory)
    }

    /// 该项目根指向的规范化目录。
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// 该项目固定的秘密文件：`<root>/.secrets/open-ssl.json`。
    pub fn secrets_file(&self) -> PathBuf {
        self.path.join(SECRETS_DIR).join(SECRETS_FILE)
    }

    /// 该项目私有状态目录：`<root>/.secrets/open-ssl`。
    pub fn state_dir(&self) -> PathBuf {
        self.path.join(SECRETS_DIR).join(STATE_DIR)
    }
}

/// 一个项目已通过校验的 DNS 凭证。
///
/// 调试输出只报告 provider id，token 始终脱敏。
#[derive(Clone, Default)]
pub struct ProjectSecrets {
    dns: BTreeMap<String, Secret>,
}

impl fmt::Debug for ProjectSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProjectSecrets").field("dns_providers", &self.dns.keys().collect::<Vec<_>>()).finish()
    }
}

impl ProjectSecrets {
    /// 读取并校验 `<root>/.secrets/open-ssl.json`。
    ///
    /// 三类失败给出可区分的错误码：
    ///
    /// - [`ErrorCode::InvalidArgument`]：文件不存在，因为调用方指向的项目没有携带凭证，
    ///   这里没有回退来源。
    /// - [`ErrorCode::Io`]：文件存在但读取失败。
    /// - [`ErrorCode::Protocol`]：内容不是 JSON、schema 不是 [`SECRETS_SCHEMA`]，或已知字段
    ///   类型不对、值为空。
    ///
    /// 读取前先解析 `.secrets` 的真实位置：如果它是指向项目根之外的链接或 junction，
    /// 加载以 [`ErrorCode::Denied`] 失败。
    pub fn load(root: &ProjectRoot) -> Result<Self> {
        ensure_secrets_dir_inside_root(root)?;
        let file = root.secrets_file();
        let text = match fs::read_to_string(&file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::new(ErrorCode::InvalidArgument, format!("项目秘密文件 `{}` 不存在", file.display())));
            }
            Err(error) => {
                return Err(Error::new(ErrorCode::Io, format!("项目秘密文件 `{}` 无法读取：{error}", file.display())));
            }
        };
        let document: Value = serde_json::from_str(&text)
            .map_err(|_| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 不是合法 JSON", file.display())))?;
        let object =
            document.as_object().ok_or_else(|| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 不是 JSON 对象", file.display())))?;
        validate_schema(object, &file)?;
        let dns = match object.get("dns") {
            None | Some(Value::Null) => BTreeMap::new(),
            Some(value) => parse_dns(value, &file)?,
        };
        Ok(Self { dns })
    }

    /// 某个 provider id 配置的 DNS API token。
    ///
    /// 返回 [`ErrorCode::InvalidArgument`] 表示调用方要求了项目没有配置的 provider。
    /// provider id 是调用方输入，永远不会被拼进路径。
    pub fn dns_token(&self, provider_id: &str) -> Result<Secret> {
        self.dns
            .get(provider_id)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("项目秘密文件没有 `dns.{provider_id}.apiToken`")))
    }
}

/// Windows 的 `canonicalize` 返回 `\\?\` 扩展长度路径；短路径的正常形式等价且可读。
/// 只在长度安全（远小于 260）且不是 UNC 时剥掉前缀，其余保留原样以保证可用。
#[cfg(windows)]
fn display_canonical(path: PathBuf) -> PathBuf {
    const VERBATIM_PREFIX: &str = r"\\?\";
    let text = path.to_string_lossy();
    let Some(stripped) = text.strip_prefix(VERBATIM_PREFIX)
    else {
        return path;
    };
    if stripped.starts_with("UNC\\") || stripped.chars().count() >= 240 {
        return path;
    }
    PathBuf::from(stripped)
}

#[cfg(not(windows))]
fn display_canonical(path: PathBuf) -> PathBuf {
    path
}

/// 拒绝解析后落在项目根之外的 `.secrets` 目录。
///
/// 目录不存在不在此处报错：文件读取会把它作为缺文件报告。
fn ensure_secrets_dir_inside_root(root: &ProjectRoot) -> Result<()> {
    let secrets_dir = root.as_path().join(SECRETS_DIR);
    let Ok(canonical) = fs::canonicalize(&secrets_dir).map(display_canonical)
    else {
        return Ok(());
    };
    if !canonical.starts_with(root.as_path()) {
        return Err(Error::new(ErrorCode::Denied, format!("项目秘密目录 `{}` 解析到了项目根之外", secrets_dir.display())));
    }
    Ok(())
}

fn validate_schema(object: &Map<String, Value>, file: &Path) -> Result<()> {
    let schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 没有声明 `schema`", file.display())))?;
    if schema != SECRETS_SCHEMA {
        // 故意不回显声明的值：文件未知键里可能带秘密，消息里只出现应遵守的合同。
        return Err(Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 没有声明 `{SECRETS_SCHEMA}` schema", file.display())));
    }
    Ok(())
}

fn parse_dns(value: &Value, file: &Path) -> Result<BTreeMap<String, Secret>> {
    let table =
        value.as_object().ok_or_else(|| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 的 `dns` 不是对象", file.display())))?;
    let mut tokens = BTreeMap::new();
    for (provider_id, entry) in table {
        let entry = entry
            .as_object()
            .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 的 `dns.{provider_id}` 不是对象", file.display())))?;
        let token = entry
            .get("apiToken")
            .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 没有 `dns.{provider_id}.apiToken`", file.display())))?;
        let token = token.as_str().ok_or_else(|| {
            Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 的 `dns.{provider_id}.apiToken` 不是字符串", file.display()))
        })?;
        if token.trim().is_empty() {
            return Err(Error::new(ErrorCode::Protocol, format!("项目秘密文件 `{}` 的 `dns.{provider_id}.apiToken` 为空", file.display())));
        }
        tokens.insert(provider_id.clone(), Secret::new(token));
    }
    Ok(tokens)
}
