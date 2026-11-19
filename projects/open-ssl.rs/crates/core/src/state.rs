//! 签发状态持久化与纯本地签发计划。
//!
//! 状态文件固定在 [`ProjectRoot::state_dir`]（`<root>/.secrets/open-ssl`）内，与输入凭证
//! `open-ssl.json` 和 [`crate::delivery`] 的 `generations/` 分开：
//!
//! ```text
//! open-ssl/
//!   accounts/staging.json      staging 账户身份
//!   accounts/production.json   production 账户身份
//!   orders/<id>.json           单个订单的恢复记录
//!   orders/<id>.json.tmp       原子写的临时文件，写完由同目录 `rename` 覆盖
//! ```
//!
//! 账户按 [`DirectoryKind`] 各占一个文件，因此 staging 与 production 的身份不会互相覆盖；
//! 读取时文件里的 `kind` 与请求的类型不一致即按损坏拒绝，不会静默当成另一个环境的身份。
//!
//! 每个订单保存恢复所需的最小上下文：directory 类型、账户 URL、order/authorization URL、
//! 原始 SAN、每项授权的记录名与 TXT 摘要、CSR 与证书指纹、DNS 记录句柄以及阶段。这里
//! **不保存** DNS token、账户私钥或叶子私钥：状态文件不是秘密文件的替代品。
//!
//! 写入是原子替换：先写 `<file>.tmp` 并 `sync_all`，再在同一个目录内 `rename` 覆盖目标。
//! 任何一步失败都不改动已有文件，因此崩溃最多留下一个 `.tmp` 残片。
//!
//! 反序列化是严格校验：`id` 必须与文件名一致，每项授权的 `record_fqdn` 必须等于
//! `_acme-challenge.<identifier>`。损坏文件按 [`ErrorCode::Protocol`] 报错，不会被修补成
//! “看起来正常”的状态，也不会被当成不存在。
//!
//! # 签发计划
//!
//! [`plan_issue`] 只做本地检查：校验 SAN、读取项目秘密文件的可用性与该 provider 的 token
//! 是否存在、查询已有账户与未完成订单，然后返回 [`IssuePlan`]。它不创建账户或订单、不写任何
//! 文件、不改 DNS、不生成密钥，也不读取或解密私钥。秘密文件缺失或内容不合 `/v0` 合同仍然是
//! 明确失败；只有“文件合法但该 provider 没有 token”才记成 `dns_token_available = false`。

use std::{
    ffi::OsString,
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Deserializer, Serialize, de};

use crate::{
    dns::{
        challenge_fqdn,
        credentials::{ProjectRoot, ProjectSecrets},
    },
    errors::{Error, ErrorCode, Result},
};

/// 账户状态所在的子目录。
const ACCOUNTS_DIR: &str = "accounts";
/// 订单状态所在的子目录。
const ORDERS_DIR: &str = "orders";
/// 待人工执行动作所在的子目录。
const ACTIONS_DIR: &str = "actions";
/// 状态文件的扩展名。
const JSON_SUFFIX: &str = ".json";
/// 原子写的临时文件后缀。
const TEMP_SUFFIX: &str = ".tmp";
/// 单个 DNS 标识允许的最大长度。
const MAX_IDENTIFIER_LENGTH: usize = 253;
/// 单个 DNS 标签允许的最大长度。
const MAX_LABEL_LENGTH: usize = 63;
/// 订单 id 允许的最大长度。
const MAX_ID_LENGTH: usize = 96;

/// 该状态属于哪一个 ACME directory，决定身份隔离。
///
/// 类型本身是隔离的依据，不从 URL 反推：同一个 CA 的 staging 与 production 是两个身份，
/// 证书也互不替代。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirectoryKind {
    /// 公共 CA 的 staging directory，签出的证书不受信。
    Staging,
    /// 公共 CA 的 production directory。
    Production,
}

impl DirectoryKind {
    /// 稳定拼写，同时也是状态文件名的主干。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

/// 一个已注册的 ACME 账户身份。
///
/// 重启后必须先按 [`DirectoryKind`] 找回它，不能因为进程退出就再生成一个新账户。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountState {
    /// 该账户所属的 directory。
    pub kind: DirectoryKind,
    /// 账户对应的 directory URL。
    pub directory_url: String,
    /// 账户 URL（`newAccount` 响应的 `Location`）。
    pub account_url: String,
    /// 账户公钥的 JWK thumbprint，是公开值，用来确认本地密钥仍是同一个账户。
    pub key_thumbprint: String,
    /// 该状态首次写入时的 Unix 秒。
    pub created_unix: u64,
}

/// 一项 identifier 的授权进度。
///
/// `record_id` 是 provider 侧句柄，用于只清理本任务创建的记录；`txt_digest` 是本任务发布到
/// DNS 的值摘要，不是 ACME token，也不是 key authorization。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationState {
    /// authorization URL。
    pub url: String,
    /// authorization 覆盖的标识，裸域形态（不含 `*.`）。
    pub identifier: String,
    /// 该授权是否来自泛域名标识。
    pub wildcard: bool,
    /// dns-01 记录名，必须等于 `_acme-challenge.<identifier>`。
    pub record_fqdn: String,
    /// 本任务要发布的 TXT 值摘要。
    pub txt_digest: String,
    /// authorization 状态：`pending`、`valid`、`invalid`、`expired`、`deactivated` 或 `revoked`。
    pub status: String,
    /// provider 侧 DNS 记录句柄，仅在记录由本任务创建时存在。
    pub record_id: Option<String>,
}

/// 订单在本产品状态机里的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderPhase {
    /// 已计划，尚未向 CA 提交订单。
    Planned,
    /// manual DNS 指引已落盘，等待操作者放置记录后用 `--action` 续跑。
    #[serde(rename = "awaiting-dns")]
    AwaitingDns,
    /// 授权已经通过验证，尚未提交 CSR。
    Authorized,
    /// CSR 已提交，等待 CA 出证。
    Submitted,
    /// 证书已下载并通过本地核验。
    Issued,
    /// 订单以失败告终，需要重新规划。
    Failed,
}

impl OrderPhase {
    /// 稳定拼写。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingDns => "awaiting-dns",
            Self::Authorized => "authorized",
            Self::Submitted => "submitted",
            Self::Issued => "issued",
            Self::Failed => "failed",
        }
    }

    /// 解析稳定拼写，未知值返回 `None`。
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "planned" => Some(Self::Planned),
            "awaiting-dns" => Some(Self::AwaitingDns),
            "authorized" => Some(Self::Authorized),
            "submitted" => Some(Self::Submitted),
            "issued" => Some(Self::Issued),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// 该阶段是否还需要继续推进（既未出证，也未失败）。
    #[must_use]
    pub const fn is_open(self) -> bool {
        matches!(self, Self::Planned | Self::AwaitingDns | Self::Authorized | Self::Submitted)
    }
}

impl<'de> Deserialize<'de> for OrderPhase {
    /// 未知阶段只说明合同，不回显文件里的原始拼写。
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PhaseVisitor;

        impl de::Visitor<'_> for PhaseVisitor {
            type Value = OrderPhase;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("`planned`, `awaiting-dns`, `authorized`, `submitted`, `issued` 或 `failed`")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<OrderPhase, E> {
                OrderPhase::parse(value).ok_or_else(|| E::custom("未知的订单阶段"))
            }
        }

        deserializer.deserialize_str(PhaseVisitor)
    }
}

/// 一个订单的恢复记录。
///
/// `identifiers` 保留调用方给的 SAN 形态（含 `*.example.com`），因为 CA 侧订单身份就是这些
/// 原始标识；授权里的 `identifier` 才是去掉 `*.` 之后的裸域。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    /// 稳定 id，同时是状态文件名的主干。
    pub id: String,
    /// 该订单所属的 directory。
    pub kind: DirectoryKind,
    /// 下该订单的账户 URL。
    pub account_url: String,
    /// order URL，提交前为 `None`。
    pub order_url: Option<String>,
    /// 原始 SAN 集，保留 `*.example.com` 形态。
    pub identifiers: Vec<String>,
    /// 每项 identifier 的授权进度。
    pub authorizations: Vec<AuthorizationState>,
    /// CSR DER 的 SHA-256，十六进制小写。
    pub csr_sha256: Option<String>,
    /// 叶子证书 DER 的 SHA-256，十六进制小写。
    pub certificate_sha256: Option<String>,
    /// 当前阶段。
    pub phase: OrderPhase,
    /// 最近一次写入的 Unix 秒。
    pub updated_unix: u64,
}

/// 一条需要操作者人工放置的 dns-01 TXT 记录。
///
/// 这是给人类的指引数据，不是授权凭证：恢复时领域层仍会向 CA 发起真实校验。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxtInstruction {
    /// 记录名，例如 `_acme-challenge.example.test`。
    pub fqdn: String,
    /// TXT 值（dns-01 摘要）。
    pub value: String,
}

/// 一个等待外部人工操作、可跨进程续跑的领域动作。
///
/// 只保存恢复所需的最小上下文：所属订单、输入指纹、阶段指引与到期时间。**不保存**
/// DNS token、账户私钥或任何凭证引用之外的秘密。`input_fingerprint` 绑定
/// directory、provider 与规范化后的 identifier 集，恢复时重算比对，防止拿错项目、
/// 错订单或改过输入的状态继续跑。状态文件可被本地编辑，因此指纹只是完整性检查，
/// 不是防篡改认证。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingAction {
    /// 稳定动作 id，同时是状态文件名的主干。
    pub id: String,
    /// 该动作所属的 directory。
    pub kind: DirectoryKind,
    /// 关联的订单 id（`statusRef`）。
    pub order_id: String,
    /// 输入指纹：directory、provider 与 identifier 集的摘要。
    pub input_fingerprint: String,
    /// 需要人工放置的 TXT 记录。
    pub records: Vec<TxtInstruction>,
    /// 首次写入的 Unix 秒。
    pub created_unix: u64,
    /// 续跑截止的 Unix 秒，过期后必须重新 prepare。
    pub expires_unix: u64,
}

/// 绑定一个项目状态目录的状态读写入口。
///
/// 构造只计算路径，不创建目录、不读取任何文件。
#[derive(Debug, Clone)]
pub struct StateStore {
    state_dir: PathBuf,
}

impl StateStore {
    /// 把状态入口绑定到该项目的私有状态目录。
    #[must_use]
    pub fn new(project: &ProjectRoot) -> Self {
        Self { state_dir: project.state_dir() }
    }

    /// 原子写入该账户身份。
    ///
    /// 目标文件由账户的 [`DirectoryKind`] 决定，因此写 staging 永远不会覆盖 production。
    pub fn save_account(&self, account: &AccountState) -> Result<()> {
        let file = self.accounts_dir().join(format!("{}{JSON_SUFFIX}", account.kind.as_str()));
        self.write_atomic(&file, account)
    }

    /// 读取某个 directory 的账户身份。
    ///
    /// 文件不存在返回 `Ok(None)`；文件是坏 JSON、或里面记录的 `kind` 与请求不一致，都按
    /// [`ErrorCode::Protocol`] 报错，不会当作另一个环境的身份使用。
    pub fn account(&self, kind: DirectoryKind) -> Result<Option<AccountState>> {
        let file = self.accounts_dir().join(format!("{}{JSON_SUFFIX}", kind.as_str()));
        let Some(account) = read_state::<AccountState>(&file, "账户状态")?
        else {
            return Ok(None);
        };
        if account.kind != kind {
            return Err(Error::new(ErrorCode::Protocol, format!("账户状态 `{}` 记录的 directory 类型与文件名不一致", file.display())));
        }
        Ok(Some(account))
    }

    /// 原子写入该订单记录。
    ///
    /// 写入前先校验 id 形状与授权记录名，避免把不可恢复的状态落盘。
    pub fn save_order(&self, order: &OrderState) -> Result<()> {
        validate_order(order, ErrorCode::InvalidArgument)?;
        let file = self.order_file(&order.id)?;
        self.write_atomic(&file, order)
    }

    /// 读取一个订单记录。
    ///
    /// 文件不存在返回 `Ok(None)`。坏 JSON、未知阶段、文件名与 `id` 不一致、授权记录名与
    /// identifier 不匹配都会明确报错。
    pub fn order(&self, id: &str) -> Result<Option<OrderState>> {
        let file = self.order_file(id)?;
        let Some(order) = read_state::<OrderState>(&file, "订单状态")?
        else {
            return Ok(None);
        };
        validate_file_identity(&order, &file)?;
        validate_order(&order, ErrorCode::Protocol)?;
        Ok(Some(order))
    }

    /// 全部订单记录，按 `updated_unix` 降序。
    ///
    /// 以 `.` 开头的条目与 `.tmp` 残片直接跳过；其余条目必须是合法订单文件，否则报错而不是
    /// 悄悄忽略。
    pub fn orders(&self) -> Result<Vec<OrderState>> {
        let directory = self.orders_dir();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&directory, "读取订单状态目录", error)),
        };
        let mut orders = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&directory, "读取订单状态条目", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name.ends_with(TEMP_SUFFIX) {
                continue;
            }
            if !name.ends_with(JSON_SUFFIX) {
                return Err(Error::new(ErrorCode::Protocol, format!("订单状态目录 `{}` 含有非状态文件", entry.path().display())));
            }
            let order = read_state::<OrderState>(&entry.path(), "订单状态")?
                .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("订单状态 `{}` 在读取过程中消失", entry.path().display())))?;
            validate_file_identity(&order, &entry.path())?;
            validate_order(&order, ErrorCode::Protocol)?;
            orders.push(order);
        }
        orders.sort_by(|left, right| right.updated_unix.cmp(&left.updated_unix).then_with(|| right.id.cmp(&left.id)));
        Ok(orders)
    }

    /// 该 directory 下最近一次写入、且尚未以 `issued`/`failed` 收尾的订单。
    ///
    /// 用于重启后继续原订单，而不是无限重建新订单。
    pub fn latest_open_order(&self, kind: DirectoryKind) -> Result<Option<OrderState>> {
        Ok(self.orders()?.into_iter().find(|order| order.kind == kind && order.phase.is_open()))
    }

    /// 原子写入一个待人工执行的动作。
    ///
    /// 写入前校验 id 形状，且 `id` 必须以关联的订单 id 为主干，避免动作与订单脱钩。
    pub fn save_action(&self, action: &PendingAction) -> Result<()> {
        if !valid_id(&action.id) {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("动作 id `{}` 不是合法的状态文件名", action.id)));
        }
        let file = self.actions_dir().join(format!("{}{JSON_SUFFIX}", action.id));
        self.write_atomic(&file, action)
    }

    /// 读取一个待人工执行的动作。
    ///
    /// 文件不存在返回 `Ok(None)`；坏 JSON 或文件名与 `id` 不一致按 [`ErrorCode::Protocol`] 报错。
    pub fn action(&self, id: &str) -> Result<Option<PendingAction>> {
        if !valid_id(id) {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("动作 id `{id}` 不是合法的状态文件名")));
        }
        let file = self.actions_dir().join(format!("{id}{JSON_SUFFIX}"));
        let Some(action) = read_state::<PendingAction>(&file, "动作状态")?
        else {
            return Ok(None);
        };
        if action.id != id {
            return Err(Error::new(ErrorCode::Protocol, format!("动作状态 `{}` 里的 id 与文件名不一致", file.display())));
        }
        Ok(Some(action))
    }

    /// 删除一个已消费的动作。文件不存在视为已删除。
    pub fn delete_action(&self, id: &str) -> Result<()> {
        if !valid_id(id) {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("动作 id `{id}` 不是合法的状态文件名")));
        }
        let file = self.actions_dir().join(format!("{id}{JSON_SUFFIX}"));
        match fs::remove_file(&file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(&file, "删除动作状态", error)),
        }
    }

    fn accounts_dir(&self) -> PathBuf {
        self.state_dir.join(ACCOUNTS_DIR)
    }

    fn orders_dir(&self) -> PathBuf {
        self.state_dir.join(ORDERS_DIR)
    }

    fn actions_dir(&self) -> PathBuf {
        self.state_dir.join(ACTIONS_DIR)
    }

    fn order_file(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("订单 id `{id}` 不是合法的状态文件名")));
        }
        Ok(self.orders_dir().join(format!("{id}{JSON_SUFFIX}")))
    }

    /// 写 `<file>.tmp`、`sync_all`，再用同目录 `rename` 覆盖目标。
    fn write_atomic<T: Serialize>(&self, file: &Path, value: &T) -> Result<()> {
        let Some(directory) = file.parent()
        else {
            return Err(Error::new(ErrorCode::Internal, format!("状态文件 `{}` 没有父目录", file.display())));
        };
        fs::create_dir_all(directory).map_err(|error| io_error(directory, "创建状态目录", error))?;
        let document = serde_json::to_string(value).map_err(|error| Error::new(ErrorCode::Internal, format!("状态记录无法序列化：{error}")))?;

        let mut temporary_name = OsString::from(file.as_os_str());
        temporary_name.push(TEMP_SUFFIX);
        let temporary = PathBuf::from(temporary_name);

        let mut temporary_file = File::create(&temporary).map_err(|error| io_error(&temporary, "写入状态临时文件", error))?;
        temporary_file.write_all(document.as_bytes()).map_err(|error| io_error(&temporary, "写入状态临时文件", error))?;
        temporary_file.sync_all().map_err(|error| io_error(&temporary, "落盘状态临时文件", error))?;
        drop(temporary_file);
        fs::rename(&temporary, file).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            io_error(file, "替换状态文件", error)
        })
    }
}

/// 一次签发在本地能确定的信息，不包含任何凭证值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuePlan {
    /// 规范化后的项目根。
    pub project_root: PathBuf,
    /// 本次计划使用的 directory。
    pub kind: DirectoryKind,
    /// DNS provider id。
    pub dns_provider: String,
    /// 规范化后的 SAN 集，保持调用方顺序。
    pub identifiers: Vec<String>,
    /// 项目秘密文件的位置，只报告定位，不报告内容。
    pub secrets_file: PathBuf,
    /// 项目秘密文件是否已经加载并通过 `/v0` 校验。
    pub secrets_available: bool,
    /// 该 provider 是否配置了可用 token。
    pub dns_token_available: bool,
    /// 该 directory 是否已有可复用的账户身份。
    pub existing_account: bool,
    /// 该 directory 下尚未收尾的订单 id。
    pub pending_order: Option<String>,
    /// 计划本身的提示，例如泛域名不覆盖裸域。
    pub required_sans_note: Vec<String>,
}

/// 生成一份纯本地的签发计划。
///
/// 只读取项目状态与项目秘密文件的**可用性**：不建账户、不建订单、不写任何文件、不改 DNS、
/// 不生成密钥、不读取私钥。秘密文件缺失、不可读或不合 `/v0` 合同仍是明确失败；文件合法但
/// 该 provider 没有 token 只记成 `dns_token_available = false`。唯一的例外是 `manual`
/// provider：它由操作者人工放置记录，天然不需要秘密文件。
///
/// `identifiers` 会被校验并规范化（去首尾空白、去末尾点、小写），非法或重复的标识按
/// [`ErrorCode::InvalidArgument`] 拒绝，不会擅自补出不存在的 SAN。
pub fn plan_issue(project: &ProjectRoot, kind: DirectoryKind, dns_provider: &str, identifiers: &[String]) -> Result<IssuePlan> {
    let dns_provider = dns_provider.trim();
    if dns_provider.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "签发计划必须指明 DNS provider"));
    }
    let (identifiers, required_sans_note) = normalize_identifiers(identifiers)?;

    let secrets_file = project.secrets_file();
    let manual = dns_provider == crate::dns::MANUAL_PROVIDER;
    let mut secrets_available = false;
    // manual 由操作者本人放置记录，不需要任何 API 凭证；token 天然可用。
    let mut dns_token_available = manual;
    if !manual || secrets_file.exists() {
        let secrets = ProjectSecrets::load(project)?;
        secrets_available = true;
        if secrets.dns_token(dns_provider).is_ok() {
            dns_token_available = true;
        }
    }

    let store = StateStore::new(project);
    let existing_account = store.account(kind)?.is_some();
    let pending_order = store.latest_open_order(kind)?.map(|order| order.id);

    Ok(IssuePlan {
        project_root: project.as_path().to_path_buf(),
        kind,
        dns_provider: dns_provider.to_owned(),
        identifiers,
        secrets_file,
        secrets_available,
        dns_token_available,
        existing_account,
        pending_order,
        required_sans_note,
    })
}

fn read_state<T: serde::de::DeserializeOwned>(file: &Path, subject: &str) -> Result<Option<T>> {
    let text = match fs::read_to_string(file) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(file, "读取状态文件", error)),
    };
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.classify() == serde_json::error::Category::Data => {
            Err(Error::new(ErrorCode::Protocol, format!("{subject} `{}` 的内容不符合状态合同", file.display())))
        }
        Err(_) => Err(Error::new(ErrorCode::Protocol, format!("{subject} `{}` 不是合法 JSON", file.display()))),
    }
}

/// 文件名主干必须与记录里的 `id` 一致，损坏文件不静默修正。
fn validate_file_identity(order: &OrderState, file: &Path) -> Result<()> {
    let matches = file.file_stem().and_then(|stem| stem.to_str()) == Some(order.id.as_str());
    if !matches {
        return Err(Error::new(ErrorCode::Protocol, format!("订单状态 `{}` 里的 id 与文件名不一致", file.display())));
    }
    Ok(())
}

fn validate_order(order: &OrderState, code: ErrorCode) -> Result<()> {
    if !valid_id(&order.id) {
        return Err(Error::new(code, format!("订单 id `{}` 不是合法的状态文件名", order.id)));
    }
    for authorization in &order.authorizations {
        let expected = challenge_fqdn(&authorization.identifier);
        if authorization.record_fqdn != expected {
            return Err(Error::new(
                code,
                format!("订单 `{}` 的授权记录名 `{}` 与 identifier `{}` 不匹配", order.id, authorization.record_fqdn, authorization.identifier),
            ));
        }
    }
    Ok(())
}

fn normalize_identifiers(identifiers: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    if identifiers.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "签发计划至少要有一个 identifier"));
    }
    let mut normalized: Vec<String> = Vec::with_capacity(identifiers.len());
    for raw in identifiers {
        let name = normalize_identifier(raw)?;
        if normalized.contains(&name) {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 在签发计划里重复")));
        }
        normalized.push(name);
    }
    let notes = sans_notes(&normalized);
    Ok((normalized, notes))
}

fn normalize_identifier(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "identifier 不能为空"));
    }
    let name = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if name.len() > MAX_IDENTIFIER_LENGTH {
        return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 超过 {MAX_IDENTIFIER_LENGTH} 字节")));
    }
    let labels: Vec<&str> = name.split('.').collect();
    if name == "*" || labels.len() < 2 {
        return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 至少需要一个域名标签")));
    }
    for (index, label) in labels.iter().enumerate() {
        if label.is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 含空标签")));
        }
        if *label == "*" {
            if index != 0 {
                return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 的 `*.` 只能出现在最左标签")));
            }
            continue;
        }
        if label.contains('*') {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 的 `*` 只能作为最左标签单独出现")));
        }
        if label.len() > MAX_LABEL_LENGTH || label.starts_with('-') || label.ends_with('-') {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 的标签 `{label}` 不合法")));
        }
        if !label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_') {
            return Err(Error::new(ErrorCode::InvalidArgument, format!("identifier `{name}` 的标签 `{label}` 含非法字符")));
        }
    }
    Ok(name)
}

/// 泛域名只覆盖一级子域，不覆盖裸域，也不覆盖更深层级。
fn sans_notes(identifiers: &[String]) -> Vec<String> {
    let mut notes = Vec::new();
    for name in identifiers {
        let Some(bare) = name.strip_prefix("*.")
        else {
            continue;
        };
        if !identifiers.iter().any(|other| other == bare) {
            notes.push(format!("`{name}` 只覆盖一级子域，裸域 `{bare}` 需要单独加入 identifier 列表"));
        }
    }
    notes
}

/// 订单 id 只允许 ASCII 字母、数字、`-` 与 `_`，避免把记录内容当成任意路径。
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LENGTH
        && id.chars().all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
}

fn io_error(path: &Path, action: &str, error: io::Error) -> Error {
    Error::new(ErrorCode::Io, format!("{action} `{}` 失败：{error}", path.display()))
}
