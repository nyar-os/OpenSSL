//! 以 provider 中立抽象承载 DNS-01 记录的落位。
//!
//! 记录按句柄拥有，而不是按名字覆盖：[`DnsProvider::put_txt`] 从不删除既有记录，只返回
//! 标识本任务新建或复用记录的句柄；[`DnsProvider::delete_txt`] 只删除它拿到的句柄对应的那条
//! 记录。裸域与泛域名共享同一个 `_acme-challenge.` 记录名，因此多个值必须能共存到各自的
//! owner 完成清理。
//!
//! [`Manual`] 是交互式 provider：它把每条记录连同值打印给操作者，等待人工在 DNS 控制台
//! 放置（或清理）后按 Enter 再继续，因此不需要任何 API 凭证；真正的校验由 CA 的 dns-01
//! 挑战完成。[`cloudflare::Cloudflare`] 是第一个 API 适配器，要求调用方显式配置 zone。

pub mod cloudflare;
pub mod credentials;

use crate::errors::{Error, ErrorCode, Result};

/// 每条 dns-01 TXT 记录所在的标签。
const CHALLENGE_LABEL: &str = "_acme-challenge";

/// provider 侧一条 TXT 记录的身份。
///
/// 值是 provider 返回的不透明 id，且不允许为空。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHandle(String);

impl RecordHandle {
    /// 接管一个 provider 侧 id。
    ///
    /// 空 id 会让之后每一次删除都产生歧义，因此按违反 provider 合同报
    /// [`ErrorCode::Protocol`]。
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(Error::new(ErrorCode::Protocol, "DNS 记录句柄不能为空"));
        }
        Ok(Self(id))
    }

    /// 原始 provider 侧 id。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// provider 为本次任务创建或复用的一条 TXT 记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    /// 完整记录名，例如 `_acme-challenge.example.test`。
    pub fqdn: String,
    /// TXT 值，是 dns-01 摘要而不是 key authorization。
    pub value: String,
    /// 在 provider 侧拥有这条记录的句柄。
    pub handle: RecordHandle,
}

/// 能够放置 dns-01 TXT 记录的 provider。
pub trait DnsProvider {
    /// 创建一条由本任务拥有的 TXT 记录。
    ///
    /// 实现不得删除任何既有记录，也不得让这条记录与其它任务共享。复用完全相同的既有记录
    /// 是允许的，并通过返回的句柄体现。
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord>;

    /// 精确查找同名同值的既有记录，供复用与对账。
    fn find_txt(&mut self, fqdn: &str, value: &str) -> Result<Option<TxtRecord>>;

    /// 只删除 `record` 句柄对应的那一条记录。
    fn delete_txt(&mut self, record: &TxtRecord) -> Result<()>;
}

/// 一个 authorization 身份对应的 dns-01 记录名。
///
/// 泛域名标识 `*.example.test` 与裸域标识在同一 `_acme-challenge.example.test` 名下完成验证，
/// 因此前导 `*.` 被剥掉，而不是被复制进记录名。
pub fn challenge_fqdn(identifier: &str) -> String {
    let name = identifier.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = name.strip_prefix("*.").unwrap_or(name.as_str());
    format!("{CHALLENGE_LABEL}.{name}")
}

/// `manual` provider 的稳定 id。
pub const MANUAL_PROVIDER: &str = "manual";

/// 交互式提示器：把操作指引交给宿主终端，等待操作者确认后继续。
pub trait Prompter {
    /// 打印 `message` 并等待操作者按 Enter。
    ///
    /// 输入结束（EOF）或读取失败表示操作者取消，必须以 [`ErrorCode::Denied`] 失败，
    /// 不能静默当作已确认。
    fn await_confirmation(&mut self, message: &str) -> Result<()>;
}

/// 交互式 manual provider：不读取任何凭证，把每条 TXT 记录打印给操作者人工放置，
/// 等待确认后才让 CA 去校验；清理阶段同样逐条打印待删除的记录。
#[derive(Debug)]
pub struct Manual<P> {
    placed: Vec<TxtRecord>,
    next_id: u64,
    prompter: P,
}

impl<P: Prompter> Manual<P> {
    /// 绑定一个提示器创建 manual provider。
    #[must_use]
    pub fn new(prompter: P) -> Self {
        Self { placed: Vec::new(), next_id: 0, prompter }
    }

    /// 当前等待人工放置的记录。
    pub fn pending_records(&self) -> &[TxtRecord] {
        &self.placed
    }
}

impl<P: Prompter> DnsProvider for Manual<P> {
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord> {
        if fqdn.trim().is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "TXT 记录名不能为空"));
        }
        if value.is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "TXT 记录值不能为空"));
        }
        self.next_id += 1;
        let record =
            TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned(), handle: RecordHandle::new(format!("manual-{}", self.next_id))? };
        self.prompter.await_confirmation(&format!(
            "请在 DNS 控制台添加 TXT 记录：\n    名称: {}\n    值:   {}\n添加完成并生效后按 Enter 继续验证。",
            record.fqdn, record.value
        ))?;
        self.placed.push(record.clone());
        Ok(record)
    }

    fn find_txt(&mut self, fqdn: &str, value: &str) -> Result<Option<TxtRecord>> {
        Ok(self.placed.iter().find(|placed| placed.fqdn == fqdn && placed.value == value).cloned())
    }

    fn delete_txt(&mut self, record: &TxtRecord) -> Result<()> {
        self.prompter.await_confirmation(&format!(
            "请从 DNS 控制台删除本次添加的 TXT 记录：\n    名称: {}\n    值:   {}\n删除后按 Enter 继续。",
            record.fqdn, record.value
        ))?;
        self.placed.retain(|placed| placed.handle != record.handle);
        Ok(())
    }
}
