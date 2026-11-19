//! 以 provider 中立抽象承载 DNS-01 记录的落位。
//!
//! 记录按句柄拥有，而不是按名字覆盖：[`DnsProvider::put_txt`] 从不删除既有记录，只返回
//! 标识本任务新建或复用记录的句柄；[`DnsProvider::delete_txt`] 只删除它拿到的句柄对应的那条
//! 记录。裸域与泛域名共享同一个 `_acme-challenge.` 记录名，因此多个值必须能共存到各自的
//! owner 完成清理。
//!
//! [`cloudflare::Cloudflare`] 是第一个 API 适配器，要求调用方显式配置 zone。人工放置的
//! `manual` 路径不经过本抽象：它由 [`crate::flow`] 以 prepare / resume 两次运行推进，
//! 提示与确认属于宿主 CLI 层，native 侧不做任何终端交互。

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
///
/// 它不是 [`DnsProvider`] 实现：人工路径由 [`crate::flow`] 的 prepare / resume 两次
/// 运行推进，记录指引以 [`crate::state::PendingAction`] 落盘，确认交互归宿主 CLI。
pub const MANUAL_PROVIDER: &str = "manual";
