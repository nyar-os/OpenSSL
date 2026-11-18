//! 签发编排：项目锁、纯本地计划与可恢复的签发会话。
//!
//! [`begin_issue`] 是 `acme-issue` 能力的唯一编排入口。它把已有原语按固定顺序串起来：
//!
//! 1. 先取 [`ProjectLock`]；拿不到锁立即返回 [`ErrorCode::Denied`]，不读状态、不读秘密文件。
//! 2. 在锁内生成 [`IssuePlan`]；计划失败时锁随作用域释放，不留下半成品状态。
//! 3. 读取该 [`DirectoryKind`] 的账户与未完成订单，决定会话处于哪个离线阶段。
//!
//! # 阶段与阻塞
//!
//! 本构建**没有可用的 HTTPS 传输**（共享 TLS 收口未完成），因此任何真实签发都只能停在
//! 离线准备完成、下一步必然被阻塞的位置。这里采用的表达是：
//!
//! - [`IssueStage::Prepared`]：离线准备完成，没有可复用的账户或未完成订单。
//! - [`IssueStage::Resumed`]：离线准备完成，并且已有账户或未完成订单可供续接。
//! - [`IssueStage::AwaitingNetwork`]：已经推进到必须发起 HTTPS 请求的位置。本构建不会返回
//!   该阶段，它留给接上真实传输之后的构建。
//! - `blocked` 统一非空（[`NO_HTTPS_TRANSPORT`]），表示网络尚未接通。调用方必须先看到这个
//!   事实，不能把 `Prepared`/`Resumed` 当成「已签发」。
//!
//! # 不做的事
//!
//! [`begin_issue`] 不创建账户、不创建订单、不改 DNS、不生成或写入私钥、不写任何状态文件
//! （锁文件除外，见 [`ProjectLock`]），也不持有 [`crate::dns::credentials::Secret`]。

use serde::Serialize;

use crate::{
    dns::credentials::ProjectRoot,
    errors::Result,
    lock::ProjectLock,
    state::{DirectoryKind, IssuePlan, StateStore, plan_issue},
};

/// 本构建缺少 HTTPS 传输时的固定阻塞原因。
///
/// 这不是调用错误，而是构建事实：能力表里的 `acme-issue` 同样以 `not_implemented` 报告该缺口。
pub const NO_HTTPS_TRANSPORT: &str = "the build has no HTTPS transport";

/// 一次签发在本地推进到的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueStage {
    /// 已取得锁并生成计划，等待 DNS 写入。
    Prepared,
    /// 已有账户与订单，等待网络阶段。
    Resumed,
    /// 需要 HTTPS 传输但当前构建没有，流程停在这里。
    ///
    /// 本构建不会返回该阶段；它由接上真实传输之后的编排产生。
    AwaitingNetwork,
}

impl IssueStage {
    /// 稳定拼写，与序列化值一致。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Resumed => "resumed",
            Self::AwaitingNetwork => "awaiting-network",
        }
    }
}

/// 一次签发会话在本地能确定的内容，不包含任何凭证值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueSession {
    /// 本地推进到的阶段。
    pub stage: IssueStage,
    /// 本次会话的计划。
    pub plan: IssuePlan,
    /// 该 directory 是否已有可复用的账户身份。
    pub account_reused: bool,
    /// 该 directory 下尚未收尾的订单 id。
    pub pending_order: Option<String>,
    /// 阻断下一步的原因；本构建固定为 [`NO_HTTPS_TRANSPORT`]。
    pub blocked: Option<&'static str>,
}

/// 一次签发请求的本地输入。
///
/// 借用调用方的标识列表，避免在编排层复制一份可变数据。
#[derive(Debug)]
pub struct IssueRequest<'a> {
    /// 目标 ACME directory。
    pub kind: DirectoryKind,
    /// DNS provider id，必须出现在项目秘密文件里。
    pub dns_provider: &'a str,
    /// 请求的 identifier 集，原样交给计划校验。
    pub identifiers: &'a [String],
}

/// 开始一次签发：取锁、生成计划、读出账户与订单的恢复线索。
///
/// 返回的 [`ProjectLock`] 由调用方持有，锁的生命周期即调用方决定的作用域。任何一步失败都会
/// 让锁随作用域释放，不会留下半成品；锁文件本身是唯一的落盘产物。
///
/// 本函数**不**建账户、建订单、改 DNS、生成或写入密钥，也不写状态文件。
pub fn begin_issue(project: &ProjectRoot, request: IssueRequest<'_>) -> Result<(ProjectLock, IssueSession)> {
    let lock = ProjectLock::acquire(project)?;
    let plan = plan_issue(project, request.kind, request.dns_provider, request.identifiers)?;

    let store = StateStore::new(project);
    let account_reused = store.account(request.kind)?.is_some();
    let pending_order = store.latest_open_order(request.kind)?.map(|order| order.id);
    let stage = if pending_order.is_some() { IssueStage::Resumed } else { IssueStage::Prepared };

    let session = IssueSession { stage, plan, account_reused, pending_order, blocked: Some(NO_HTTPS_TRANSPORT) };
    Ok((lock, session))
}
