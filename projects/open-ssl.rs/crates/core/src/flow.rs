//! 真实签发编排：账户、订单、DNS、挑战、CSR、下载、交付与清理。
//!
//! [`issue`] 是 `acme-issue` 的真实执行入口。它按固定顺序推进同一条状态机，任何一步失败都
//! 保留已经落盘的账户/订单状态，供下一次用同一账户与同一订单续跑：
//!
//! 1. 取项目锁，生成计划（校验 SAN 与 provider token 的可用性）。
//! 2. 读取或创建该 directory 的账户密钥，bootstrap，复用已有账户或新建账户。
//! 3. 复用未完成订单或新建订单。
//! 4. 逐项发布 `_acme-challenge` TXT，回复 dns-01 挑战，轮询授权到 `valid`。
//! 5. 生成/复用叶子私钥，提交 CSR，轮询订单到 `valid`。
//! 6. 下载证书链，拆分叶子与中间证书，经 `delivery` 原子交付。
//! 7. 无论成功与否，只删除本任务创建的 TXT 记录。
//!
//! 传输由调用方注入，DNS 的驱动方式由入口函数决定：
//!
//! - [`issue_api`]：provider 直接落位记录，单 run 走完全部状态机。
//! - [`issue_manual`]：人工放置记录，拆成两次运行。第一次（不带 action id）取到
//!   每条挑战的 TXT 指引后落盘 [`crate::state::PendingAction`] 并返回
//!   [`FlowOutcome::ActionRequired`]，**不回复任何挑战**；操作者放好记录后，第二次带
//!   `--action <actionId>` 续跑，先校验项目输入指纹、阶段与到期，再对同一订单回复挑战、
//!   轮询、finalize 并交付。恢复消费成功后动作记录即删除，重复续跑会被明确拒绝。
//!
//! 本模块不做任何终端交互：提示与确认属于宿主 CLI 层，native 侧只返回值或类型化结果。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boost_net::http::Transport;
use serde::Serialize;

use crate::{
    acme::{AcmeClient, AuthorizationStatus},
    csr,
    delivery::Delivery,
    dns::{DnsProvider, TxtRecord},
    dns::credentials::ProjectRoot,
    errors::{Error, ErrorCode, Result},
    keys,
    lock::ProjectLock,
    state::{AccountState, AuthorizationState, DirectoryKind, IssuePlan, OrderPhase, OrderState, PendingAction, StateStore, TxtInstruction, plan_issue},
    x509::{Certificate, pem_bundle, pem_encode},
};

/// 一个 CA 的 directory URL。
#[must_use]
pub const fn directory_url(kind: DirectoryKind) -> &'static str {
    match kind {
        DirectoryKind::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        DirectoryKind::Production => "https://acme-v02.api.letsencrypt.org/directory",
    }
}

/// manual 动作从 prepare 起允许续跑的时长。过期后必须重新 prepare 获取新指引。
pub const ACTION_TTL: Duration = Duration::from_secs(24 * 3600);

/// 一次真实签发的输入。
#[derive(Debug, Clone)]
pub struct FlowOptions<'a> {
    /// 目标 ACME directory。
    pub kind: DirectoryKind,
    /// 覆盖默认 directory URL；fixture 用它指向 loopback。
    pub directory_url: &'a str,
    /// DNS provider id，必须出现在项目秘密文件里。
    pub dns_provider: &'a str,
    /// 原始 SAN，保留 `*.example.com` 形态。
    pub identifiers: &'a [String],
    /// 账户联系人，例如 `mailto:ops@example.com`。
    pub contact: &'a [String],
    /// 授权/订单轮询的最大次数。
    pub poll_attempts: usize,
    /// 两次轮询之间的基础等待。
    pub poll_delay: Duration,
}

/// manual 路径一次运行的结果。
#[derive(Debug)]
pub enum FlowOutcome {
    /// 证书已交付（resume 运行的结果）。
    Report(IssueReport),
    /// 领域已准备，等待外部人工操作后用 `--action` 续跑（prepare 运行的结果）。
    ActionRequired(ActionRequired),
}

/// 一条续跑指令：可复跑的命令名与字面 argv（不是 shell 串）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NextAction {
    /// 复跑的命令名。
    pub command: String,
    /// 复跑所需的字面参数，含 `--action <actionId>` 与 identifier。
    pub argv: Vec<String>,
}

/// manual 路径第一次运行的返回：待人工放置的记录与续跑引用。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionRequired {
    /// 稳定动作 id，第二次运行以 `--action <actionId>` 提交。
    pub action_id: String,
    /// 领域状态引用（订单 id）。
    pub status_ref: String,
    /// 续跑截止的 Unix 秒。
    pub expires_unix: u64,
    /// 需要操作者逐条放置的 TXT 记录。
    pub records: Vec<TxtInstruction>,
    /// 结构化续跑指令，机器消费者不必解析任何人类文本。
    pub next_action: NextAction,
}

/// 一次成功签发的报告。
///
/// 只包含公开标识、有效期、generation 身份与受控文件位置，不含私钥正文、token 或 key
/// authorization。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueReport {
    /// 账户 URL。
    pub account_url: String,
    /// 订单 URL。
    pub order_url: String,
    /// 交付代。
    pub generation: String,
    /// 本次实际删除的 TXT 记录数。
    pub dns_records_removed: usize,
    /// manual 路径交付后仍需操作者从 DNS 控制台删除的记录。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub manual_records_to_remove: Vec<TxtInstruction>,
    /// 叶子证书里的 SAN。
    pub sans: Vec<String>,
    /// 叶子 DER 的 SHA-256 指纹，十六进制小写。
    pub certificate_sha256: String,
    /// 有效期起点（Unix 秒）。
    pub not_before_unix: u64,
    /// 有效期终点（Unix 秒）。
    pub not_after_unix: u64,
    /// 证书、链与私钥的受控位置。
    pub paths: crate::delivery::GenerationPaths,
}

/// 执行一次 API provider 驱动的真实签发：provider 自己落位记录，单 run 完成。
///
/// 锁覆盖完整流程。失败时已发布的 TXT 仍会被清理，账户与订单状态保留供续跑。
pub fn issue_api<T: Transport, D: DnsProvider>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, dns: &mut D) -> Result<IssueReport> {
    let _lock = ProjectLock::acquire(project)?;
    let plan = plan_issue(project, options.kind, options.dns_provider, options.identifiers)?;
    let store = StateStore::new(project);
    let mut published: Vec<TxtRecord> = Vec::new();
    let outcome = run_api(project, options, transport, dns, &store, &plan, &mut published);
    let removed = cleanup(dns, &published);
    let report = outcome?;
    Ok(IssueReport { dns_records_removed: removed, ..report })
}

/// 执行一次 manual 路径的运行。
///
/// `action` 为 `None` 时是 prepare：取到全部 TXT 指引、落盘 [`PendingAction`] 并返回
/// [`FlowOutcome::ActionRequired`]，绝不回复任何挑战。带 id 时是 resume：先校验项目输入
/// 指纹、阶段与到期，再对同一订单回复挑战、轮询、finalize 并交付；消费成功后动作删除，
/// 重复续跑会被明确拒绝。
pub fn issue_manual<T: Transport>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, action: Option<&str>) -> Result<FlowOutcome> {
    let _lock = ProjectLock::acquire(project)?;
    let plan = plan_issue(project, options.kind, options.dns_provider, options.identifiers)?;
    let store = StateStore::new(project);
    match action {
        None => prepare_manual(project, options, transport, &store, &plan),
        Some(id) => resume_manual(project, options, transport, &store, &plan, id).map(FlowOutcome::Report),
    }
}

/// 建立账户与订单上下文：账户复用/新建、订单复用/新建，返回可继续推进的状态。
fn bootstrap_order<T: Transport>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, store: &StateStore, order_id: &str) -> Result<(AcmeClient<T>, String, OrderState, crate::acme::Order)> {
    let account_key = keys::account_key(project, options.kind)?;
    let thumbprint = account_key.thumbprint();
    let mut client = AcmeClient::bootstrap(transport, account_key, options.directory_url)?;

    let account_url = match store.account(options.kind)? {
        Some(account) => {
            if account.key_thumbprint != thumbprint {
                return Err(Error::new(
                    ErrorCode::Protocol,
                    "本地账户密钥与状态文件记录的 thumbprint 不一致，拒绝使用另一个身份续跑",
                ));
            }
            client.bind_account(account.account_url.clone());
            account.account_url
        }
        None => {
            let account = client.new_account(options.contact, true)?;
            store.save_account(&AccountState {
                kind: options.kind,
                directory_url: options.directory_url.to_owned(),
                account_url: account.url.clone(),
                key_thumbprint: thumbprint,
                created_unix: unix_now(),
            })?;
            account.url
        }
    };

    let resumed = store.order(order_id)?.filter(|order| order.phase.is_open() && order.account_url == account_url);
    let mut order_state = match &resumed {
        Some(state) => state.clone(),
        None => OrderState {
            id: order_id.to_owned(),
            kind: options.kind,
            account_url: account_url.clone(),
            order_url: None,
            identifiers: options.identifiers.to_vec(),
            authorizations: Vec::new(),
            csr_sha256: None,
            certificate_sha256: None,
            phase: OrderPhase::Planned,
            updated_unix: unix_now(),
        },
    };

    let order = match order_state.order_url.as_deref() {
        Some(url) => client.order(url)?,
        None => {
            let order = client.new_order(options.identifiers)?;
            order_state.order_url = Some(order.url.clone());
            // 授权状态在取到 challenge 时才填充：那时才有 identifier 与记录名，
            // 提前写空占位会让状态校验失败。
            store.save_order(&order_state)?;
            order
        }
    };
    Ok((client, account_url, order_state, order))
}

/// API provider 路径：发布 DNS、回复挑战、轮询、finalize、交付。
#[allow(clippy::too_many_arguments)]
fn run_api<T: Transport, D: DnsProvider>(
    project: &ProjectRoot,
    options: &FlowOptions<'_>,
    transport: T,
    dns: &mut D,
    store: &StateStore,
    plan: &IssuePlan,
    published: &mut Vec<TxtRecord>,
) -> Result<IssueReport> {
    let id = order_id(options.kind, options.identifiers);
    let (mut client, account_url, mut order_state, order) = bootstrap_order(project, options, transport, store, &id)?;

    // 授权：发布 DNS、回复挑战、轮询到 valid。
    for (index, url) in order.authorizations.iter().enumerate() {
        let already_valid = order_state.authorizations.get(index).is_some_and(|state| state.status == "valid");
        if already_valid {
            continue;
        }
        let challenge = client.dns_challenge(url)?;
        let fqdn = challenge.record_fqdn();
        let value = challenge.txt_value();
        let record = dns.put_txt(&fqdn, &value)?;
        published.push(record.clone());
        let state = AuthorizationState {
            url: url.clone(),
            identifier: challenge.identifier.clone(),
            wildcard: challenge.wildcard,
            record_fqdn: fqdn,
            txt_digest: value,
            status: "pending".to_owned(),
            record_id: Some(record.handle.as_str().to_owned()),
        };
        store_authorization(&mut order_state, index, state.clone());
        store.save_order(&order_state)?;

        client.respond_challenge(&challenge.challenge.url)?;
        poll_authorization(&mut client, url, options.poll_attempts, options.poll_delay)?;
        store_authorization(&mut order_state, index, AuthorizationState { status: "valid".to_owned(), ..state });
        store.save_order(&order_state)?;
    }
    order_state.phase = OrderPhase::Authorized;
    store.save_order(&order_state)?;

    finalize_and_deliver(project, options, &mut client, account_url, store, plan, &id, &mut order_state, order, Vec::new())
}

/// manual prepare：取到全部 TXT 指引并落盘，不回复任何挑战。
fn prepare_manual<T: Transport>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, store: &StateStore, plan: &IssuePlan) -> Result<FlowOutcome> {
    let id = order_id(options.kind, options.identifiers);
    let (mut client, _account_url, mut order_state, order) = bootstrap_order(project, options, transport, store, &id)?;

    let mut records: Vec<TxtInstruction> = Vec::new();
    for (index, url) in order.authorizations.iter().enumerate() {
        let already_valid = order_state.authorizations.get(index).is_some_and(|state| state.status == "valid");
        if already_valid {
            continue;
        }
        let challenge = client.dns_challenge(url)?;
        let fqdn = challenge.record_fqdn();
        let value = challenge.txt_value();
        records.push(TxtInstruction { fqdn: fqdn.clone(), value: value.clone() });
        store_authorization(
            &mut order_state,
            index,
            AuthorizationState {
                url: url.clone(),
                identifier: challenge.identifier.clone(),
                wildcard: challenge.wildcard,
                record_fqdn: fqdn,
                txt_digest: value,
                status: "pending".to_owned(),
                record_id: None,
            },
        );
    }
    order_state.phase = OrderPhase::AwaitingDns;
    store.save_order(&order_state)?;

    let now = unix_now();
    let expires_unix = now + ACTION_TTL.as_secs();
    let action = PendingAction {
        id: action_id(&id),
        kind: options.kind,
        order_id: id.clone(),
        input_fingerprint: input_fingerprint(options.kind, plan),
        records: records.clone(),
        created_unix: now,
        expires_unix,
    };
    store.save_action(&action)?;

    let mut argv = vec!["--action".to_owned(), action.id.clone()];
    argv.extend(plan.identifiers.iter().cloned());
    Ok(FlowOutcome::ActionRequired(ActionRequired {
        action_id: action.id,
        status_ref: id,
        expires_unix,
        records,
        next_action: NextAction { command: "acme-issue".to_owned(), argv },
    }))
}

/// manual resume：校验动作后对同一订单回复挑战、轮询并交付。
fn resume_manual<T: Transport>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, store: &StateStore, plan: &IssuePlan, requested_id: &str) -> Result<IssueReport> {
    let action = store
        .action(requested_id)?
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("动作 `{requested_id}` 不存在或已被消费，请重新运行不带 `--action` 的签发获取指引")))?;

    if action.kind != options.kind {
        return Err(Error::new(ErrorCode::InvalidArgument, format!("动作 `{requested_id}` 属于 `{}` directory，与本次请求不一致", action.kind.as_str())));
    }
    let fingerprint = input_fingerprint(options.kind, plan);
    if action.input_fingerprint != fingerprint {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("动作 `{requested_id}` 的输入指纹与当前请求（provider、identifier）不匹配，拒绝跨输入续跑"),
        ));
    }
    if unix_now() > action.expires_unix {
        return Err(Error::new(ErrorCode::InvalidArgument, format!("动作 `{requested_id}` 已过期，请重新 prepare 获取新的 TXT 指引")));
    }

    let order_state = store
        .order(&action.order_id)?
        .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("动作 `{requested_id}` 关联的订单状态 `{}` 已不存在", action.order_id)))?;
    if order_state.phase != OrderPhase::AwaitingDns {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!("动作 `{requested_id}` 关联的订单当前阶段是 `{}`，不处于等待人工 DNS 的状态", order_state.phase.as_str()),
        ));
    }

    let id = action.order_id.clone();
    let (mut client, account_url, mut order_state, order) = bootstrap_order(project, options, transport, store, &id)?;

    // 对每条尚未 valid 的授权：重取 challenge 确认记录名一致，回复并轮询。
    for (index, url) in order.authorizations.iter().enumerate() {
        let state = order_state
            .authorizations
            .get(index)
            .cloned()
            .ok_or_else(|| Error::new(ErrorCode::Protocol, "订单状态缺少 prepare 阶段应已落盘的授权记录"))?;
        if state.status == "valid" {
            continue;
        }
        let challenge = client.dns_challenge(url)?;
        if challenge.record_fqdn() != state.record_fqdn {
            return Err(Error::new(
                ErrorCode::Protocol,
                format!("授权 `{url}` 的记录名与 prepare 时落盘的不一致，拒绝继续"),
            ));
        }
        client.respond_challenge(&challenge.challenge.url)?;
        poll_authorization(&mut client, url, options.poll_attempts, options.poll_delay)?;
        store_authorization(&mut order_state, index, AuthorizationState { status: "valid".to_owned(), ..state });
        store.save_order(&order_state)?;
    }
    order_state.phase = OrderPhase::Authorized;
    store.save_order(&order_state)?;

    let report = finalize_and_deliver(project, options, &mut client, account_url, store, plan, &id, &mut order_state, order, action.records.clone())?;
    store.delete_action(requested_id)?;
    Ok(report)
}

/// 授权完成后的共同尾部：CSR、finalize、下载、SAN 核验、交付。
#[allow(clippy::too_many_arguments)]
fn finalize_and_deliver<T: Transport>(
    project: &ProjectRoot,
    options: &FlowOptions<'_>,
    client: &mut AcmeClient<T>,
    account_url: String,
    store: &StateStore,
    plan: &IssuePlan,
    order_id: &str,
    order_state: &mut OrderState,
    order: crate::acme::Order,
    manual_records_to_remove: Vec<TxtInstruction>,
) -> Result<IssueReport> {
    // 叶子私钥与 CSR。
    let leaf_key = keys::order_key(project, order_id)?;
    let common_name = plan.identifiers.iter().find(|name| !name.starts_with("*.")).unwrap_or(&plan.identifiers[0]).clone();
    let csr_der = csr::create(&leaf_key, &common_name, options.identifiers);
    order_state.csr_sha256 = Some(sha256_hex(&csr_der));
    store.save_order(order_state)?;

    let order = client.finalize(&order, &csr_der)?;
    order_state.phase = OrderPhase::Submitted;
    store.save_order(order_state)?;
    let order = client.poll_order(&order.url, options.poll_attempts, options.poll_delay)?;
    let certificate_url = order
        .certificate
        .clone()
        .ok_or_else(|| Error::new(ErrorCode::Protocol, "订单已 valid，但响应没有 certificate URL"))?;

    let chain_pem = client.certificate(&certificate_url)?;
    let certificates = pem_bundle("CERTIFICATE", &chain_pem);
    if certificates.len() < 2 {
        return Err(Error::new(ErrorCode::Protocol, "CA 返回的证书链缺少中间证书"));
    }
    let leaf = Certificate::parse(&certificates[0]).map_err(|error| Error::new(ErrorCode::Protocol, format!("叶子证书无法解析：{error}")))?;
    for identifier in options.identifiers {
        let bare = identifier.trim_start_matches("*.");
        if !leaf.extensions.dns_names.iter().any(|name| name.eq_ignore_ascii_case(identifier) || name.eq_ignore_ascii_case(bare)) {
            return Err(Error::new(ErrorCode::Protocol, format!("证书 SAN 不包含 `{identifier}`")));
        }
    }

    let bundle = crate::delivery::CertificateBundle {
        certificate_pem: pem_encode("CERTIFICATE", &certificates[0]),
        chain_pem: certificates[1..].iter().map(|der| pem_encode("CERTIFICATE", der)).collect(),
        private_key_pem: keys::private_key_pem(&leaf_key)?,
    };
    let delivery = Delivery::new(project);
    let staged = delivery.stage(&bundle)?;
    let generation = delivery.commit(staged)?;
    order_state.phase = OrderPhase::Issued;
    order_state.certificate_sha256 = Some(generation.certificate_sha256.clone());
    store.save_order(order_state)?;

    let paths = delivery.paths(&generation.id);
    Ok(IssueReport {
        account_url,
        order_url: order.url,
        generation: generation.id,
        dns_records_removed: 0,
        manual_records_to_remove,
        sans: leaf.extensions.dns_names.clone(),
        certificate_sha256: generation.certificate_sha256,
        not_before_unix: crate::delivery::epoch_seconds(leaf.not_before),
        not_after_unix: crate::delivery::epoch_seconds(leaf.not_after),
        paths,
    })
}

fn poll_authorization<T: Transport>(client: &mut AcmeClient<T>, url: &str, attempts: usize, delay: Duration) -> Result<()> {
    let attempts = attempts.max(1);
    for attempt in 0..attempts {
        let authorization = client.authorization(url)?;
        match authorization.status {
            AuthorizationStatus::Valid => return Ok(()),
            AuthorizationStatus::Pending => {}
            other => {
                return Err(Error::new(ErrorCode::Protocol, format!("授权 `{url}` 进入终态 `{}`", other.as_str())));
            }
        }
        if attempt + 1 < attempts && !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }
    Err(Error::new(ErrorCode::Network, format!("授权 `{url}` 轮询超时")))
}

fn store_authorization(order: &mut OrderState, index: usize, state: AuthorizationState) {
    if let Some(slot) = order.authorizations.get_mut(index) {
        *slot = state;
    }
    else {
        order.authorizations.push(state);
    }
    order.updated_unix = unix_now();
}

fn cleanup<D: DnsProvider>(dns: &mut D, records: &[TxtRecord]) -> usize {
    let mut removed = 0;
    for record in records {
        if dns.delete_txt(record).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// 同一 directory 与同一组标识的稳定订单 id。
///
/// 恢复路径依赖它找到未完成订单；fixture 也用它预先放置叶子私钥。
#[must_use]
pub fn order_id(kind: DirectoryKind, identifiers: &[String]) -> String {
    let mut material = format!("{}:", kind.as_str());
    for identifier in identifiers {
        material.push_str(identifier);
        material.push('\n');
    }
    sha256_hex(material.as_bytes())[..16].to_owned()
}

/// 一个订单对应的 manual 动作的稳定 id。
///
/// 同一订单同一时刻只有一个待执行动作；重新 prepare 会覆盖它。
#[must_use]
pub fn action_id(order: &str) -> String {
    format!("dns01-{order}")
}

/// 绑定续跑合法性的输入指纹：directory、provider 与规范化 identifier 集的摘要。
///
/// 恢复时由当前请求重算比对。它防的是拿错项目/改过输入的误用，不是防篡改认证。
#[must_use]
pub fn input_fingerprint(kind: DirectoryKind, plan: &IssuePlan) -> String {
    let mut material = format!("{}:{}:", kind.as_str(), plan.dns_provider);
    for identifier in &plan.identifiers {
        material.push_str(identifier);
        material.push('\n');
    }
    sha256_hex(material.as_bytes())[..16].to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}
