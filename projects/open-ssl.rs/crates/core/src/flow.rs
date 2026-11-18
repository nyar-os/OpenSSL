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
//! 传输与 DNS 都由调用方注入，因此同一实现既能在 loopback fixture 上验证成功、失败与
//! 恢复，也能用 [`crate::tls::HttpsTransport`] 与 `Cloudflare` 打真实 CA。

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boost_net::http::Transport;

use crate::{
    acme::{AccountKey, AcmeClient, AuthorizationStatus},
    csr::{self},
    delivery::Delivery,
    dns::{DnsProvider, TxtRecord, challenge_fqdn},
    dns::credentials::ProjectRoot,
    errors::{Error, ErrorCode, Result},
    keys,
    lock::ProjectLock,
    state::{AccountState, AuthorizationState, DirectoryKind, OrderPhase, OrderState, StateStore, plan_issue},
    x509::{Certificate, pem_bundle},
};

/// 一个 CA 的 directory URL。
#[must_use]
pub const fn directory_url(kind: DirectoryKind) -> &'static str {
    match kind {
        DirectoryKind::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        DirectoryKind::Production => "https://acme-v02.api.letsencrypt.org/directory",
    }
}

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

/// 一次成功签发的报告。
///
/// 只包含公开标识与 generation 身份，不含私钥、token 或 key authorization。
#[derive(Debug, Clone)]
pub struct IssueReport {
    /// 账户 URL。
    pub account_url: String,
    /// 订单 URL。
    pub order_url: String,
    /// 交付代。
    pub generation: String,
    /// 本次实际删除的 TXT 记录数。
    pub dns_records_removed: usize,
}

/// 执行一次真实签发。
///
/// 锁覆盖完整流程。失败时已发布的 TXT 仍会被清理，账户与订单状态保留供续跑。
pub fn issue<T: Transport, D: DnsProvider>(project: &ProjectRoot, options: &FlowOptions<'_>, transport: T, dns: &mut D) -> Result<IssueReport> {
    let _lock = ProjectLock::acquire(project)?;
    let plan = plan_issue(project, options.kind, options.dns_provider, options.identifiers)?;
    let store = StateStore::new(project);

    let mut published: Vec<TxtRecord> = Vec::new();
    let outcome = run(project, options, transport, dns, &store, &plan, &mut published);
    let removed = cleanup(dns, &published);
    let report = outcome?;
    Ok(IssueReport { dns_records_removed: removed, ..report })
}

fn run<T: Transport, D: DnsProvider>(
    project: &ProjectRoot,
    options: &FlowOptions<'_>,
    transport: T,
    dns: &mut D,
    store: &StateStore,
    plan: &crate::state::IssuePlan,
    published: &mut Vec<TxtRecord>,
) -> Result<IssueReport> {
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

    let order_id = order_id(options.kind, options.identifiers);
    let resumed = store.order(&order_id)?.filter(|order| order.phase.is_open() && order.account_url == account_url);
    let mut order_state = match &resumed {
        Some(state) => state.clone(),
        None => OrderState {
            id: order_id.clone(),
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
            order_state.authorizations = order
                .authorizations
                .iter()
                .map(|url| AuthorizationState {
                    url: url.clone(),
                    identifier: String::new(),
                    wildcard: false,
                    record_fqdn: String::new(),
                    txt_digest: String::new(),
                    status: "pending".to_owned(),
                    record_id: None,
                })
                .collect();
            store.save_order(&order_state)?;
            order
        }
    };

    // 授权：发布 DNS、回复挑战、轮询到 valid。
    for index in 0..order.authorizations.len() {
        let url = order.authorizations[index].clone();
        let already_valid = order_state.authorizations.get(index).is_some_and(|state| state.status == "valid");
        if already_valid {
            continue;
        }
        let challenge = client.dns_challenge(&url)?;
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
        poll_authorization(&mut client, &url, options.poll_attempts, options.poll_delay)?;
        store_authorization(&mut order_state, index, AuthorizationState { status: "valid".to_owned(), ..state });
        store.save_order(&order_state)?;
    }
    order_state.phase = OrderPhase::Authorized;
    store.save_order(&order_state)?;

    // 叶子私钥与 CSR。
    let leaf_key = keys::order_key(project, &order_id)?;
    let common_name = plan.identifiers.iter().find(|name| !name.starts_with("*.")).unwrap_or(&plan.identifiers[0]).clone();
    let csr_der = csr::create(&leaf_key, &common_name, options.identifiers);
    order_state.csr_sha256 = Some(sha256_hex(&csr_der));
    store.save_order(&order_state)?;

    let order = client.finalize(&order, &csr_der)?;
    order_state.phase = OrderPhase::Submitted;
    store.save_order(&order_state)?;
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
        certificate_pem: keys::pem_body(&certificates[0]),
        chain_pem: certificates[1..].iter().map(|der| keys::pem_body(der)).collect(),
        private_key_pem: keys::private_key_pem(&leaf_key)?,
    };
    let delivery = Delivery::new(project);
    let staged = delivery.stage(&bundle)?;
    let generation = delivery.commit(staged)?;
    order_state.phase = OrderPhase::Issued;
    order_state.certificate_sha256 = Some(generation.certificate_sha256.clone());
    store.save_order(&order_state)?;

    Ok(IssueReport { account_url, order_url: order.url, generation: generation.id, dns_records_removed: 0 })
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

fn order_id(kind: DirectoryKind, identifiers: &[String]) -> String {
    let mut material = format!("{}:", kind.as_str());
    for identifier in identifiers {
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
