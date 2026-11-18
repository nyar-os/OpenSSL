//! The ACME client: directory bootstrap, nonce management, and the issuance flow.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use boost_net::http::{Method, Request, Response, Transport, Url};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    directory::{self, Directory},
    jws::{AccountKey, AccountRef, b64url, build_jws},
    types::{
        Account, Authorization, Challenge, ChallengeStatus, Order, OrderStatus, Problem, parse_account, parse_authorization, parse_challenge,
        parse_order,
    },
};
use crate::errors::{Error, ErrorCode, Result};

/// The replay-nonce response header.
const NONCE_HEADER: &str = "replay-nonce";
/// The resource location response header.
const LOCATION_HEADER: &str = "location";
/// The polling hint response header.
const RETRY_AFTER_HEADER: &str = "retry-after";
/// The only ACME problem type that makes a request worth repeating.
const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

/// 一个 key authorization 对应的 dns-01 TXT 值（RFC 8555 §8.4）：
/// `base64url-nopad(SHA-256(key authorization))`。key authorization 本身永不发布。
///
/// 本仓 pin 的 Boost revision 尚未提供 hash 与 URL-safe 编码门面，因此这里用依赖里已有的
/// `sha2` 计算摘要，并手工套用 URL-safe 字母表、去掉填充。A2 收口共享基础后改用 Boost 的
/// 正式 hash 与 URL-safe 编码实现，不为此提前升级 `rev`。
#[must_use]
pub fn txt_digest(key_authorization: &str) -> String {
    base64url_nopad(&Sha256::digest(key_authorization.as_bytes()))
}

/// 不带填充的 URL-safe base64。
fn base64url_nopad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = chunk.get(1).map_or(0, |byte| u32::from(*byte));
        let third = chunk.get(2).map_or(0, |byte| u32::from(*byte));
        let triple = (first << 16) | (second << 8) | third;
        encoded.push(char::from(ALPHABET[(triple >> 18) as usize & 0x3f]));
        encoded.push(char::from(ALPHABET[(triple >> 12) as usize & 0x3f]));
        if chunk.len() > 1 {
            encoded.push(char::from(ALPHABET[(triple >> 6) as usize & 0x3f]));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[triple as usize & 0x3f]));
        }
    }
    encoded
}

/// 一个 dns-01 挑战及其对应的 authorization 身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsChallenge {
    /// 挑战资源。
    pub challenge: Challenge,
    /// authorization 覆盖的标识，已去掉 `*.` 前缀。
    pub identifier: String,
    /// authorization 是否覆盖泛域名标识。
    pub wildcard: bool,
    /// `token '.' thumbprint`。它是摘要输入，不是 TXT 值。
    pub key_authorization: String,
}

impl DnsChallenge {
    /// 本次 authorization 验证所用的 `_acme-challenge.` 记录名。
    #[must_use]
    pub fn record_fqdn(&self) -> String {
        crate::dns::challenge_fqdn(&self.identifier)
    }

    /// 应当发布的 TXT 值：key authorization 的摘要。
    #[must_use]
    pub fn txt_value(&self) -> String {
        txt_digest(&self.key_authorization)
    }
}

/// 一次订单轮询响应如何处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderPollVerdict {
    /// 订单进入 `valid`，可以下载证书。
    Issued,
    /// 订单仍是 `pending`、`ready` 或 `processing`。
    Pending,
    /// 订单进入终态 `invalid`。
    Failed,
}

/// 归类一个订单状态用于轮询。
#[must_use]
pub const fn order_poll_verdict(status: OrderStatus) -> OrderPollVerdict {
    match status {
        OrderStatus::Valid => OrderPollVerdict::Issued,
        OrderStatus::Pending | OrderStatus::Ready | OrderStatus::Processing => OrderPollVerdict::Pending,
        OrderStatus::Invalid => OrderPollVerdict::Failed,
    }
}

/// 下一次轮询前的等待时长，尊重 `Retry-After`。
///
/// `now_unix` 是当前 Unix 秒，因此 HTTP 日期被换算成相对延迟。既不是 delta-seconds 也不是
/// HTTP 日期的值退回 `fallback`，且所有结果都被 `max` 截断，避免恶意响应头拖死流程。
#[must_use]
pub fn retry_after_delay(value: Option<&str>, now_unix: u64, fallback: Duration, max: Duration) -> Duration {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty())
    else {
        return fallback.min(max);
    };
    let seconds = if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u64>().ok()
    }
    else {
        parse_http_date(value).map(|epoch| epoch.saturating_sub(now_unix))
    };
    match seconds {
        Some(seconds) => Duration::from_secs(seconds).min(max),
        None => fallback.min(max),
    }
}

/// 把 IMF-fixdate（`Sun, 06 Nov 1994 08:49:37 GMT`）解析成 Unix 秒。
fn parse_http_date(value: &str) -> Option<u64> {
    let rest = value.strip_suffix(" GMT")?;
    let mut parts = rest.split(' ');
    let weekday = parts.next()?;
    if !weekday.ends_with(',') {
        return None;
    }
    let day = parts.next()?.parse::<i64>().ok()?;
    let month = match parts.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = parts.next()?.parse::<i64>().ok()?;
    let clock = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let mut fields = clock.split(':');
    let hour = fields.next()?.parse::<i64>().ok()?;
    let minute = fields.next()?.parse::<i64>().ok()?;
    let second = fields.next()?.parse::<i64>().ok()?;
    if fields.next().is_some()
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

/// 按 Howard Hinnant 算法计算公历日期距 1970-01-01 的天数。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// 当前 Unix 秒；主机时钟早于纪元时返回零。
fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

/// An RFC 8555 client over an injected family HTTP transport.
#[derive(Debug)]
pub struct AcmeClient<T: Transport> {
    transport: T,
    directory: Directory,
    key: AccountKey,
    account_url: Option<String>,
    nonce: Option<String>,
}

impl<T: Transport> AcmeClient<T> {
    /// Fetch the directory and adopt the account key before any account exists.
    pub fn bootstrap(transport: T, key: AccountKey, directory_url: &str) -> Result<Self> {
        let url = parse_url(directory_url)?;
        let response = transport.send(&Request::new(Method::Get, url))?;
        if response.status >= 400 {
            return Err(reject(&response));
        }
        let directory = directory::parse(&response.body)?;
        let nonce = response.headers.get(NONCE_HEADER).map(str::to_owned);
        Ok(Self { transport, directory, key, account_url: None, nonce })
    }

    /// The parsed directory URL table.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The account URL once `new_account` succeeded.
    pub fn account_url(&self) -> Option<&str> {
        self.account_url.as_deref()
    }

    /// Create (or idempotently retrieve) the account, binding the client to its URL.
    pub fn new_account(&mut self, contact: &[String], agree_terms: bool) -> Result<Account> {
        let mut payload = Map::new();
        payload.insert("termsOfServiceAgreed".to_owned(), Value::Bool(agree_terms));
        if !contact.is_empty() {
            payload.insert("contact".to_owned(), Value::Array(contact.iter().cloned().map(Value::String).collect()));
        }
        let response = self.post(&self.directory.new_account.clone(), &Value::Object(payload).to_string(), &AccountRef::Jwk)?;
        let url = location(&response)?;
        let account = parse_account(&url, &response.body)?;
        self.account_url = Some(url);
        Ok(account)
    }

    /// Query the bound account with a POST-as-GET.
    pub fn account(&mut self) -> Result<Account> {
        let url = self.kid()?;
        let response = self.post_as_get(&url)?;
        parse_account(&url, &response.body)
    }

    /// Create an order for the given DNS names (duplicate SANs included as-is).
    pub fn new_order(&mut self, dns_names: &[String]) -> Result<Order> {
        let identifiers: Vec<Value> = dns_names
            .iter()
            .map(|name| {
                let mut identifier = Map::new();
                identifier.insert("type".to_owned(), Value::String("dns".to_owned()));
                identifier.insert("value".to_owned(), Value::String(name.clone()));
                Value::Object(identifier)
            })
            .collect();
        let mut payload = Map::new();
        payload.insert("identifiers".to_owned(), Value::Array(identifiers));
        let kid = self.kid()?;
        let response = self.post(&self.directory.new_order.clone(), &Value::Object(payload).to_string(), &AccountRef::Kid(kid))?;
        let url = location(&response)?;
        parse_order(&url, &response.body)
    }

    /// Fetch one order resource.
    pub fn order(&mut self, url: &str) -> Result<Order> {
        let response = self.post_as_get(url)?;
        parse_order(url, &response.body)
    }

    /// 轮询订单直到进入终态，或到达由 `attempts` 与 `delay` 界定的截止点。
    ///
    /// `valid` 才算成功；`invalid` 立即以错误返回并带上 problem 详情；仍在 `pending`、
    /// `ready`、`processing` 时继续等待，等待时长取响应里的 `Retry-After`（不超过 `delay`）。
    /// 截止点到达后返回明确的超时错误，绝不把最后一次的未完成状态当成成功。
    pub fn poll_order(&mut self, url: &str, attempts: usize, delay: Duration) -> Result<Order> {
        let attempts = attempts.max(1);
        let mut last_status = None;
        for attempt in 0..attempts {
            let response = self.post_as_get(url)?;
            let order = parse_order(url, &response.body)?;
            match order_poll_verdict(order.status) {
                OrderPollVerdict::Issued => return Ok(order),
                OrderPollVerdict::Failed => {
                    let detail = order
                        .error
                        .as_ref()
                        .map(|problem| problem.detail.as_str())
                        .filter(|detail| !detail.is_empty())
                        .unwrap_or("响应没有给出 problem 详情");
                    return Err(Error::new(ErrorCode::Protocol, format!("订单 {} 进入终态 `{}`：{detail}", order.url, order.status.as_str())));
                }
                OrderPollVerdict::Pending => last_status = Some(order.status),
            }
            if attempt + 1 < attempts {
                let wait = retry_after_delay(response.headers.get(RETRY_AFTER_HEADER), unix_now(), delay, delay);
                if !wait.is_zero() {
                    std::thread::sleep(wait);
                }
            }
        }
        Err(Error::new(ErrorCode::Network, format!("轮询订单 {url} 超时，最后状态为 `{}`", last_status.map_or("unknown", OrderStatus::as_str))))
    }

    /// Fetch one authorization resource.
    pub fn authorization(&mut self, url: &str) -> Result<Authorization> {
        let response = self.post_as_get(url)?;
        parse_authorization(url, &response.body)
    }

    /// 取得一个 authorization，并选出它的 `dns-01` 挑战与 key authorization。
    pub fn dns_challenge(&mut self, authorization_url: &str) -> Result<DnsChallenge> {
        let authorization = self.authorization(authorization_url)?;
        let challenge = authorization.dns01().ok_or_else(|| Error::new(ErrorCode::Protocol, "该 authorization 没有提供 dns-01 挑战"))?.clone();
        let key_authorization = self.key.key_authorization(&challenge.token);
        Ok(DnsChallenge { challenge, identifier: authorization.identifier.value, wildcard: authorization.wildcard, key_authorization })
    }

    /// Tell the server that the challenge response is ready and return its new status.
    pub fn respond_challenge(&mut self, url: &str) -> Result<ChallengeStatus> {
        let response = self.post_json(url, "{}")?;
        Ok(parse_challenge(url, &response.body)?.status)
    }

    /// Submit the finalized CSR and return the updated order.
    pub fn finalize(&mut self, order: &Order, csr_der: &[u8]) -> Result<Order> {
        let mut payload = Map::new();
        payload.insert("csr".to_owned(), Value::String(b64url(csr_der)));
        let response = self.post_json(&order.finalize, &Value::Object(payload).to_string())?;
        parse_order(&order.url, &response.body)
    }

    /// Download the certificate chain in PEM encoding.
    pub fn certificate(&mut self, url: &str) -> Result<String> {
        let response = self.post_as_get(url)?;
        String::from_utf8(response.body).map_err(|_| Error::new(ErrorCode::Protocol, "the certificate chain is not UTF-8 PEM"))
    }

    /// The bound account URL, required by every account-bound request.
    fn kid(&self) -> Result<String> {
        self.account_url.clone().ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "no ACME account is bound to this client"))
    }

    /// Take the cached nonce or fetch a fresh one from the directory's `newNonce`.
    fn refresh_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let url = parse_url(&self.directory.new_nonce)?;
        let response = self.transport.send(&Request::new(Method::Head, url))?;
        response
            .headers
            .get(NONCE_HEADER)
            .map(str::to_owned)
            .ok_or_else(|| Error::new(ErrorCode::Protocol, "the server did not issue a replay nonce"))
    }

    /// 发送一次 JWS；只有当响应 problem 类型是 `badNonce` 时才用新 nonce 重试一次。
    fn post(&mut self, url: &str, payload_json: &str, account: &AccountRef) -> Result<Response> {
        let mut retried = false;
        loop {
            let nonce = self.refresh_nonce()?;
            let document = build_jws(&self.key, account, url, &nonce, payload_json)?;
            let response = self.transport.send(
                &Request::new(Method::Post, parse_url(url)?)
                    .with_header("Content-Type", "application/jose+json")
                    .with_body(document.into_bytes()),
            )?;
            if let Some(nonce) = response.headers.get(NONCE_HEADER) {
                self.nonce = Some(nonce.to_owned());
            }
            if response.status >= 400 {
                let problem = Problem::parse(response.status, &response.body);
                if problem.problem_type.as_deref() == Some(BAD_NONCE) && !retried {
                    retried = true;
                    continue;
                }
                return Err(reject(&response));
            }
            return Ok(response);
        }
    }

    /// A POST-as-GET: an empty payload authenticated with the account URL.
    fn post_as_get(&mut self, url: &str) -> Result<Response> {
        let kid = self.kid()?;
        self.post(url, "", &AccountRef::Kid(kid))
    }

    /// A POST with a JSON payload authenticated with the account URL.
    fn post_json(&mut self, url: &str, payload_json: &str) -> Result<Response> {
        let kid = self.kid()?;
        self.post(url, payload_json, &AccountRef::Kid(kid))
    }
}

fn parse_url(url: &str) -> Result<Url> {
    Url::parse(url).map_err(|error| Error::new(ErrorCode::Protocol, format!("invalid URL `{url}`: {error}")))
}

fn location(response: &Response) -> Result<String> {
    response
        .headers
        .get(LOCATION_HEADER)
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, "the server omitted the Location header"))
}

fn reject(response: &Response) -> Error {
    let problem = Problem::parse(response.status, &response.body);
    let code = if response.status == 403 { ErrorCode::Denied } else { ErrorCode::Protocol };
    let detail = if problem.detail.is_empty() { format!("status {}", response.status) } else { problem.detail };
    Error::new(code, format!("the ACME server rejected the request to {}: {detail}", response.url))
}
