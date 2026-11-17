//! The ACME client: directory bootstrap, nonce management, and the issuance flow.

use std::time::Duration;

use boost_net::http::{Method, Request, Response, Transport, Url};
use serde_json::{Map, Value};

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

/// A dns-01 challenge paired with the key authorization the account expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsChallenge {
    /// The challenge resource.
    pub challenge: Challenge,
    /// The value to place in the `_acme-challenge.` TXT record.
    pub key_authorization: String,
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

    /// Poll an order until it reaches a terminal status or the attempts run out.
    pub fn poll_order(&mut self, url: &str, attempts: usize, delay: Duration) -> Result<Order> {
        let mut last = None;
        for attempt in 0..attempts.max(1) {
            let order = self.order(url)?;
            if matches!(order.status, OrderStatus::Valid | OrderStatus::Invalid) {
                return Ok(order);
            }
            last = Some(order);
            if !delay.is_zero() && attempt + 1 < attempts {
                std::thread::sleep(delay);
            }
        }
        last.ok_or_else(|| Error::new(ErrorCode::Internal, "the order poll made no request"))
    }

    /// Fetch one authorization resource.
    pub fn authorization(&mut self, url: &str) -> Result<Authorization> {
        let response = self.post_as_get(url)?;
        parse_authorization(url, &response.body)
    }

    /// Fetch an authorization and select its `dns-01` challenge with the key authorization.
    pub fn dns_challenge(&mut self, authorization_url: &str) -> Result<DnsChallenge> {
        let authorization = self.authorization(authorization_url)?;
        let challenge =
            authorization.dns01().ok_or_else(|| Error::new(ErrorCode::Protocol, "the authorization offers no dns-01 challenge"))?.clone();
        let key_authorization = self.key.key_authorization(&challenge.token);
        Ok(DnsChallenge { challenge, key_authorization })
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

    /// POST one JWS, retrying exactly once after a `409 badNonce`.
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
            if response.status == 409 && !retried {
                retried = true;
                continue;
            }
            if response.status >= 400 {
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
