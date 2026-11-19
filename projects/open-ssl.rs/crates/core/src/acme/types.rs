//! ACME resource documents: accounts, orders, authorizations, challenges, and problems.

use serde_json::Value;

use crate::errors::{Error, ErrorCode, Result};

/// Account lifecycle (RFC 8555 §7.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// The account is usable.
    Valid,
    /// The account awaits server-side review.
    Pending,
    /// The account was deactivated by the client.
    Deactivated,
    /// The account was revoked by the server.
    Revoked,
}

impl AccountStatus {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Pending => "pending",
            Self::Deactivated => "deactivated",
            Self::Revoked => "revoked",
        }
    }

    /// Parse the wire spelling, rejecting unknown values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "valid" => Ok(Self::Valid),
            "pending" => Ok(Self::Pending),
            "deactivated" => Ok(Self::Deactivated),
            "revoked" => Ok(Self::Revoked),
            _ => Err(unknown_status("account", value)),
        }
    }
}

/// Order lifecycle (RFC 8555 §7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    /// The order was created and authorizations are not complete.
    Pending,
    /// All authorizations are valid and the order awaits finalization.
    Ready,
    /// The server is issuing the certificate.
    Processing,
    /// The certificate is available.
    Valid,
    /// The order failed.
    Invalid,
}

impl OrderStatus {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }

    /// Parse the wire spelling, rejecting unknown values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(unknown_status("order", value)),
        }
    }
}

/// Authorization lifecycle (RFC 8555 §7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationStatus {
    /// The identifier is not yet validated.
    Pending,
    /// The identifier was validated.
    Valid,
    /// The validation failed.
    Invalid,
    /// The authorization was deactivated.
    Deactivated,
    /// The authorization expired before validation finished.
    Expired,
    /// The authorization was revoked by the server.
    Revoked,
}

impl AuthorizationStatus {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Deactivated => "deactivated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    /// Parse the wire spelling, rejecting unknown values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "deactivated" => Ok(Self::Deactivated),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(unknown_status("authorization", value)),
        }
    }

    /// 是否已经不可能再通过轮询改变。
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }

    /// 是否以失败告终（`invalid`、`deactivated`、`expired`、`revoked`）。
    pub const fn is_failed(self) -> bool {
        matches!(self, Self::Invalid | Self::Deactivated | Self::Expired | Self::Revoked)
    }
}

/// Challenge lifecycle (RFC 8555 §7.1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// The challenge was created and awaits a client response.
    Pending,
    /// The server is validating the response.
    Processing,
    /// The validation succeeded.
    Valid,
    /// The validation failed.
    Invalid,
}

impl ChallengeStatus {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Valid => "valid",
            Self::Invalid => "invalid",
        }
    }

    /// Parse the wire spelling, rejecting unknown values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            _ => Err(unknown_status("challenge", value)),
        }
    }
}

/// The challenge types this client understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// `dns-01`: a TXT record under `_acme-challenge.`.
    Dns01,
    /// `http-01`: a well-known HTTP resource.
    Http01,
    /// `tls-alpn-01`: an ALPN-based TLS response.
    TlsAlpn01,
}

impl ChallengeType {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns01 => "dns-01",
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }

    /// Parse the wire spelling, rejecting unknown values.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "dns-01" => Ok(Self::Dns01),
            "http-01" => Ok(Self::Http01),
            "tls-alpn-01" => Ok(Self::TlsAlpn01),
            _ => Err(unknown_status("challenge type", value)),
        }
    }
}

/// One identifier inside an authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identifier {
    /// The identifier type, `dns` for every flow this client supports.
    pub kind: String,
    /// The identifier value, for example `example.test`.
    pub value: String,
}

/// One challenge offered for an authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The challenge URL to POST a response to.
    pub url: String,
    /// The challenge type.
    pub kind: ChallengeType,
    /// The random token that feeds the key authorization.
    pub token: String,
    /// The current status.
    pub status: ChallengeStatus,
}

/// An authorization for one identifier of an order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The authorization URL to POST-as-GET for updates.
    pub url: String,
    /// The current status.
    pub status: AuthorizationStatus,
    /// The identifier this authorization covers.
    pub identifier: Identifier,
    /// Whether the server marked this authorization as a wildcard validation.
    pub wildcard: bool,
    /// The challenges the server offers, in server order.
    pub challenges: Vec<Challenge>,
}

impl Authorization {
    /// The `dns-01` challenge, when the server offers one.
    pub fn dns01(&self) -> Option<&Challenge> {
        self.challenges.iter().find(|challenge| challenge.kind == ChallengeType::Dns01)
    }
}

/// An ACME order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    /// The order URL (the `Location` of the creation response).
    pub url: String,
    /// The current status.
    pub status: OrderStatus,
    /// The authorization URLs to complete before finalizing.
    pub authorizations: Vec<String>,
    /// The finalize URL for the CSR.
    pub finalize: String,
    /// The certificate download URL, once the order is valid.
    pub certificate: Option<String>,
    /// The problem document, when the order is invalid.
    pub error: Option<Problem>,
}

/// An ACME account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// The account URL (the `Location` of the creation response).
    pub url: String,
    /// The current status.
    pub status: AccountStatus,
    /// The registered contact URLs.
    pub contact: Vec<String>,
    /// Whether the server recorded terms agreement.
    pub terms_of_service_agreed: bool,
}

/// An RFC 7807 problem document returned by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The HTTP status the problem arrived with.
    pub status: u16,
    /// The `urn:ietf:params:acme:error:` type, when present.
    pub problem_type: Option<String>,
    /// The human-readable detail.
    pub detail: String,
}

impl Problem {
    /// Parse a problem body best-effort; any non-JSON body keeps its text as the detail.
    pub fn parse(status: u16, body: &[u8]) -> Self {
        let document: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let detail =
            document.get("detail").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
        Self { status, problem_type: document.get("type").and_then(Value::as_str).map(str::to_owned), detail }
    }
}

fn unknown_status(context: &str, value: &str) -> Error {
    Error::new(ErrorCode::Protocol, format!("unknown {context} status `{value}`"))
}

fn document(body: &[u8], context: &str) -> Result<Value> {
    serde_json::from_slice(body).map_err(|error| Error::new(ErrorCode::Protocol, format!("{context} body is not JSON: {error}")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| Error::new(ErrorCode::Protocol, format!("{context} is missing `{key}`")))
}

fn string_array(value: &Value, key: &str, context: &str) -> Result<Vec<String>> {
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("{context} is missing the `{key}` array")))?;
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| Error::new(ErrorCode::Protocol, format!("{context} `{key}` has a non-string entry")))
        })
        .collect()
}

/// Parse an account document; the URL comes from the creation response's `Location`.
pub fn parse_account(url: &str, body: &[u8]) -> Result<Account> {
    let document = document(body, "account")?;
    Ok(Account {
        url: url.to_owned(),
        status: AccountStatus::parse(string_field(&document, "status", "account")?)?,
        contact: match document.get("contact") {
            Some(Value::Null) | None => Vec::new(),
            Some(_) => string_array(&document, "contact", "account")?,
        },
        terms_of_service_agreed: document.get("termsOfServiceAgreed").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Parse an order document.
pub fn parse_order(url: &str, body: &[u8]) -> Result<Order> {
    let document = document(body, "order")?;
    let error = document.get("error").map(|error| {
        let status = error.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
        let detail = error.get("detail").and_then(Value::as_str).map(str::to_owned).unwrap_or_default();
        let problem_type = error.get("type").and_then(Value::as_str).map(str::to_owned);
        Problem { status, problem_type, detail }
    });
    Ok(Order {
        url: url.to_owned(),
        status: OrderStatus::parse(string_field(&document, "status", "order")?)?,
        authorizations: string_array(&document, "authorizations", "order")?,
        finalize: string_field(&document, "finalize", "order")?.to_owned(),
        certificate: document.get("certificate").and_then(Value::as_str).map(str::to_owned),
        error,
    })
}

/// Parse one challenge document; `url` overrides the body's `url` when the server omits it.
pub fn parse_challenge(url: &str, body: &[u8]) -> Result<Challenge> {
    let document = document(body, "challenge")?;
    Ok(Challenge {
        url: document.get("url").and_then(Value::as_str).unwrap_or(url).to_owned(),
        kind: ChallengeType::parse(string_field(&document, "type", "challenge")?)?,
        token: string_field(&document, "token", "challenge")?.to_owned(),
        status: match document.get("status").and_then(Value::as_str) {
            Some(status) => ChallengeStatus::parse(status)?,
            None => ChallengeStatus::Pending,
        },
    })
}

/// Parse an authorization document.
pub fn parse_authorization(url: &str, body: &[u8]) -> Result<Authorization> {
    let document = document(body, "authorization")?;
    let identifier =
        document.get("identifier").cloned().ok_or_else(|| Error::new(ErrorCode::Protocol, "authorization is missing `identifier`"))?;
    let challenges = document
        .get("challenges")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, "authorization is missing the `challenges` array"))?;
    let mut parsed = Vec::with_capacity(challenges.len());
    for challenge in challenges {
        // RFC 8555 §3.2.6: a client MUST ignore challenge objects whose type it
        // does not understand (LE staging now offers `dns-persist-01`), while
        // still rejecting malformed challenges of known types.
        if let Some(raw) = challenge.get("type").and_then(Value::as_str) {
            if ChallengeType::parse(raw).is_err() {
                continue;
            }
        }
        parsed.push(parse_challenge(url, challenge.to_string().as_bytes())?);
    }
    Ok(Authorization {
        url: url.to_owned(),
        status: AuthorizationStatus::parse(string_field(&document, "status", "authorization")?)?,
        identifier: Identifier {
            kind: string_field(&identifier, "type", "identifier")?.to_owned(),
            value: string_field(&identifier, "value", "identifier")?.to_owned(),
        },
        wildcard: document.get("wildcard").and_then(Value::as_bool).unwrap_or(false),
        challenges: parsed,
    })
}
