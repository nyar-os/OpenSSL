//! The ACME directory document: the server's URL table.

use serde_json::Value;

use crate::errors::{Error, ErrorCode, Result};

/// The URL table every ACME server publishes at its directory endpoint (RFC 8555 §6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    /// `newNonce` — endpoint for fresh replay nonces.
    pub new_nonce: String,
    /// `newAccount` — account creation endpoint.
    pub new_account: String,
    /// `newOrder` — order creation endpoint.
    pub new_order: String,
    /// `revokeCert` — certificate revocation endpoint.
    pub revoke_cert: String,
    /// `keyChange`, when the server advertises one.
    pub key_change: Option<String>,
    /// The terms-of-service URL, when the server requires agreement.
    pub terms_of_service: Option<String>,
    /// Whether the server requires an external account binding.
    pub external_account_required: bool,
}

fn required<'a>(document: &'a Value, key: &str) -> Result<&'a str> {
    document.get(key).and_then(Value::as_str).ok_or_else(|| Error::new(ErrorCode::Protocol, format!("directory is missing `{key}`")))
}

/// Parse the JSON directory document returned by a `GET` on the directory URL.
pub fn parse(body: &[u8]) -> Result<Directory> {
    let document: Value =
        serde_json::from_slice(body).map_err(|error| Error::new(ErrorCode::Protocol, format!("directory is not JSON: {error}")))?;
    let meta = document.get("meta").cloned().unwrap_or(Value::Null);
    let terms_of_service =
        meta.get("terms_of_service").and_then(Value::as_str).or_else(|| meta.get("termsOfService").and_then(Value::as_str)).map(str::to_owned);
    Ok(Directory {
        new_nonce: required(&document, "newNonce")?.to_owned(),
        new_account: required(&document, "newAccount")?.to_owned(),
        new_order: required(&document, "newOrder")?.to_owned(),
        revoke_cert: required(&document, "revokeCert")?.to_owned(),
        key_change: document.get("keyChange").and_then(Value::as_str).map(str::to_owned),
        terms_of_service,
        external_account_required: meta.get("externalAccountRequired").and_then(Value::as_bool).unwrap_or(false),
    })
}
