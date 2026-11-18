//! The Cloudflare zones/records DNS adapter over the family HTTP transport.

use boost_net::http::{Method, Request, Response, Transport, Url};
use serde_json::{Map, Value};

use super::{DnsProvider, TxtRecord, credentials::Secret};
use crate::errors::{Error, ErrorCode, Result};

/// The provider id used in the secrets file schema.
pub const PROVIDER_ID: &str = "cloudflare";
/// The Cloudflare API base with the version prefix.
pub const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A Cloudflare DNS provider over an injected transport.
#[derive(Debug)]
pub struct Cloudflare<T: Transport> {
    transport: T,
    api_base: Url,
    token: Secret,
}

impl<T: Transport> Cloudflare<T> {
    /// Build the adapter with an explicit transport, API base, and token.
    pub fn with_token(transport: T, api_base: Url, token: Secret) -> Self {
        let mut api_base = api_base;
        if !api_base.path().ends_with('/') {
            let mut path = api_base.path().to_owned();
            path.push('/');
            api_base.set_path(&path);
        }
        Self { transport, api_base, token }
    }

    /// The API base actually used for requests.
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    fn zone_id(&self, zone: &str) -> Result<String> {
        let result = self.call(Method::Get, "zones", &[("name", zone), ("per_page", "1")], None)?;
        first_id(result, format!("the zone `{zone}` was not found"))
    }

    fn txt_record_ids(&self, zone_id: &str, fqdn: &str) -> Result<Vec<String>> {
        let path = format!("zones/{zone_id}/dns_records");
        let result = self.call(Method::Get, &path, &[("type", "TXT"), ("name", fqdn)], None)?;
        match result {
            Value::Null => Ok(Vec::new()),
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    item.get("id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| Error::new(ErrorCode::Protocol, "a DNS record carries no `id`".to_owned()))
                })
                .collect(),
            _ => Err(Error::new(ErrorCode::Protocol, "the DNS record list is not an array")),
        }
    }

    fn call(&self, method: Method, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Value> {
        let response = self.send(method, path, query, body)?;
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|error| Error::new(ErrorCode::Protocol, format!("the DNS API returned no JSON: {error}")))?;
        let success = document.get("success").and_then(Value::as_bool).unwrap_or(false);
        if response.status >= 400 || !success {
            return Err(reject(response.status, &document));
        }
        Ok(document.get("result").cloned().unwrap_or(Value::Null))
    }

    fn send(&self, method: Method, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Response> {
        let mut url = self
            .api_base
            .join(path)
            .map_err(|error| Error::new(ErrorCode::Protocol, format!("the DNS API path `{path}` is invalid: {error}")))?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in query {
                pairs.append_pair(name, value);
            }
            drop(pairs);
        }
        let mut request = Request::new(method, url)
            .with_header("Authorization", format!("Bearer {}", self.token.expose()))
            .with_header("Accept", "application/json");
        if let Some(body) = body {
            request = request.with_header("Content-Type", "application/json").with_body(body.to_string().into_bytes());
        }
        Ok(self.transport.send(&request)?)
    }
}

impl<T: Transport> DnsProvider for Cloudflare<T> {
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord> {
        let zone = super::zone_name(fqdn)?;
        let zone_id = self.zone_id(zone)?;
        for record_id in self.txt_record_ids(&zone_id, fqdn)? {
            self.call(Method::Delete, &format!("zones/{zone_id}/dns_records/{record_id}"), &[], None)?;
        }
        let mut record = Map::new();
        record.insert("type".to_owned(), Value::String("TXT".to_owned()));
        record.insert("name".to_owned(), Value::String(fqdn.to_owned()));
        record.insert("content".to_owned(), Value::String(value.to_owned()));
        self.call(Method::Post, &format!("zones/{zone_id}/dns_records"), &[], Some(&Value::Object(record)))?;
        Ok(TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned() })
    }

    fn delete_txt(&mut self, fqdn: &str) -> Result<()> {
        let zone = super::zone_name(fqdn)?;
        let zone_id = self.zone_id(zone)?;
        for record_id in self.txt_record_ids(&zone_id, fqdn)? {
            self.call(Method::Delete, &format!("zones/{zone_id}/dns_records/{record_id}"), &[], None)?;
        }
        Ok(())
    }
}

fn first_id(result: Value, missing: impl Into<String>) -> Result<String> {
    result
        .get(0)
        .and_then(Value::as_object)
        .and_then(|zone| zone.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, missing.into()))
}

fn reject(status: u16, document: &Value) -> Error {
    let code = if status == 403 { ErrorCode::Denied } else { ErrorCode::Protocol };
    let message = document
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("the DNS API refused the request");
    Error::new(code, format!("the DNS API rejected the request with status {status}: {message}"))
}
