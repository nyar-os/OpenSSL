//! Cloudflare zones/records DNS 适配器，通过家族 HTTP 传输层发请求。
//!
//! zone 由调用方显式配置：要么给 zone id，要么给 zone 名称，绝不从挑战记录名反推后缀。
//! 按名称配置时用一次 `GET zones?name=` 解析，结果在适配器生命周期内缓存。
//!
//! 本适配器的范围限制是明确的：不跟随 `_acme-challenge` 的委派 zone，也不处理 `CNAME`
//! 间接。使用这两种配置的调用方必须直接把真正托管记录名的 zone 传进来，否则写入会落到
//! 错误的 zone。
//!
//! 创建或删除失败、超时都属于未知结果：适配器返回错误，由调用方通过
//! [`DnsProvider::find_txt`] 对账决定后续动作，这里既不重试，也不删除不属于自己的记录。

use boost_net::http::{Method, Request, Response, Transport, Url};
use serde_json::{Map, Value};

use super::{DnsProvider, RecordHandle, TxtRecord, credentials::Secret};
use crate::errors::{Error, ErrorCode, Result};
use crate::perf;

/// 项目秘密文件 schema 中使用的 provider id。
pub const PROVIDER_ID: &str = "cloudflare";
/// 带版本前缀的 Cloudflare API 基地址。
pub const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// 一个适配器实例允许写入的 zone。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zone {
    /// zone id，每条记录调用直接使用。
    Id(String),
    /// zone 名称，用一次 `zones?name=` 查询解析。
    Name(String),
}

impl Zone {
    /// 用已知的 zone id 配置适配器。
    pub fn id(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "Cloudflare zone id 不能为空"));
        }
        Ok(Self::Id(id))
    }

    /// 用 `example.com` 这类 zone 名称配置适配器。
    pub fn name(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(Error::new(ErrorCode::InvalidArgument, "Cloudflare zone 名称不能为空"));
        }
        Ok(Self::Name(name))
    }
}

/// 通过注入传输层发请求的 Cloudflare DNS provider。
#[derive(Debug)]
pub struct Cloudflare<T: Transport> {
    transport: T,
    api_base: Url,
    token: Secret,
    zone: Zone,
    zone_id: Option<String>,
}

impl<T: Transport> Cloudflare<T> {
    /// 用显式传输层、API 基地址、token 与 zone 构造适配器。
    pub fn with_zone(transport: T, api_base: Url, token: Secret, zone: Zone) -> Self {
        let mut api_base = api_base;
        if !api_base.path().ends_with('/') {
            let mut path = api_base.path().to_owned();
            path.push('/');
            api_base.set_path(&path);
        }
        Self { transport, api_base, token, zone, zone_id: None }
    }

    /// 实际用于请求的 API 基地址。
    pub fn api_base(&self) -> &Url {
        &self.api_base
    }

    /// 本适配器显式配置的 zone。
    pub fn zone(&self) -> &Zone {
        &self.zone
    }

    /// zone id；按名称配置时在首次使用时解析。
    fn zone_id(&mut self) -> Result<String> {
        if let Some(id) = &self.zone_id {
            return Ok(id.clone());
        }
        let id = match &self.zone {
            Zone::Id(id) => id.clone(),
            Zone::Name(name) => {
                let result = self.call(Method::Get, "zones", &[("name", name), ("per_page", "1")], None)?;
                first_id(result, format!("未找到 zone `{name}`"))?
            }
        };
        self.zone_id = Some(id.clone());
        Ok(id)
    }

    fn call(&self, method: Method, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Value> {
        let response = self.send(method, path, query, body)?;
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|error| Error::new(ErrorCode::Protocol, format!("DNS API 没有返回 JSON：{error}")))?;
        let success = document.get("success").and_then(Value::as_bool).unwrap_or(false);
        if response.status >= 400 || !success {
            return Err(reject(response.status, &document));
        }
        Ok(document.get("result").cloned().unwrap_or(Value::Null))
    }

    fn send(&self, method: Method, path: &str, query: &[(&str, &str)], body: Option<&Value>) -> Result<Response> {
        let mut url =
            self.api_base.join(path).map_err(|error| Error::new(ErrorCode::Protocol, format!("DNS API 路径 `{path}` 非法：{error}")))?;
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
        Ok(perf::time("dns.cloudflare", || self.transport.send(&request))?)
    }
}

impl<T: Transport> DnsProvider for Cloudflare<T> {
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord> {
        if let Some(existing) = self.find_txt(fqdn, value)? {
            return Ok(existing);
        }
        let zone_id = self.zone_id()?;
        let mut record = Map::new();
        record.insert("type".to_owned(), Value::String("TXT".to_owned()));
        record.insert("name".to_owned(), Value::String(fqdn.to_owned()));
        record.insert("content".to_owned(), Value::String(value.to_owned()));
        let result = self.call(Method::Post, &format!("zones/{zone_id}/dns_records"), &[], Some(&Value::Object(record)))?;
        let id = result.get("id").and_then(Value::as_str).ok_or_else(|| Error::new(ErrorCode::Protocol, "DNS API 创建的记录没有 `id`"))?;
        Ok(TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned(), handle: RecordHandle::new(id)? })
    }

    fn find_txt(&mut self, fqdn: &str, value: &str) -> Result<Option<TxtRecord>> {
        let zone_id = self.zone_id()?;
        let path = format!("zones/{zone_id}/dns_records");
        let result = self.call(Method::Get, &path, &[("type", "TXT"), ("name", fqdn)], None)?;
        let items = match result {
            Value::Null => return Ok(None),
            Value::Array(items) => items,
            _ => return Err(Error::new(ErrorCode::Protocol, "DNS 记录列表不是数组")),
        };
        for item in items {
            let id = item.get("id").and_then(Value::as_str).ok_or_else(|| Error::new(ErrorCode::Protocol, "DNS 记录没有 `id`"))?;
            let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
            let content = item.get("content").and_then(Value::as_str).unwrap_or_default();
            if name.eq_ignore_ascii_case(fqdn) && content == value {
                return Ok(Some(TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned(), handle: RecordHandle::new(id)? }));
            }
        }
        Ok(None)
    }

    fn delete_txt(&mut self, record: &TxtRecord) -> Result<()> {
        let zone_id = self.zone_id()?;
        self.call(Method::Delete, &format!("zones/{zone_id}/dns_records/{}", record.handle.as_str()), &[], None)?;
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
        .unwrap_or("DNS API 拒绝了该请求");
    Error::new(code, format!("DNS API 以状态 {status} 拒绝了请求：{message}"))
}
