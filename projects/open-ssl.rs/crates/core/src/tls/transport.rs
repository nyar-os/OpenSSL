//! HTTPS transport built on the product's own TLS 1.3 client.
//!
//! `boost.net::http` owns the request/response model and the `Transport` trait.
//! This adapter supplies the secure leg without `rustls`, `webpki-roots`, or any
//! OS certificate store: the handshake and chain validation run through
//! [`crate::tls::TlsClient`] with the pinned ISRG anchors. It speaks HTTP/1.1
//! with `Connection: close`, which is sufficient for ACME and DNS APIs.
//!
//! Plain `http` URLs are rejected instead of silently downgrading. Redirects are
//! not followed here; the callers (`AcmeClient`, `Cloudflare`) treat every
//! non-2xx response as a protocol result and never rely on transport-level
//! redirects.

use std::{io, time::Duration};

use boost_net::{
    NetError,
    http::{Headers, Request, Response, Transport, Url},
};

use crate::{
    tls::{ClientConfig, TlsClient},
    x509::TrustAnchor,
};

/// Maximum response body accepted by this adapter.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// An HTTPS transport over the product-owned TLS client.
#[derive(Debug, Clone)]
pub struct HttpsTransport {
    anchors: Vec<TrustAnchor>,
    timeout: Duration,
}

impl Default for HttpsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsTransport {
    /// Build the transport with the pinned Let's Encrypt anchors.
    #[must_use]
    pub fn new() -> Self {
        Self { anchors: crate::x509::lets_encrypt_anchors(), timeout: Duration::from_secs(30) }
    }

    /// Build the transport with explicit anchors and timeout.
    #[must_use]
    pub fn with_anchors(anchors: Vec<TrustAnchor>, timeout: Duration) -> Self {
        Self { anchors, timeout }
    }
}

impl Transport for HttpsTransport {
    fn send(&self, request: &Request) -> Result<Response, NetError> {
        if request.url.scheme() != "https" {
            return Err(NetError::Unsupported(format!("`{}` is not an HTTPS target", request.url)));
        }
        let host = request.url.host_str().ok_or_else(|| NetError::Protocol(format!("URL `{}` has no host", request.url)))?.to_owned();
        let port = request.url.port_or_known_default().unwrap_or(443);
        let target = match request.url.query() {
            Some(query) => format!("{}?{query}", path_of(&request.url)),
            None => path_of(&request.url),
        };

        let config = ClientConfig { hostname: &host, anchors: &self.anchors, timeout: self.timeout };
        let mut client = TlsClient::connect(&config, (host.as_str(), port)).map_err(|error| NetError::Transport(error.to_string()))?;

        let mut head = format!("{} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n", request.method.as_str());
        if !request.body.is_empty() || matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
            head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
        }
        for (name, value) in request.headers.iter() {
            if matches!(name.to_ascii_lowercase().as_str(), "host" | "content-length" | "connection") {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");

        let mut wire = head.into_bytes();
        wire.extend_from_slice(&request.body);
        client.send(&wire).map_err(|error| NetError::Transport(error.to_string()))?;

        let mut raw = Vec::new();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = client.receive(&mut buffer).map_err(|error| NetError::Transport(error.to_string()))?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
            if raw.len() > MAX_BODY_BYTES {
                return Err(NetError::BodyTooLarge { limit: MAX_BODY_BYTES });
            }
        }
        parse_response(&request.url, &raw)
    }
}

fn path_of(url: &Url) -> String {
    if url.path().is_empty() { "/".to_owned() } else { url.path().to_owned() }
}

/// Parse one HTTP/1.1 response that was fully read until the peer closed.
fn parse_response(url: &Url, raw: &[u8]) -> Result<Response, NetError> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| NetError::Protocol("the response has no header terminator".to_owned()))?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| NetError::Protocol("the response head is not UTF-8".to_owned()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(NetError::Protocol(format!("bad status line `{status_line}`")));
    }
    let status =
        parts.next().and_then(|code| code.parse::<u16>().ok()).ok_or_else(|| NetError::Protocol(format!("bad status line `{status_line}`")))?;

    let mut headers = Headers::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':')
        else {
            return Err(NetError::Protocol(format!("bad header line `{line}`")));
        };
        headers.append(name.trim(), value.trim());
    }

    let body_bytes = &raw[split + 4..];
    let body = if headers.get("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        decode_chunked(body_bytes)?
    }
    else if let Some(length) = headers.get("content-length").and_then(|value| value.trim().parse::<usize>().ok()) {
        if body_bytes.len() < length {
            return Err(NetError::Protocol(format!("the body declared {length} bytes but only {} arrived", body_bytes.len())));
        }
        body_bytes[..length].to_vec()
    }
    else {
        body_bytes.to_vec()
    };

    Ok(Response { url: url.clone(), status, headers, body, redirects: Vec::new() })
}

fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, NetError> {
    let mut body = Vec::new();
    loop {
        let Some(end) = data.windows(2).position(|window| window == b"\r\n")
        else {
            return Err(NetError::Protocol("a chunk has no size line terminator".to_owned()));
        };
        let size_line = std::str::from_utf8(&data[..end]).map_err(|_| NetError::Protocol("a chunk size line is not UTF-8".to_owned()))?;
        let size_text = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| NetError::Protocol(format!("bad chunk size `{size_text}`")))?;
        data = &data[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if data.len() < size + 2 {
            return Err(NetError::Protocol("a chunk is shorter than its declared size".to_owned()));
        }
        body.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            return Err(NetError::Protocol("a chunk is not terminated by CRLF".to_owned()));
        }
        data = &data[size + 2..];
        if body.len() > MAX_BODY_BYTES {
            return Err(NetError::BodyTooLarge { limit: MAX_BODY_BYTES });
        }
    }
}

/// Errors that come from the underlying socket are reported as transport
/// failures; protocol violations keep their own class so callers can tell a
/// broken peer from an unreachable one.
#[allow(dead_code)]
fn transport_error(error: io::Error) -> NetError {
    NetError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        Url::parse("https://acme-staging-v02.api.letsencrypt.org/directory").expect("static URL")
    }

    #[test]
    fn content_length_response_is_split_at_the_header_terminator() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nReplay-Nonce: abc\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        let response = parse_response(&url(), raw).expect("well formed response");
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get("replay-nonce"), Some("abc"));
        assert_eq!(response.body, b"{\"a\":1}");
        assert!(response.redirects.is_empty());
    }

    #[test]
    fn chunked_response_is_decoded() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let response = parse_response(&url(), raw).expect("well formed response");
        assert_eq!(response.body, b"{\"a\":1}");
    }

    #[test]
    fn short_body_and_bad_status_are_protocol_errors() {
        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}";
        assert!(matches!(parse_response(&url(), short), Err(NetError::Protocol(_))));

        let bad = b"NOT-HTTP 200 OK\r\n\r\n";
        assert!(matches!(parse_response(&url(), bad), Err(NetError::Protocol(_))));
    }

    #[test]
    fn plain_http_targets_are_rejected() {
        let transport = HttpsTransport::new();
        let request = Request::new(boost_net::http::Method::Get, Url::parse("http://example.test/").expect("URL"));
        assert!(matches!(transport.send(&request), Err(NetError::Unsupported(_))));
    }
}
