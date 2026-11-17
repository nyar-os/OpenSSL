//! A minimal loopback HTTP/1.1 server that scripts ACME and DNS provider responses.

#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

/// One recorded request.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// Uppercase HTTP method token.
    pub method: String,
    /// Raw request target, path plus query string.
    pub path: String,
    /// Request headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Raw request body.
    pub body: Vec<u8>,
}

impl RecordedRequest {
    /// The path without the query string.
    pub fn route(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }

    /// The query string without the leading `?`, empty when absent.
    pub fn query(&self) -> &str {
        self.path.split_once('?').map(|(_, query)| query).unwrap_or("")
    }

    /// The first value of a header, case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(header, _)| header.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    /// The body parsed as JSON.
    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("recorded body is JSON")
    }
}

/// One scripted response.
#[derive(Debug, Clone)]
pub struct MockResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Raw response body.
    pub body: Vec<u8>,
}

impl MockResponse {
    /// A JSON response.
    pub fn json(status: u16, body: &str) -> Self {
        Self { status, headers: vec![("Content-Type".to_owned(), "application/json".to_owned())], body: body.as_bytes().to_vec() }
    }

    /// A response with an explicit content type.
    pub fn text(status: u16, content_type: &str, body: &str) -> Self {
        Self { status, headers: vec![("Content-Type".to_owned(), content_type.to_owned())], body: body.as_bytes().to_vec() }
    }

    /// Append one header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// The scripted responder: request, zero-based request index, and the server base URL.
pub type Script = Arc<dyn Fn(&RecordedRequest, usize, &str) -> MockResponse + Send + Sync>;

/// A running loopback server and its request log.
pub struct MockServer {
    /// The `http://127.0.0.1:<port>` base of this server.
    pub base: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
}

impl MockServer {
    /// Start the server on an ephemeral loopback port.
    pub fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let port = listener.local_addr().expect("listener address").port();
        let base = format!("http://127.0.0.1:{port}");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            let thread_base = base.clone();
            std::thread::spawn(move || {
                let mut index = 0usize;
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream
                    else {
                        continue;
                    };
                    let Some(request) = read_request(&mut stream)
                    else {
                        continue;
                    };
                    let response = script(&request, index, &thread_base);
                    index += 1;
                    requests.lock().expect("request log").push(request);
                    let _ = write_response(&mut stream, &response);
                }
            });
        }
        Self { base, requests, stop }
    }

    /// One absolute URL on this server.
    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// A snapshot of every request received so far.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.requests.lock().expect("request log").clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base.replace("http://", ""));
    }
}

fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.trim_end().split(' ');
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).ok()? == 0 {
            break;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().unwrap_or(0);
        }
        headers.push((name.to_owned(), value));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(RecordedRequest { method, path, headers, body })
}

fn write_response(stream: &mut TcpStream, response: &MockResponse) -> std::io::Result<()> {
    let mut wire = format!("HTTP/1.1 {} {}\r\n", response.status, reason(response.status));
    for (name, value) in &response.headers {
        wire.push_str(&format!("{name}: {value}\r\n"));
    }
    wire.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", response.body.len()));
    stream.write_all(wire.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    }
}
