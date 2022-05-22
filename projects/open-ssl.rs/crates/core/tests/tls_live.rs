//! Live TLS 1.3 interoperability gate against Let's Encrypt staging.
//!
//! Run explicitly with `cargo test -p open-ssl-core --test tls_live -- --ignored`.

use std::time::Duration;

use open_ssl_core::x509::lets_encrypt_anchors;

#[test]
#[ignore = "live network test"]
fn handshakes_with_lets_encrypt_staging() {
    let anchors = lets_encrypt_anchors();
    let config = open_ssl_core::tls::ClientConfig {
        hostname: "acme-staging-v02.api.letsencrypt.org",
        anchors: &anchors,
        timeout: Duration::from_secs(20),
    };
    let mut client = open_ssl_core::tls::TlsClient::connect(&config, ("acme-staging-v02.api.letsencrypt.org", 443u16)).expect("handshake");
    assert_eq!(client.alpn(), Some("http/1.1"));

    let request = "GET /directory HTTP/1.1\r\nHost: acme-staging-v02.api.letsencrypt.org\r\nUser-Agent: open-ssl\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
    client.send(request.as_bytes()).expect("send");

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match client.receive(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(open_ssl_core::tls::TlsError::Io(_)) | Err(open_ssl_core::tls::TlsError::Alert(0)) => break,
            Err(error) => panic!("receive: {error}"),
        }
    }
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 200"), "response head: {}", &text[..text.len().min(120)]);
    assert!(text.contains("newNonce"), "directory body missing newNonce");
}
