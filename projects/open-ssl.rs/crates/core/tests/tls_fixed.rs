use std::time::Duration;

use open_ssl_core::x509::{Certificate, TrustAnchor, pem_decode};

fn connect_and_echo(port: u16) -> Vec<u8> {
    let ca_der =
        pem_decode("CERTIFICATE", &std::fs::read_to_string(std::env::temp_dir().join("ossl-loopback").join("ca.pem")).expect("read ca"))
            .expect("pem");
    let ca = Certificate::parse(&ca_der).expect("parse ca");
    let anchors = vec![TrustAnchor::from_cert(&ca)];
    let config = open_ssl_core::tls::ClientConfig { hostname: "localhost", anchors: &anchors, timeout: Duration::from_secs(5) };
    let mut client = open_ssl_core::tls::TlsClient::connect(&config, ("127.0.0.1", port)).expect("handshake");
    client.send(b"hello").expect("send");
    let mut buf = [0u8; 64];
    let read = client.receive(&mut buf).expect("receive");
    buf[..read].to_vec()
}

#[test]
#[ignore = "requires the loopback node server on 18443"]
fn rust_client_against_node_server() {
    assert_eq!(connect_and_echo(18443), b"echo:hello");
}

#[test]
#[ignore = "requires the loopback python server on 18444"]
fn rust_client_against_python_server() {
    assert_eq!(connect_and_echo(18444), b"echo:hello");
}

#[test]
#[ignore = "requires the constrained python server on 18445"]
fn rust_client_against_python_no_hrr() {
    assert_eq!(connect_and_echo(18445), b"echo:hello");
}
