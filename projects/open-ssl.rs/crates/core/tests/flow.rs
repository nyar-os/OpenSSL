//! 端到端签发状态机验收：loopback CA + 假 DNS provider。
//!
//! 证书由仓内 PKI 现场签出，叶子公钥就是 flow 自己落盘的订单私钥，因此交付校验
//! （证书/私钥 SPKI 一致、SAN、链、有效期）走的是真实路径，不是占位字节。

mod mock;

use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use boost_net::http::HttpTransport;
use open_ssl_core::{
    der::{Tag, Writer, oids},
    dns::{DnsProvider, RecordHandle, TxtRecord},
    flow::{self, FlowOptions},
    x509::{Certificate, EcCurve, PublicKey, SignatureAlgorithm, pem_encode},
};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::Value;
use signature::Signer;

struct FakeDns {
    records: Vec<TxtRecord>,
    next_id: u64,
}

impl FakeDns {
    fn new() -> Self {
        Self { records: Vec::new(), next_id: 0 }
    }
}

impl DnsProvider for FakeDns {
    fn put_txt(&mut self, fqdn: &str, value: &str) -> open_ssl_core::Result<TxtRecord> {
        if let Some(existing) = self.records.iter().find(|record| record.fqdn == fqdn && record.value == value) {
            return Ok(existing.clone());
        }
        self.next_id += 1;
        let record = TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned(), handle: RecordHandle::new(self.next_id.to_string())? };
        self.records.push(record.clone());
        Ok(record)
    }

    fn find_txt(&mut self, fqdn: &str, value: &str) -> open_ssl_core::Result<Option<TxtRecord>> {
        Ok(self.records.iter().find(|record| record.fqdn == fqdn && record.value == value).cloned())
    }

    fn delete_txt(&mut self, record: &TxtRecord) -> open_ssl_core::Result<()> {
        let before = self.records.len();
        self.records.retain(|existing| existing.handle != record.handle);
        if self.records.len() == before {
            return Err(open_ssl_core::Error::new(open_ssl_core::ErrorCode::Protocol, "fake dns record not found"));
        }
        Ok(())
    }
}

fn name_der(cn: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|seq| {
        seq.set(|set| {
            set.sequence(|atv| {
                atv.write_oid(&oids::common_name());
                atv.write_utf8(cn);
            });
        });
    });
    w.finish()
}

fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() }.to_der()
}

fn san_der(names: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|seq| {
        for name in names {
            seq.context_primitive(2, name.as_bytes());
        }
    });
    w.finish()
}

fn extension_der(oid: open_ssl_core::der::Oid, value: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|ext| {
        ext.write_oid(&oid);
        ext.write_octetstring(value);
    });
    w.finish()
}

fn issue(serial: u64, cn: &str, subject_key: &VerifyingKey, issuer_cn: &str, issuer_key: &SigningKey, ca: bool, dns: Option<Vec<u8>>) -> Vec<u8> {
    let mut exts = Vec::new();
    if ca {
        let mut bc = Writer::new();
        bc.sequence(|b| b.write_boolean(true));
        exts.push(extension_der(oids::basic_constraints(), &bc.finish()));
    }
    if let Some(san) = dns {
        exts.push(extension_der(oids::subject_alt_name(), &san));
    }
    let mut ext_list = Writer::new();
    ext_list.sequence(|list| {
        for item in &exts {
            list.write_raw(item);
        }
    });
    let mut w = Writer::new();
    w.sequence(|tbs| {
        tbs.context(0, |v| v.write_u64(2));
        tbs.write_u64(serial);
        tbs.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        tbs.write_raw(&name_der(issuer_cn));
        tbs.sequence(|v| {
            v.write_tlv(Tag::UTCTIME, b"230101000000Z");
            v.write_tlv(Tag::UTCTIME, b"331231235959Z");
        });
        tbs.write_raw(&name_der(cn));
        tbs.write_raw(&spki_der(subject_key));
        if !exts.is_empty() {
            tbs.context(3, |x| x.write_raw(&ext_list.finish()));
        }
    });
    let tbs = w.finish();
    let signature: Signature = issuer_key.sign(&tbs);
    let mut cert = Writer::new();
    cert.sequence(|c| {
        c.write_raw(&tbs);
        c.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        c.write_bitstring(signature.to_der().as_bytes(), 0);
    });
    cert.finish()
}

fn project_root(tag: &str) -> (open_ssl_core::dns::credentials::ProjectRoot, PathBuf) {
    let root = std::env::temp_dir().join(format!("open-ssl-flow-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join(".secrets")).expect("secrets dir");
    fs::write(
        root.join(".secrets/open-ssl.json"),
        r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"test-token"}}}"#,
    )
    .expect("secrets file");
    (open_ssl_core::dns::credentials::ProjectRoot::new(&root).expect("project root"), root)
}

fn chain_for(leaf_key: &VerifyingKey) -> String {
    let ca_key = SigningKey::from_slice(&[21u8; 32]).expect("ca key");
    let intermediate_key = SigningKey::from_slice(&[22u8; 32]).expect("intermediate key");
    let ca_der = issue(1, "Flow Test CA", ca_key.verifying_key(), "Flow Test CA", &ca_key, true, None);
    let intermediate_der = issue(2, "Flow Test Intermediate", intermediate_key.verifying_key(), "Flow Test CA", &ca_key, true, None);
    let leaf_der = issue(3, "example.test", leaf_key, "Flow Test Intermediate", &intermediate_key, false, Some(san_der(&["example.test", "*.example.test"])));
    let _ = Certificate::parse(&ca_der).expect("ca parses");
    format!("{}{}", pem_encode("CERTIFICATE", &leaf_der), pem_encode("CERTIFICATE", &intermediate_der))
}

fn script(chain_pem: String, authz_valid: Arc<AtomicBool>) -> mock::Script {
    Arc::new(move |request: &mock::RecordedRequest, _index: usize, base: &str| -> mock::MockResponse {
        let route = request.route().to_owned();
        match (request.method.as_str(), route.as_str()) {
            ("GET", "/directory") => mock::MockResponse::json(
                200,
                &serde_json::json!({
                    "newNonce": format!("{base}/new-nonce"),
                    "newAccount": format!("{base}/new-account"),
                    "newOrder": format!("{base}/new-order"),
                    "revokeCert": format!("{base}/revoke-cert"),
                })
                .to_string(),
            )
            .with_header("Replay-Nonce", "nonce-directory"),
            ("HEAD", "/new-nonce") => mock::MockResponse::text(200, "application/octet-stream", "").with_header("Replay-Nonce", "nonce-head"),
            ("POST", "/new-account") => mock::MockResponse::json(201, r#"{"status":"valid"}"#)
                .with_header("Location", &format!("{base}/account/42"))
                .with_header("Replay-Nonce", "nonce-account"),
            ("POST", "/account/42") => mock::MockResponse::json(200, r#"{"status":"valid"}"#).with_header("Replay-Nonce", "nonce-query"),
            ("POST", "/new-order") => mock::MockResponse::json(
                201,
                &serde_json::json!({
                    "status": "pending",
                    "identifiers": [{"type":"dns","value":"example.test"},{"type":"dns","value":"*.example.test"}],
                    "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                    "finalize": format!("{base}/finalize/1"),
                })
                .to_string(),
            )
            .with_header("Location", &format!("{base}/order/1"))
            .with_header("Replay-Nonce", "nonce-order"),
            ("POST", "/authz/1") | ("POST", "/authz/2") => {
                let wildcard = route == "/authz/2";
                let value = if wildcard { "*.example.test" } else { "example.test" };
                let status = if authz_valid.load(Ordering::SeqCst) { "valid" } else { "pending" };
                mock::MockResponse::json(
                    200,
                    &serde_json::json!({
                        "status": status,
                        "identifier": { "type": "dns", "value": value },
                        "challenges": [{
                            "url": format!("{base}/challenge/{}", if wildcard { 2 } else { 1 }),
                            "type": "dns-01",
                            "token": if wildcard { "wildcard-token" } else { "plain-token" },
                        }],
                    })
                    .to_string(),
                )
                .with_header("Replay-Nonce", "nonce-authz")
            }
            ("POST", "/challenge/1") | ("POST", "/challenge/2") => {
                authz_valid.store(true, Ordering::SeqCst);
                mock::MockResponse::json(200, &format!(r#"{{"type":"dns-01","status":"processing","token":"t","url":"{base}{route}"}}"#))
                    .with_header("Replay-Nonce", "nonce-challenge")
            }
            ("POST", "/finalize/1") => mock::MockResponse::json(
                200,
                &serde_json::json!({
                    "status": "processing",
                    "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                    "finalize": format!("{base}/finalize/1"),
                })
                .to_string(),
            )
            .with_header("Replay-Nonce", "nonce-finalize"),
            ("POST", "/order/1") => {
                let mut body = serde_json::json!({
                    "status": "valid",
                    "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                    "finalize": format!("{base}/finalize/1"),
                });
                body["certificate"] = Value::String(format!("{base}/cert/1"));
                mock::MockResponse::json(200, &body.to_string()).with_header("Replay-Nonce", "nonce-poll")
            }
            ("POST", "/cert/1") => mock::MockResponse::text(200, "application/pem-certificate-chain", &chain_pem).with_header("Replay-Nonce", "nonce-cert"),
            _ => mock::MockResponse::json(500, r#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"unhandled fixture path"}"#),
        }
    })
}

fn options<'a>(base: &'a str, identifiers: &'a [String]) -> FlowOptions<'a> {
    FlowOptions {
        kind: open_ssl_core::state::DirectoryKind::Staging,
        directory_url: base,
        dns_provider: "cloudflare",
        identifiers,
        contact: &[],
        poll_attempts: 4,
        poll_delay: Duration::ZERO,
    }
}

#[test]
fn full_issuance_delivers_a_real_generation_and_cleans_dns() {
    let (project, root) = project_root("full");
    let identifiers = vec!["example.test".to_owned(), "*.example.test".to_owned()];
    let leaf_key = flow::order_id(open_ssl_core::state::DirectoryKind::Staging, &identifiers);
    let placed = open_ssl_core::keys::order_key(&project, &leaf_key).expect("pre-place leaf key");
    let chain = chain_for(placed.verifying_key());

    let server = mock::MockServer::start(script(chain, Arc::new(AtomicBool::new(false))));
    let mut dns = FakeDns::new();
    let report = flow::issue(&project, &options(&server.url("/directory"), &identifiers), HttpTransport::new(), &mut dns).expect("issuance succeeds");

    assert_eq!(report.account_url, server.url("/account/42"));
    assert_eq!(report.order_url, server.url("/order/1"));
    assert_eq!(report.dns_records_removed, 2, "两条同名不同值的 TXT 都必须被精确删除");
    assert!(dns.records.is_empty(), "provider 侧不得留下残余记录");

    let delivery = open_ssl_core::delivery::Delivery::new(&project);
    let generation = delivery.current().expect("current readable").expect("a generation was committed");
    assert_eq!(generation.id, report.generation);
    let cert_path = root.join(".secrets/open-ssl/generations").join(&generation.id).join("cert.pem");
    let delivered = open_ssl_core::x509::pem_bundle("CERTIFICATE", &fs::read_to_string(&cert_path).expect("cert file"));
    let issued = Certificate::parse(&delivered[0]).expect("delivered leaf parses");
    assert!(issued.extensions.dns_names.iter().any(|name| name == "*.example.test"));

    let account = open_ssl_core::state::StateStore::new(&project).account(open_ssl_core::state::DirectoryKind::Staging).expect("state");
    assert!(account.is_some(), "account state must survive the run");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn second_run_reuses_the_account_and_issues_a_new_generation() {
    let (project, root) = project_root("resume");
    let identifiers = vec!["example.test".to_owned(), "*.example.test".to_owned()];
    let id = flow::order_id(open_ssl_core::state::DirectoryKind::Staging, &identifiers);
    let placed = open_ssl_core::keys::order_key(&project, &id).expect("pre-place leaf key");
    let chain = chain_for(placed.verifying_key());

    let authz_valid = Arc::new(AtomicBool::new(false));
    let server = mock::MockServer::start(script(chain.clone(), Arc::clone(&authz_valid)));
    let mut dns = FakeDns::new();
    let first = flow::issue(&project, &options(&server.url("/directory"), &identifiers), HttpTransport::new(), &mut dns).expect("first run");

    authz_valid.store(false, Ordering::SeqCst);
    let second = flow::issue(&project, &options(&server.url("/directory"), &identifiers), HttpTransport::new(), &mut dns).expect("second run");
    assert_ne!(first.generation, second.generation, "每次成功交付都是新的一代");

    let accounts = server.requests().iter().filter(|request| request.route() == "/new-account").count();
    assert_eq!(accounts, 1, "第二次运行必须复用账户，而不是再建一个");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn failure_cleans_the_records_it_published() {
    let (project, root) = project_root("failure");
    let identifiers = vec!["example.test".to_owned(), "*.example.test".to_owned()];
    // 订单永远停在 processing：poll_order 超时必须失败，且已发布的 TXT 仍被清理。
    let base_script = script(String::new(), Arc::new(AtomicBool::new(true)));
    let failing = Arc::new(move |request: &mock::RecordedRequest, index: usize, base: &str| -> mock::MockResponse {
        let route = request.route().to_owned();
        if route == "/order/1" {
            return mock::MockResponse::json(
                200,
                &serde_json::json!({
                    "status": "processing",
                    "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                    "finalize": format!("{base}/finalize/1"),
                })
                .to_string(),
            )
            .with_header("Replay-Nonce", "nonce-poll");
        }
        if route == "/cert/1" {
            return mock::MockResponse::text(200, "application/pem-certificate-chain", "").with_header("Replay-Nonce", "nonce-cert");
        }
        base_script(request, index, base)
    });
    let server = mock::MockServer::start(failing);
    let mut dns = FakeDns::new();
    let error = flow::issue(&project, &options(&server.url("/directory"), &identifiers), HttpTransport::new(), &mut dns)
        .expect_err("order polling must time out");
    assert_eq!(error.code(), open_ssl_core::ErrorCode::Network);
    assert!(dns.records.is_empty(), "失败路径同样要精确清理已发布的 TXT");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_bogus_chain_is_rejected_before_delivery() {
    let (project, root) = project_root("bogus");
    let identifiers = vec!["example.test".to_owned(), "*.example.test".to_owned()];
    let server = mock::MockServer::start(script("not a certificate chain".to_owned(), Arc::new(AtomicBool::new(false))));
    let mut dns = FakeDns::new();
    let error = flow::issue(&project, &options(&server.url("/directory"), &identifiers), HttpTransport::new(), &mut dns)
        .expect_err("a chain without a parseable leaf must fail");
    assert_eq!(error.code(), open_ssl_core::ErrorCode::Protocol);
    assert!(dns.records.is_empty());
    let delivery = open_ssl_core::delivery::Delivery::new(&project);
    assert!(delivery.current().expect("current").is_none(), "拒绝的链不得交付");
    let _ = fs::remove_dir_all(root);
}
