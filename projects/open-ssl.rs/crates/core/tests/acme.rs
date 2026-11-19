//! ACME conformance against a loopback fixture server, plus JWS and thumbprint vectors.

mod mock;

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use boost_net::http::HttpTransport;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signature::Verifier;

use open_ssl_core::{
    ErrorCode,
    acme::{
        AccountKey, AccountRef, AccountStatus, AcmeClient, AuthorizationStatus, ChallengeStatus, OrderPollVerdict, OrderStatus, b64url,
        build_jws, jwk_thumbprint, order_poll_verdict, retry_after_delay, txt_digest, types::parse_authorization,
    },
    dns::challenge_fqdn,
};

const CHAIN_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "Zm9yLXRlc3Rpbmctb25seS1sZWFmLWNlcnRpZmljYXRl\n",
    "-----END CERTIFICATE-----\n",
    "-----BEGIN CERTIFICATE-----\n",
    "Zm9yLXRlc3Rpbmctb25seS1sZWFmLWludGVybWVkaWF0ZQ==\n",
    "-----END CERTIFICATE-----\n",
);

fn protected_of(request: &mock::RecordedRequest) -> Value {
    let document = request.body_json();
    let bytes = URL_SAFE_NO_PAD.decode(document["protected"].as_str().expect("protected header")).expect("protected is base64url");
    serde_json::from_slice(&bytes).expect("protected is JSON")
}

fn payload_of(request: &mock::RecordedRequest) -> String {
    let document = request.body_json();
    let value = document["payload"].as_str().expect("payload");
    if value.is_empty() {
        String::new()
    }
    else {
        String::from_utf8(URL_SAFE_NO_PAD.decode(value).expect("payload is base64url")).expect("payload is UTF-8")
    }
}

fn verify_jws(request: &mock::RecordedRequest, verifying: &p256::ecdsa::VerifyingKey) {
    let document = request.body_json();
    let protected = document["protected"].as_str().expect("protected");
    let payload = document["payload"].as_str().expect("payload");
    let raw = URL_SAFE_NO_PAD.decode(document["signature"].as_str().expect("signature")).expect("signature is base64url");
    let signature = Signature::from_slice(&raw).expect("signature is a raw ES256 r||s");
    verifying.verify(format!("{protected}.{payload}").as_bytes(), &signature).expect("the ES256 signature verifies");
}

#[test]
fn full_dns01_flow_against_a_loopback_acme_server() {
    let signing = SigningKey::from_slice(&[7u8; 32]).expect("test key");
    let verifying = *signing.verifying_key();
    let key = AccountKey::from_signing_key(signing.clone());
    let thumbprint = key.thumbprint();
    let order_polls = Arc::new(AtomicUsize::new(0));
    let script = {
        let order_polls = Arc::clone(&order_polls);
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
                        "keyChange": format!("{base}/key-change"),
                        "meta": { "termsOfService": format!("{base}/terms"), "externalAccountRequired": false },
                    })
                    .to_string(),
                )
                .with_header("Replay-Nonce", "nonce-directory"),
                ("HEAD", "/new-nonce") => {
                    mock::MockResponse::text(200, "application/octet-stream", "").with_header("Replay-Nonce", "nonce-head")
                }
                ("POST", "/new-account") => {
                    mock::MockResponse::json(201, r#"{"status":"valid","contact":["mailto:ops@example.test"],"termsOfServiceAgreed":true}"#)
                        .with_header("Location", &format!("{base}/account/42"))
                        .with_header("Replay-Nonce", "nonce-account")
                }
                ("POST", "/account/42") => {
                    mock::MockResponse::json(200, r#"{"status":"valid","contact":["mailto:ops@example.test"],"termsOfServiceAgreed":true}"#)
                        .with_header("Replay-Nonce", "nonce-query")
                }
                ("POST", "/new-order") => mock::MockResponse::json(
                    201,
                    &serde_json::json!({
                        "status": "pending",
                        "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                        "finalize": format!("{base}/finalize/1"),
                    })
                    .to_string(),
                )
                .with_header("Location", &format!("{base}/order/1"))
                .with_header("Replay-Nonce", "nonce-order"),
                ("POST", "/authz/1") => mock::MockResponse::json(
                    200,
                    &serde_json::json!({
                        "status": "pending",
                        "identifier": { "type": "dns", "value": "example.test" },
                        "challenges": [{
                            "url": format!("{base}/challenge/1"),
                            "type": "dns-01",
                            "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
                        }],
                    })
                    .to_string(),
                )
                .with_header("Replay-Nonce", "nonce-authz"),
                ("POST", "/challenge/1") => mock::MockResponse::json(
                    200,
                    &serde_json::json!({
                        "type": "dns-01",
                        "url": format!("{base}/challenge/1"),
                        "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
                        "status": "processing",
                    })
                    .to_string(),
                )
                .with_header("Replay-Nonce", "nonce-challenge"),
                ("POST", "/order/1") => {
                    let poll = order_polls.fetch_add(1, Ordering::SeqCst);
                    let mut body = serde_json::json!({
                        "status": if poll == 0 { "processing" } else { "valid" },
                        "authorizations": [format!("{base}/authz/1"), format!("{base}/authz/2")],
                        "finalize": format!("{base}/finalize/1"),
                    });
                    if poll > 0 {
                        body["certificate"] = Value::String(format!("{base}/cert/1"));
                    }
                    mock::MockResponse::json(200, &body.to_string()).with_header("Replay-Nonce", "nonce-poll")
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
                ("POST", "/cert/1") => {
                    mock::MockResponse::text(200, "application/pem-certificate-chain", CHAIN_PEM).with_header("Replay-Nonce", "nonce-cert")
                }
                _ => mock::MockResponse::json(500, r#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"unhandled fixture path"}"#),
            }
        })
    };
    let server = mock::MockServer::start(script);

    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key.clone(), &server.url("/directory")).expect("directory bootstrap");
    assert_eq!(client.directory().new_account, server.url("/new-account"));
    assert_eq!(client.directory().revoke_cert, server.url("/revoke-cert"));
    assert_eq!(client.directory().key_change.as_deref(), Some(server.url("/key-change").as_str()));
    assert_eq!(client.directory().terms_of_service.as_deref(), Some(server.url("/terms").as_str()));

    let account = client.new_account(&["mailto:ops@example.test".to_owned()], true).expect("new account");
    assert_eq!(account.url, server.url("/account/42"));
    assert_eq!(account.status, AccountStatus::Valid);
    assert!(account.terms_of_service_agreed);

    let order = client.new_order(&["example.test".to_owned(), "*.example.test".to_owned()]).expect("new order");
    assert_eq!(order.status, OrderStatus::Pending);
    assert_eq!(order.authorizations, vec![server.url("/authz/1"), server.url("/authz/2")]);

    let dns = client.dns_challenge(&order.authorizations[0]).expect("dns-01 challenge");
    assert_eq!(dns.challenge.token, "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA");
    assert_eq!(dns.key_authorization, format!("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.{thumbprint}"));
    assert_eq!(dns.identifier, "example.test");
    assert!(!dns.wildcard);
    assert_eq!(dns.record_fqdn(), "_acme-challenge.example.test");
    assert_eq!(dns.txt_value(), txt_digest(&dns.key_authorization), "TXT 值是 key authorization 的摘要");
    assert_ne!(dns.txt_value(), dns.key_authorization, "key authorization 本身不得发布");

    assert_eq!(client.respond_challenge(&dns.challenge.url).expect("challenge response"), ChallengeStatus::Processing);

    let names = vec!["example.test".to_owned(), "*.example.test".to_owned()];
    let csr = open_ssl_core::csr::create(&signing, "example.test", &names);
    let finalized = client.finalize(&order, &csr).expect("finalize");
    assert_eq!(finalized.status, OrderStatus::Processing);

    let issued = client.poll_order(&order.url, 4, Duration::from_millis(5)).expect("order poll");
    assert_eq!(issued.status, OrderStatus::Valid);
    let certificate_url = issued.certificate.clone().expect("certificate url");

    let chain = client.certificate(&certificate_url).expect("certificate download");
    assert_eq!(chain, CHAIN_PEM);

    let queried = client.account().expect("account query");
    assert_eq!(queried.contact, vec!["mailto:ops@example.test".to_owned()]);

    let requests = server.requests();
    assert_eq!(requests.len(), 10);
    let posts: Vec<&mock::RecordedRequest> = requests.iter().filter(|request| request.method == "POST").collect();
    for request in &posts {
        assert_eq!(request.header("content-type"), Some("application/jose+json"));
        verify_jws(request, &verifying);
    }

    let account_post = posts.iter().find(|request| request.route() == "/new-account").expect("account POST");
    assert!(protected_of(account_post).get("jwk").is_some(), "newAccount must self-certify with the JWK");
    assert_eq!(protected_of(account_post)["nonce"], "nonce-directory");
    assert_eq!(protected_of(account_post)["url"], server.url("/new-account"));
    assert_eq!(protected_of(account_post)["aud"], server.url("/new-account"));
    let account_payload: Value = serde_json::from_str(&payload_of(account_post)).expect("account payload");
    assert_eq!(account_payload["termsOfServiceAgreed"], true);
    assert_eq!(account_payload["contact"][0], "mailto:ops@example.test");

    let order_post = posts.iter().find(|request| request.route() == "/new-order").expect("order POST");
    assert_eq!(protected_of(order_post)["kid"], server.url("/account/42"));
    assert_eq!(protected_of(order_post)["nonce"], "nonce-account");
    let order_payload: Value = serde_json::from_str(&payload_of(order_post)).expect("order payload");
    let identifiers = order_payload["identifiers"].as_array().expect("identifiers");
    assert_eq!(identifiers.len(), 2);
    assert_eq!(identifiers[0]["type"], "dns");
    assert_eq!(identifiers[0]["value"], "example.test");
    assert_eq!(identifiers[1]["value"], "*.example.test");

    let challenge_post = posts.iter().find(|request| request.route() == "/challenge/1").expect("challenge POST");
    assert_eq!(payload_of(challenge_post), "{}");
    let cert_post = posts.iter().find(|request| request.route() == "/cert/1").expect("certificate POST");
    assert_eq!(payload_of(cert_post), "", "certificate download is a POST-as-GET");
    let finalize_post = posts.iter().find(|request| request.route() == "/finalize/1").expect("finalize POST");
    let finalize_payload: Value = serde_json::from_str(&payload_of(finalize_post)).expect("finalize payload");
    assert_eq!(finalize_payload["csr"], b64url(&csr));

    assert!(requests.iter().all(|request| request.route() != "/new-nonce"), "every response carried a fresh Replay-Nonce");
}

#[test]
fn bad_nonce_is_retried_once_with_the_refreshed_nonce() {
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[9u8; 32]).expect("test key"));
    let attempts = Arc::new(AtomicUsize::new(0));
    let script = {
        let attempts = Arc::clone(&attempts);
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
                ),
                ("HEAD", "/new-nonce") => {
                    mock::MockResponse::text(200, "application/octet-stream", "").with_header("Replay-Nonce", "nonce-head")
                }
                ("POST", "/new-account") => {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        mock::MockResponse::json(409, r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale nonce"}"#)
                            .with_header("Replay-Nonce", "nonce-retry")
                    }
                    else {
                        mock::MockResponse::json(201, r#"{"status":"valid"}"#).with_header("Location", &format!("{base}/account/1"))
                    }
                }
                _ => mock::MockResponse::json(500, r#"{"detail":"unhandled fixture path"}"#),
            }
        })
    };
    let server = mock::MockServer::start(script);
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    let account = client.new_account(&[], true).expect("account creation survives one badNonce");
    assert_eq!(account.url, server.url("/account/1"));
    let requests = server.requests();
    let posts: Vec<&mock::RecordedRequest> = requests.iter().filter(|request| request.method == "POST").collect();
    assert_eq!(posts.len(), 2);
    assert_eq!(protected_of(posts[0])["nonce"], "nonce-head", "the HEAD newNonce nonce seeds the first attempt");
    assert_eq!(protected_of(posts[1])["nonce"], "nonce-retry", "the 409 response nonce seeds the retry");
}

#[test]
fn a_second_bad_nonce_stops_after_exactly_one_retry() {
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[11u8; 32]).expect("test key"));
    let script = Arc::new(move |request: &mock::RecordedRequest, _index: usize, base: &str| -> mock::MockResponse {
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
            ("POST", "/new-account") => {
                mock::MockResponse::json(409, r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale nonce"}"#)
                    .with_header("Replay-Nonce", "nonce-retry")
            }
            _ => mock::MockResponse::json(500, r#"{"detail":"unhandled fixture path"}"#),
        }
    });
    let server = mock::MockServer::start(script);
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    let error = client.new_account(&[], true).expect_err("a persistent badNonce must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("stale nonce"), "the problem detail must surface: {error}");
    let posts = server.requests().into_iter().filter(|request| request.method == "POST").count();
    assert_eq!(posts, 2, "exactly one retry after the first 409");
}

#[test]
fn bad_nonce_is_recognized_by_the_problem_type_not_the_status() {
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[13u8; 32]).expect("test key"));
    let attempts = Arc::new(AtomicUsize::new(0));
    let script = {
        let attempts = Arc::clone(&attempts);
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
                ("POST", "/new-account") => {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        // 规范里 badNonce 常见状态是 400，不能只认 409。
                        mock::MockResponse::json(400, r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale nonce"}"#)
                            .with_header("Replay-Nonce", "nonce-retry")
                    }
                    else {
                        mock::MockResponse::json(201, r#"{"status":"valid"}"#).with_header("Location", &format!("{base}/account/1"))
                    }
                }
                _ => mock::MockResponse::json(500, r#"{"detail":"unhandled fixture path"}"#),
            }
        })
    };
    let server = mock::MockServer::start(script);
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    let account = client.new_account(&[], true).expect("a badNonce on 400 is retried once");
    assert_eq!(account.url, server.url("/account/1"));
    let posts = server.requests().into_iter().filter(|request| request.method == "POST").count();
    assert_eq!(posts, 2, "exactly one retry after the 400 badNonce");
}

#[test]
fn a_conflict_without_a_bad_nonce_problem_is_not_retried() {
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[17u8; 32]).expect("test key"));
    let script = Arc::new(move |request: &mock::RecordedRequest, _index: usize, base: &str| -> mock::MockResponse {
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
            ("POST", "/new-account") => {
                mock::MockResponse::json(409, r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"account already exists"}"#)
            }
            _ => mock::MockResponse::json(500, r#"{"detail":"unhandled fixture path"}"#),
        }
    });
    let server = mock::MockServer::start(script);
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    let error = client.new_account(&[], true).expect_err("only badNonce is retried");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("account already exists"), "the problem detail must surface: {error}");
    let posts = server.requests().into_iter().filter(|request| request.method == "POST").count();
    assert_eq!(posts, 1, "a non-badNonce conflict must not be retried");
}

#[test]
fn dns01_txt_digest_matches_independently_derived_vectors() {
    // 独立推导（本机 Python，不依赖被测实现）：
    //   python -c "import base64,hashlib; f=lambda s: base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).rstrip(b'=').decode(); print(f('...'))"
    // 输入是 key authorization（`token.thumbprint`），输出是应当发布的 TXT 值。
    //
    // 向量 1 使用 RFC 8555 §8.1 的示例 token 与 RFC 7638 的示例 thumbprint：
    //   sha256(b'evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs')
    //   = 653471d42925d7eb4cd39a39cda8b34d3034c94cb9006ade32048d582ebb2e5f
    //   → base64url 去填充 → ZTRx1Ckl1-tM05o5zaizTTA0yUy5AGereMgSNWC6Ll8
    assert_eq!(
        txt_digest("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"),
        "ZTRx1Ckl1-tM05o5zaizTTA0yUy5AGereMgSNWC6Ll8"
    );
    // 向量 2 用最简输入，便于核对长度与 URL-safe 字母表：
    //   sha256(b'token.thumbprint') = eb5ac167fe249c76e53b430da3116c5d9fde4c5507ba6d01e885516e1bd49f92
    //   → 61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I
    assert_eq!(txt_digest("token.thumbprint"), "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I");

    let encoded = txt_digest("token.thumbprint");
    assert_eq!(encoded.len(), 43, "SHA-256 摘要编码后固定 43 个字符");
    assert!(!encoded.contains('='), "不得保留填充");
    assert!(!encoded.contains('+') && !encoded.contains('/'), "必须使用 URL-safe 字母表");
}

#[test]
fn a_wildcard_authorization_keeps_the_flag_and_shares_the_record_name() {
    let body = serde_json::json!({
        "status": "pending",
        "identifier": { "type": "dns", "value": "*.example.test" },
        "wildcard": true,
        "challenges": [{
            "url": "https://acme.example.test/challenge/1",
            "type": "dns-01",
            "token": "tok",
        }],
    })
    .to_string();
    let authorization = parse_authorization("https://acme.example.test/authz/1", body.as_bytes()).expect("wildcard authorization");
    assert!(authorization.wildcard);
    assert_eq!(authorization.identifier.value, "*.example.test");
    assert_eq!(challenge_fqdn(&authorization.identifier.value), "_acme-challenge.example.test");
    assert_eq!(challenge_fqdn("example.test"), "_acme-challenge.example.test");
}

#[test]
fn unknown_challenge_types_are_ignored_not_fatal() {
    // RFC 8555 §3.2.6：真实 LE staging 已在 dns-01 前面提供 `dns-persist-01`，
    // 未知类型必须被跳过，dns-01 仍可取到。
    let body = serde_json::json!({
        "status": "pending",
        "identifier": { "type": "dns", "value": "*.wxtoken.work" },
        "wildcard": true,
        "challenges": [
            { "url": "https://acme.example.test/challenge/persist", "type": "dns-persist-01", "token": "persist-tok" },
            { "url": "https://acme.example.test/challenge/1", "type": "dns-01", "token": "tok" },
        ],
    })
    .to_string();
    let authorization = parse_authorization("https://acme.example.test/authz/1", body.as_bytes()).expect("未知类型被忽略");
    assert_eq!(authorization.challenges.len(), 1);
    let challenge = authorization.dns01().expect("dns-01 仍然可选");
    assert_eq!(challenge.token, "tok");
}

#[test]
fn order_poll_verdicts_distinguish_progress_from_terminal_states() {
    assert_eq!(order_poll_verdict(OrderStatus::Pending), OrderPollVerdict::Pending);
    assert_eq!(order_poll_verdict(OrderStatus::Ready), OrderPollVerdict::Pending);
    assert_eq!(order_poll_verdict(OrderStatus::Processing), OrderPollVerdict::Pending);
    assert_eq!(order_poll_verdict(OrderStatus::Valid), OrderPollVerdict::Issued);
    assert_eq!(order_poll_verdict(OrderStatus::Invalid), OrderPollVerdict::Failed);
}

#[test]
fn authorization_statuses_separate_pending_from_terminal_failures() {
    assert!(!AuthorizationStatus::parse("pending").expect("pending").is_terminal());
    assert_eq!(AuthorizationStatus::parse("expired").expect("expired"), AuthorizationStatus::Expired);
    assert_eq!(AuthorizationStatus::parse("revoked").expect("revoked"), AuthorizationStatus::Revoked);
    assert!(AuthorizationStatus::Expired.is_failed());
    assert!(AuthorizationStatus::Revoked.is_failed());
    assert!(AuthorizationStatus::Deactivated.is_failed());
    assert!(AuthorizationStatus::Invalid.is_failed());
    assert!(!AuthorizationStatus::Valid.is_failed());
    assert!(AuthorizationStatus::Valid.is_terminal());
}

#[test]
fn retry_after_honors_seconds_dates_and_the_cap() {
    let fallback = Duration::from_secs(2);
    let max = Duration::from_secs(10);
    assert_eq!(retry_after_delay(None, 0, fallback, max), fallback);
    assert_eq!(retry_after_delay(Some("  "), 0, fallback, max), fallback);
    assert_eq!(retry_after_delay(Some("3"), 0, fallback, max), Duration::from_secs(3));
    assert_eq!(retry_after_delay(Some("300"), 0, fallback, max), max, "a huge delta is capped");
    // `Sun, 06 Nov 1994 08:49:37 GMT` = 784111777 Unix 秒（python calendar.timegm 推导）。
    assert_eq!(retry_after_delay(Some("Sun, 06 Nov 1994 08:49:37 GMT"), 784_111_777, fallback, max), Duration::ZERO);
    assert_eq!(retry_after_delay(Some("Sun, 06 Nov 1994 08:49:42 GMT"), 784_111_777, fallback, max), Duration::from_secs(5));
    assert_eq!(retry_after_delay(Some("Sun, 06 Nov 1994 09:00:00 GMT"), 784_111_777, fallback, max), max);
    assert_eq!(retry_after_delay(Some("not a delay"), 0, fallback, max), fallback, "unparseable values fall back");
}

/// 绑定账户的最小目录脚本，供轮询终止状态用例复用。
fn polling_server(order_body: fn(&str) -> String) -> mock::MockServer {
    let script = Arc::new(move |request: &mock::RecordedRequest, _index: usize, base: &str| -> mock::MockResponse {
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
            ("POST", "/new-account") => mock::MockResponse::json(201, r#"{"status":"valid"}"#)
                .with_header("Location", &format!("{base}/account/1"))
                .with_header("Replay-Nonce", "nonce-account"),
            ("HEAD", "/new-nonce") => mock::MockResponse::text(200, "application/octet-stream", "").with_header("Replay-Nonce", "nonce-head"),
            ("POST", "/order/1") => mock::MockResponse::json(200, &order_body(base)).with_header("Replay-Nonce", "nonce-order"),
            _ => mock::MockResponse::json(500, r#"{"detail":"unhandled fixture path"}"#),
        }
    });
    mock::MockServer::start(script)
}

#[test]
fn poll_order_reports_a_timeout_instead_of_returning_pending() {
    let server = polling_server(|base| {
        serde_json::json!({
            "status": "processing",
            "authorizations": [format!("{base}/authz/1")],
            "finalize": format!("{base}/finalize/1"),
        })
        .to_string()
    });
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[19u8; 32]).expect("test key"));
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    client.new_account(&[], true).expect("account");
    let error = client.poll_order(&server.url("/order/1"), 2, Duration::from_millis(1)).expect_err("an unfinished order is not success");
    assert_eq!(error.code(), ErrorCode::Network);
    assert!(error.message().contains("processing"), "the last status must be named: {error}");
}

#[test]
fn poll_order_fails_fast_on_a_terminal_invalid_order() {
    let server = polling_server(|base| {
        serde_json::json!({
            "status": "invalid",
            "authorizations": [format!("{base}/authz/1")],
            "finalize": format!("{base}/finalize/1"),
            "error": { "type": "urn:ietf:params:acme:error:dns", "detail": "dns validation failed", "status": 403 },
        })
        .to_string()
    });
    let key = AccountKey::from_signing_key(SigningKey::from_slice(&[23u8; 32]).expect("test key"));
    let mut client = AcmeClient::bootstrap(HttpTransport::new(), key, &server.url("/directory")).expect("bootstrap");
    client.new_account(&[], true).expect("account");
    let error = client.poll_order(&server.url("/order/1"), 4, Duration::from_millis(1)).expect_err("an invalid order is a failure");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("dns validation failed"), "the problem detail must surface: {error}");
    let polls = server.requests().into_iter().filter(|request| request.route() == "/order/1").count();
    assert_eq!(polls, 1, "an invalid order stops immediately");
}

#[test]
fn thumbprint_matches_the_rfc_7638_example_vector() {
    // RFC 8555 §8.1 defers the fingerprint computation to RFC 7638; §3.1 of that
    // document carries the canonical JSON and the expected base64url SHA-256.
    let canonical = concat!(
        r#"{"e":"AQAB","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt"#,
        r#"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt"#,
        r#"7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9"#,
        r#"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-"#,
        r#"kEgU8awapJzKnqDKgw"}"#
    );
    assert_eq!(jwk_thumbprint(canonical), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
}

#[test]
fn ec_canonical_jwk_and_thumbprint_recompute_independently() {
    let signing = SigningKey::from_slice(&[5u8; 32]).expect("test key");
    let key = AccountKey::from_signing_key(signing.clone());
    let point = signing.verifying_key().to_encoded_point(false);
    let expected = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        b64url(&point.as_bytes()[1..33]),
        b64url(&point.as_bytes()[33..65])
    );
    assert_eq!(key.canonical_jwk(), expected);
    assert_eq!(key.thumbprint(), b64url(&Sha256::digest(expected.as_bytes())));
    assert_eq!(key.key_authorization("tok"), format!("tok.{}", key.thumbprint()));
}

#[test]
fn es256_jws_matches_the_known_answer_vector() {
    let signing = SigningKey::from_slice(&[3u8; 32]).expect("test key");
    let key = AccountKey::from_signing_key(signing.clone());
    let jws = build_jws(&key, &AccountRef::Jwk, "https://acme.example.test/new-order", "c2hpcmE1LW5vbmNl", r#"{"identifiers":[]}"#)
        .expect("build JWS");
    assert_eq!(jws, KNOWN_ANSWER_JWS);
    let document: Value = serde_json::from_str(&jws).expect("the JWS is JSON");
    let protected = {
        let bytes = URL_SAFE_NO_PAD.decode(document["protected"].as_str().expect("protected")).expect("protected is base64url");
        serde_json::from_slice::<Value>(&bytes).expect("protected is JSON")
    };
    assert_eq!(protected["alg"], "ES256");
    assert_eq!(protected["url"], "https://acme.example.test/new-order");
    assert_eq!(protected["aud"], "https://acme.example.test/new-order");
    assert_eq!(protected["nonce"], "c2hpcmE1LW5vbmNl");
    assert_eq!(protected["jwk"], serde_json::from_str::<Value>(&key.canonical_jwk()).expect("canonical JWK parses"));
    let raw = URL_SAFE_NO_PAD.decode(document["signature"].as_str().expect("signature")).expect("signature is base64url");
    let signature = Signature::from_slice(&raw).expect("signature is a raw ES256 r||s");
    signing
        .verifying_key()
        .verify(format!("{}.{}", document["protected"].as_str().unwrap(), document["payload"].as_str().unwrap()).as_bytes(), &signature)
        .expect("the known-answer signature verifies");
}

/// Flattened ES256 JWS for the fixed key `0x03 * 32`, fixed URL, nonce, and payload.
/// RFC 6979 makes the P-256 signature deterministic, so this vector is stable; the test
/// additionally verifies it with the account key.
const KNOWN_ANSWER_JWS: &str = r#"{"payload":"eyJpZGVudGlmaWVycyI6W119","protected":"eyJhbGciOiJFUzI1NiIsImF1ZCI6Imh0dHBzOi8vYWNtZS5leGFtcGxlLnRlc3QvbmV3LW9yZGVyIiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiV1JxM2NldThfVzJjdVFsTkVHVW9yZEdtblVUQ3dmWW44SW5zV0xuR0d0OCIsInkiOiJuMDVxdncwRVhBeHBPanhvclh5WHluSy1aTjcwb21fczBtUGRtS2tuZ1BBIn0sIm5vbmNlIjoiYzJocGNtRTFMVzV2Ym1ObCIsInVybCI6Imh0dHBzOi8vYWNtZS5leGFtcGxlLnRlc3QvbmV3LW9yZGVyIn0","signature":"S0GL_9ME3unq5F1FzzwlXE6pAeYN_PwT6i10g_pRPAlQzJzHIDFx4_gVLcP8bI-M-u8GDG9lafoa-SofErr0Kg"}"#;
