//! DNS provider 符合性：句柄所有权、挑战记录名，以及针对 loopback 夹具 API 的
//! Cloudflare 适配器。

mod mock;

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use boost_net::http::{HttpTransport, Url};
use serde_json::{Value, json};

use open_ssl_core::{
    ErrorCode,
    dns::{
        DnsProvider, RecordHandle, TxtRecord, challenge_fqdn,
        cloudflare::{Cloudflare, Zone},
        credentials::Secret,
    },
};

const FQDN: &str = "_acme-challenge.wxtoken.work";
const TOKEN: &str = "cf-token-keep-out-of-errors";

/// 一条脚本化的 provider 记录：id、name、content。
type Registry = Arc<Mutex<Vec<(String, String, String)>>>;

fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then(|| value.to_owned())
    })
}

fn json_response(status: u16, body: Value) -> mock::MockResponse {
    mock::MockResponse::json(status, &body.to_string())
}

/// 一个最小的 Cloudflare TXT 记录注册表：查询、创建、按 id 删除。
fn cloudflare_registry() -> (mock::Script, Registry, Arc<AtomicU32>) {
    let state: Registry = Arc::new(Mutex::new(Vec::new()));
    let next = Arc::new(AtomicU32::new(0));
    let script = {
        let state = Arc::clone(&state);
        let next = Arc::clone(&next);
        Arc::new(move |request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
            let method = request.method.as_str();
            let route = request.route().to_owned();
            if method == "GET" && route == "/client/v4/zones" {
                return json_response(200, json!({ "success": true, "result": [{ "id": "zone-1" }] }));
            }
            if method == "GET" && route == "/client/v4/zones/zone-1/dns_records" {
                let name = query_value(request.query(), "name").unwrap_or_default();
                let records: Vec<Value> = state
                    .lock()
                    .expect("registry")
                    .iter()
                    .filter(|(_, record_name, _)| record_name == &name)
                    .map(|(id, name, content)| json!({ "id": id, "name": name, "content": content }))
                    .collect();
                return json_response(200, json!({ "success": true, "result": records }));
            }
            if method == "POST" && route == "/client/v4/zones/zone-1/dns_records" {
                let body = request.body_json();
                let id = format!("rec-{}", next.fetch_add(1, Ordering::SeqCst) + 1);
                let name = body["name"].as_str().unwrap_or_default().to_owned();
                let content = body["content"].as_str().unwrap_or_default().to_owned();
                state.lock().expect("registry").push((id.clone(), name, content));
                return json_response(200, json!({ "success": true, "result": { "id": id } }));
            }
            if method == "DELETE" && route.starts_with("/client/v4/zones/zone-1/dns_records/") {
                let id = route.rsplit('/').next().unwrap_or_default().to_owned();
                state.lock().expect("registry").retain(|(record_id, _, _)| record_id != &id);
                return json_response(200, json!({ "success": true, "result": { "id": id } }));
            }
            json_response(500, json!({ "success": false, "errors": [{ "message": "unhandled fixture path" }] }))
        })
    };
    (script, state, next)
}

fn loopback_cloudflare(script: mock::Script, zone: Zone) -> (mock::MockServer, Cloudflare<HttpTransport>) {
    let server = mock::MockServer::start(script);
    let api_base = Url::parse(&format!("{}/client/v4", server.base)).expect("loopback API base");
    let provider = Cloudflare::with_zone(HttpTransport::new(), api_base, Secret::new(TOKEN), zone);
    (server, provider)
}

#[test]
fn challenge_fqdn_strips_the_wildcard_label() {
    assert_eq!(challenge_fqdn("*.example.com"), "_acme-challenge.example.com");
    assert_eq!(challenge_fqdn("example.com"), "_acme-challenge.example.com");
    assert_eq!(challenge_fqdn("*.Example.COM."), "_acme-challenge.example.com");
}

#[test]
fn record_handle_rejects_an_empty_provider_id() {
    assert_eq!(RecordHandle::new("   ").expect_err("empty handle").code(), ErrorCode::Protocol);
    assert_eq!(RecordHandle::new("rec-1").expect("handle").as_str(), "rec-1");
}

#[test]
fn cloudflare_reuses_an_identical_record_instead_of_deleting() {
    let (script, state, _next) = cloudflare_registry();
    state.lock().expect("registry").push(("rec-existing".to_owned(), FQDN.to_owned(), "value-one".to_owned()));
    let (server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));

    let record = provider.put_txt(FQDN, "value-one").expect("reuse");
    assert_eq!(
        record,
        TxtRecord { fqdn: FQDN.to_owned(), value: "value-one".to_owned(), handle: RecordHandle::new("rec-existing").expect("handle") }
    );
    assert_eq!(state.lock().expect("registry").len(), 1);

    let routes: Vec<(String, String)> = server.requests().iter().map(|request| (request.method.clone(), request.route().to_owned())).collect();
    assert_eq!(
        routes,
        vec![("GET".to_owned(), "/client/v4/zones".to_owned()), ("GET".to_owned(), "/client/v4/zones/zone-1/dns_records".to_owned())],
        "a reuse must not create or delete anything"
    );
}

#[test]
fn cloudflare_keeps_two_values_for_the_same_name() {
    let (script, state, _next) = cloudflare_registry();
    let (server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));

    let first = provider.put_txt(FQDN, "value-one").expect("first placement");
    let second = provider.put_txt(FQDN, "value-two").expect("second placement");
    assert_ne!(first.handle, second.handle);
    assert_eq!(state.lock().expect("registry").len(), 2, "both values coexist");

    let deletes = server.requests().iter().filter(|request| request.method == "DELETE").count();
    assert_eq!(deletes, 0, "placing a value never removes another task's record");
}

#[test]
fn cloudflare_deletes_only_the_owned_record() {
    let (script, state, _next) = cloudflare_registry();
    let (server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));

    let first = provider.put_txt(FQDN, "value-one").expect("first placement");
    let second = provider.put_txt(FQDN, "value-two").expect("second placement");
    provider.delete_txt(&first).expect("delete owned record");

    let remaining = state.lock().expect("registry").clone();
    assert_eq!(remaining, vec![("rec-2".to_owned(), FQDN.to_owned(), "value-two".to_owned())]);
    assert_eq!(provider.find_txt(FQDN, "value-two").expect("find"), Some(second));

    let deletes: Vec<String> =
        server.requests().iter().filter(|request| request.method == "DELETE").map(|request| request.route().to_owned()).collect();
    assert_eq!(deletes, vec!["/client/v4/zones/zone-1/dns_records/rec-1".to_owned()]);
}

#[test]
fn cloudflare_uses_a_configured_zone_id_without_a_name_lookup() {
    let script = Arc::new(|request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        let route = request.route().to_owned();
        match (request.method.as_str(), route.as_str()) {
            ("GET", "/client/v4/zones/zone-9/dns_records") => mock::MockResponse::json(200, r#"{"success":true,"result":[]}"#),
            ("POST", "/client/v4/zones/zone-9/dns_records") => mock::MockResponse::json(200, r#"{"success":true,"result":{"id":"rec-9"}}"#),
            _ => mock::MockResponse::json(500, r#"{"success":false,"errors":[{"message":"unexpected path"}]}"#),
        }
    });
    let (server, mut provider) = loopback_cloudflare(script, Zone::id("zone-9").expect("zone"));

    let record = provider.put_txt(FQDN, "value-one").expect("placement");
    assert_eq!(record.handle.as_str(), "rec-9");
    let routes: Vec<String> = server.requests().iter().map(|request| request.route().to_owned()).collect();
    assert_eq!(routes, vec!["/client/v4/zones/zone-9/dns_records".to_owned(), "/client/v4/zones/zone-9/dns_records".to_owned()]);
}

#[test]
fn cloudflare_reports_a_missing_zone_name() {
    let script = Arc::new(|_request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        mock::MockResponse::json(200, r#"{"success":true,"result":[]}"#)
    });
    let (_server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));
    let error = provider.put_txt(FQDN, "value").expect_err("an unknown zone must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("wxtoken.work"), "the zone name must be named: {error}");
}

#[test]
fn cloudflare_maps_api_failures_to_structured_errors_without_leaking_the_token() {
    let script = Arc::new(|_request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        mock::MockResponse::json(200, r#"{"success":false,"errors":[{"code":10000,"message":"Could not route your request"}]}"#)
    });
    let (_server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));
    let error = provider.put_txt(FQDN, "value").expect_err("a refused API call must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("Could not route your request"), "the API message must surface: {error}");
    assert!(!error.message().contains(TOKEN), "the token must never leak: {error}");
    assert!(!format!("{provider:?}").contains(TOKEN), "the token must not render in debug output");
}

#[test]
fn cloudflare_maps_forbidden_responses_to_denied() {
    let script = Arc::new(|_request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        mock::MockResponse::json(403, r#"{"success":false,"errors":[{"message":"Token does not have permission"}]}"#)
    });
    let (_server, mut provider) = loopback_cloudflare(script, Zone::name("wxtoken.work").expect("zone"));
    let error = provider.put_txt(FQDN, "value").expect_err("a forbidden API call must fail");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(!error.message().contains(TOKEN), "the token must never leak: {error}");
}

#[test]
fn secret_debug_output_is_redacted() {
    let secret = Secret::new("super-secret-value");
    assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    assert_eq!(secret.expose(), "super-secret-value");
}
