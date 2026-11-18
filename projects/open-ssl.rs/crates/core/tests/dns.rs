//! DNS provider conformance: manual placement and the Cloudflare adapter against a
//! loopback fixture API.

mod mock;

use std::sync::Arc;

use boost_net::http::{HttpTransport, Url};
use serde_json::Value;

use open_ssl_core::{
    ErrorCode,
    dns::{DnsProvider, Manual, TxtRecord, challenge_fqdn, cloudflare::Cloudflare, credentials::Secret, zone_name},
};

const FQDN: &str = "_acme-challenge.wxtoken.work";
const TOKEN: &str = "cf-token-keep-out-of-errors";

#[test]
fn manual_provider_reports_the_record_to_place_and_replaces_idempotently() {
    let mut provider = Manual::new();
    let fqdn = challenge_fqdn("WXTOKEN.WORK.");
    assert_eq!(fqdn, FQDN);
    let record = provider.put_txt(&fqdn, "value-one").expect("manual placement");
    assert_eq!(record, TxtRecord { fqdn: FQDN.to_owned(), value: "value-one".to_owned() });
    provider.put_txt(&fqdn, "value-two").expect("manual replacement");
    assert_eq!(provider.pending_records(), &[TxtRecord { fqdn: FQDN.to_owned(), value: "value-two".to_owned() }]);
    provider.delete_txt(&fqdn).expect("manual removal");
    assert!(provider.pending_records().is_empty());
    assert!(provider.put_txt("wxtoken.work", "not-a-challenge-name").is_err());
}

#[test]
fn zone_name_requires_the_challenge_label() {
    assert_eq!(zone_name(FQDN).expect("zone"), "wxtoken.work");
    assert_eq!(zone_name("wxtoken.work").expect_err("missing label").code(), ErrorCode::InvalidArgument);
    assert_eq!(zone_name("_acme-challenge.").expect_err("empty zone").code(), ErrorCode::InvalidArgument);
}

fn loopback_cloudflare(script: mock::Script) -> (mock::MockServer, Cloudflare<HttpTransport>) {
    let server = mock::MockServer::start(script);
    let api_base = Url::parse(&format!("{}/client/v4", server.base)).expect("loopback API base");
    let provider = Cloudflare::with_token(HttpTransport::new(), api_base, Secret::new(TOKEN));
    (server, provider)
}

#[test]
fn cloudflare_replaces_existing_txt_records_before_creating() {
    let script = Arc::new(|request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        let route = request.route().to_owned();
        match (request.method.as_str(), route.as_str()) {
            ("GET", "/client/v4/zones") => mock::MockResponse::json(200, r#"{"success":true,"result":[{"id":"zone-1"}]}"#),
            ("GET", "/client/v4/zones/zone-1/dns_records") => {
                mock::MockResponse::json(200, r#"{"success":true,"result":[{"id":"rec-1"},{"id":"rec-2"}]}"#)
            }
            ("DELETE", "/client/v4/zones/zone-1/dns_records/rec-1") | ("DELETE", "/client/v4/zones/zone-1/dns_records/rec-2") => {
                mock::MockResponse::json(200, r#"{"success":true,"result":{"id":"deleted"}}"#)
            }
            ("POST", "/client/v4/zones/zone-1/dns_records") => mock::MockResponse::json(200, r#"{"success":true,"result":{"id":"rec-3"}}"#),
            _ => mock::MockResponse::json(500, r#"{"success":false,"errors":[{"message":"unhandled fixture path"}]}"#),
        }
    });
    let (server, mut provider) = loopback_cloudflare(script);
    let record = provider.put_txt(FQDN, "token.thumbprint").expect("cloudflare placement");
    assert_eq!(record, TxtRecord { fqdn: FQDN.to_owned(), value: "token.thumbprint".to_owned() });

    let requests = server.requests();
    let routes: Vec<(&str, &str)> = requests.iter().map(|request| (request.method.as_str(), request.route())).collect();
    assert_eq!(
        routes,
        vec![
            ("GET", "/client/v4/zones"),
            ("GET", "/client/v4/zones/zone-1/dns_records"),
            ("DELETE", "/client/v4/zones/zone-1/dns_records/rec-1"),
            ("DELETE", "/client/v4/zones/zone-1/dns_records/rec-2"),
            ("POST", "/client/v4/zones/zone-1/dns_records"),
        ]
    );
    for request in &requests {
        assert_eq!(request.header("authorization"), Some(&format!("Bearer {TOKEN}")[..]), "every API call authenticates");
    }
    let zone_query = requests[0].query();
    assert!(zone_query.contains("name=wxtoken.work"), "the zone is looked up by name: {zone_query}");
    let list_query = requests[1].query();
    assert!(
        list_query.contains("type=TXT") && list_query.contains("name=_acme-challenge.wxtoken.work"),
        "TXT records are listed by name: {list_query}"
    );
    let created: Value = requests[4].body_json();
    assert_eq!(created["type"], "TXT");
    assert_eq!(created["name"], FQDN);
    assert_eq!(created["content"], "token.thumbprint");
}

#[test]
fn cloudflare_delete_txt_without_existing_records_touches_nothing() {
    let script = Arc::new(|request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        let route = request.route().to_owned();
        match (request.method.as_str(), route.as_str()) {
            ("GET", "/client/v4/zones") => mock::MockResponse::json(200, r#"{"success":true,"result":[{"id":"zone-1"}]}"#),
            ("GET", "/client/v4/zones/zone-1/dns_records") => mock::MockResponse::json(200, r#"{"success":true,"result":[]}"#),
            _ => mock::MockResponse::json(500, r#"{"success":false,"errors":[{"message":"unhandled fixture path"}]}"#),
        }
    });
    let (server, mut provider) = loopback_cloudflare(script);
    provider.delete_txt(FQDN).expect("empty removal");
    assert_eq!(server.requests().len(), 2);
}

#[test]
fn cloudflare_maps_api_failures_to_structured_errors_without_leaking_the_token() {
    let script = Arc::new(|_request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        mock::MockResponse::json(200, r#"{"success":false,"errors":[{"code":10000,"message":"Could not route your request"}]}"#)
    });
    let (_server, mut provider) = loopback_cloudflare(script);
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
    let (_server, mut provider) = loopback_cloudflare(script);
    let error = provider.put_txt(FQDN, "value").expect_err("a forbidden API call must fail");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(!error.message().contains(TOKEN), "the token must never leak: {error}");
}

#[test]
fn cloudflare_reports_a_missing_zone_as_a_protocol_error() {
    let script = Arc::new(|_request: &mock::RecordedRequest, _index: usize, _base: &str| -> mock::MockResponse {
        mock::MockResponse::json(200, r#"{"success":true,"result":[]}"#)
    });
    let (_server, mut provider) = loopback_cloudflare(script);
    let error = provider.put_txt(FQDN, "value").expect_err("an unknown zone must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("wxtoken.work"), "the zone name must be named: {error}");
}

#[test]
fn secret_debug_output_is_redacted() {
    let secret = Secret::new("super-secret-value");
    assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
    assert_eq!(secret.expose(), "super-secret-value");
}
