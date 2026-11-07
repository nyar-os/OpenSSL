use open_ssl_core::{
    CapabilityState, Error, ErrorCode,
    audit::{AuditFields, capability_ids},
    platform::{capabilities, platform},
};

const DOMAIN: [&str; 11] = [
    capability_ids::CERTIFICATE_INSPECT,
    capability_ids::CERTIFICATE_ISSUE,
    capability_ids::CERTIFICATE_RENEW,
    capability_ids::CERTIFICATE_REVOKE,
    capability_ids::CA_CREATE,
    capability_ids::CSR_CREATE,
    capability_ids::PRIVATE_KEY_STORE,
    capability_ids::CERTIFICATE_STORE,
    capability_ids::REMOTE_AGENT,
    capability_ids::HOST_INSTALL,
    capability_ids::HOST_UNINSTALL,
];

const META: [&str; 4] = [capability_ids::CAPABILITIES, capability_ids::VERSION, capability_ids::AUDIT_QUERY, capability_ids::AUDIT_CONFIGURE];

#[test]
fn every_domain_capability_is_registered_as_not_implemented() {
    let report = capabilities();
    for id in DOMAIN {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert_eq!(item.state, Some(CapabilityState::NotImplemented), "{id} must stay not_implemented");
        assert_eq!(item.code, Some("not_implemented"), "{id} must carry the stable code");
        assert!(!item.is_available(), "{id} must not report as available");
        assert!(!item.reason.is_empty(), "{id} must explain why it is unavailable");
        assert!(!item.detail.is_empty(), "{id} must describe the target behaviour");
    }
}

#[test]
fn inspection_and_issuance_stay_separate_capabilities() {
    let report = capabilities();
    for id in [capability_ids::CERTIFICATE_INSPECT, capability_ids::CERTIFICATE_ISSUE] {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert_eq!(item.state, Some(CapabilityState::NotImplemented));
    }
    let inspect = report.get(capability_ids::CERTIFICATE_INSPECT).expect("inspect row");
    assert!(inspect.detail.contains("display"));
    let issue = report.get(capability_ids::CERTIFICATE_ISSUE).expect("issue row");
    assert!(issue.detail.contains("Sign"));
}

#[test]
fn remote_agent_is_a_separate_capability() {
    let report = capabilities();
    let item = report.get(capability_ids::REMOTE_AGENT).unwrap_or_else(|| panic!("missing remote agent row"));
    assert_eq!(item.state, Some(CapabilityState::NotImplemented));
    assert!(!item.reason.is_empty());
}

#[test]
fn meta_capabilities_are_available() {
    let report = capabilities();
    for id in META {
        let item = report.get(id).unwrap_or_else(|| panic!("missing capability row: {id}"));
        assert!(item.is_available(), "{id} must be available in the skeleton round");
        assert_eq!(item.state, None);
        assert_eq!(item.code, None);
    }
}

#[test]
fn capability_ids_are_unique() {
    let report = capabilities();
    let mut seen = Vec::with_capacity(report.items.len());
    for item in &report.items {
        assert!(!seen.contains(&item.id), "duplicate capability id: {}", item.id);
        seen.push(item.id);
    }
    assert_eq!(report.app, "open-ssl");
    assert_eq!(report.items.len(), DOMAIN.len() + META.len());
    assert!(report.notes.iter().any(|note| note.contains("no capability may fall back") || note.contains("No capability may fall back")));
}

#[test]
fn capability_state_codes_round_trip() {
    for state in [CapabilityState::UnsupportedPlatform, CapabilityState::NotImplemented, CapabilityState::DependencyBlocked] {
        assert_eq!(CapabilityState::from_code(state.code()), Some(state));
    }
    assert_eq!(CapabilityState::from_code("available"), None);
    assert_eq!(ErrorCode::from_state(CapabilityState::NotImplemented).as_str(), "not_implemented");
    assert_eq!(ErrorCode::InvalidArgument.as_str(), "invalid_argument");
    assert_eq!(ErrorCode::Io.as_str(), "io_error");
}

#[test]
fn unavailable_errors_expose_the_capability_and_code() {
    let error = Error::unavailable(CapabilityState::NotImplemented, capability_ids::CERTIFICATE_ISSUE, "skeleton round");
    assert_eq!(error.code(), ErrorCode::NotImplemented);
    assert_eq!(error.capability(), Some(capability_ids::CERTIFICATE_ISSUE));
    assert_eq!(error.message(), "skeleton round");
    assert_eq!(error.to_string(), "not_implemented (certificate-issue): skeleton round");
}

#[test]
fn audit_fields_are_redacted_and_typed() {
    let fields = AuditFields::new(capability_ids::CERTIFICATE_ISSUE, 2, "subject hash only");
    let value = serde_json::to_value(&fields).expect("audit fields serialize");
    assert_eq!(value["capability"], capability_ids::CERTIFICATE_ISSUE);
    assert_eq!(value["targetCount"], 2);
    assert_eq!(value["targetSummary"], "subject hash only");
}

#[test]
fn platform_reports_the_build_host() {
    let info = platform();
    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
}
