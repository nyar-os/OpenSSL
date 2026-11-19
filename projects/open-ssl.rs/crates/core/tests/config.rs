//! 项目签发配置 `open-ssl.json` 的合同测试。

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    config::{IssueConfig, ZoneSelection},
    dns::credentials::ProjectRoot,
    state::DirectoryKind,
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn project_with(content: Option<&str>) -> (ProjectRoot, PathBuf) {
    let root = std::env::temp_dir().join(format!("open-ssl-config-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    fs::create_dir_all(&root).expect("project root");
    if let Some(content) = content {
        fs::write(root.join("open-ssl.json"), content).expect("config file");
    }
    (ProjectRoot::new(&root).expect("root"), root)
}

#[test]
fn a_missing_configuration_is_not_an_error() {
    let (project, root) = project_with(None);
    assert_eq!(IssueConfig::load(&project).expect("missing is Ok(None)"), None);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_valid_configuration_round_trips() {
    let (project, root) = project_with(Some(
        r#"{"schema":"open-ssl/config/v0","dnsProvider":"cloudflare","kind":"production","zone":{"id":"zone-1"},"contact":["mailto:ops@example.test"]}"#,
    ));
    let config = IssueConfig::load(&project).expect("valid").expect("present");
    assert_eq!(config.dns_provider.as_deref(), Some("cloudflare"));
    assert_eq!(config.kind, Some(DirectoryKind::Production));
    assert_eq!(config.zone, Some(ZoneSelection { id: Some("zone-1".to_owned()), name: None }));
    assert_eq!(config.contact, vec!["mailto:ops@example.test".to_owned()]);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn every_field_is_optional() {
    let (project, root) = project_with(Some(r#"{"schema":"open-ssl/config/v0"}"#));
    let config = IssueConfig::load(&project).expect("minimal").expect("present");
    assert!(config.dns_provider.is_none() && config.kind.is_none() && config.zone.is_none() && config.contact.is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_foreign_schema_is_rejected() {
    let (project, root) = project_with(Some(r#"{"schema":"open-ssl/config/v1"}"#));
    assert_eq!(IssueConfig::load(&project).expect_err("unknown schema").code(), ErrorCode::Protocol);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn unknown_fields_are_rejected() {
    let (project, root) = project_with(Some(r#"{"schema":"open-ssl/config/v0","dnsprovider":"cloudflare"}"#));
    assert_eq!(IssueConfig::load(&project).expect_err("snake_case 拼写不是本合同字段").code(), ErrorCode::Protocol);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn an_empty_zone_value_says_what_to_fix() {
    let (project, root) = project_with(Some(r#"{"schema":"open-ssl/config/v0","zone":{"name":""}}"#));
    let error = IssueConfig::load(&project).expect_err("空 zone 名必须显式失败");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("zone.name"), "{}", error.message());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn a_zone_with_both_forms_is_rejected() {
    let (project, root) = project_with(Some(r#"{"schema":"open-ssl/config/v0","zone":{"id":"a","name":"b"}}"#));
    assert_eq!(IssueConfig::load(&project).expect_err("id 与 name 互斥").code(), ErrorCode::Protocol);
    let _ = fs::remove_dir_all(root);
}
