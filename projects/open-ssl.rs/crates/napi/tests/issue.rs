//! `acmePlan` and `acmeIssue` at the native boundary.
//!
//! The tests call the same helpers the exported functions call. Every project,
//! secret file, and state is built in a temp directory: no real credential, no
//! network, and no CA is involved.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{ErrorCode, state::DirectoryKind};
use open_ssl_napi::{IssueArguments, run_acme_issue, run_acme_plan};

/// A token that must never appear in any report.
const TOKEN: &str = "cf-super-secret-token";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-napi-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    let secrets = root.join(".secrets");
    std::fs::create_dir_all(&secrets).expect("secrets directory");
    let document = format!(r#"{{"schema":"open-ssl/secrets/v0","dns":{{"cloudflare":{{"apiToken":"{TOKEN}"}}}}}}"#);
    std::fs::write(secrets.join("open-ssl.json"), document).expect("secrets file");
    root
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn state_dir(root: &Path) -> PathBuf {
    root.join(".secrets").join("open-ssl")
}

fn arguments(root: &Path) -> IssueArguments {
    IssueArguments {
        project_root: Some(root.to_path_buf()),
        kind: DirectoryKind::Staging,
        dns_provider: "cloudflare".to_owned(),
        identifiers: vec!["example.test".to_owned(), "*.example.test".to_owned()],
        dns_zone_id: None,
        dns_zone_name: None,
        contact: Vec::new(),
    }
}

#[test]
fn the_plan_report_never_carries_the_provider_token() {
    let root = temp_project("plan-token");
    let plan = run_acme_plan(&arguments(&root)).expect("local plan");
    let report = serde_json::to_string(&plan).expect("plan serializes");

    assert!(report.contains("example.test"), "计划要报告非秘密的 SAN：{report}");
    assert!(report.contains("dnsTokenAvailable"), "计划要报告 token 可用性：{report}");
    assert!(!report.contains(TOKEN), "计划不得回显 token：{report}");
    assert!(!state_dir(&root).exists(), "纯本地的计划不得创建状态目录");

    cleanup(&root);
}

#[test]
fn a_dry_run_takes_no_lock_and_writes_nothing() {
    let root = temp_project("dry-run");
    let outcome = run_acme_issue(&arguments(&root), true).expect("dry run");

    assert!(outcome.dry_run);
    assert!(outcome.report.is_none(), "dry-run 不产生签发报告");
    let plan = outcome.plan.expect("dry-run 携带计划");
    assert!(plan.dns_token_available);
    assert!(!state_dir(&root).join("issue.lock").exists(), "dry-run 不得创建锁文件");
    assert!(!state_dir(&root).exists(), "dry-run 不得创建状态目录");

    cleanup(&root);
}

#[test]
fn a_real_run_refuses_without_an_explicit_zone() {
    // 没有 zone 时必须在任何网络与 DNS 动作之前失败，并且不留下半成品。
    let root = temp_project("no-zone");
    let error = run_acme_issue(&arguments(&root), false).expect_err("a real run must demand the zone");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("dnsZoneId") || error.message().contains("dnsZoneName"), "{}", error.message());
    assert!(!state_dir(&root).exists(), "被拒绝的签发不得创建状态目录");
    cleanup(&root);
}

#[test]
fn a_real_run_refuses_both_zone_forms_at_once() {
    let root = temp_project("both-zones");
    let mut arguments = arguments(&root);
    arguments.dns_zone_id = Some("zone-id".to_owned());
    arguments.dns_zone_name = Some("example.test".to_owned());
    let error = run_acme_issue(&arguments, false).expect_err("两种 zone 形态互斥");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    cleanup(&root);
}

#[test]
fn a_real_run_refuses_an_unsupported_provider() {
    let root = temp_project("other-provider");
    let mut arguments = arguments(&root);
    arguments.dns_provider = "dnspod".to_owned();
    arguments.dns_zone_name = Some("example.test".to_owned());
    let error = run_acme_issue(&arguments, false).expect_err("dnspod 还不是受支持的 provider");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    cleanup(&root);
}

#[test]
fn a_manual_plan_needs_no_secrets_file() {
    // 交互式模式的前提：没有 `.secrets` 也能出计划，token 天然可用。
    let root = std::env::temp_dir().join(format!("open-ssl-napi-manual-plan-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    let mut arguments = arguments(&root);
    arguments.dns_provider = "manual".to_owned();
    let outcome = run_acme_issue(&arguments, true).expect("manual dry run");
    let plan = outcome.plan.expect("dry run carries the plan");
    assert!(plan.dns_token_available, "manual 由操作者放置记录，天然可用");
    assert!(!plan.secrets_available, "manual 不要求秘密文件存在");
    assert!(!root.join(".secrets").exists(), "manual 计划不得创建秘密目录");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_refused_run_never_echoes_the_token() {
    // 不触网的拒绝路径：provider 在秘密文件里没有 token。
    let root = temp_project("token-leak");
    let mut arguments = arguments(&root);
    arguments.dns_provider = "route53".to_owned();
    arguments.dns_zone_name = Some("example.test".to_owned());
    let error = run_acme_issue(&arguments, false).expect_err("route53 没有配置秘密");
    assert!(!error.to_string().contains(TOKEN), "拒绝消息不得回显 token：{error}");
    cleanup(&root);
}
