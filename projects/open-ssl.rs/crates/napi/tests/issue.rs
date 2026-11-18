//! `acmePlan` and `acmeIssue` at the native boundary.
//!
//! The tests call the same helpers the exported functions call. Every project,
//! secret file, and state is built in a temp directory: no real credential, no
//! network, and no CA is involved.

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{issue::NO_HTTPS_TRANSPORT, state::DirectoryKind};
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
    assert!(outcome.session.is_none(), "dry-run 不产生会话");
    let plan = outcome.plan.expect("dry-run 携带计划");
    assert!(plan.dns_token_available);
    assert!(!state_dir(&root).join("issue.lock").exists(), "dry-run 不得创建锁文件");
    assert!(!state_dir(&root).exists(), "dry-run 不得创建状态目录");

    cleanup(&root);
}

#[test]
fn a_real_run_reports_the_blocked_transport_and_never_claims_issuance() {
    let root = temp_project("blocked");
    let outcome = run_acme_issue(&arguments(&root), false).expect("session");

    assert!(!outcome.dry_run);
    let session = outcome.session.as_ref().expect("real run 携带会话");
    assert_eq!(session.blocked, Some(NO_HTTPS_TRANSPORT), "必须暴露未接通 HTTPS 的事实");
    assert_ne!(session.stage.as_str(), "issued", "阶段不得伪装成已签发");
    assert!(!state_dir(&root).join("issue.lock").exists(), "报告离开边界前必须释放锁");

    let report = serde_json::to_string(&outcome).expect("outcome serializes");
    assert!(!report.contains(TOKEN), "会话不得回显 token：{report}");
    assert!(report.contains("blocked"), "会话必须携带 blocked 字段：{report}");
    assert!(!report.contains("issued"), "不得出现已签发的假象：{report}");

    cleanup(&root);
}
