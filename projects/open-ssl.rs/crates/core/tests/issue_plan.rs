//! 签发计划符合性：纯本地、只报可用性、不创建任何文件。
//!
//! 所有项目与秘密文件都在临时目录里现场构造，不读取仓库或主机上的任何真实凭证。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    Error, ErrorCode, Result,
    dns::credentials::ProjectRoot,
    state::{AccountState, AuthorizationState, DirectoryKind, IssuePlan, OrderPhase, OrderState, StateStore, plan_issue},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-plan-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn cleanup(root: &Path) {
    if !root.exists() {
        return;
    }
    std::fs::remove_dir_all(root).expect("temp cleanup");
}

fn write_secrets(root: &Path, contents: &str) {
    let directory = root.join(".secrets");
    std::fs::create_dir_all(&directory).expect("secrets directory");
    std::fs::write(directory.join("open-ssl.json"), contents).expect("secrets file");
}

/// 一份带有 cloudflare token 的最小合法秘密文件。
fn cloudflare_secrets(token: &str) -> String {
    format!(r#"{{"schema":"open-ssl/secrets/v0","dns":{{"cloudflare":{{"apiToken":"{token}"}}}}}}"#)
}

fn plan_for(root: &Path, provider: &str, names: &[&str]) -> Result<IssuePlan> {
    let project = ProjectRoot::new(root).expect("project root");
    plan(&project, DirectoryKind::Staging, provider, names)
}

fn plan(project: &ProjectRoot, kind: DirectoryKind, provider: &str, names: &[&str]) -> Result<IssuePlan> {
    let identifiers: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
    plan_issue(project, kind, provider, &identifiers)
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .expect("read directory")
        .map(|entry| entry.expect("directory entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn error_of(root: &Path, names: &[&str]) -> Error {
    plan_for(root, "cloudflare", names).expect_err("the plan must be rejected")
}

#[test]
fn a_missing_secrets_file_is_a_hard_failure() {
    let root = temp_project("missing");
    let error = error_of(&root, &["example.test"]);
    assert_eq!(error.code(), ErrorCode::InvalidArgument, "缺文件必须明确失败，不能记成 token 不可用：{error}");
    assert!(error.message().contains("不存在") || error.message().contains("exist"), "错误要说明缺文件：{error}");
    assert!(!error.message().contains("apiToken"), "错误不得回显字段名：{error}");

    cleanup(&root);
}

#[test]
fn a_provider_without_a_token_is_reported_as_unavailable() {
    let root = temp_project("no-provider");
    write_secrets(&root, r#"{"schema":"open-ssl/secrets/v0","dns":{"route53":{"apiToken":"token-value"}}}"#);

    let plan = plan_for(&root, "cloudflare", &["example.test"]).expect("a missing provider token is not a plan failure");
    assert!(plan.secrets_available, "秘密文件本身可用");
    assert!(!plan.dns_token_available, "该 provider 没有 token");
    assert!(plan.secrets_file.ends_with(".secrets/open-ssl.json"));
    assert!(!plan.existing_account);
    assert!(plan.pending_order.is_none());

    cleanup(&root);
}

#[test]
fn a_configured_token_is_available_and_never_printed() {
    let root = temp_project("token");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));

    let plan = plan_for(&root, "cloudflare", &["example.test"]).expect("plan with a configured token");
    assert!(plan.dns_token_available);
    assert_eq!(plan.dns_provider, "cloudflare");

    let debug = format!("{plan:?}");
    assert!(!debug.contains("cf-super-secret-token"), "计划不得输出 token 值：{debug}");
    assert!(debug.contains("example.test"), "计划可以报告非秘密的 SAN：{debug}");

    cleanup(&root);
}

#[test]
fn a_wildcard_without_the_bare_domain_is_only_noted() {
    let root = temp_project("wildcard");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));

    let plan = plan_for(&root, "cloudflare", &["*.example.test"]).expect("plan for a wildcard only");
    assert_eq!(plan.identifiers, vec!["*.example.test".to_owned()], "不得擅自补出裸域");
    assert!(!plan.required_sans_note.is_empty(), "必须提示裸域需要单独申请");
    assert!(
        plan.required_sans_note.iter().any(|note| note.contains("裸域") && note.contains("example.test")),
        "提示要说明裸域：{:?}",
        plan.required_sans_note
    );

    let both = plan_for(&root, "cloudflare", &["example.test", "*.example.test"]).expect("plan for both");
    assert!(both.required_sans_note.is_empty(), "裸域已申请时不再提示：{:?}", both.required_sans_note);

    cleanup(&root);
}

#[test]
fn invalid_identifiers_are_rejected() {
    let root = temp_project("identifiers");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));

    let empty = plan_for(&root, "cloudflare", &[]).expect_err("an empty plan must fail");
    assert_eq!(empty.code(), ErrorCode::InvalidArgument);

    let inner_wildcard = plan_for(&root, "cloudflare", &["a.*.b"]).expect_err("`*.` is only allowed leftmost");
    assert_eq!(inner_wildcard.code(), ErrorCode::InvalidArgument);
    assert!(inner_wildcard.message().contains("最左"), "错误要说明星号位置：{inner_wildcard}");

    let blank = plan_for(&root, "cloudflare", &["  "]).expect_err("a blank identifier must fail");
    assert_eq!(blank.code(), ErrorCode::InvalidArgument);

    let duplicate = plan_for(&root, "cloudflare", &["example.test", "example.test"]).expect_err("duplicates must fail");
    assert_eq!(duplicate.code(), ErrorCode::InvalidArgument);

    let case_duplicate = plan_for(&root, "cloudflare", &["*.Example.Test", "*.example.test"]).expect_err("normalized duplicates must fail");
    assert_eq!(case_duplicate.code(), ErrorCode::InvalidArgument);

    let no_provider = plan_for(&root, "   ", &["example.test"]).expect_err("a provider id is required");
    assert_eq!(no_provider.code(), ErrorCode::InvalidArgument);

    cleanup(&root);
}

#[test]
fn planning_creates_no_state_at_all() {
    let root = temp_project("readonly");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    let secrets_before = entries(&root.join(".secrets"));

    let plan = plan(&project, DirectoryKind::Staging, "cloudflare", &["example.test", "*.example.test"]).expect("plan");
    assert!(!plan.existing_account);
    assert!(plan.pending_order.is_none());

    assert!(!project.state_dir().exists(), "dry-run 不得创建状态目录：{}", project.state_dir().display());
    assert_eq!(entries(&root.join(".secrets")), secrets_before, "dry-run 不得改动秘密目录");

    cleanup(&root);
}

#[test]
fn an_existing_account_and_order_are_reported_for_resume() {
    let root = temp_project("resume");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    let store = StateStore::new(&project);
    store
        .save_account(&AccountState {
            kind: DirectoryKind::Staging,
            directory_url: "https://acme-staging.test/directory".to_owned(),
            account_url: "https://acme-staging.test/acct/1".to_owned(),
            key_thumbprint: "thumb-staging".to_owned(),
            created_unix: 1_700_000_000,
        })
        .expect("save the staging account");
    store
        .save_order(&OrderState {
            id: "order-open".to_owned(),
            kind: DirectoryKind::Staging,
            account_url: "https://acme-staging.test/acct/1".to_owned(),
            order_url: Some("https://acme-staging.test/order/1".to_owned()),
            identifiers: vec!["example.test".to_owned()],
            authorizations: vec![AuthorizationState {
                url: "https://acme-staging.test/authz/1".to_owned(),
                identifier: "example.test".to_owned(),
                wildcard: false,
                record_fqdn: "_acme-challenge.example.test".to_owned(),
                txt_digest: "digest-value".to_owned(),
                status: "pending".to_owned(),
                record_id: None,
            }],
            csr_sha256: None,
            certificate_sha256: None,
            phase: OrderPhase::Authorized,
            updated_unix: 1_700_000_100,
        })
        .expect("save the open order");

    let staging = plan(&project, DirectoryKind::Staging, "cloudflare", &["example.test"]).expect("plan");
    assert!(staging.existing_account, "必须报告可复用的账户，避免重启就新建账户");
    assert_eq!(staging.pending_order.as_deref(), Some("order-open"), "必须报告可从原订单恢复");

    let production = plan(&project, DirectoryKind::Production, "cloudflare", &["example.test"]).expect("plan");
    assert!(!production.existing_account, "staging 身份不得被 production 复用");
    assert!(production.pending_order.is_none(), "staging 订单不得被 production 复用");

    cleanup(&root);
}
