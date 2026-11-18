//! 签发会话：取锁、离线准备、账户与订单恢复，以及「不写状态」的边界。
//!
//! 所有项目、秘密文件与状态都在临时目录里现场构造，不读取仓库或主机上的任何真实凭证。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    dns::credentials::ProjectRoot,
    issue::{IssueRequest, IssueStage, NO_HTTPS_TRANSPORT, begin_issue},
    lock::ProjectLock,
    state::{AccountState, AuthorizationState, DirectoryKind, OrderPhase, OrderState, StateStore},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-issue-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
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

fn request(kind: DirectoryKind, names: &[String]) -> IssueRequest<'_> {
    IssueRequest { kind, dns_provider: "cloudflare", identifiers: names }
}

fn names(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// 状态目录里的条目名，目录不存在时视为空。
fn state_entries(project: &ProjectRoot) -> Vec<String> {
    let directory = project.state_dir();
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut names: Vec<String> = entries.map(|entry| entry.expect("state entry").file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

fn lock_file(project: &ProjectRoot) -> PathBuf {
    project.state_dir().join("issue.lock")
}

fn save_account(project: &ProjectRoot, kind: DirectoryKind) {
    StateStore::new(project)
        .save_account(&AccountState {
            kind,
            directory_url: format!("https://acme-{}.test/directory", kind.as_str()),
            account_url: format!("https://acme-{}.test/acct/1", kind.as_str()),
            key_thumbprint: format!("thumb-{}", kind.as_str()),
            created_unix: 1_700_000_000,
        })
        .expect("save the account");
}

fn save_open_order(project: &ProjectRoot, kind: DirectoryKind, id: &str) {
    StateStore::new(project)
        .save_order(&OrderState {
            id: id.to_owned(),
            kind,
            account_url: format!("https://acme-{}.test/acct/1", kind.as_str()),
            order_url: None,
            identifiers: vec!["example.test".to_owned()],
            authorizations: vec![AuthorizationState {
                url: format!("https://acme-{}.test/authz/1", kind.as_str()),
                identifier: "example.test".to_owned(),
                wildcard: false,
                record_fqdn: "_acme-challenge.example.test".to_owned(),
                txt_digest: "digest-value".to_owned(),
                status: "pending".to_owned(),
                record_id: None,
            }],
            csr_sha256: None,
            certificate_sha256: None,
            phase: OrderPhase::Planned,
            updated_unix: 1_700_000_100,
        })
        .expect("save the open order");
}

#[test]
fn a_missing_secrets_file_fails_and_leaves_no_lock() {
    let root = temp_project("missing");
    let project = ProjectRoot::new(&root).expect("project root");

    let error =
        begin_issue(&project, request(DirectoryKind::Staging, &names(&["example.test"]))).expect_err("a missing secrets file must fail");
    assert_eq!(error.code(), ErrorCode::InvalidArgument, "缺文件是明确失败，不是可继续的计划：{error}");
    assert!(!lock_file(&project).exists(), "失败的会话必须释放锁：{}", lock_file(&project).display());

    cleanup(&root);
}

#[test]
fn a_normal_project_prepares_and_reports_the_missing_transport() {
    let root = temp_project("prepared");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");

    let (lock, session) =
        begin_issue(&project, request(DirectoryKind::Staging, &names(&["example.test", "*.example.test"]))).expect("begin issue");
    assert_eq!(session.stage, IssueStage::Prepared, "没有账户与订单时只能停在离线准备");
    assert_eq!(session.blocked, Some(NO_HTTPS_TRANSPORT), "本构建必须报告缺少 HTTPS 传输");
    assert!(!session.account_reused);
    assert!(session.pending_order.is_none());
    assert_eq!(session.plan.identifiers, names(&["example.test", "*.example.test"]));
    assert!(session.plan.dns_token_available, "秘密文件里的 token 必须与计划一致");
    assert_eq!(session.stage.as_str(), "prepared");
    assert!(lock.path().exists(), "编排期间由调用方持有锁");

    lock.release().expect("release");
    cleanup(&root);
}

#[test]
fn an_open_order_is_resumed_instead_of_replanned() {
    let root = temp_project("resumed");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    save_account(&project, DirectoryKind::Staging);
    save_open_order(&project, DirectoryKind::Staging, "order-open");

    let (lock, session) = begin_issue(&project, request(DirectoryKind::Staging, &names(&["example.test"]))).expect("begin issue");
    assert_eq!(session.stage, IssueStage::Resumed, "有未完成订单时必须续接而不是重建");
    assert_eq!(session.pending_order.as_deref(), Some("order-open"));
    assert!(session.account_reused);
    assert_eq!(session.plan.pending_order.as_deref(), Some("order-open"));
    assert_eq!(session.blocked, Some(NO_HTTPS_TRANSPORT));
    lock.release().expect("release");

    cleanup(&root);
}

#[test]
fn an_existing_account_is_reused_without_writing_a_new_one() {
    let root = temp_project("account");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    save_account(&project, DirectoryKind::Staging);
    let before = state_entries(&project);

    let (lock, session) = begin_issue(&project, request(DirectoryKind::Staging, &names(&["example.test"]))).expect("begin issue");
    assert!(session.account_reused, "重启后必须复用已有账户");
    assert!(session.plan.existing_account);
    assert!(session.pending_order.is_none(), "只有账户没有订单时不需要续接订单");
    assert_eq!(session.stage, IssueStage::Prepared);

    let mut expected = before;
    expected.push("issue.lock".to_owned());
    expected.sort();
    assert_eq!(state_entries(&project), expected, "除锁文件外不得新增状态");

    lock.release().expect("release");
    cleanup(&root);
}

#[test]
fn beginning_an_issue_writes_only_the_lock_file() {
    let root = temp_project("readonly");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    let state_before = state_entries(&project);
    assert!(state_before.is_empty(), "构造后状态目录应为空");

    let (lock, _session) = begin_issue(&project, request(DirectoryKind::Production, &names(&["example.test"]))).expect("begin issue");
    assert_eq!(state_entries(&project), vec!["issue.lock".to_owned()], "编排只允许留下锁文件");

    lock.release().expect("release");
    assert!(state_entries(&project).is_empty(), "释放后状态目录回到空");

    cleanup(&root);
}

#[test]
fn a_held_lock_denies_the_second_begin_without_side_effects() {
    let root = temp_project("denied");
    write_secrets(&root, &cloudflare_secrets("cf-super-secret-token"));
    let project = ProjectRoot::new(&root).expect("project root");
    let held = ProjectLock::acquire(&project).expect("first lock");

    let error =
        begin_issue(&project, request(DirectoryKind::Staging, &names(&["example.test"]))).expect_err("a held lock must deny the session");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(lock_file(&project).exists(), "被拒的调用不得删除别人的锁");
    assert_eq!(state_entries(&project), vec!["issue.lock".to_owned()], "被拒的调用不得留下别的东西");

    held.release().expect("release");
    cleanup(&root);
}
