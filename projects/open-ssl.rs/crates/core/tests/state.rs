//! 签发状态持久化符合性：账户按 directory 隔离、订单恢复、原子替换与损坏检测。
//!
//! 所有状态文件都在临时目录里现场构造，不读取仓库或主机上的任何真实状态与凭证。

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    dns::credentials::ProjectRoot,
    state::{AccountState, AuthorizationState, DirectoryKind, OrderPhase, OrderState, StateStore},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-state-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn cleanup(root: &Path) {
    std::fs::remove_dir_all(root).expect("temp cleanup");
}

fn state_dir(root: &Path) -> PathBuf {
    root.join(".secrets").join("open-ssl")
}

fn store_for(root: &Path) -> StateStore {
    StateStore::new(&ProjectRoot::new(root).expect("project root"))
}

fn account(kind: DirectoryKind, account_url: &str, key_thumbprint: &str) -> AccountState {
    AccountState {
        kind,
        directory_url: format!("https://acme.{}.test/directory", kind.as_str()),
        account_url: account_url.to_owned(),
        key_thumbprint: key_thumbprint.to_owned(),
        created_unix: 1_700_000_000,
    }
}

fn authorization(identifier: &str, wildcard: bool, record_id: Option<&str>) -> AuthorizationState {
    AuthorizationState {
        url: format!("https://acme.test/authz/{identifier}"),
        identifier: identifier.to_owned(),
        wildcard,
        record_fqdn: format!("_acme-challenge.{identifier}"),
        txt_digest: format!("digest-{identifier}"),
        status: "pending".to_owned(),
        record_id: record_id.map(str::to_owned),
    }
}

fn order(id: &str, kind: DirectoryKind, phase: OrderPhase, updated_unix: u64) -> OrderState {
    OrderState {
        id: id.to_owned(),
        kind,
        account_url: "https://acme.test/acct/1".to_owned(),
        order_url: Some(format!("https://acme.test/order/{id}")),
        identifiers: vec!["example.test".to_owned(), "*.example.test".to_owned()],
        authorizations: vec![authorization("example.test", false, Some("record-1")), authorization("example.test", true, None)],
        csr_sha256: Some("csr-sha256".to_owned()),
        certificate_sha256: None,
        phase,
        updated_unix,
    }
}

/// 一份形状完整的订单文档，用来覆盖反序列化校验的各个分支。
fn order_document(id: &str, phase: &str, record_fqdn: &str) -> String {
    format!(
        r#"{{"id":"{id}","kind":"staging","accountUrl":"https://acme.test/acct/1","orderUrl":"https://acme.test/order/1","identifiers":["example.test"],"authorizations":[{{"url":"https://acme.test/authz/1","identifier":"example.test","wildcard":false,"recordFqdn":"{record_fqdn}","txtDigest":"digest-value","status":"pending","recordId":"record-1"}}],"csrSha256":null,"certificateSha256":null,"phase":"{phase}","updatedUnix":10}}"#
    )
}

fn write_order(root: &Path, id: &str, contents: &str) {
    let directory = state_dir(root).join("orders");
    std::fs::create_dir_all(&directory).expect("orders directory");
    std::fs::write(directory.join(format!("{id}.json")), contents).expect("order file");
}

#[test]
fn accounts_are_isolated_by_directory_kind() {
    let root = temp_project("accounts");
    let store = store_for(&root);
    assert!(store.account(DirectoryKind::Staging).expect("no staging account").is_none());
    assert!(store.account(DirectoryKind::Production).expect("no production account").is_none());

    let staging = account(DirectoryKind::Staging, "https://acme-staging.test/acct/1", "thumb-staging");
    let production = account(DirectoryKind::Production, "https://acme.test/acct/9", "thumb-production");
    store.save_account(&staging).expect("save the staging account");
    store.save_account(&production).expect("save the production account");

    assert_eq!(store.account(DirectoryKind::Staging).expect("staging").expect("present"), staging);
    assert_eq!(store.account(DirectoryKind::Production).expect("production").expect("present"), production);
    assert!(state_dir(&root).join("accounts").join("staging.json").is_file());
    assert!(state_dir(&root).join("accounts").join("production.json").is_file());

    let replaced = account(DirectoryKind::Staging, "https://acme-staging.test/acct/2", "thumb-staging-2");
    store.save_account(&replaced).expect("replace the staging account");
    assert_eq!(store.account(DirectoryKind::Staging).expect("staging").expect("present"), replaced);
    assert_eq!(store.account(DirectoryKind::Production).expect("production").expect("present"), production, "覆盖 staging 不得改动 production");

    cleanup(&root);
}

#[test]
fn an_account_file_recording_another_kind_is_rejected() {
    let root = temp_project("account-kind");
    let store = store_for(&root);
    store.save_account(&account(DirectoryKind::Production, "https://acme.test/acct/9", "thumb-production")).expect("save");
    let file = state_dir(&root).join("accounts").join("staging.json");
    std::fs::write(&file, std::fs::read_to_string(state_dir(&root).join("accounts").join("production.json")).expect("read")).expect("copy");

    let error = store.account(DirectoryKind::Staging).expect_err("a production identity must not be read as staging");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(error.message().contains("不一致"), "错误要说明是类型不一致：{error}");

    cleanup(&root);
}

#[test]
fn orders_round_trip_and_the_latest_open_order_skips_finished_ones() {
    let root = temp_project("orders");
    let store = store_for(&root);
    assert!(store.orders().expect("an empty project lists nothing").is_empty());
    assert!(store.order("order-missing").expect("a missing order is absent").is_none());
    assert!(store.latest_open_order(DirectoryKind::Staging).expect("no open order yet").is_none());

    let planned = order("order-planned", DirectoryKind::Staging, OrderPhase::Planned, 10);
    let authorized = order("order-authorized", DirectoryKind::Staging, OrderPhase::Authorized, 20);
    let issued = order("order-issued", DirectoryKind::Staging, OrderPhase::Issued, 30);
    let failed = order("order-failed", DirectoryKind::Staging, OrderPhase::Failed, 40);
    let production = order("order-production", DirectoryKind::Production, OrderPhase::Planned, 50);
    for item in [&planned, &authorized, &issued, &failed, &production] {
        store.save_order(item).expect("save the order");
    }

    let restored = store.order("order-authorized").expect("read the order").expect("present");
    assert_eq!(restored, authorized, "订单必须原样 round-trip，包含授权句柄与指纹");

    let orders = store.orders().expect("list every order");
    assert_eq!(orders.len(), 5);
    assert!(orders.windows(2).all(|pair| pair[0].updated_unix >= pair[1].updated_unix), "订单必须按 updated_unix 降序：{orders:?}");

    let open = store.latest_open_order(DirectoryKind::Staging).expect("find the open order").expect("present");
    assert_eq!(open.id, "order-authorized", "必须跳过 issued 与 failed");
    let production_open = store.latest_open_order(DirectoryKind::Production).expect("find the production order").expect("present");
    assert_eq!(production_open.id, "order-production");

    cleanup(&root);
}

#[test]
fn a_failed_replacement_keeps_the_previous_record() {
    let root = temp_project("atomic");
    let store = store_for(&root);
    let original = order("order-atomic", DirectoryKind::Staging, OrderPhase::Authorized, 10);
    store.save_order(&original).expect("save the original order");

    // 用目录占住 `<id>.json.tmp`，让临时文件写入失败。
    let blocker = state_dir(&root).join("orders").join("order-atomic.json.tmp");
    std::fs::create_dir(&blocker).expect("block the temporary file");

    let mut updated = original.clone();
    updated.phase = OrderPhase::Submitted;
    updated.updated_unix = 20;
    assert_eq!(store.save_order(&updated).expect_err("the replacement must fail").code(), ErrorCode::Io);
    assert_eq!(store.order("order-atomic").expect("read the order").expect("present"), original, "失败的替换不得改动已有记录");

    std::fs::remove_dir(&blocker).expect("unblock the temporary file");
    cleanup(&root);
}

#[test]
fn every_corrupted_record_fails_distinctly() {
    let root = temp_project("corrupted");
    let store = store_for(&root);
    let id = "order-broken";

    let cases = [
        ("broken json", "{ not json".to_owned()),
        ("unknown phase", order_document(id, "archived", "_acme-challenge.example.test")),
        ("id mismatch", order_document("order-other", "planned", "_acme-challenge.example.test")),
        ("record name mismatch", order_document(id, "planned", "_acme-challenge.other.test")),
    ];

    let mut messages = Vec::new();
    for (label, contents) in cases {
        write_order(&root, id, &contents);
        let error = store.order(id).expect_err("a corrupted record must fail");
        assert_eq!(error.code(), ErrorCode::Protocol, "{label} 必须以 Protocol 失败：{error}");
        assert!(!error.message().contains('{'), "{label} 不得回显文件内容：{error}");
        assert!(store.orders().expect_err("listing must fail as well").code() == ErrorCode::Protocol, "{label} 不得被列表静默跳过");
        messages.push(error.message().to_owned());
    }
    let unique: BTreeSet<&String> = messages.iter().collect();
    assert_eq!(unique.len(), messages.len(), "每种损坏都要给出可区分的错误：{messages:?}");

    cleanup(&root);
}

#[test]
fn saving_a_record_with_a_mismatched_record_name_is_rejected() {
    let root = temp_project("invalid-save");
    let store = store_for(&root);
    let mut broken = order("order-invalid", DirectoryKind::Staging, OrderPhase::Planned, 10);
    broken.authorizations[0].record_fqdn = "_acme-challenge.other.test".to_owned();

    let error = store.save_order(&broken).expect_err("a mismatched record name must not be written");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(!state_dir(&root).join("orders").join("order-invalid.json").exists(), "拒绝的记录不得落盘");

    cleanup(&root);
}

#[test]
fn error_messages_never_echo_the_record_body() {
    let root = temp_project("redaction");
    let store = store_for(&root);
    let marker = "SECRET-MARKER-VALUE";

    write_order(&root, "order-redacted", &order_document("order-redacted", marker, "_acme-challenge.example.test"));
    let error = store.order("order-redacted").expect_err("an unknown phase must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(!error.message().contains(marker), "错误不得回显阶段值：{error}");

    write_order(&root, "order-redacted", &format!(r#"{{"txtDigest":"{marker}""#));
    let error = store.order("order-redacted").expect_err("a truncated document must fail");
    assert_eq!(error.code(), ErrorCode::Protocol);
    assert!(!error.message().contains(marker), "错误不得回显文件内容：{error}");

    cleanup(&root);
}
