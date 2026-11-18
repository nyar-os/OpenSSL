//! 项目级签发锁的独占、释放与残留观察。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    dns::credentials::ProjectRoot,
    lock::{ProjectLock, holder},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-lock-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn root_of(path: &Path) -> ProjectRoot {
    ProjectRoot::new(path).expect("project root")
}

fn cleanup(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
}

fn lock_path(path: &Path) -> PathBuf {
    path.join(".secrets").join("open-ssl").join("issue.lock")
}

#[test]
fn second_acquire_is_denied_and_names_the_holder() {
    let directory = temp_project("exclusive");
    let project = root_of(&directory);

    let lock = ProjectLock::acquire(&project).expect("first acquisition");
    let error = ProjectLock::acquire(&project).expect_err("second acquisition must be denied");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(error.message().contains(&std::process::id().to_string()), "拒绝信息应指出持有者 pid: {}", error.message());

    lock.release().expect("release");
    ProjectLock::acquire(&project).expect("reacquire after release");
    cleanup(&directory);
}

#[test]
fn release_removes_the_file_and_drop_is_idempotent() {
    let directory = temp_project("release");
    let project = root_of(&directory);

    let lock = ProjectLock::acquire(&project).expect("acquire");
    let path = lock.path().to_path_buf();
    assert!(path.exists());
    lock.release().expect("release");
    assert!(!path.exists(), "显式释放后锁文件必须消失");

    let lock = ProjectLock::acquire(&project).expect("acquire again");
    drop(lock);
    assert!(!path.exists(), "离开作用域也应释放");

    cleanup(&directory);
}

#[test]
fn holder_reports_pid_and_timestamp() {
    let directory = temp_project("holder");
    let project = root_of(&directory);

    assert!(holder(&project).expect("no lock").is_none());

    let lock = ProjectLock::acquire(&project).expect("acquire");
    let observed = holder(&project).expect("read holder").expect("holder present");
    assert_eq!(observed.pid, std::process::id());
    assert!(observed.acquired_unix > 0);

    lock.release().expect("release");
    assert!(holder(&project).expect("after release").is_none());

    cleanup(&directory);
}

#[test]
fn a_stale_lock_stays_visible_and_is_not_silently_removed() {
    let directory = temp_project("stale");
    let project = root_of(&directory);

    let path = lock_path(&directory);
    std::fs::create_dir_all(path.parent().expect("lock parent")).expect("create state dir");
    std::fs::write(&path, "pid=999999\nacquired_unix=1\n").expect("write stale lock");

    let observed = holder(&project).expect("read stale holder").expect("stale holder visible");
    assert_eq!(observed.pid, 999_999);
    assert!(path.exists(), "残留锁不能被自动删除，必须由上层决定");

    let error = ProjectLock::acquire(&project).expect_err("stale lock still blocks");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(error.message().contains("999999"));

    std::fs::remove_file(&path).expect("manual cleanup");
    ProjectLock::acquire(&project).expect("acquire after cleanup");
    cleanup(&directory);
}

#[test]
fn an_unparsable_lock_file_blocks_without_guessing_a_holder() {
    let directory = temp_project("corrupt");
    let project = root_of(&directory);

    let path = lock_path(&directory);
    std::fs::create_dir_all(path.parent().expect("lock parent")).expect("create state dir");
    std::fs::write(&path, "not a lock").expect("write corrupt lock");

    assert!(holder(&project).expect("corrupt lock").is_none(), "无法解析时不得猜出持有者");

    let error = ProjectLock::acquire(&project).expect_err("corrupt lock still blocks");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(error.message().contains("无法解析"));

    cleanup(&directory);
}
