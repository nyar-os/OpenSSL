//! 项目秘密文件符合性：只认 `<projectRoot>/.secrets/open-ssl.json`。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    dns::credentials::{ProjectRoot, ProjectSecrets},
};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("open-ssl-secrets-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn write_secrets(root: &Path, contents: &str) -> PathBuf {
    let directory = root.join(".secrets");
    std::fs::create_dir_all(&directory).expect("secrets directory");
    let file = directory.join("open-ssl.json");
    std::fs::write(&file, contents).expect("secrets file");
    file
}

fn cleanup(root: &Path) {
    std::fs::remove_dir_all(root).expect("temp cleanup");
}

fn error_of(root: &Path) -> (ErrorCode, String) {
    let error = ProjectSecrets::load(&ProjectRoot::new(root).expect("project root")).expect_err("the document must be rejected");
    (error.code(), error.message().to_owned())
}

#[test]
fn two_projects_never_share_tokens() {
    let first = temp_project("first");
    let second = temp_project("second");
    write_secrets(&first, r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"token-first"}}}"#);
    write_secrets(&second, r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"token-second"}}}"#);

    let first_secrets = ProjectSecrets::load(&ProjectRoot::new(&first).expect("root")).expect("first project");
    let second_secrets = ProjectSecrets::load(&ProjectRoot::new(&second).expect("root")).expect("second project");
    assert_eq!(first_secrets.dns_token("cloudflare").expect("token").expose(), "token-first");
    assert_eq!(second_secrets.dns_token("cloudflare").expect("token").expose(), "token-second");

    let debug = format!("{first_secrets:?}");
    assert!(!debug.contains("token-first"), "token 不得进入调试输出：{debug}");
    assert!(debug.contains("cloudflare"), "调试输出只报告 provider id：{debug}");

    cleanup(&first);
    cleanup(&second);
}

#[test]
fn a_missing_file_fails_without_any_fallback() {
    let root = temp_project("missing");
    let error = ProjectSecrets::load(&ProjectRoot::new(&root).expect("root")).expect_err("a project without secrets must fail");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("does not exist") || error.message().contains("不存在"), "缺文件要说明原因：{error}");
    assert!(!error.message().contains("apiToken"), "错误不得回显 schema：{error}");
    assert!(!error.message().contains("token"), "错误不得回显 token：{error}");
    cleanup(&root);
}

#[test]
fn each_malformed_document_fails_distinctly() {
    let root = temp_project("malformed");
    let cases = [
        ("not json", "{ not json"),
        ("wrong schema", r#"{"schema":"open-ssl/secrets/v1","dns":{"cloudflare":{"apiToken":"token-value"}}}"#),
        ("missing schema", r#"{"dns":{}}"#),
        ("empty token", r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"   "}}}"#),
        ("non-string token", r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":42}}}"#),
        ("missing token", r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{}}}"#),
        ("provider not an object", r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":"token-value"}}"#),
        ("dns not an object", r#"{"schema":"open-ssl/secrets/v0","dns":["token-value"]}"#),
    ];

    let mut messages = Vec::new();
    for (label, contents) in cases {
        write_secrets(&root, contents);
        let (code, message) = error_of(&root);
        assert_eq!(code, ErrorCode::Protocol, "{label} 必须以 Protocol 失败：{message}");
        assert!(!message.contains("token-value"), "{label} 不得回显文件内容：{message}");
        assert!(!message.contains("42"), "{label} 不得回显文件内容：{message}");
        messages.push(message);
    }
    let unique: std::collections::BTreeSet<&String> = messages.iter().collect();
    assert_eq!(unique.len(), messages.len(), "每种坏文档都要给出可区分的错误：{messages:?}");
    cleanup(&root);
}

#[test]
fn unknown_keys_and_valid_documents_load() {
    let root = temp_project("valid");
    write_secrets(
        &root,
        r#"{"schema":"open-ssl/secrets/v0","future":{"note":"ignored"},"dns":{"cloudflare":{"apiToken":"token-value","accountId":"ignored"}}}"#,
    );
    let secrets = ProjectSecrets::load(&ProjectRoot::new(&root).expect("root")).expect("forward-compatible document");
    assert_eq!(secrets.dns_token("cloudflare").expect("token").expose(), "token-value");
    assert_eq!(secrets.dns_token("route53").expect_err("unconfigured provider").code(), ErrorCode::InvalidArgument);
    cleanup(&root);
}

#[test]
fn the_dns_section_may_be_absent() {
    let root = temp_project("no-dns");
    write_secrets(&root, r#"{"schema":"open-ssl/secrets/v0"}"#);
    let secrets = ProjectSecrets::load(&ProjectRoot::new(&root).expect("root")).expect("a document without dns");
    assert_eq!(secrets.dns_token("cloudflare").expect_err("no token").code(), ErrorCode::InvalidArgument);
    cleanup(&root);
}

#[test]
fn project_root_requires_an_existing_directory() {
    let root = temp_project("root-checks");
    let missing = root.join("does-not-exist");
    assert_eq!(ProjectRoot::new(&missing).expect_err("missing root").code(), ErrorCode::Io);

    let file = root.join("file.txt");
    std::fs::write(&file, "not a directory").expect("temp file");
    assert_eq!(ProjectRoot::new(&file).expect_err("file root").code(), ErrorCode::InvalidArgument);
    cleanup(&root);
}

#[test]
fn a_subdirectory_is_its_own_project() {
    let parent = temp_project("parent");
    write_secrets(&parent, r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"token-parent"}}}"#);

    let nested = parent.join("nested");
    std::fs::create_dir_all(&nested).expect("nested directory");
    write_secrets(&nested, r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"token-nested"}}}"#);

    let nested_secrets = ProjectSecrets::load(&ProjectRoot::new(&nested).expect("nested root")).expect("nested project");
    assert_eq!(nested_secrets.dns_token("cloudflare").expect("token").expose(), "token-nested");

    let sibling = parent.join("sibling");
    std::fs::create_dir_all(&sibling).expect("sibling directory");
    assert_eq!(
        ProjectSecrets::load(&ProjectRoot::new(&sibling).expect("sibling root")).expect_err("no upward walk").code(),
        ErrorCode::InvalidArgument
    );
    cleanup(&parent);
}

#[test]
fn secrets_and_state_paths_are_project_local() {
    let root = temp_project("paths");
    let project = ProjectRoot::new(&root).expect("root");
    assert_eq!(project.secrets_file(), project.as_path().join(".secrets").join("open-ssl.json"));
    assert_eq!(project.state_dir(), project.as_path().join(".secrets").join("open-ssl"));
    cleanup(&root);
}

#[test]
fn from_current_dir_uses_the_process_directory() {
    let cwd = std::env::current_dir().expect("cwd");
    let root = ProjectRoot::from_current_dir().expect("current directory");
    let again = ProjectRoot::new(&cwd).expect("explicit cwd root");
    assert_eq!(root.as_path(), again.as_path());
    assert!(root.as_path().is_dir());
    // 报告路径必须是可读的正常形式：测试 cwd 短且本地，不得带 `\\?\` 扩展前缀。
    assert!(!root.as_path().to_string_lossy().starts_with(r"\\?\"), "展示路径带扩展前缀：{}", root.as_path().display());
}

#[test]
fn a_secrets_link_out_of_the_project_is_rejected() {
    let project = temp_project("link");
    let outside = temp_project("outside");
    write_secrets(&outside, r#"{"schema":"open-ssl/secrets/v0","dns":{"cloudflare":{"apiToken":"token-outside"}}}"#);

    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_dir(outside.join(".secrets"), project.join(".secrets"));
    #[cfg(not(windows))]
    let created = std::os::unix::fs::symlink(outside.join(".secrets"), project.join(".secrets"));

    if let Err(error) = created {
        // 本机可能没有创建目录链接的权限（Windows 需要开发者模式或管理员）。
        eprintln!("跳过越界链接用例：当前主机无法创建目录链接（{error}）");
        cleanup(&project);
        cleanup(&outside);
        return;
    }

    let error = ProjectSecrets::load(&ProjectRoot::new(&project).expect("root")).expect_err("a link out of the project must fail");
    assert_eq!(error.code(), ErrorCode::Denied);
    assert!(!error.message().contains("token-outside"), "错误不得回显 token：{error}");

    cleanup(&project);
    cleanup(&outside);
}
