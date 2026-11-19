//! 账户密钥与叶子私钥的项目级持久化。
//!
//! 密钥固定放在项目私有状态目录（`<root>/.secrets/open-ssl`）内，与账户/订单状态和
//! 交付代分开：
//!
//! ```text
//! open-ssl/
//!   keys/accounts/<kind>.key.pem   ACME 账户私钥（PKCS#8）
//!   keys/orders/<id>.key.pem       该订单的叶子私钥（PKCS#8）
//! ```
//!
//! 合同：账户密钥在同一个 directory 上必须复用，否则重启会再建一个账户并丢掉续期身份；
//! 叶子私钥必须跨重启保留，否则已提交的 CSR 无法再对应同一份证书。两者都不进入状态 JSON，
//! 也不写进日志或报告。Unix 上目录用 `0700`、文件用 `0600` 创建；Windows 的宿主 ACL 由
//! `.secrets` 目录策略承担，本模块不声称已设置 ACL。
//!
//! 读取时先解码 PEM，再用 `from_pkcs8_der` 重建密钥；文件损坏按
//! [`crate::errors::ErrorCode::Protocol`] 拒绝，不静默重新生成。

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};

use crate::{
    acme::AccountKey,
    dns::credentials::ProjectRoot,
    errors::{Error, ErrorCode, Result},
    state::DirectoryKind,
};

const ACCOUNTS_DIR: &str = "accounts";
const ORDERS_DIR: &str = "orders";
const KEY_SUFFIX: &str = ".key.pem";
const PEM_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER: &str = "-----END PRIVATE KEY-----";

/// 读取或创建该 directory 的 ACME 账户密钥。
pub fn account_key(project: &ProjectRoot, kind: DirectoryKind) -> Result<AccountKey> {
    let file = key_path(project, ACCOUNTS_DIR, kind.as_str());
    Ok(AccountKey::from_signing_key(load_or_create(&file)?))
}

/// 读取或创建该订单的叶子私钥。
pub fn order_key(project: &ProjectRoot, order_id: &str) -> Result<SigningKey> {
    let file = key_path(project, ORDERS_DIR, order_id);
    load_or_create(&file)
}

fn key_path(project: &ProjectRoot, folder: &str, stem: &str) -> PathBuf {
    project.state_dir().join("keys").join(folder).join(format!("{stem}{KEY_SUFFIX}"))
}

fn load_or_create(file: &Path) -> Result<SigningKey> {
    match fs::read_to_string(file) {
        Ok(text) => parse_pem(file, &text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = crate::csr::generate_p256_key();
            write_private(file, &encode_pem(&key)?)?;
            Ok(key)
        }
        Err(error) => Err(Error::new(ErrorCode::Io, format!("私钥文件 `{}` 无法读取：{error}", file.display()))),
    }
}

fn parse_pem(file: &Path, text: &str) -> Result<SigningKey> {
    let body = text
        .trim()
        .strip_prefix(PEM_HEADER)
        .and_then(|rest| rest.strip_suffix(PEM_FOOTER))
        .map(str::trim)
        .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("私钥文件 `{}` 不是 PEM `PRIVATE KEY` 块", file.display())))?;
    let der = STANDARD
        .decode(body.replace(['\r', '\n'], ""))
        .map_err(|_| Error::new(ErrorCode::Protocol, format!("私钥文件 `{}` 的 base64 无效", file.display())))?;
    SigningKey::from_pkcs8_der(&der)
        .map_err(|_| Error::new(ErrorCode::Protocol, format!("私钥文件 `{}` 不是可用的 P-256 PKCS#8 密钥", file.display())))
}

/// 把叶子私钥编码成交付要求的 PKCS#8 PEM。
pub fn private_key_pem(key: &SigningKey) -> Result<String> {
    encode_pem(key)
}

fn encode_pem(key: &SigningKey) -> Result<String> {
    let document = key
        .to_pkcs8_der()
        .map_err(|error| Error::new(ErrorCode::Internal, format!("私钥无法编码为 PKCS#8：{error}")))?;
    Ok(pem_body(document.as_bytes()))
}

/// 把 DER 包装成 PEM；每行 64 列，末尾带换行。
#[must_use]
pub fn pem_body(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut text = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    text.push_str(PEM_HEADER);
    text.push('\n');
    for chunk in encoded.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        text.push('\n');
    }
    text.push_str(PEM_FOOTER);
    text.push('\n');
    text
}

fn write_private(file: &Path, text: &str) -> Result<()> {
    let Some(folder) = file.parent()
    else {
        return Err(Error::new(ErrorCode::Internal, "私钥路径没有父目录"));
    };
    fs::create_dir_all(folder).map_err(|error| Error::new(ErrorCode::Io, format!("无法创建私钥目录 `{}`：{error}", folder.display())))?;
    restrict_folder(folder);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut handle = options
        .open(file)
        .map_err(|error| Error::new(ErrorCode::Io, format!("无法创建私钥文件 `{}`：{error}", file.display())))?;
    handle
        .write_all(text.as_bytes())
        .and_then(|()| handle.sync_all())
        .map_err(|error| Error::new(ErrorCode::Io, format!("无法写入私钥文件 `{}`：{error}", file.display())))
}

fn restrict_folder(folder: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(folder, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = folder;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str) -> (ProjectRoot, PathBuf) {
        let root = std::env::temp_dir().join(format!("open-ssl-keys-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temp project");
        (ProjectRoot::new(&root).expect("project root"), root)
    }

    #[test]
    fn account_key_is_created_once_and_reused() {
        let (project, root) = project("account");
        let first = account_key(&project, DirectoryKind::Staging).expect("first key");
        let second = account_key(&project, DirectoryKind::Staging).expect("second key");
        assert_eq!(first.thumbprint(), second.thumbprint(), "the account key must survive a restart");

        // staging 与 production 是两条独立身份。
        let production = account_key(&project, DirectoryKind::Production).expect("production key");
        assert_ne!(first.thumbprint(), production.thumbprint());
        assert!(root.join(".secrets/open-ssl/keys/accounts/staging.key.pem").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn order_key_round_trips_through_pem() {
        let (project, root) = project("order");
        let first = order_key(&project, "abc").expect("first key");
        let second = order_key(&project, "abc").expect("second key");
        assert_eq!(first.verifying_key(), second.verifying_key());
        let pem = private_key_pem(&first).expect("encode");
        assert!(pem.starts_with(PEM_HEADER) && pem.contains('\n'));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_key_file_is_rejected_instead_of_regenerated() {
        let (project, root) = project("corrupt");
        let file = key_path(&project, ORDERS_DIR, "abc");
        fs::create_dir_all(file.parent().expect("parent")).expect("dirs");
        fs::write(&file, "not a pem").expect("write");
        assert_eq!(order_key(&project, "abc").unwrap_err().code(), ErrorCode::Protocol);
        let _ = fs::remove_dir_all(root);
    }
}
