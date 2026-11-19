//! 证书代交付：以 generation 清单关联证书、链、私钥与元数据，并把切换收敛到一个提交点。
//!
//! 全部路径都落在 [`ProjectRoot::state_dir`]（`<root>/.secrets/open-ssl`）内，与输入凭证
//! `open-ssl.json` 分开：
//!
//! ```text
//! open-ssl/
//!   current                    指针，内容是 `{"id":"<generation id>"}`
//!   current.tmp                指针的临时文件，写完由同目录 `rename` 覆盖 `current`
//!   generations/
//!     <id>/cert.pem            叶子证书
//!     <id>/chain.pem           中间证书
//!     <id>/key.pem             叶子私钥
//!     <id>/generation.json     generation 清单（id、证书指纹、到期与创建时间）
//! ```
//!
//! 提交分两步，任何一步失败都不会改动已有的 `current`：先把 `.staging-*` 目录 `rename` 成
//! `generations/<id>`，再写 `current.tmp` 并 `rename` 覆盖 `current`。两次 `rename` 都在同一个
//! 目录树内完成，因此不会出现逐文件覆盖导致的 cert 与 key 来自不同代的组合；失败时上一可用
//! 代仍然是 `current` 指向的那一代。
//!
//! 私钥只写进本状态目录（Unix 上权限 `0o600`），不进入 public/dist/static。明文导出不是交付
//! 的副作用：本模块不提供导出入口，导出必须是调用方单独的显式动作。
//!
//! # cert/key 匹配
//!
//! staging 会把 PEM `PRIVATE KEY`（PKCS#8）解析成 P-256 私钥，用推导出的 SPKI 与证书公钥
//! 逐字节比对。其它私钥算法（例如 RSA 或 P-384）目前无法从私钥推导公钥，因此以
//! [`ErrorCode::NotImplemented`] 显式拒绝，而不是放行一项没校验过的交付。
//!
//! # 文件权限
//!
//! Unix 上私钥文件与目录写入后显式设成 `0o600`。Windows 没有等价的简单设置：本模块不调用
//! 任何 ACL API，所以不声称已经设置 ACL，`key.pem` 的实际访问控制依赖 `.secrets` 目录的
//! 既定位置与后续宿主 ACL 能力。

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use p256::{
    ecdsa::SigningKey,
    pkcs8::{DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    der::DateTime,
    dns::credentials::ProjectRoot,
    errors::{Error, ErrorCode, Result},
    x509::{Certificate, EcCurve, PublicKey, pem_bundle, pem_decode},
};

/// generation 清单所在的子目录。
const GENERATIONS_DIR: &str = "generations";
/// 指向当前可用代的指针文件。
const CURRENT_FILE: &str = "current";
/// 指针的临时文件，写完后覆盖 [`CURRENT_FILE`]。
const CURRENT_TEMP_FILE: &str = "current.tmp";
/// 叶子证书文件名。
const CERT_FILE: &str = "cert.pem";
/// 中间证书文件名。
const CHAIN_FILE: &str = "chain.pem";
/// 叶子私钥文件名。
const KEY_FILE: &str = "key.pem";
/// generation 清单文件名。
const MANIFEST_FILE: &str = "generation.json";
/// 暂存目录前缀；以 `.` 开头，因此不会被 [`Delivery::generations`] 当成正式代。
const STAGING_PREFIX: &str = ".staging-";
/// generation 清单的 schema。
const GENERATION_SCHEMA: &str = "open-ssl/generation/v0";
/// `id-ecPublicKey`。
const ID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
/// `prime256v1`（P-256）。
const ID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
/// 公开产物（证书、链、清单）的权限。
const PUBLIC_MODE: u32 = 0o644;
/// 私钥的权限。
const PRIVATE_MODE: u32 = 0o600;

/// 同一进程内 staging 目录名的去重计数。
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 一次签发要交付的证书、链与私钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBundle {
    /// 叶子证书，必须是 PEM `CERTIFICATE` 块。
    pub certificate_pem: String,
    /// 中间证书，至少要有一个 PEM `CERTIFICATE` 块。
    pub chain_pem: String,
    /// 叶子私钥，必须是 PEM `PRIVATE KEY`（PKCS#8）块。
    pub private_key_pem: String,
}

/// 一个已提交的证书代。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Generation {
    /// 稳定 id，形如 `{unix_millis}-{证书 SHA-256 前 12 位}`。
    pub id: String,
    /// 证书 DER 的 SHA-256，十六进制小写。
    pub certificate_sha256: String,
    /// 证书 `notAfter` 对应的 Unix 秒。
    pub not_after_unix: u64,
    /// 该代写入暂存目录时的 Unix 秒。
    pub created_unix: u64,
}

/// 已提交一代的落盘位置。路径是受控句柄，不含私钥正文。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerationPaths {
    /// 叶子证书 PEM。
    pub certificate: PathBuf,
    /// 中间证书链 PEM。
    pub chain: PathBuf,
    /// 叶子私钥 PEM 的受控位置。
    pub private_key: PathBuf,
}

/// 已经通过全部校验、但还没有切换成当前代的暂存结果。
///
/// 只能由 [`Delivery::stage`] 产生。没有交给 [`Delivery::commit`] 就离开作用域的暂存目录会被
/// 清理，因此失败的 stage/commit 不会留下可见的半成品。
#[derive(Debug)]
pub struct Staged {
    directory: Option<PathBuf>,
    generation: Generation,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let Some(directory) = self.directory.take()
        else {
            return;
        };
        // 只删本模块自己写入的固定文件，不做递归删除。
        for name in [CERT_FILE, CHAIN_FILE, KEY_FILE, MANIFEST_FILE] {
            let _ = fs::remove_file(directory.join(name));
        }
        let _ = fs::remove_dir(&directory);
    }
}

/// 绑定一个项目状态目录的交付入口。
#[derive(Debug, Clone)]
pub struct Delivery {
    state_dir: PathBuf,
}

impl Delivery {
    /// 把交付入口绑定到该项目的私有状态目录。
    ///
    /// 这里只计算路径，不创建目录，也不读取任何凭证文件。
    #[must_use]
    pub fn new(project: &ProjectRoot) -> Self {
        Self { state_dir: project.state_dir() }
    }

    /// 校验一次交付并写入 `generations/.staging-*`。
    ///
    /// 校验在写文件之前完成：证书可解析、SAN 非空、链里至少有一个 `CERTIFICATE` 块、私钥是
    /// 非空 PKCS#8 `PRIVATE KEY`，且证书公钥与私钥 SPKI 一致。任何一项失败都不会留下可见的
    /// 半成品，暂存目录会被删除。
    pub fn stage(&self, bundle: &CertificateBundle) -> Result<Staged> {
        let generation = validate(bundle)?;
        let generations = self.generations_dir();
        fs::create_dir_all(&generations).map_err(|error| io_error(&generations, "创建 generation 目录", error))?;

        let directory = generations.join(staging_name());
        fs::create_dir(&directory).map_err(|error| io_error(&directory, "创建暂存目录", error))?;
        let staged = Staged { directory: Some(directory.clone()), generation };

        write_new_file(&directory.join(CERT_FILE), &bundle.certificate_pem, PUBLIC_MODE)?;
        write_new_file(&directory.join(CHAIN_FILE), &bundle.chain_pem, PUBLIC_MODE)?;
        write_new_file(&directory.join(KEY_FILE), &bundle.private_key_pem, PRIVATE_MODE)?;
        let manifest = Manifest { schema: GENERATION_SCHEMA.to_owned(), generation: staged.generation.clone() };
        let document =
            serde_json::to_string(&manifest).map_err(|error| Error::new(ErrorCode::Internal, format!("generation 清单无法序列化：{error}")))?;
        write_new_file(&directory.join(MANIFEST_FILE), &document, PUBLIC_MODE)?;
        Ok(staged)
    }

    /// 把暂存结果切换成当前代。
    ///
    /// 先把暂存目录 `rename` 成 `generations/<id>`，再写 `current.tmp` 并 `rename` 覆盖
    /// `current`。第二步失败时会撤销刚放好的那一代，`current` 仍指向上一可用代。
    pub fn commit(&self, mut staged: Staged) -> Result<Generation> {
        let target = self.generations_dir().join(&staged.generation.id);
        if target.exists() {
            return Err(Error::new(ErrorCode::Internal, format!("generation `{}` 已经存在", staged.generation.id)));
        }
        let Some(directory) = staged.directory.as_ref()
        else {
            return Err(Error::new(ErrorCode::Internal, "暂存结果已经提交过"));
        };
        fs::rename(directory, &target).map_err(|error| io_error(&target, "提交 generation 目录", error))?;
        staged.directory = None;
        if let Err(error) = self.switch_current(&staged.generation.id) {
            remove_generation(&target);
            return Err(error);
        }
        Ok(staged.generation.clone())
    }

    /// 当前代。
    ///
    /// 指针缺失返回 `Ok(None)`；指针不是合法 JSON、id 非法、指向不存在的代目录、清单与指针
    /// 不一致、或者 `cert.pem` 不可读都会报错，不会静默当成空。
    pub fn current(&self) -> Result<Option<Generation>> {
        let pointer_file = self.state_dir.join(CURRENT_FILE);
        let text = match fs::read_to_string(&pointer_file) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&pointer_file, "读取 current 指针", error)),
        };
        let pointer: Pointer = serde_json::from_str(&text)
            .map_err(|_| Error::new(ErrorCode::Protocol, format!("current 指针 `{}` 不是合法 JSON", pointer_file.display())))?;
        if !valid_id(&pointer.id) {
            return Err(Error::new(ErrorCode::Protocol, format!("current 指针 `{}` 里的 generation id 非法", pointer_file.display())));
        }
        let directory = self.generations_dir().join(&pointer.id);
        if !directory.is_dir() {
            return Err(Error::new(ErrorCode::Protocol, format!("current 指针指向的 generation `{}` 不存在", pointer.id)));
        }
        let generation = read_manifest(&directory)?;
        if generation.id != pointer.id {
            return Err(Error::new(ErrorCode::Protocol, format!("generation `{}` 的清单 id 与 current 指针不一致", pointer.id)));
        }
        let certificate = directory.join(CERT_FILE);
        fs::read(&certificate).map_err(|error| io_error(&certificate, "读取当前代证书", error))?;
        Ok(Some(generation))
    }

    /// 把 `current` 切回上一代（按 `created_unix` 降序的第二项）。
    ///
    /// 没有当前代或没有更早的一代时返回 [`ErrorCode::InvalidArgument`]。
    pub fn rollback(&self) -> Result<Generation> {
        let generations = self.generations()?;
        let current = self.current()?.ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "当前没有已提交的 generation，无法回退"))?;
        let position = generations
            .iter()
            .position(|generation| generation.id == current.id)
            .ok_or_else(|| Error::new(ErrorCode::Protocol, format!("当前 generation `{}` 不在 generations 清单里", current.id)))?;
        let previous = generations.get(position + 1).ok_or_else(|| Error::new(ErrorCode::InvalidArgument, "没有上一代可以回退"))?;
        self.switch_current(&previous.id)?;
        Ok(previous.clone())
    }

    /// 所有已提交的代，按 `created_unix` 降序。
    ///
    /// 以 `.` 开头的条目（含 `.staging-*` 与其它隐藏文件）直接跳过，因此进程崩溃留下的暂存目录
    /// 不会污染清单。其余条目必须是带合法清单的 generation 目录，否则按 [`ErrorCode::Protocol`]
    /// 报错而不是悄悄忽略。
    pub fn generations(&self) -> Result<Vec<Generation>> {
        let directory = self.generations_dir();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io_error(&directory, "读取 generation 目录", error)),
        };
        let mut generations = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io_error(&directory, "读取 generation 条目", error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if !valid_id(&name) {
                return Err(Error::new(ErrorCode::Protocol, format!("generation 目录 `{}` 的名字不是合法 id", entry.path().display())));
            }
            if !entry.path().is_dir() {
                return Err(Error::new(ErrorCode::Protocol, format!("generation 条目 `{}` 不是目录", entry.path().display())));
            }
            let generation = read_manifest(&entry.path())?;
            if generation.id != name {
                return Err(Error::new(ErrorCode::Protocol, format!("generation 目录 `{}` 与清单 id 不一致", entry.path().display())));
            }
            generations.push(generation);
        }
        generations.sort_by(|left, right| right.created_unix.cmp(&left.created_unix).then_with(|| right.id.cmp(&left.id)));
        Ok(generations)
    }

    fn generations_dir(&self) -> PathBuf {
        self.state_dir.join(GENERATIONS_DIR)
    }

    /// 已提交 generation 的落盘位置：公开证书、链与受控私钥文件。
    pub fn paths(&self, id: &str) -> GenerationPaths {
        let directory = self.generations_dir().join(id);
        GenerationPaths {
            certificate: directory.join(CERT_FILE),
            chain: directory.join(CHAIN_FILE),
            private_key: directory.join(KEY_FILE),
        }
    }

    /// 写指针临时文件，再用同目录 `rename` 覆盖 `current`。
    fn switch_current(&self, id: &str) -> Result<()> {
        let temporary = self.state_dir.join(CURRENT_TEMP_FILE);
        let document = serde_json::to_string(&Pointer { id: id.to_owned() })
            .map_err(|error| Error::new(ErrorCode::Internal, format!("current 指针无法序列化：{error}")))?;
        let mut file = File::create(&temporary).map_err(|error| io_error(&temporary, "写入 current 指针", error))?;
        file.write_all(document.as_bytes()).map_err(|error| io_error(&temporary, "写入 current 指针", error))?;
        file.sync_all().map_err(|error| io_error(&temporary, "落盘 current 指针", error))?;
        drop(file);
        fs::rename(&temporary, self.state_dir.join(CURRENT_FILE)).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            io_error(&self.state_dir.join(CURRENT_FILE), "切换 current 指针", error)
        })
    }
}

/// 指针文件的内容。
#[derive(Debug, Serialize, Deserialize)]
struct Pointer {
    id: String,
}

/// generation 清单的文件内容。
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema: String,
    #[serde(flatten)]
    generation: Generation,
}

fn read_manifest(directory: &Path) -> Result<Generation> {
    let file = directory.join(MANIFEST_FILE);
    let text = fs::read_to_string(&file).map_err(|error| io_error(&file, "读取 generation 清单", error))?;
    let manifest: Manifest = serde_json::from_str(&text)
        .map_err(|_| Error::new(ErrorCode::Protocol, format!("generation 清单 `{}` 不是合法 JSON", file.display())))?;
    if manifest.schema != GENERATION_SCHEMA {
        return Err(Error::new(ErrorCode::Protocol, format!("generation 清单 `{}` 没有声明 `{GENERATION_SCHEMA}` schema", file.display())));
    }
    Ok(manifest.generation)
}

/// 全部校验都在写文件之前完成。
fn validate(bundle: &CertificateBundle) -> Result<Generation> {
    let certificate_der = pem_decode("CERTIFICATE", &bundle.certificate_pem)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "证书不是可解码的 PEM `CERTIFICATE` 块"))?;
    let certificate = Certificate::parse(&certificate_der).map_err(|_| Error::new(ErrorCode::InvalidArgument, "证书 DER 无法解析"))?;
    if certificate.extensions.dns_names.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "证书的 subjectAltName 没有任何 DNS 名称"));
    }
    if pem_bundle("CERTIFICATE", &bundle.chain_pem).is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "证书链没有任何 `CERTIFICATE` 块"));
    }

    let private_key_der = pem_decode("PRIVATE KEY", &bundle.private_key_pem)
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "私钥不是 PEM `PRIVATE KEY`（PKCS#8）块"))?;
    if private_key_der.is_empty() {
        return Err(Error::new(ErrorCode::InvalidArgument, "私钥内容为空"));
    }
    let private_key = PrivateKeyInfo::try_from(private_key_der.as_slice())
        .map_err(|_| Error::new(ErrorCode::InvalidArgument, "私钥不是合法的 PKCS#8 `PrivateKeyInfo`"))?;
    if private_key.algorithm.oid != ObjectIdentifier::new_unwrap(ID_EC_PUBLIC_KEY) {
        return Err(Error::new(ErrorCode::NotImplemented, "私钥不是 EC 私钥，cert/key 匹配尚未覆盖该算法，因此拒绝交付"));
    }
    let curve = private_key.algorithm.parameters.and_then(|parameters| ObjectIdentifier::from_bytes(parameters.value()).ok());
    if curve != Some(ObjectIdentifier::new_unwrap(ID_PRIME256V1)) {
        return Err(Error::new(ErrorCode::NotImplemented, "私钥曲线不是 P-256，cert/key 匹配尚未覆盖该曲线，因此拒绝交付"));
    }
    let signing =
        SigningKey::from_pkcs8_der(&private_key_der).map_err(|_| Error::new(ErrorCode::InvalidArgument, "私钥不是可用的 P-256 PKCS#8 密钥"))?;
    let point = signing.verifying_key().to_encoded_point(false);
    let derived = PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() };
    if certificate.public_key.to_der() != derived.to_der() {
        return Err(Error::new(ErrorCode::InvalidArgument, "证书公钥与私钥不匹配"));
    }

    let certificate_sha256 = hex_sha256(&certificate_der);
    let id = format!("{}-{}", now_millis(), &certificate_sha256[..12]);
    Ok(Generation { id, certificate_sha256, not_after_unix: epoch_seconds(certificate.not_after), created_unix: now_unix() })
}

fn write_new_file(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(|error| io_error(path, "写入文件", error))?;
    file.write_all(contents.as_bytes()).map_err(|error| io_error(path, "写入文件", error))?;
    // 先落盘再 rename / 交付，避免崩溃后读到半截文件。
    file.sync_all().map_err(|error| io_error(path, "落盘文件", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| io_error(path, "设置文件权限", error))?;
    }
    Ok(())
}

/// 只删本模块写入的固定文件与目录，不做递归删除。
fn remove_generation(directory: &Path) {
    for name in [CERT_FILE, CHAIN_FILE, KEY_FILE, MANIFEST_FILE] {
        let _ = fs::remove_file(directory.join(name));
    }
    let _ = fs::remove_dir(directory);
}

fn io_error(path: &Path, action: &str, error: io::Error) -> Error {
    Error::new(ErrorCode::Io, format!("{action} `{}` 失败：{error}", path.display()))
}

fn staging_name() -> String {
    let sequence = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{STAGING_PREFIX}{}-{}-{sequence}", now_millis(), std::process::id())
}

/// generation id 只允许 ASCII 字母、数字、`-` 与 `_`，避免把指针内容当成任意路径。
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 96 && id.chars().all(|character| character.is_ascii_alphanumeric() || character == '-' || character == '_')
}

fn hex_sha256(der: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(der) {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs())
}

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) fn epoch_seconds(time: DateTime) -> u64 {
    let days = days_from_civil(i64::from(time.year), i64::from(time.month), i64::from(time.day));
    let seconds = days * 86_400 + i64::from(time.hour) * 3_600 + i64::from(time.minute) * 60 + i64::from(time.second);
    u64::try_from(seconds).unwrap_or(0)
}

/// 按 Howard Hinnant 算法计算公历日期距 1970-01-01 的天数。
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (month + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}
