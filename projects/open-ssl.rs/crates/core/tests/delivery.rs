//! 证书代交付符合性：generation 清单、单一提交点切换与回滚。
//!
//! 所有 PEM 都在临时目录里现场构造，不读取仓库或主机上的任何真实证书与私钥。

use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

use open_ssl_core::{
    ErrorCode,
    delivery::{CertificateBundle, Delivery},
    der::{DateTime, Oid, Tag, Writer, oids},
    dns::credentials::ProjectRoot,
    x509::{EcCurve, PublicKey, SignatureAlgorithm, pem_encode},
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use signature::Signer;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_project(label: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("open-ssl-delivery-{label}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&root).expect("temp project root");
    root
}

fn cleanup(root: &Path) {
    std::fs::remove_dir_all(root).expect("temp cleanup");
}

fn state_dir(root: &Path) -> PathBuf {
    root.join(".secrets").join("open-ssl")
}

fn staging_directories(root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(state_dir(root).join("generations"))
    else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(".staging-")))
        .collect()
}

fn delivery_for(root: &Path) -> Delivery {
    Delivery::new(&ProjectRoot::new(root).expect("project root"))
}

fn name_der(common_name: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|sequence| {
        sequence.set(|set| {
            set.sequence(|attribute| {
                attribute.write_oid(&oids::common_name());
                attribute.write_utf8(common_name);
            });
        });
    });
    writer.finish()
}

fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() }.to_der()
}

fn san_der(names: &[&str]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|sequence| {
        for name in names {
            sequence.context_primitive(2, name.as_bytes());
        }
    });
    writer.finish()
}

fn extensions_der(items: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|list| {
        for item in items {
            list.write_raw(item);
        }
    });
    writer.finish()
}

fn extension(oid: Oid, value: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|item| {
        item.write_oid(&oid);
        item.write_octetstring(value);
    });
    writer.finish()
}

fn key_usage_der(mask: u16) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_bitstring(&[(mask >> 8) as u8, mask as u8], 0);
    writer.finish()
}

fn issue_cert(serial: u64, common_name: &str, subject_key: &VerifyingKey, issuer_key: &SigningKey, names: &[&str]) -> Vec<u8> {
    let extensions = if names.is_empty() {
        None
    }
    else {
        Some(extensions_der(&[extension(oids::subject_alt_name(), &san_der(names)), extension(oids::key_usage(), &key_usage_der(0xA000))]))
    };
    let mut writer = Writer::new();
    writer.sequence(|tbs| {
        tbs.context(0, |version| version.write_u64(2));
        tbs.write_u64(serial);
        tbs.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        tbs.write_raw(&name_der("Delivery Test CA"));
        tbs.sequence(|validity| {
            validity.write_tlv(Tag::UTCTIME, b"230101000000Z");
            validity.write_tlv(Tag::UTCTIME, b"331231235959Z");
        });
        tbs.write_raw(&name_der(common_name));
        tbs.write_raw(&spki_der(subject_key));
        if let Some(extensions) = extensions {
            tbs.context(3, |wrapper| wrapper.write_raw(&extensions));
        }
    });
    let tbs = writer.finish();
    let signature: p256::ecdsa::Signature = issuer_key.sign(&tbs);
    let mut writer = Writer::new();
    writer.sequence(|certificate| {
        certificate.write_raw(&tbs);
        certificate.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        certificate.write_bitstring(signature.to_der().as_bytes(), 0);
    });
    writer.finish()
}

fn sec1_der(secret: &[u8], point: &[u8], curve: Oid) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|key| {
        key.write_u64(1);
        key.write_tlv(Tag::OCTET_STRING, secret);
        key.context(0, |parameters| parameters.write_oid(&curve));
        key.context(1, |public| public.write_bitstring(point, 0));
    });
    writer.finish()
}

fn pkcs8_der(secret: &[u8], point: &[u8], curve: Oid) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|key| {
        key.write_u64(0);
        key.sequence(|algorithm| {
            algorithm.write_oid(&oids::ec_public_key());
            algorithm.write_oid(&curve);
        });
        key.write_tlv(Tag::OCTET_STRING, &sec1_der(secret, point, curve));
    });
    writer.finish()
}

fn private_key_pem(signing: &SigningKey) -> String {
    let point = signing.verifying_key().to_encoded_point(false);
    let secret = signing.to_bytes();
    pem_encode("PRIVATE KEY", &pkcs8_der(&secret[..], point.as_bytes(), oids::prime256v1()))
}

fn certificate_for(signing: &SigningKey, names: &[&str]) -> Vec<u8> {
    let issuer = SigningKey::from_slice(&[31u8; 32]).expect("issuer key");
    issue_cert(7, names[0], signing.verifying_key(), &issuer, names)
}

fn bundle(signing: &SigningKey, names: &[&str]) -> CertificateBundle {
    let issuer = SigningKey::from_slice(&[31u8; 32]).expect("issuer key");
    let chain = issue_cert(1, "Delivery Test CA", issuer.verifying_key(), &issuer, &[]);
    CertificateBundle {
        certificate_pem: pem_encode("CERTIFICATE", &certificate_for(signing, names)),
        chain_pem: pem_encode("CERTIFICATE", &chain),
        private_key_pem: private_key_pem(signing),
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).expect("test key")
}

#[test]
fn committing_publishes_the_current_generation_and_lists_every_generation() {
    let root = temp_project("commit");
    let delivery = delivery_for(&root);
    assert!(delivery.current().expect("an empty project has no current generation").is_none());
    assert!(delivery.generations().expect("an empty project lists nothing").is_empty());

    let first = delivery.commit(delivery.stage(&bundle(&key(41), &["first.delivery.test"])).expect("stage first")).expect("commit first");
    assert_eq!(delivery.current().expect("current").expect("committed").id, first.id);
    assert_eq!(first.certificate_sha256.len(), 64);
    assert_eq!(DateTime::from_epoch(first.not_after_unix), DateTime { year: 2033, month: 12, day: 31, hour: 23, minute: 59, second: 59 });

    let second = delivery.commit(delivery.stage(&bundle(&key(42), &["second.delivery.test"])).expect("stage second")).expect("commit second");
    assert_ne!(first.id, second.id, "每个证书必须得到自己的 id");
    assert_eq!(delivery.current().expect("current").expect("committed").id, second.id);

    let generations = delivery.generations().expect("list generations");
    assert_eq!(generations.len(), 2);
    assert!(
        generations.windows(2).all(|pair| pair[0].created_unix >= pair[1].created_unix),
        "generations 必须按 created_unix 降序：{generations:?}"
    );
    let ids: Vec<&str> = generations.iter().map(|generation| generation.id.as_str()).collect();
    assert!(ids.contains(&first.id.as_str()) && ids.contains(&second.id.as_str()));
    assert!(staging_directories(&root).is_empty(), "提交后不得残留暂存目录");

    cleanup(&root);
}

#[test]
fn an_unparseable_certificate_fails_without_a_staging_directory() {
    let root = temp_project("bad-certificate");
    let delivery = delivery_for(&root);
    let valid = bundle(&key(43), &["broken.delivery.test"]);

    let mut not_pem = valid.clone();
    not_pem.certificate_pem = "not a pem".to_owned();
    assert_eq!(delivery.stage(&not_pem).expect_err("garbage certificate").code(), ErrorCode::InvalidArgument);

    let mut not_der = valid.clone();
    not_der.certificate_pem = pem_encode("CERTIFICATE", &[0x30, 0x03, 0x02, 0x01, 0x00]);
    assert_eq!(delivery.stage(&not_der).expect_err("unparseable certificate DER").code(), ErrorCode::InvalidArgument);

    assert!(staging_directories(&root).is_empty(), "失败的 stage 不得留下 `.staging-*`：{:?}", staging_directories(&root));
    assert!(delivery.current().expect("current").is_none());

    cleanup(&root);
}

#[test]
fn an_empty_chain_is_rejected() {
    let root = temp_project("empty-chain");
    let delivery = delivery_for(&root);
    let mut broken = bundle(&key(44), &["chain.delivery.test"]);
    broken.chain_pem.clear();
    assert_eq!(delivery.stage(&broken).expect_err("an empty chain must fail").code(), ErrorCode::InvalidArgument);
    assert!(staging_directories(&root).is_empty());
    cleanup(&root);
}

#[test]
fn a_private_key_that_is_not_pkcs8_p256_is_rejected() {
    let root = temp_project("bad-key");
    let delivery = delivery_for(&root);
    let signing = key(45);
    let point = signing.verifying_key().to_encoded_point(false);

    let mut sec1 = bundle(&signing, &["key.delivery.test"]);
    let secret = signing.to_bytes();
    sec1.private_key_pem = pem_encode("EC PRIVATE KEY", &sec1_der(&secret[..], point.as_bytes(), oids::prime256v1()));
    assert_eq!(delivery.stage(&sec1).expect_err("SEC1 is not PKCS#8").code(), ErrorCode::InvalidArgument);

    let mut garbage = bundle(&signing, &["key.delivery.test"]);
    garbage.private_key_pem = pem_encode("PRIVATE KEY", &[0x30, 0x00]);
    assert_eq!(delivery.stage(&garbage).expect_err("garbage PKCS#8").code(), ErrorCode::InvalidArgument);

    // P-384 私钥形状合法，但当前无法从它推导公钥，因此必须显式报未实现而不是放行。
    let wide = p384::ecdsa::SigningKey::from_slice(&[46u8; 48]).expect("p384 key");
    let wide_point = wide.verifying_key().to_encoded_point(false);
    let wide_secret = wide.to_bytes();
    let mut wrong_curve = bundle(&signing, &["key.delivery.test"]);
    wrong_curve.private_key_pem = pem_encode("PRIVATE KEY", &pkcs8_der(&wide_secret[..], wide_point.as_bytes(), oids::secp384r1()));
    assert_eq!(delivery.stage(&wrong_curve).expect_err("an uncovered key algorithm must fail").code(), ErrorCode::NotImplemented);

    assert!(staging_directories(&root).is_empty());
    cleanup(&root);
}

#[test]
fn a_broken_or_dangling_pointer_reports_an_error() {
    let root = temp_project("pointer");
    let delivery = delivery_for(&root);
    delivery.commit(delivery.stage(&bundle(&key(47), &["pointer.delivery.test"])).expect("stage")).expect("commit");
    let pointer = state_dir(&root).join("current");

    std::fs::write(&pointer, "{ not json").expect("break the pointer");
    assert_eq!(delivery.current().expect_err("a broken pointer must fail").code(), ErrorCode::Protocol);

    std::fs::write(&pointer, r#"{"id":"does-not-exist"}"#).expect("dangling pointer");
    assert_eq!(delivery.current().expect_err("a dangling pointer must fail").code(), ErrorCode::Protocol);

    cleanup(&root);
}

#[test]
fn rollback_returns_to_the_previous_generation() {
    let root = temp_project("rollback");
    let delivery = delivery_for(&root);
    let first = delivery.commit(delivery.stage(&bundle(&key(48), &["first.rollback.test"])).expect("stage first")).expect("commit first");
    let second = delivery.commit(delivery.stage(&bundle(&key(49), &["second.rollback.test"])).expect("stage second")).expect("commit second");
    assert_eq!(delivery.current().expect("current").expect("committed").id, second.id);

    let previous = delivery.rollback().expect("rollback");
    assert_eq!(previous.id, first.id);
    assert_eq!(delivery.current().expect("current").expect("committed").id, first.id);
    assert_eq!(delivery.generations().expect("list").len(), 2, "回退只切指针，不删除已有的代");
    assert_eq!(delivery.rollback().expect_err("the first generation has no predecessor").code(), ErrorCode::InvalidArgument);

    cleanup(&root);
}

#[test]
fn rollback_without_a_previous_generation_fails() {
    let root = temp_project("rollback-single");
    let delivery = delivery_for(&root);
    assert_eq!(delivery.rollback().expect_err("nothing committed yet").code(), ErrorCode::InvalidArgument);

    delivery.commit(delivery.stage(&bundle(&key(50), &["single.rollback.test"])).expect("stage")).expect("commit");
    assert_eq!(delivery.rollback().expect_err("only one generation exists").code(), ErrorCode::InvalidArgument);

    cleanup(&root);
}

#[test]
fn a_failed_pointer_switch_keeps_the_previous_generation() {
    let root = temp_project("atomic");
    let delivery = delivery_for(&root);
    let first = delivery.commit(delivery.stage(&bundle(&key(51), &["first.atomic.test"])).expect("stage first")).expect("commit first");

    // 用目录占住 `current.tmp`，让指针写入在 rename 之前失败。
    let blocker = state_dir(&root).join("current.tmp");
    std::fs::create_dir(&blocker).expect("block the pointer temp file");

    let staged = delivery.stage(&bundle(&key(52), &["second.atomic.test"])).expect("stage second");
    assert_eq!(delivery.commit(staged).expect_err("the pointer switch must fail").code(), ErrorCode::Io);

    assert_eq!(delivery.current().expect("current").expect("committed").id, first.id, "失败的切换不得改动 current");
    let generations = delivery.generations().expect("list");
    assert_eq!(generations.len(), 1, "失败提交的那一代必须撤销：{generations:?}");
    assert_eq!(generations[0].id, first.id);

    std::fs::remove_dir(&blocker).expect("unblock the pointer temp file");
    cleanup(&root);
}

#[test]
fn a_certificate_for_another_key_is_rejected() {
    let root = temp_project("mismatch");
    let delivery = delivery_for(&root);
    let mut mismatched = bundle(&key(53), &["mismatch.delivery.test"]);
    mismatched.private_key_pem = private_key_pem(&key(54));

    let error = delivery.stage(&mismatched).expect_err("a certificate for another key must fail");
    assert_eq!(error.code(), ErrorCode::InvalidArgument);
    assert!(error.message().contains("不匹配"), "错误要说明是 cert/key 不匹配：{error}");
    assert!(staging_directories(&root).is_empty());

    cleanup(&root);
}

#[cfg(unix)]
#[test]
fn the_private_key_is_owner_only_on_unix() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_project("permissions");
    let delivery = delivery_for(&root);
    let generation = delivery.commit(delivery.stage(&bundle(&key(55), &["permissions.delivery.test"])).expect("stage")).expect("commit");
    let directory = state_dir(&root).join("generations").join(&generation.id);

    let mode = std::fs::metadata(directory.join("key.pem")).expect("key metadata").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "私钥必须是属主可读写、其他用户不可访问");
    let certificate_mode = std::fs::metadata(directory.join("cert.pem")).expect("certificate metadata").permissions().mode();
    assert_eq!(certificate_mode & 0o777, 0o644, "证书是公开产物");

    cleanup(&root);
}
