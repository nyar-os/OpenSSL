//! X.509 conformance tests over a self-built ECDSA test PKI.

use open_ssl_core::{
    der::{DateTime, Oid, Tag, Writer, oids},
    x509::{
        Certificate, EcCurve, PublicKey, SignatureAlgorithm, TrustAnchor, VerifyError, matches_dns, pem_encode, verify_chain, verify_signature,
    },
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use signature::Signer;

fn name_der(cn: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|seq| {
        seq.set(|set| {
            set.sequence(|atv| {
                atv.write_oid(&oids::common_name());
                atv.write_utf8(cn);
            });
        });
    });
    writer.finish()
}

fn validity_der(not_before: &str, not_after: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|v| {
        v.write_tlv(Tag::UTCTIME, not_before.as_bytes());
        v.write_tlv(Tag::UTCTIME, not_after.as_bytes());
    });
    writer.finish()
}

fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() }.to_der()
}

fn extension(oid: Oid, value: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|ext| {
        ext.write_oid(&oid);
        ext.write_octetstring(value);
    });
    writer.finish()
}

fn san_der(names: &[&str]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|seq| {
        for name in names {
            seq.context_primitive(2, name.as_bytes());
        }
    });
    writer.finish()
}

fn basic_constraints_ca_der() -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|bc| bc.write_boolean(true));
    writer.finish()
}

fn key_usage_der(mask: u16) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_bitstring(&[(mask >> 8) as u8, mask as u8], 0);
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

fn tbs_der(serial: u64, issuer: &[u8], subject: &[u8], spki: &[u8], extensions: Option<Vec<u8>>) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|tbs| {
        tbs.context(0, |version| version.write_u64(2));
        tbs.write_u64(serial);
        tbs.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        tbs.write_raw(issuer);
        tbs.write_raw(&validity_der("230101000000Z", "331231235959Z"));
        tbs.write_raw(subject);
        tbs.write_raw(spki);
        if let Some(extensions) = extensions {
            tbs.context(3, |wrapper| wrapper.write_raw(&extensions));
        }
    });
    writer.finish()
}

fn issue_cert(
    serial: u64,
    subject_cn: &str,
    subject_key: &VerifyingKey,
    issuer_cn: &str,
    issuer_key: &SigningKey,
    extensions: Option<Vec<u8>>,
) -> Vec<u8> {
    let tbs = tbs_der(serial, &name_der(issuer_cn), &name_der(subject_cn), &spki_der(subject_key), extensions);
    let signature: p256::ecdsa::Signature = issuer_key.sign(&tbs);
    let mut writer = Writer::new();
    writer.sequence(|cert| {
        cert.write_raw(&tbs);
        cert.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        cert.write_bitstring(signature.to_der().as_bytes(), 0);
    });
    writer.finish()
}

fn verifying_key(signing: &SigningKey) -> VerifyingKey {
    *signing.verifying_key()
}

fn test_ca() -> (SigningKey, Vec<u8>) {
    let key = SigningKey::from_slice(&[7u8; 32]).expect("test key");
    let extensions = extensions_der(&[
        extension(oids::basic_constraints(), &basic_constraints_ca_der()),
        extension(oids::key_usage(), &key_usage_der(0x0600)),
    ]);
    let der = issue_cert(1, "Test Root CA", &verifying_key(&key), "Test Root CA", &key, Some(extensions));
    (key, der)
}

#[test]
fn parses_self_signed_ca() {
    let (_key, der) = test_ca();
    let cert = Certificate::parse(&der).expect("parse");
    assert_eq!(cert.version, 3);
    assert_eq!(cert.subject.common_name(), Some("Test Root CA"));
    assert!(cert.extensions.is_ca);
    assert_eq!(cert.signature_algorithm, SignatureAlgorithm::EcdsaSha256);
    assert!(verify_signature(&cert, &cert.public_key).is_ok());
}

#[test]
fn verifies_leaf_chain_and_hostname() {
    let (ca_key, ca_der) = test_ca();
    let leaf_key = SigningKey::from_slice(&[9u8; 32]).expect("leaf key");
    let extensions = extensions_der(&[
        extension(oids::subject_alt_name(), &san_der(&["*.wxtoken.work"])),
        extension(oids::key_usage(), &key_usage_der(0xA000)),
    ]);
    let leaf_der = issue_cert(42, "*.wxtoken.work", &verifying_key(&leaf_key), "Test Root CA", &ca_key, Some(extensions));

    let ca = Certificate::parse(&ca_der).expect("ca parse");
    let leaf = Certificate::parse(&leaf_der).expect("leaf parse");
    assert_eq!(leaf.serial, &[42]);
    assert_eq!(leaf.extensions.dns_names, vec!["*.wxtoken.work".to_string()]);

    let anchor = TrustAnchor::from_cert(&ca);
    let now = DateTime::from_epoch(1_763_000_000);
    let chain = verify_chain(&leaf, &[], &[anchor], &now).expect("chain verifies");
    // The trusted anchor itself is not part of the returned chain.
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].subject.common_name(), Some("*.wxtoken.work"));

    assert!(matches_dns(&leaf, "api.wxtoken.work"));
    assert!(!matches_dns(&leaf, "wxtoken.work"));
}

#[test]
fn tampered_signature_is_rejected() {
    let (ca_key, _ca_der) = test_ca();
    let leaf_key = SigningKey::from_slice(&[9u8; 32]).expect("leaf key");
    let mut der = issue_cert(7, "bad", &verifying_key(&leaf_key), "Test Root CA", &ca_key, None);
    if let Some(byte) = der.last_mut() {
        *byte ^= 0x01;
    }
    let cert = Certificate::parse(&der).expect("parse");
    assert_eq!(verify_signature(&cert, &cert.public_key), Err(VerifyError::BadSignature));
}

#[test]
fn expired_leaf_is_rejected() {
    let (ca_key, ca_der) = test_ca();
    let leaf_key = SigningKey::from_slice(&[9u8; 32]).expect("leaf key");
    let leaf_der = issue_cert(8, "old.wxtoken.work", &verifying_key(&leaf_key), "Test Root CA", &ca_key, None);
    let ca = Certificate::parse(&ca_der).expect("ca parse");
    let leaf = Certificate::parse(&leaf_der).expect("leaf parse");
    let anchor = TrustAnchor::from_cert(&ca);
    let future = DateTime { year: 2035, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
    assert_eq!(verify_chain(&leaf, &[], &[anchor], &future).err(), Some(VerifyError::Expired));
}

#[test]
fn untrusted_issuer_is_rejected() {
    let (ca_key, _ca_der) = test_ca();
    let leaf_key = SigningKey::from_slice(&[9u8; 32]).expect("leaf key");
    let leaf_der = issue_cert(9, "orphan", &verifying_key(&leaf_key), "Test Root CA", &ca_key, None);
    let leaf = Certificate::parse(&leaf_der).expect("parse");
    let empty_anchor = TrustAnchor {
        label: "other".to_string(),
        subject_raw: name_der("Other CA"),
        public_key: PublicKey::Ec { curve: EcCurve::P256, point: vec![4u8; 65] },
    };
    let now = DateTime::from_epoch(1_763_000_000);
    assert_eq!(verify_chain(&leaf, &[], &[empty_anchor], &now).err(), Some(VerifyError::UntrustedIssuer));
}

#[test]
fn pem_round_trips_a_certificate() {
    let (_key, der) = test_ca();
    let text = pem_encode("CERTIFICATE", &der);
    let decoded = open_ssl_core::x509::pem_decode("CERTIFICATE", &text).expect("decode");
    assert_eq!(decoded, der);
    Certificate::parse(&decoded).expect("reparse");
}

#[test]
fn non_ca_issuer_is_rejected() {
    let (ca_key, ca_der) = test_ca();
    // Issue an intermediate WITHOUT basicConstraints, then a leaf under it.
    let inter_key = SigningKey::from_slice(&[11u8; 32]).expect("inter key");
    let inter_der = issue_cert(100, "Sneaky CA", &verifying_key(&inter_key), "Test Root CA", &ca_key, None);
    let leaf_key = SigningKey::from_slice(&[13u8; 32]).expect("leaf key");
    let leaf_der = issue_cert(101, "leaf", &verifying_key(&leaf_key), "Sneaky CA", &inter_key, None);
    let ca = Certificate::parse(&ca_der).expect("ca parse");
    let inter = Certificate::parse(&inter_der).expect("inter parse");
    let leaf = Certificate::parse(&leaf_der).expect("leaf parse");
    let anchor = TrustAnchor::from_cert(&ca);
    let now = DateTime::from_epoch(1_763_000_000);
    assert_eq!(verify_chain(&leaf, &[&inter], &[anchor], &now).err(), Some(VerifyError::NotCa));
}
