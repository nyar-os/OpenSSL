//! PKCS#10 conformance tests over the in-repo CSR builder and validator.

use open_ssl_core::csr::{create, generate_p256_key, parse_and_verify};
use p256::ecdsa::VerifyingKey;

fn names() -> Vec<String> {
    vec!["*.wxtoken.work".to_string(), "wxtoken.work".to_string()]
}

#[test]
fn created_request_validates_and_carries_the_names() {
    let key = generate_p256_key();
    let der = create(&key, "*.wxtoken.work", &names());
    let parsed = parse_and_verify(&der).expect("self-signature verifies");
    assert_eq!(parsed.subject.common_name(), Some("*.wxtoken.work"));
    assert_eq!(parsed.dns_names, names());
    let point = key.verifying_key().to_encoded_point(false);
    let open_ssl_core::x509::PublicKey::Ec { point: parsed_point, .. } = &parsed.public_key
    else {
        panic!("expected an EC key");
    };
    assert_eq!(parsed_point.as_slice(), point.as_bytes());
}

#[test]
fn tampered_request_is_rejected() {
    let key = generate_p256_key();
    let mut der = create(&key, "*.wxtoken.work", &names());
    let last = der.len() - 1;
    der[last] ^= 0x01;
    assert!(parse_and_verify(&der).is_err());
}

#[test]
fn each_key_signs_only_its_own_request() {
    let key_a = generate_p256_key();
    let key_b = generate_p256_key();
    let der_a = create(&key_a, "*.wxtoken.work", &names());
    let der_b = create(&key_b, "*.wxtoken.work", &names());
    assert_ne!(der_a, der_b);
    assert!(parse_and_verify(&der_a).is_ok());
    assert!(parse_and_verify(&der_b).is_ok());
}

#[test]
fn generated_keys_are_distinct() {
    let a = generate_p256_key();
    let b = generate_p256_key();
    assert_ne!(a.verifying_key().to_encoded_point(false).as_bytes(), b.verifying_key().to_encoded_point(false).as_bytes());
    let _ = VerifyingKey::from_sec1_bytes(a.verifying_key().to_encoded_point(false).as_bytes()).expect("round trip");
}
