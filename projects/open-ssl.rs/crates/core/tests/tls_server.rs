//! A minimal TLS 1.3 server used only by tests, built on the same `tls`
//! primitives as the client. It exists to close the loop: if the client and
//! this server interoperate, the shared record/key-schedule code is coherent;
//! divergence from OpenSSL servers is then isolated to message-level choices.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use open_ssl_core::tls::{__test_derive_secret as derive_secret, __test_expand_label as expand_label, __test_extract as extract};
use p256::ecdsa::{Signature as EcSignature, SigningKey};
use sha2::{Digest, Sha256};
use signature::Signer;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

const EMPTY_HASH: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93,
    0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

fn seal(key: &[u8], iv: &[u8], seq: u64, inner_type: u8, body: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("key");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(iv);
    let s = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= s[i];
    }
    let mut plaintext = body.to_vec();
    plaintext.push(inner_type);
    let aad = [0x17u8, 0x03, 0x03, ((plaintext.len() + 16) as u16 >> 8) as u8, (plaintext.len() + 16) as u16 as u8];
    let sealed = cipher.encrypt(&aes_gcm::aead::Nonce::<Aes128Gcm>::from(nonce), Payload { msg: &plaintext, aad: &aad }).expect("seal");
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    record.extend_from_slice(&sealed);
    record
}

fn read_record(stream: &mut TcpStream) -> (u8, Vec<u8>) {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).expect("header");
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).expect("body");
    (header[0], body)
}

fn hs_message(type_byte: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![type_byte];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

/// Serve one connection: handshake with `leaf_key` signing, then echo `prefix + data`.
pub fn serve_once(listener: &TcpListener, leaf_key: &SigningKey, leaf_der: &[u8]) {
    let (mut stream, _) = listener.accept().expect("accept");
    let (_type, hello) = read_record(&mut stream);
    // Parse ClientHello: legacy_version(2)+random(32)+sid(1+n)+cs+comp+exts.
    // The record body already carries the handshake header.
    let mut transcript = hello.clone();
    let mut o = 4 + 2 + 32;
    let sid_len = hello[o] as usize;
    o += 1 + sid_len;
    let csl = u16::from_be_bytes([hello[o], hello[o + 1]]) as usize;
    o += 2 + csl;
    let cl = hello[o] as usize;
    o += 1 + cl;
    let el = u16::from_be_bytes([hello[o], hello[o + 1]]) as usize;
    let exts = &hello[o + 2..o + 2 + el];
    let mut client_share = [0u8; 32];
    let mut p = 0usize;
    while p + 4 <= exts.len() {
        let kind = u16::from_be_bytes([exts[p], exts[p + 1]]);
        let length = u16::from_be_bytes([exts[p + 2], exts[p + 3]]) as usize;
        if kind == 51 {
            // key_share: list length(2), entry: group(2)+len(2)+data
            let entry = &exts[p + 6..];
            client_share.copy_from_slice(&entry[4..36]);
        }
        p += 4 + length;
    }

    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes).expect("rng");
    let my_secret = StaticSecret::from(secret_bytes);
    let my_public = XPublicKey::from(&my_secret).to_bytes();
    let shared = my_secret.diffie_hellman(&XPublicKey::from(client_share)).to_bytes();

    let mut sh_exts = Vec::new();
    sh_exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    let mut ks = vec![0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20];
    ks.extend_from_slice(&my_public);
    sh_exts.extend_from_slice(&ks);
    let mut sh_body = vec![0x03, 0x03];
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).expect("rng");
    sh_body.extend_from_slice(&random);
    sh_body.push(32);
    sh_body.extend_from_slice(&hello[4 + 2 + 32 + 1..4 + 2 + 32 + 1 + 32]);
    sh_body.extend_from_slice(&[0x13, 0x01]);
    sh_body.push(0x00);
    sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
    sh_body.extend_from_slice(&sh_exts);
    let sh = hs_message(2, &sh_body);
    transcript.extend_from_slice(&sh);
    let mut frame = vec![0x16, 0x03, 0x03];
    frame.extend_from_slice(&(sh.len() as u16).to_be_bytes());
    frame.extend_from_slice(&sh);
    stream.write_all(&frame).expect("sh");
    stream.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).expect("ccs");

    let early = extract(&[0u8; 32], &[0u8; 32]);
    let derived0 = derive_secret(&early, "derived", &EMPTY_HASH);
    let handshake_secret = extract(&derived0, &shared);
    let hash_after_sh = Sha256::digest(&transcript);
    let client_hs = derive_secret(&handshake_secret, "c hs traffic", &hash_after_sh);
    let server_hs = derive_secret(&handshake_secret, "s hs traffic", &hash_after_sh);
    let s_key = expand_label(&server_hs, "key", &[], 16);
    let s_iv = expand_label(&server_hs, "iv", &[], 12);

    let ee = hs_message(8, &[0x00, 0x00]);
    let mut cert_body = vec![0x00];
    let mut list = Vec::new();
    list.extend_from_slice(&(leaf_der.len() as u32).to_be_bytes()[1..]);
    list.extend_from_slice(leaf_der);
    list.extend_from_slice(&[0x00, 0x00]);
    cert_body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
    cert_body.extend_from_slice(&list);
    let cert = hs_message(11, &cert_body);
    transcript.extend_from_slice(&ee);
    transcript.extend_from_slice(&cert);

    let cv_hash = Sha256::digest(&transcript);
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0);
    content.extend_from_slice(&cv_hash);
    let signature: EcSignature = leaf_key.sign(&content);
    let sig_der = signature.to_der().as_bytes().to_vec();
    let mut cv_body = vec![0x04, 0x03];
    cv_body.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
    cv_body.extend_from_slice(&sig_der);
    let cv = hs_message(15, &cv_body);
    transcript.extend_from_slice(&cv);

    let server_finished_key = derive_secret(&server_hs, "finished", &[]);
    let verify_data = hmac_sha256(&server_finished_key, &Sha256::digest(&transcript));
    let fin = hs_message(20, &verify_data);
    transcript.extend_from_slice(&fin);

    let mut flight = ee.clone();
    flight.extend_from_slice(&cert);
    flight.extend_from_slice(&cv);
    flight.extend_from_slice(&fin);
    stream.write_all(&seal(&s_key, &s_iv, 0, 0x16, &flight)).expect("flight");
    stream.flush().expect("flush");

    // Client Finished.
    let (rtype, body) = read_record(&mut stream);
    assert_eq!(rtype, 0x17);
    let c_key = expand_label(&client_hs, "key", &[], 16);
    let c_iv = expand_label(&client_hs, "iv", &[], 12);
    let cipher = Aes128Gcm::new_from_slice(&c_key).expect("key");
    let aad = [0x17u8, 0x03, 0x03, (body.len() as u16 >> 8) as u8, body.len() as u16 as u8];
    let mut c_ivb = [0u8; 12];
    c_ivb.copy_from_slice(&c_iv);
    let opened = cipher.decrypt(&aes_gcm::aead::Nonce::<Aes128Gcm>::from(c_ivb), Payload { msg: &body, aad: &aad }).expect("open finished");
    assert_eq!(*opened.last().expect("inner"), 0x16);
    let client_verify = &opened[..opened.len() - 1];
    let client_finished_key = derive_secret(&client_hs, "finished", &[]);
    let expected = hmac_sha256(&client_finished_key, &Sha256::digest(&transcript));
    assert_eq!(&client_verify[4..], expected.as_slice(), "client Finished MAC");
    // RFC 8446 §7.1: application traffic secrets cover the transcript up to the
    // server's Finished, excluding the client's Finished.
    let hash_after = Sha256::digest(&transcript);

    // App data: read request, send echo.
    let derived1 = derive_secret(&handshake_secret, "derived", &EMPTY_HASH);
    let master = extract(&derived1, &[0u8; 32]);
    let server_app = derive_secret(&master, "s ap traffic", &hash_after);
    let sa_key = expand_label(&server_app, "key", &[], 16);
    let sa_iv = expand_label(&server_app, "iv", &[], 12);
    let ca_secret = derive_secret(&master, "c ap traffic", &hash_after);
    let ca_key = expand_label(&ca_secret, "key", &[], 16);
    let ca_iv = expand_label(&ca_secret, "iv", &[], 12);
    let (rtype, body) = read_record(&mut stream);
    assert_eq!(rtype, 0x17);
    let app_cipher = Aes128Gcm::new_from_slice(&ca_key).expect("app key");
    let mut ca_ivb = [0u8; 12];
    ca_ivb.copy_from_slice(&ca_iv);
    let opened = app_cipher
        .decrypt(
            &aes_gcm::aead::Nonce::<Aes128Gcm>::from(ca_ivb),
            Payload { msg: &body, aad: &[0x17, 0x03, 0x03, (body.len() as u16 >> 8) as u8, body.len() as u16 as u8] },
        )
        .expect("open app");
    let request = opened[..opened.len() - 1].to_vec();
    let mut echo = b"echo:".to_vec();
    echo.extend_from_slice(&request);
    stream.write_all(&seal(&sa_key, &sa_iv, 0, 0x17, &echo)).expect("echo");
    stream.flush().expect("flush");
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[test]
fn client_and_server_interoperate() {
    use data_binary_asn1::{Tag, Writer, oids};
    use open_ssl_core::x509::{Certificate, EcCurve, PublicKey, SignatureAlgorithm, TrustAnchor, verify_signature};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use signature::Signer;

    let ca_key = SigningKey::from_slice(&[31u8; 32]).expect("ca");
    let leaf_key = SigningKey::from_slice(&[32u8; 32]).expect("leaf");
    fn name_der(cn: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.sequence(|seq| {
            seq.set(|set| {
                set.sequence(|atv| {
                    atv.write_oid(&oids::common_name());
                    atv.write_utf8(cn);
                })
            })
        });
        w.finish()
    }
    fn spki(key: &VerifyingKey) -> Vec<u8> {
        let point = key.to_encoded_point(false);
        PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() }.to_der()
    }
    fn issue(serial: u64, cn: &str, subject: &VerifyingKey, issuer_cn: &str, issuer: &SigningKey, ca: bool, san: Option<Vec<u8>>) -> Vec<u8> {
        let mut tbs = Writer::new();
        tbs.sequence(|t| {
            t.context(0, |v| v.write_u64(2));
            t.write_u64(serial);
            t.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
            t.write_raw(&name_der(issuer_cn));
            t.sequence(|v| {
                v.write_tlv(Tag::UTCTIME, b"230101000000Z");
                v.write_tlv(Tag::UTCTIME, b"331231235959Z");
            });
            t.write_raw(&name_der(cn));
            t.write_raw(&spki(subject));
            let mut items = Vec::new();
            if ca {
                let mut bc = Writer::new();
                bc.sequence(|b| b.write_boolean(true));
                items.push((oids::basic_constraints(), bc.finish()));
            }
            if let Some(san) = &san {
                items.push((oids::subject_alt_name(), san.clone()));
            }
            if !items.is_empty() {
                t.context(3, |x| {
                    x.sequence(|list| {
                        for (oid, value) in &items {
                            list.sequence(|e| {
                                e.write_oid(oid);
                                e.write_octetstring(value);
                            });
                        }
                    })
                });
            }
        });
        let tbs = tbs.finish();
        let signature: Signature = issuer.sign(&tbs);
        let mut cert = Writer::new();
        cert.sequence(|c| {
            c.write_raw(&tbs);
            c.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
            c.write_bitstring(signature.to_der().as_bytes(), 0);
        });
        cert.finish()
    }
    let mut san = Writer::new();
    san.sequence(|s| s.context_primitive(2, b"localhost"));
    let ca_der = issue(1, "Interop CA", ca_key.verifying_key(), "Interop CA", &ca_key, true, None);
    let leaf_der = issue(2, "localhost", leaf_key.verifying_key(), "Interop CA", &ca_key, false, Some(san.finish()));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server_leaf = leaf_key.clone();
    let leaf_for_server = leaf_der.clone();
    std::thread::spawn(move || serve_once(&listener, &server_leaf, &leaf_for_server));

    let ca = Certificate::parse(&ca_der).expect("ca parse");
    let anchors = vec![TrustAnchor::from_cert(&ca)];
    let config = open_ssl_core::tls::ClientConfig { hostname: "localhost", anchors: &anchors, timeout: std::time::Duration::from_secs(5) };
    let mut client = open_ssl_core::tls::TlsClient::connect(&config, ("127.0.0.1", port)).expect("client handshake");
    client.send(b"ping").expect("send");
    let mut buf = [0u8; 64];
    let read = client.receive(&mut buf).expect("receive");
    assert_eq!(&buf[..read], b"echo:ping");
    let _ = verify_signature;
}
