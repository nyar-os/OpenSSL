//! Loopback TLS interop: the in-repo client against a node (OpenSSL) server,
//! with certificates issued by the in-repo PKI.

use std::{
    net::TcpListener,
    process::{Command, Stdio},
    time::Duration,
};

use data_binary_asn1::{Tag, Writer, oids};
use open_ssl_core::x509::{Certificate, EcCurve, PublicKey, SignatureAlgorithm, TrustAnchor};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use signature::Signer;

fn name_der(cn: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|seq| {
        seq.set(|set| {
            set.sequence(|atv| {
                atv.write_oid(&oids::common_name());
                atv.write_utf8(cn);
            });
        });
    });
    w.finish()
}

fn spki_der(key: &VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() }.to_der()
}

fn san_der(names: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|seq| {
        for name in names {
            seq.context_primitive(2, name.as_bytes());
        }
    });
    w.finish()
}

fn extension_der(oid: data_binary_asn1::Oid, value: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.sequence(|ext| {
        ext.write_oid(&oid);
        ext.write_octetstring(value);
    });
    w.finish()
}

fn issue(
    serial: u64,
    cn: &str,
    subject_key: &VerifyingKey,
    issuer_cn: &str,
    issuer_key: &SigningKey,
    ca: bool,
    dns: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut exts = Vec::new();
    if ca {
        let mut bc = Writer::new();
        bc.sequence(|b| b.write_boolean(true));
        exts.push(extension_der(oids::basic_constraints(), &bc.finish()));
        let mut ku = Writer::new();
        ku.write_bitstring(&[0x06, 0x00], 0);
        exts.push(extension_der(oids::key_usage(), &ku.finish()));
    }
    if let Some(san) = dns {
        exts.push(extension_der(oids::subject_alt_name(), &san));
        let mut ku = Writer::new();
        ku.write_bitstring(&[0xA0, 0x00], 0);
        exts.push(extension_der(oids::key_usage(), &ku.finish()));
    }
    let mut ext_list = Writer::new();
    ext_list.sequence(|list| {
        for item in &exts {
            list.write_raw(item);
        }
    });
    let mut w = Writer::new();
    w.sequence(|tbs| {
        tbs.context(0, |v| v.write_u64(2));
        tbs.write_u64(serial);
        tbs.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        tbs.write_raw(&name_der(issuer_cn));
        tbs.sequence(|v| {
            v.write_tlv(Tag::UTCTIME, b"230101000000Z");
            v.write_tlv(Tag::UTCTIME, b"331231235959Z");
        });
        tbs.write_raw(&name_der(cn));
        tbs.write_raw(&spki_der(subject_key));
        if !exts.is_empty() {
            tbs.context(3, |x| x.write_raw(&ext_list.finish()));
        }
    });
    let tbs = w.finish();
    let signature: Signature = issuer_key.sign(&tbs);
    let mut cert = Writer::new();
    cert.sequence(|c| {
        c.write_raw(&tbs);
        c.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        c.write_bitstring(signature.to_der().as_bytes(), 0);
    });
    cert.finish()
}

fn pem(label: &str, der: &[u8]) -> String {
    open_ssl_core::x509::pem_encode(label, der)
}

#[test]
fn loopback_handshake_with_node_server() {
    let dir = std::env::temp_dir().join("ossl-loopback");
    let _ = std::fs::create_dir_all(&dir);
    let ca_key = SigningKey::from_slice(&[21u8; 32]).expect("ca key");
    let leaf_key = SigningKey::from_slice(&[22u8; 32]).expect("leaf key");
    let ca_der = issue(1, "Loopback CA", ca_key.verifying_key(), "Loopback CA", &ca_key, true, None);
    let leaf_der = issue(2, "localhost", leaf_key.verifying_key(), "Loopback CA", &ca_key, false, Some(san_der(&["localhost", "127.0.0.1"])));
    std::fs::write(dir.join("ca.pem"), pem("CERTIFICATE", &ca_der)).expect("write ca");
    std::fs::write(dir.join("leaf.pem"), pem("CERTIFICATE", &leaf_der)).expect("write leaf");
    let leaf_pkcs8 = {
        // SEC1 EC private key wrapped in PKCS#8 for node.
        let secret = leaf_key.to_bytes();
        let mut sec1 = Writer::new();
        sec1.sequence(|s| {
            s.write_u64(1);
            s.write_tlv(Tag::OCTET_STRING, &secret[..]);
            s.context(0, |c| c.write_oid(&oids::prime256v1()));
            s.context(1, |pubbits| {
                let point = leaf_key.verifying_key().to_encoded_point(false);
                pubbits.write_bitstring(point.as_bytes(), 0);
            });
        });
        let sec1 = sec1.finish();
        let mut pkcs8 = Writer::new();
        pkcs8.sequence(|p| {
            p.write_u64(0);
            p.sequence(|alg| {
                alg.write_oid(&oids::ec_public_key());
                alg.write_oid(&oids::prime256v1());
            });
            p.write_tlv(Tag::OCTET_STRING, &sec1);
        });
        pkcs8.finish()
    };
    std::fs::write(dir.join("leaf-key.pem"), pem("PRIVATE KEY", &leaf_pkcs8)).expect("write key");

    // Bind only to learn a free port; the listener must be dropped before node
    // can own the port, otherwise node fails to listen and the client would
    // connect into this socket's backlog and time out.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let script = dir.join("server.js");
    std::fs::write(
        &script,
        format!(
            r#"const tls=require('tls');const fs=require('fs');const dir={:?};
const srv=tls.createServer({{key:fs.readFileSync(dir+'/leaf-key.pem'),cert:fs.readFileSync(dir+'/leaf.pem')}},s=>{{s.on('data',d=>{{s.write('echo:'+d.toString());}});}});
srv.listen({port},"127.0.0.1",()=>console.log('LISTENING'));
process.on('uncaughtException',e=>console.log('ERR',e.message));"#,
            dir.display()
        ),
    )
    .expect("write script");

    let mut child = Command::new("node").arg(&script).stdout(Stdio::piped()).spawn().expect("node server");
    // Read node's ready marker so the port is actually listening before connecting.
    {
        use std::io::BufRead;
        let mut reader = std::io::BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        reader.read_line(&mut line).expect("ready line");
        assert!(line.contains("LISTENING"), "node server reported: {line}");
    }

    let ca_cert = Certificate::parse(&ca_der).expect("ca parse");
    let anchors = vec![TrustAnchor::from_cert(&ca_cert)];
    let config = open_ssl_core::tls::ClientConfig { hostname: "localhost", anchors: &anchors, timeout: Duration::from_secs(5) };
    let mut client = open_ssl_core::tls::TlsClient::connect(&config, ("127.0.0.1", port)).expect("handshake");
    client.send(b"hello").expect("send");
    let mut buf = [0u8; 64];
    let read = client.receive(&mut buf).expect("receive");
    assert_eq!(&buf[..read], b"echo:hello");
    let _ = child.kill();
    let _ = child.wait();
}
