//! Product-owned PKCS#10 certificate signing requests.
//!
//! Builds a `CertificationRequest` for an ECDSA P-256 key with the SAN, key
//! usage, and extended key usage requested by the ACME flow, and validates a
//! request by verifying its self-signature over the raw
//! `CertificationRequestInfo` bytes.

use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use signature::{Signer, Verifier};

use crate::x509::{EcCurve, Name, PublicKey, SignatureAlgorithm};
use data_binary_asn1::{DerError, DerErrorKind, DerResult, Reader, Tag, Writer, oids};

/// Generate a fresh P-256 private key from the system CSPRNG.
///
/// Invalid scalar draws are retried; host entropy failures are returned.
pub fn generate_p256_key() -> crate::Result<SigningKey> {
    let mut entropy = boost_random::Secure::system();
    loop {
        let mut bytes = [0u8; 32];
        entropy.fill(&mut bytes).map_err(|error| crate::Error::new(crate::ErrorCode::Io, format!("system entropy unavailable: {error}")))?;
        if let Ok(key) = SigningKey::from_slice(&bytes) {
            return Ok(key);
        }
    }
}

/// The subject and DNS names a request carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrInfo<'a> {
    /// The parsed subject name.
    pub subject: Name,
    /// The subject public key.
    pub public_key: PublicKey,
    /// The DNS names from the `extensionRequest` attribute.
    pub dns_names: Vec<String>,
    /// The raw `CertificationRequestInfo` element covered by the signature.
    pub cri: &'a [u8],
}

fn name_der(common_name: &str) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sequence(|seq| {
        seq.set(|set| {
            set.sequence(|atv| {
                atv.write_oid(&oids::common_name());
                atv.write_utf8(common_name);
            });
        });
    });
    writer.finish()
}

fn extensions_der(dns_names: &[String]) -> Vec<u8> {
    let mut san = Writer::new();
    san.sequence(|seq| {
        for name in dns_names {
            seq.context_primitive(2, name.as_bytes());
        }
    });
    let san = san.finish();

    let mut key_usage = Writer::new();
    key_usage.write_bitstring(&[0xA0, 0x00], 0);
    let key_usage = key_usage.finish();

    let mut eku = Writer::new();
    eku.sequence(|list| list.write_oid(&oids::server_auth()));
    let eku = eku.finish();

    let mut list = Writer::new();
    list.sequence(|outer| {
        for (oid, value) in [(&oids::subject_alt_name(), &san), (&oids::key_usage(), &key_usage), (&oids::extended_key_usage(), &eku)] {
            outer.sequence(|ext| {
                ext.write_oid(oid);
                ext.write_octetstring(value);
            });
        }
    });
    list.finish()
}

fn certification_request_info(common_name: &str, public_key: &PublicKey, dns_names: &[String]) -> Vec<u8> {
    let extensions = extensions_der(dns_names);
    let mut writer = Writer::new();
    writer.sequence(|cri| {
        cri.write_u64(0);
        cri.write_raw(&name_der(common_name));
        cri.write_raw(&public_key.to_der());
        cri.context(0, |attributes| {
            attributes.sequence(|attribute| {
                attribute.write_oid(&oids::extension_request());
                attribute.set(|values| {
                    values.write_raw(&extensions);
                });
            });
        });
    });
    writer.finish()
}

/// Build a signed PKCS#10 DER request for the given names.
pub fn create(signing_key: &SigningKey, common_name: &str, dns_names: &[String]) -> Vec<u8> {
    let verifying = signing_key.verifying_key();
    let point = verifying.to_encoded_point(false);
    let public_key = PublicKey::Ec { curve: EcCurve::P256, point: point.as_bytes().to_vec() };
    let cri = certification_request_info(common_name, &public_key, dns_names);
    let signature: Signature = signing_key.sign(&cri);
    let mut writer = Writer::new();
    writer.sequence(|csr| {
        csr.write_raw(&cri);
        csr.write_raw(&SignatureAlgorithm::EcdsaSha256.to_der());
        csr.write_bitstring(signature.to_der().as_bytes(), 0);
    });
    writer.finish()
}

/// Parse a PKCS#10 request and verify its self-signature.
pub fn parse_and_verify(der: &[u8]) -> DerResult<CsrInfo<'_>> {
    let mut reader = Reader::new(der);
    let outer = reader.expect(Tag::SEQUENCE)?;
    reader.expect_end()?;
    let mut body = outer.reader();
    let cri = body.expect_number(Tag::SEQUENCE)?;
    let cri_element = &outer.value[cri.offset..body.position()];
    let algorithm = SignatureAlgorithm::parse(&mut body)?;
    let signature = body.expect_bitstring()?;
    if signature.unused_bits != 0 || algorithm != SignatureAlgorithm::EcdsaSha256 {
        return Err(DerError::new(DerErrorKind::MalformedContent, cri.offset));
    }

    let mut cri_reader = cri.reader();
    let version = cri_reader.expect_u64()?;
    if version != 0 {
        return Err(DerError::new(DerErrorKind::MalformedContent, cri.offset));
    }
    let subject = Name::parse(&mut cri_reader)?;
    let public_key = PublicKey::parse(&mut cri_reader)?;
    let mut dns_names = Vec::new();
    if cri_reader.remaining() > 0 {
        let attributes = cri_reader.expect_context(0, true)?;
        let mut attribute_reader = attributes.reader();
        while !attribute_reader.is_empty() {
            let attribute = attribute_reader.expect(Tag::SEQUENCE)?;
            let mut item = attribute.reader();
            let oid = item.expect_oid()?;
            if oid.dotted() != "1.2.840.113549.1.9.14" {
                continue;
            }
            let values = item.expect(Tag::SET)?;
            let mut values_reader = values.reader();
            while !values_reader.is_empty() {
                let ext_list = values_reader.expect(Tag::SEQUENCE)?;
                let mut ext_reader = ext_list.reader();
                while !ext_reader.is_empty() {
                    let extension = ext_reader.expect(Tag::SEQUENCE)?;
                    let mut ext_item = extension.reader();
                    let ext_oid = ext_item.expect_oid()?;
                    if ext_oid.dotted() != "2.5.29.17" {
                        continue;
                    }
                    let _critical = if ext_item.peek_tag()? == Tag::BOOLEAN { ext_item.expect_boolean()? } else { false };
                    let value = ext_item.expect_octetstring()?;
                    let mut san_reader = Reader::new(value);
                    let names = san_reader.expect(Tag::SEQUENCE)?;
                    let mut name_reader = names.reader();
                    while !name_reader.is_empty() {
                        let entry = name_reader.read_tlv()?;
                        if entry.tag == Tag::context(2, false) {
                            dns_names.push(entry.text()?.to_ascii_lowercase());
                        }
                    }
                }
            }
        }
    }

    let verifying = verifying_key_for(&public_key)?;
    let signature = Signature::from_der(signature.bytes).map_err(|_| DerError::new(DerErrorKind::MalformedContent, cri.offset))?;
    verifying.verify(cri_element, &signature).map_err(|_| DerError::new(DerErrorKind::MalformedContent, cri.offset))?;
    Ok(CsrInfo { subject, public_key, dns_names, cri: cri_element })
}

fn verifying_key_for(public_key: &PublicKey) -> DerResult<VerifyingKey> {
    match public_key {
        PublicKey::Ec { curve: EcCurve::P256, point } => {
            VerifyingKey::from_sec1_bytes(point).map_err(|_| DerError::new(DerErrorKind::MalformedContent, 0))
        }
        _ => Err(DerError::new(DerErrorKind::MalformedContent, 0)),
    }
}
