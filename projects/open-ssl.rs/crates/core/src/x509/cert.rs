use crate::der::{BitString, DateTime, DerError, DerErrorKind, DerResult, Oid, Reader, Tag, Writer, encode_element, oids};

use super::{name::Name, spki::PublicKey};

/// The signature algorithms this product can verify or emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with SHA-256 over P-256.
    EcdsaSha256,
    /// ECDSA with SHA-384 over P-384.
    EcdsaSha384,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaSha384,
    /// RSA PSS with SHA-256 and full-length salt.
    RsaPssSha256,
    /// RSA PSS with SHA-384 and full-length salt.
    RsaPssSha384,
}

impl SignatureAlgorithm {
    /// The `AlgorithmIdentifier` OID for this algorithm.
    pub fn oid(self) -> Oid {
        match self {
            Self::EcdsaSha256 => oids::ecdsa_with_sha256(),
            Self::EcdsaSha384 => oids::ecdsa_with_sha384(),
            Self::RsaSha256 => oids::sha256_with_rsa(),
            Self::RsaSha384 => oids::sha384_with_rsa(),
            Self::RsaPssSha256 | Self::RsaPssSha384 => oids::rsa_pss(),
        }
    }

    /// The digest size this algorithm hashes to.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::EcdsaSha256 | Self::RsaSha256 | Self::RsaPssSha256 => 32,
            Self::EcdsaSha384 | Self::RsaSha384 | Self::RsaPssSha384 => 48,
        }
    }

    /// Parse an `AlgorithmIdentifier` into a supported algorithm.
    pub fn parse(reader: &mut Reader<'_>) -> DerResult<Self> {
        let element = reader.expect(Tag::SEQUENCE)?;
        let mut body = element.reader();
        let oid = body.expect_oid()?;
        match oid.dotted().as_str() {
            "1.2.840.10045.4.3.2" => Ok(Self::EcdsaSha256),
            "1.2.840.10045.4.3.3" => Ok(Self::EcdsaSha384),
            "1.2.840.113549.1.1.11" => Ok(Self::RsaSha256),
            "1.2.840.113549.1.1.12" => Ok(Self::RsaSha384),
            "1.2.840.113549.1.1.10" => {
                // RSASSA-PSS parameters carry the hash OID; SHA-256 is the default.
                let mut hash = "2.16.840.1.101.3.4.2.1";
                if body.remaining() > 0 {
                    let params = body.expect(Tag::SEQUENCE)?;
                    let mut params_reader = params.reader();
                    if params_reader.peek_tag()? == Tag::context(0, true) {
                        let explicit = params_reader.expect_context(0, true)?;
                        let hash_oid = explicit.reader().expect_oid()?;
                        hash = if hash_oid.dotted() == "2.16.840.1.101.3.4.2.2" { "2.16.840.1.101.3.4.2.2" } else { "2.16.840.1.101.3.4.2.1" };
                    }
                }
                if hash == "2.16.840.1.101.3.4.2.2" { Ok(Self::RsaPssSha384) } else { Ok(Self::RsaPssSha256) }
            }
            _ => Err(DerError::new(DerErrorKind::MalformedContent, element.offset)),
        }
    }

    /// Write this algorithm as a DER `AlgorithmIdentifier` element.
    pub fn to_der(self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.sequence(|outer| {
            outer.write_oid(&self.oid());
            match self {
                Self::EcdsaSha256 | Self::EcdsaSha384 | Self::RsaSha256 | Self::RsaSha384 => outer.write_null(),
                Self::RsaPssSha256 => write_pss_params(outer, &oids::sha256(), 32),
                Self::RsaPssSha384 => write_pss_params(outer, &oids::sha384(), 48),
            }
        });
        writer.finish()
    }
}

fn write_pss_params(outer: &mut Writer, hash_oid: &Oid, salt_len: u64) {
    outer.sequence(|params| {
        params.context(0, |inner| {
            inner.sequence(|hash| hash.write_oid(hash_oid));
        });
        params.context(1, |inner| {
            inner.sequence(|mgf| {
                mgf.write_oid(&oids::mgf1());
                mgf.sequence(|hash| hash.write_oid(hash_oid));
            });
        });
        params.context(2, |inner| inner.write_u64(salt_len));
    });
}

/// Key usage bits as a mask over the first two content bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    /// `digitalSignature` (bit 0).
    pub const DIGITAL_SIGNATURE: u16 = 1 << 15;
    /// `keyEncipherment` (bit 2).
    pub const KEY_ENCIPHERMENT: u16 = 1 << 13;
    /// `keyCertSign` (bit 5).
    pub const KEY_CERT_SIGN: u16 = 1 << 10;
    /// `cRLSign` (bit 6).
    pub const CRL_SIGN: u16 = 1 << 9;

    /// True when every bit of `mask` is set.
    pub const fn contains(self, mask: u16) -> bool {
        self.0 & mask == mask
    }
}

/// The parsed extension set a chain policy needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extensions {
    /// DNS names from the subjectAltName extension, lower-cased.
    pub dns_names: Vec<String>,
    /// Whether basicConstraints marks this as a CA.
    pub is_ca: bool,
    /// The pathLenConstraint when present.
    pub path_len: Option<u64>,
    /// Key usage bits.
    pub key_usage: Option<KeyUsage>,
    /// The subjectKeyIdentifier content.
    pub subject_key_id: Option<Vec<u8>>,
    /// The authorityKeyIdentifier keyIdentifier content.
    pub authority_key_id: Option<Vec<u8>>,
    /// Extended key usage OIDs in dotted form.
    pub extended_key_usage: Vec<String>,
}

impl Extensions {
    fn empty() -> Self {
        Self {
            dns_names: Vec::new(),
            is_ca: false,
            path_len: None,
            key_usage: None,
            subject_key_id: None,
            authority_key_id: None,
            extended_key_usage: Vec::new(),
        }
    }
}

/// A parsed X.509 certificate borrowing its input bytes.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    /// The full DER document.
    pub raw: &'a [u8],
    /// The complete DER-encoded `TBSCertificate` element covered by the signature.
    pub tbs: Vec<u8>,
    /// Version number, `1` for v1 through `3` for v3.
    pub version: u8,
    /// The serial number magnitude.
    pub serial: &'a [u8],
    /// The `signature` algorithm inside the TBS.
    pub signature_algorithm: SignatureAlgorithm,
    /// The issuer name.
    pub issuer: Name,
    /// Start of the validity window.
    pub not_before: DateTime,
    /// End of the validity window.
    pub not_after: DateTime,
    /// The subject name.
    pub subject: Name,
    /// The subject public key.
    pub public_key: PublicKey,
    /// Parsed extensions.
    pub extensions: Extensions,
    /// The outer signature algorithm identifier.
    pub outer_algorithm: SignatureAlgorithm,
    /// The signature value bytes.
    pub signature: &'a [u8],
}

impl<'a> Certificate<'a> {
    /// Parse one DER certificate.
    pub fn parse(der: &'a [u8]) -> DerResult<Self> {
        let mut reader = Reader::new(der);
        let cert = reader.expect(Tag::SEQUENCE)?;
        reader.expect_end()?;
        let mut body = cert.reader();
        let tbs = body.expect_number(Tag::SEQUENCE)?;
        let outer_algorithm = SignatureAlgorithm::parse(&mut body)?;
        let signature = body.expect_bitstring()?;
        if signature.unused_bits != 0 {
            return Err(DerError::new(DerErrorKind::MalformedContent, tbs.offset));
        }

        let mut tbs_reader = tbs.reader();
        let version = if tbs_reader.peek_tag()? == Tag::context(0, true) {
            let explicit = tbs_reader.expect_context(0, true)?;
            let value = explicit.reader().expect_u64()?;
            u8::try_from(value + 1).map_err(|_| DerError::new(DerErrorKind::MalformedContent, explicit.offset))?
        }
        else {
            1
        };
        let serial_element = tbs_reader.expect_number(Tag::INTEGER)?;
        let serial = trim_serial(serial_element.value);
        let signature_algorithm = SignatureAlgorithm::parse(&mut tbs_reader)?;
        let issuer = Name::parse(&mut tbs_reader)?;
        let validity = tbs_reader.expect(Tag::SEQUENCE)?;
        let mut validity_reader = validity.reader();
        let not_before = parse_time(&mut validity_reader)?;
        let not_after = parse_time(&mut validity_reader)?;
        let subject = Name::parse(&mut tbs_reader)?;
        let public_key = PublicKey::parse(&mut tbs_reader)?;
        let mut extensions = Extensions::empty();
        if tbs_reader.remaining() > 0 {
            let explicit = tbs_reader.expect_context(3, true)?;
            let mut ext_reader = explicit.reader();
            let list = ext_reader.expect(Tag::SEQUENCE)?;
            let mut list_reader = list.reader();
            while !list_reader.is_empty() {
                let extension = list_reader.expect(Tag::SEQUENCE)?;
                let mut item = extension.reader();
                let oid = item.expect_oid()?;
                let critical = if item.peek_tag()? == Tag::BOOLEAN { item.expect_boolean()? } else { false };
                let value = item.expect_octetstring()?;
                parse_extension(&oid, critical, value, &mut extensions)?;
            }
        }
        Ok(Self {
            raw: der,
            tbs: encode_element(Tag::SEQUENCE, tbs.value),
            version,
            serial,
            signature_algorithm,
            issuer,
            not_before,
            not_after,
            subject,
            public_key,
            extensions,
            outer_algorithm,
            signature: signature.bytes,
        })
    }
}

fn trim_serial(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    bytes
}

fn parse_time(reader: &mut Reader<'_>) -> DerResult<DateTime> {
    let element = reader.read_tlv()?;
    match element.tag {
        Tag::UTCTIME | Tag::GENERALIZED_TIME => DateTime::parse(element.value).map_err(|error| DerError { offset: element.offset, ..error }),
        _ => Err(DerError::tag_mismatch(Tag::UTCTIME.number, element.tag.number, element.offset)),
    }
}

fn parse_extension(oid: &Oid, _critical: bool, value: &[u8], out: &mut Extensions) -> DerResult<()> {
    let mut reader = Reader::new(value);
    match oid.dotted().as_str() {
        "2.5.29.17" => {
            let mut seq = reader.expect(Tag::SEQUENCE)?.reader();
            while !seq.is_empty() {
                let name = seq.read_tlv()?;
                if name.tag == Tag::context(2, false) {
                    let text = name.text()?;
                    if !text.is_ascii() {
                        return Err(DerError::new(DerErrorKind::MalformedContent, name.offset));
                    }
                    out.dns_names.push(text.to_ascii_lowercase());
                }
            }
        }
        "2.5.29.19" => {
            let bc = reader.expect(Tag::SEQUENCE)?;
            let mut bc_reader = bc.reader();
            if bc_reader.remaining() > 0 && bc_reader.peek_tag()? == Tag::BOOLEAN {
                out.is_ca = bc_reader.expect_boolean()?;
            }
            if bc_reader.remaining() > 0 && bc_reader.peek_tag()? == Tag::context(0, false) {
                let explicit = bc_reader.expect_context(0, false)?;
                out.path_len = Some(explicit.reader().expect_u64()?);
            }
        }
        "2.5.29.15" => {
            let bits: BitString<'_> = reader.expect_bitstring()?;
            let first = bits.bytes.first().copied().unwrap_or(0);
            let second = bits.bytes.get(1).copied().unwrap_or(0);
            out.key_usage = Some(KeyUsage((u16::from(first) << 8) | u16::from(second)));
        }
        "2.5.29.14" => {
            out.subject_key_id = Some(reader.expect_octetstring()?.to_vec());
        }
        "2.5.29.35" => {
            let aki = reader.expect(Tag::SEQUENCE)?;
            let mut aki_reader = aki.reader();
            if aki_reader.remaining() > 0 && aki_reader.peek_tag()? == Tag::context(0, false) {
                out.authority_key_id = Some(aki_reader.expect_context(0, false)?.value.to_vec());
            }
        }
        "2.5.29.37" => {
            let eku = reader.expect(Tag::SEQUENCE)?;
            let mut eku_reader = eku.reader();
            while !eku_reader.is_empty() {
                out.extended_key_usage.push(eku_reader.expect_oid()?.dotted());
            }
        }
        _ => {}
    }
    Ok(())
}
