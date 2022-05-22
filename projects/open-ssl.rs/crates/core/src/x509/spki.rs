use crate::der::{DerError, DerErrorKind, DerResult, Oid, Reader, Tag, Writer, oids};

/// The elliptic curves this product understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 (prime256v1).
    P256,
    /// NIST P-384 (secp384r1).
    P384,
}

impl EcCurve {
    /// The uncompressed SEC1 point length including the `0x04` prefix.
    pub const fn point_len(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
        }
    }

    /// The curve OID.
    pub fn oid(self) -> Oid {
        match self {
            Self::P256 => oids::prime256v1(),
            Self::P384 => oids::secp384r1(),
        }
    }
}

/// A public key carried in a SubjectPublicKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An EC public key with its curve and uncompressed SEC1 point.
    Ec {
        /// The curve the point lives on.
        curve: EcCurve,
        /// Uncompressed SEC1 point bytes starting with `0x04`.
        point: Vec<u8>,
    },
    /// An RSA public key as big-endian modulus and public exponent.
    Rsa {
        /// Big-endian modulus bytes.
        modulus: Vec<u8>,
        /// Public exponent.
        exponent: u64,
    },
}

impl PublicKey {
    /// Parse a `SubjectPublicKeyInfo` element from a certificate or CSR body.
    pub fn parse(reader: &mut Reader<'_>) -> DerResult<Self> {
        let spki = reader.expect(Tag::SEQUENCE)?;
        let mut body = spki.reader();
        let algorithm = body.expect(Tag::SEQUENCE)?;
        let mut algorithm_reader = algorithm.reader();
        let oid = algorithm_reader.expect_oid()?;
        if oid == oids::ec_public_key() {
            let curve_oid = algorithm_reader.expect_oid()?;
            let curve = match curve_oid.dotted().as_str() {
                "1.2.840.10045.3.1.7" => EcCurve::P256,
                "1.3.132.0.34" => EcCurve::P384,
                _ => return Err(DerError::new(DerErrorKind::MalformedContent, algorithm.offset)),
            };
            let bit = body.expect_bitstring()?;
            if bit.bytes.len() != curve.point_len() || bit.bytes[0] != 0x04 {
                return Err(DerError::new(DerErrorKind::MalformedContent, spki.offset));
            }
            Ok(Self::Ec { curve, point: bit.bytes.to_vec() })
        }
        else if oid == oids::rsa_encryption() {
            algorithm_reader.expect_null()?;
            let bit = body.expect_bitstring()?;
            if bit.unused_bits != 0 {
                return Err(DerError::new(DerErrorKind::MalformedContent, spki.offset));
            }
            let mut inner = Reader::new(bit.bytes);
            let rsa = inner.expect(Tag::SEQUENCE)?;
            let mut rsa_reader = rsa.reader();
            let modulus = rsa_reader.expect_integer_bytes()?;
            let exponent = rsa_reader.expect_u64()?;
            Ok(Self::Rsa { modulus: modulus.to_vec(), exponent })
        }
        else {
            Err(DerError::new(DerErrorKind::MalformedContent, algorithm.offset))
        }
    }

    /// Encode this key as a DER `SubjectPublicKeyInfo`.
    pub fn to_der(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.sequence(|outer| match self {
            PublicKey::Ec { curve, point } => {
                outer.sequence(|algorithm| {
                    algorithm.write_oid(&oids::ec_public_key());
                    algorithm.write_oid(&curve.oid());
                });
                outer.write_bitstring(point, 0);
            }
            PublicKey::Rsa { modulus, exponent } => {
                outer.sequence(|algorithm| {
                    algorithm.write_oid(&oids::rsa_encryption());
                    algorithm.write_null();
                });
                let mut rsa = Writer::new();
                rsa.sequence(|inner| {
                    inner.write_integer(modulus);
                    inner.write_u64(*exponent);
                });
                outer.write_bitstring(&rsa.finish(), 0);
            }
        });
        writer.finish()
    }

    /// The EC curve when this is an EC key.
    pub const fn ec_curve(&self) -> Option<EcCurve> {
        match self {
            Self::Ec { curve, .. } => Some(*curve),
            Self::Rsa { .. } => None,
        }
    }
}
