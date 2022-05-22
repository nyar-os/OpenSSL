use core::fmt;

use sha2::{Digest, Sha256, Sha384};
use signature::Verifier;

use crate::der::DateTime;

use super::{
    cert::{Certificate, SignatureAlgorithm},
    spki::{EcCurve, PublicKey},
};

/// Why a certificate or chain failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature does not verify under the issuer key.
    BadSignature,
    /// The issuer key type does not match the signature algorithm.
    AlgorithmMismatch,
    /// The public key or signature is malformed.
    Malformed,
    /// The current time is before `notBefore`.
    NotYetValid,
    /// The current time is after `notAfter`.
    Expired,
    /// No intermediate or anchor matches the issuer name.
    UntrustedIssuer,
    /// An issuer is not allowed to sign certificates.
    NotCa,
    /// A path length constraint was exceeded.
    PathLength,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::BadSignature => "certificate signature does not verify",
            Self::AlgorithmMismatch => "issuer key does not match signature algorithm",
            Self::Malformed => "certificate key or signature is malformed",
            Self::NotYetValid => "certificate is not yet valid",
            Self::Expired => "certificate has expired",
            Self::UntrustedIssuer => "certificate issuer is not trusted",
            Self::NotCa => "issuer is not a certificate authority",
            Self::PathLength => "certificate path exceeds the issuer path length constraint",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for VerifyError {}

/// A trusted root expressed as its subject name and public key.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Human-readable label for diagnostics.
    pub label: String,
    /// The DER encoding of the root's `Name`.
    pub subject_raw: Vec<u8>,
    /// The root's public key.
    pub public_key: PublicKey,
}

impl TrustAnchor {
    /// Build an anchor from a self-signed root certificate.
    pub fn from_cert(cert: &Certificate<'_>) -> Self {
        Self {
            label: cert.subject.common_name().unwrap_or("trust anchor").to_string(),
            subject_raw: cert.subject.raw().to_vec(),
            public_key: cert.public_key.clone(),
        }
    }
}

/// Verify one certificate's signature under the given issuer key.
pub fn verify_signature(cert: &Certificate<'_>, issuer: &PublicKey) -> Result<(), VerifyError> {
    match (issuer, cert.signature_algorithm) {
        (PublicKey::Ec { curve: EcCurve::P256, point }, SignatureAlgorithm::EcdsaSha256) => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| VerifyError::Malformed)?;
            let signature = p256::ecdsa::Signature::from_der(cert.signature).map_err(|_| VerifyError::Malformed)?;
            key.verify(&cert.tbs, &signature).map_err(|_| VerifyError::BadSignature)
        }
        (PublicKey::Ec { curve: EcCurve::P384, point }, SignatureAlgorithm::EcdsaSha384) => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| VerifyError::Malformed)?;
            let signature = p384::ecdsa::Signature::from_der(cert.signature).map_err(|_| VerifyError::Malformed)?;
            key.verify(&cert.tbs, &signature).map_err(|_| VerifyError::BadSignature)
        }
        (PublicKey::Rsa { modulus, exponent }, algorithm)
            if matches!(
                algorithm,
                SignatureAlgorithm::RsaSha256
                    | SignatureAlgorithm::RsaSha384
                    | SignatureAlgorithm::RsaPssSha256
                    | SignatureAlgorithm::RsaPssSha384
            ) =>
        {
            let exponent = u32::try_from(*exponent).map_err(|_| VerifyError::Malformed)?;
            let key = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(modulus), rsa::BigUint::from(exponent))
                .map_err(|_| VerifyError::Malformed)?;
            let result = match algorithm {
                SignatureAlgorithm::RsaSha256 => key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&cert.tbs), cert.signature),
                SignatureAlgorithm::RsaSha384 => key.verify(rsa::Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(&cert.tbs), cert.signature),
                SignatureAlgorithm::RsaPssSha256 => key.verify(rsa::Pss::new::<Sha256>(), &Sha256::digest(&cert.tbs), cert.signature),
                _ => key.verify(rsa::Pss::new::<Sha384>(), &Sha384::digest(&cert.tbs), cert.signature),
            };
            result.map_err(|_| VerifyError::BadSignature)
        }
        (PublicKey::Ec { .. }, _) => Err(VerifyError::AlgorithmMismatch),
        (PublicKey::Rsa { .. }, _) => Err(VerifyError::AlgorithmMismatch),
    }
}

/// Check the validity window of one certificate against `now`.
pub fn check_validity(cert: &Certificate<'_>, now: &DateTime) -> Result<(), VerifyError> {
    if now < &cert.not_before {
        return Err(VerifyError::NotYetValid);
    }
    if now > &cert.not_after {
        return Err(VerifyError::Expired);
    }
    Ok(())
}

/// The maximum number of intermediates accepted between a leaf and an anchor.
pub const MAX_CHAIN_DEPTH: usize = 4;

/// Verify a leaf against intermediates and trust anchors, returning the chain.
///
/// The returned vector starts with the leaf and ends with the certificate
/// signed directly by an anchor. Every link is checked for signature, validity,
/// CA status, key usage, and path length.
pub fn verify_chain<'a>(
    leaf: &'a Certificate<'a>,
    intermediates: &[&'a Certificate<'a>],
    anchors: &[TrustAnchor],
    now: &DateTime,
) -> Result<Vec<&'a Certificate<'a>>, VerifyError> {
    let mut chain = vec![leaf];
    let mut current = leaf;
    for _ in 0..=MAX_CHAIN_DEPTH {
        check_validity(current, now)?;
        if let Some(anchor) = anchors.iter().find(|a| a.subject_raw == current.issuer.raw()) {
            verify_signature(current, &anchor.public_key)?;
            return Ok(chain);
        }
        let Some(issuer) = intermediates.iter().copied().find(|c| c.subject.raw() == current.issuer.raw())
        else {
            return Err(VerifyError::UntrustedIssuer);
        };
        if !issuer.extensions.is_ca {
            return Err(VerifyError::NotCa);
        }
        if !issuer.extensions.key_usage.is_none_or(|ku| ku.contains(crate::x509::cert::KeyUsage::KEY_CERT_SIGN)) {
            return Err(VerifyError::NotCa);
        }
        if let Some(path_len) = issuer.extensions.path_len {
            // Certificates below the issuer: `chain.len()` minus the leaf slot the issuer itself fills.
            if (chain.len() as u64 - 1) > path_len {
                return Err(VerifyError::PathLength);
            }
        }
        verify_signature(current, &issuer.public_key)?;
        chain.push(issuer);
        current = issuer;
    }
    Err(VerifyError::UntrustedIssuer)
}
