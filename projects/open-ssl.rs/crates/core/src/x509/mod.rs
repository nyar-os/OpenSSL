//! Product-owned X.509 certificate parsing, PEM containers, and chain policy.
//!
//! This module decodes certificates strictly from DER with the in-repo `der`
//! codec, validates signatures over the raw `TBSCertificate` bytes, and builds
//! chains against explicit trust anchors. It deliberately knows nothing about
//! TLS or ACME; those layers consume these types.

mod anchors;
mod cert;
mod hostname;
mod name;
mod pem;
mod spki;
mod verify;

pub use anchors::{ISRG_ROOT_X1_DER, ISRG_ROOT_X1_SHA256, ISRG_ROOT_X2_DER, ISRG_ROOT_X2_SHA256, lets_encrypt_anchors};
pub use cert::{Certificate, Extensions, KeyUsage, SignatureAlgorithm};
pub use hostname::matches_dns;
pub use name::{AttributeTypeAndValue, Name};
pub use pem::{pem_bundle, pem_decode, pem_encode};
pub use spki::{EcCurve, PublicKey};
pub use verify::{MAX_CHAIN_DEPTH, TrustAnchor, VerifyError, check_validity, verify_chain, verify_signature};
