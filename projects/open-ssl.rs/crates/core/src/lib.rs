#![deny(missing_debug_implementations, missing_copy_implementations)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![doc = include_str!("../readme.md")]

/// Stable capability ids and the audit summary vocabulary.
pub mod audit;
/// Product-owned PKCS#10 certificate signing requests.
pub mod csr;
/// Product-owned ASN.1 DER codec.
pub mod der;
/// Capability states, stable error codes, and the structured error type.
pub mod errors;
/// Host platform descriptor and the capability report.
pub mod platform;
/// Product-owned TLS 1.3 client.
pub mod tls;
/// Product-owned X.509 parsing, PEM, and chain policy.
pub mod x509;

pub use errors::{CapabilityState, Error, ErrorCode, Result};
