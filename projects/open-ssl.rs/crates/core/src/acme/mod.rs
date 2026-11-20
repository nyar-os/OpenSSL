//! RFC 8555 ACME automation lives in the family crate `boost.net`.
//!
//! The protocol — directory documents, nonces, ES256 JWS, order and challenge
//! resources, `dns-01` TXT material, and `Retry-After`-aware polling — is owned
//! by [`boost_net::acme`] and shared with the other OpenX TLS products. This
//! product keeps account and leaf key persistence, DNS provider adapters,
//! certificate delivery, renewal state, and every interactive decision.

pub use boost_net::acme::*;

/// Path kept for callers and tests that import `acme::types::*`.
pub mod types {
    pub use boost_net::acme::types::*;
}
