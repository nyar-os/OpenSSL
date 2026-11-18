//! RFC 8555 ACME automation: directory, nonces, JWS, accounts, orders, and issuance.
//!
//! The product owns the protocol automation; every HTTP request travels through
//! the family transport `boost.net::http`. [`client::AcmeClient`] is generic over
//! [`boost_net::http::Transport`] so conformance runs against loopback fixtures
//! without real network access.

pub mod client;
pub mod directory;
pub mod jws;
pub mod types;

pub use client::{AcmeClient, DnsChallenge, OrderPollVerdict, order_poll_verdict, retry_after_delay, txt_digest};
pub use directory::Directory;
pub use jws::{AccountKey, AccountRef, b64url, build_jws, jwk_thumbprint};
pub use types::{
    Account, AccountStatus, Authorization, AuthorizationStatus, Challenge, ChallengeStatus, ChallengeType, Identifier, Order, OrderStatus,
    Problem,
};
