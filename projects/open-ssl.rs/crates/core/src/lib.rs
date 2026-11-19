#![deny(missing_debug_implementations, missing_copy_implementations)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]
#![doc = include_str!("../readme.md")]

/// RFC 8555 ACME automation over the family HTTP transport.
pub mod acme;
/// Stable capability ids and the audit summary vocabulary.
pub mod audit;
/// 项目签发配置：provider、zone、directory 与联系人的默认值。
pub mod config;
/// Product-owned PKCS#10 certificate signing requests.
pub mod csr;
/// 证书代交付：generation 清单、单一提交点与回滚。
pub mod delivery;
/// Product-owned ASN.1 DER codec.
pub mod der;
/// DNS-01 record placement, provider adapters, and project-scoped credentials.
pub mod dns;
/// 真实签发编排：账户、订单、DNS、挑战、CSR、下载与交付。
pub mod flow;
/// 账户密钥与叶子私钥的项目级持久化。
pub mod keys;
/// Capability states, stable error codes, and the structured error type.
pub mod errors;
/// 项目级签发锁：同一访问根下只允许一个签发流程。
pub mod lock;
/// Host platform descriptor and the capability report.
pub mod platform;
/// 项目私有签发状态与纯本地签发计划。
pub mod state;
/// Product-owned TLS 1.3 client.
pub mod tls;
/// Product-owned X.509 parsing, PEM, and chain policy.
pub mod x509;

pub use errors::{CapabilityState, Error, ErrorCode, Result};
