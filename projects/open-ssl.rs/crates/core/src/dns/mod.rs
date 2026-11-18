//! DNS-01 record placement behind a provider-neutral abstraction.
//!
//! [`DnsProvider`] implementations replace the `_acme-challenge.` TXT record for one
//! fqdn idempotently. [`Manual`] is the fallback that hands the record back for a human
//! to place; [`cloudflare::Cloudflare`] is the first API adapter.

pub mod cloudflare;
pub mod credentials;

use crate::errors::{Error, ErrorCode, Result};

/// The label every dns-01 TXT record is placed under.
const CHALLENGE_LABEL: &str = "_acme-challenge";

/// One TXT record a provider must place or remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRecord {
    /// The fully qualified record name, for example `_acme-challenge.example.test`.
    pub fqdn: String,
    /// The TXT value: the key authorization string.
    pub value: String,
}

/// A provider that can place dns-01 TXT records.
pub trait DnsProvider {
    /// Place the TXT record for one challenge fqdn, replacing any previous value idempotently.
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord>;

    /// Remove every TXT record placed for one challenge fqdn.
    fn delete_txt(&mut self, fqdn: &str) -> Result<()>;
}

/// The dns-01 record name for one domain.
pub fn challenge_fqdn(domain: &str) -> String {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    format!("{CHALLENGE_LABEL}.{domain}")
}

/// The zone a challenge fqdn belongs to: the fqdn without the `_acme-challenge.` label.
pub fn zone_name(fqdn: &str) -> Result<&str> {
    let zone = fqdn
        .strip_prefix(&format!("{CHALLENGE_LABEL}."))
        .filter(|zone| !zone.is_empty())
        .ok_or_else(|| Error::new(ErrorCode::InvalidArgument, format!("`{fqdn}` is not an `_acme-challenge.` record name")))?;
    Ok(zone)
}

/// The fallback provider: records are kept for a human to place by hand.
#[derive(Debug, Default)]
pub struct Manual {
    placed: Vec<TxtRecord>,
}

impl Manual {
    /// Create an empty manual provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The records currently awaiting manual placement.
    pub fn pending_records(&self) -> &[TxtRecord] {
        &self.placed
    }
}

impl DnsProvider for Manual {
    fn put_txt(&mut self, fqdn: &str, value: &str) -> Result<TxtRecord> {
        zone_name(fqdn)?;
        let record = TxtRecord { fqdn: fqdn.to_owned(), value: value.to_owned() };
        self.placed.retain(|placed| placed.fqdn != fqdn);
        self.placed.push(record.clone());
        Ok(record)
    }

    fn delete_txt(&mut self, fqdn: &str) -> Result<()> {
        zone_name(fqdn)?;
        self.placed.retain(|placed| placed.fqdn != fqdn);
        Ok(())
    }
}
