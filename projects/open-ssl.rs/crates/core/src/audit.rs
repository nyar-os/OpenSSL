use serde::Serialize;

/// Stable capability ids shared by the native boundary, CLI, skills, and audit.
pub mod capability_ids {
    /// Report the capability table.
    pub const CAPABILITIES: &str = "capabilities";
    /// Report the product and native versions.
    pub const VERSION: &str = "version";
    /// Query local audit records.
    pub const AUDIT_QUERY: &str = "audit-query";
    /// Configure audit actor resolution.
    pub const AUDIT_CONFIGURE: &str = "audit-configure";
    /// Host the WebView GUI.
    pub const GUI: &str = "gui";

    /// Parse and display an X.509 certificate.
    pub const CERTIFICATE_INSPECT: &str = "certificate-inspect";
    /// Issue a certificate from a CA.
    pub const CERTIFICATE_ISSUE: &str = "certificate-issue";
    /// Renew a certificate with an idempotent reissue policy.
    pub const CERTIFICATE_RENEW: &str = "certificate-renew";
    /// Revoke a certificate and publish a CRL.
    pub const CERTIFICATE_REVOKE: &str = "certificate-revoke";
    /// Create and manage a root or intermediate CA.
    pub const CA_CREATE: &str = "ca-create";
    /// Build and validate a certificate signing request.
    pub const CSR_CREATE: &str = "csr-create";
    /// Generate, protect, import, and export private keys.
    pub const PRIVATE_KEY_STORE: &str = "private-key-store";
    /// Enumerate and manage the local certificate store.
    pub const CERTIFICATE_STORE: &str = "certificate-store";
    /// Manage certificates on a remote computer through the first-party agent.
    pub const REMOTE_AGENT: &str = "remote-agent";

    /// Install the host integration and desktop entry.
    pub const HOST_INSTALL: &str = "host-install";
    /// Remove the host integration and clean residual state.
    pub const HOST_UNINSTALL: &str = "host-uninstall";
}

/// Audit fields recorded at the native boundary.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFields {
    /// Stable capability id.
    pub capability: String,
    /// Number of targets in the call.
    pub target_count: usize,
    /// Redacted target summary. Never contains credentials, private keys, or full remote addresses.
    pub target_summary: String,
}

impl AuditFields {
    /// Build redacted audit fields for one capability call.
    pub fn new(capability: impl Into<String>, target_count: usize, target_summary: impl Into<String>) -> Self {
        Self { capability: capability.into(), target_count, target_summary: target_summary.into() }
    }
}
