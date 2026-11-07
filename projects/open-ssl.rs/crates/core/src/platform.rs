use crate::{audit::capability_ids, errors::CapabilityState};
use serde::Serialize;

/// The host platform reported by the native crate.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    /// Operating system constant such as `windows`.
    pub os: &'static str,
    /// Architecture constant such as `x86_64`.
    pub arch: &'static str,
}

/// One row in the capability matrix.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityItem {
    /// Stable capability id.
    pub id: &'static str,
    /// `null` when the capability is available, otherwise one of the three states.
    pub state: Option<CapabilityState>,
    /// Stable error code matching `state`. `null` when available.
    pub code: Option<&'static str>,
    /// Why the capability is unavailable.
    pub reason: &'static str,
    /// What the capability does once implemented.
    pub detail: &'static str,
}

impl CapabilityItem {
    /// Whether the capability can be invoked on this host right now.
    pub const fn is_available(&self) -> bool {
        self.state.is_none()
    }
}

/// The full capability report returned to CLI, GUI, and agents.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesReport {
    /// Product name.
    pub app: &'static str,
    /// Current host platform.
    pub platform: PlatformInfo,
    /// Native package version.
    pub version: &'static str,
    /// Every registered capability, including unavailable rows.
    pub items: Vec<CapabilityItem>,
    /// Contract notes that apply to the whole table.
    pub notes: Vec<&'static str>,
}

impl CapabilitiesReport {
    /// Look up a capability row by its stable id.
    pub fn get(&self, id: &str) -> Option<&CapabilityItem> {
        self.items.iter().find(|item| item.id == id)
    }
}

const SKELETON_REASON: &str = "The skeleton round registers the capability but does not implement it.";

const DOMAIN: &[(&str, &str)] = &[
    (capability_ids::CERTIFICATE_INSPECT, "Parse X.509, ASN.1, DER, and PEM input and display a normalized certificate view."),
    (capability_ids::CERTIFICATE_ISSUE, "Sign a CSR with a CA and write the issued certificate without external tools."),
    (capability_ids::CERTIFICATE_RENEW, "Reissue a certificate from the same key or a new key with an idempotent policy."),
    (capability_ids::CERTIFICATE_REVOKE, "Revoke a certificate and publish a CRL with an explicit reason code."),
    (capability_ids::CA_CREATE, "Create and manage a root or intermediate CA with its own key protection."),
    (capability_ids::CSR_CREATE, "Build and validate a certificate signing request with key usage and extensions."),
    (capability_ids::PRIVATE_KEY_STORE, "Generate, protect, import, and export private keys through CNG or a DPAPI container."),
    (capability_ids::CERTIFICATE_STORE, "Enumerate, import, and export certificates in the local Windows store."),
    (capability_ids::REMOTE_AGENT, "Manage certificates on a remote computer through the first-party agent channel."),
    (capability_ids::HOST_INSTALL, "Install the host integration and desktop entry."),
    (capability_ids::HOST_UNINSTALL, "Remove the host integration and clean residual state."),
];

const META: &[(&str, &str)] = &[
    (capability_ids::CAPABILITIES, "Report the capability matrix."),
    (capability_ids::VERSION, "Report product and native versions."),
    (capability_ids::AUDIT_QUERY, "Query local audit records."),
    (capability_ids::AUDIT_CONFIGURE, "Resolve and configure the audit actor."),
];

/// Current host platform.
pub const fn platform() -> PlatformInfo {
    PlatformInfo { os: std::env::consts::OS, arch: std::env::consts::ARCH }
}

/// Build the capability report. Domain rows stay unavailable in the skeleton round.
pub fn capabilities() -> CapabilitiesReport {
    let mut items = Vec::with_capacity(DOMAIN.len() + META.len());
    for (id, detail) in META {
        items.push(CapabilityItem { id, state: None, code: None, reason: "available", detail });
    }
    for (id, detail) in DOMAIN {
        items.push(CapabilityItem {
            id,
            state: Some(CapabilityState::NotImplemented),
            code: Some("not_implemented"),
            reason: SKELETON_REASON,
            detail,
        });
    }
    CapabilitiesReport {
        app: "open-ssl",
        platform: platform(),
        version: env!("CARGO_PKG_VERSION"),
        items,
        notes: vec![
            "Domain capabilities are intentionally not_implemented in this skeleton round.",
            "Capability, version, audit, and GUI meta capabilities are available.",
            "Remote channels reuse the product-owned TLS stack. No capability may fall back to an external openssl, certutil, certreq, or PowerShell process.",
        ],
    }
}
