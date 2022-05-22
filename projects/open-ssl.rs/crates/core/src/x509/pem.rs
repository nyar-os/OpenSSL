use base64::{Engine, engine::general_purpose::STANDARD};

use crate::der::{DerError, DerErrorKind, DerResult};

/// The padded standard base64 engine used for PEM bodies.
const B64: base64::engine::general_purpose::GeneralPurpose = STANDARD;

/// Decode one PEM block with the given label, ignoring surrounding text.
pub fn pem_decode(label: &str, text: &str) -> DerResult<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin).ok_or_else(|| DerError::new(DerErrorKind::MalformedContent, 0))?;
    let rest = &text[start + begin.len()..];
    let stop = rest.find(&end).ok_or_else(|| DerError::new(DerErrorKind::MalformedContent, 0))?;
    let body: String = rest[..stop].chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    B64.decode(body).map_err(|_| DerError::new(DerErrorKind::MalformedContent, 0))
}

/// Encode DER bytes as a PEM block with 64-column wrapped base64.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let encoded = B64.encode(der);
    let mut out = String::with_capacity(encoded.len() + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Split a PEM bundle into every block with the given label.
pub fn pem_bundle(label: &str, text: &str) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(position) = rest.find(&format!("-----BEGIN {label}-----")) {
        rest = &rest[position..];
        match pem_decode(label, rest) {
            Ok(der) => {
                blocks.push(der);
                if let Some(stop) = rest.find(&format!("-----END {label}-----")) {
                    rest = &rest[stop..];
                }
            }
            Err(_) => break,
        }
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_round_trip() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x00];
        let text = pem_encode("CERTIFICATE", &der);
        assert!(text.contains("BEGIN CERTIFICATE"));
        assert_eq!(pem_decode("CERTIFICATE", &text).expect("decode"), der);
    }

    #[test]
    fn bundle_splits_multiple_blocks() {
        let a = pem_encode("CERTIFICATE", &[1, 2, 3]);
        let b = pem_encode("CERTIFICATE", &[4, 5, 6]);
        let bundle = format!("{a}{b}");
        let blocks = pem_bundle("CERTIFICATE", &bundle);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], vec![1, 2, 3]);
        assert_eq!(blocks[1], vec![4, 5, 6]);
    }

    #[test]
    fn decode_rejects_missing_markers() {
        assert!(pem_decode("CERTIFICATE", "not a pem").is_err());
    }
}
