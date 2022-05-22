use super::cert::Certificate;

/// Match a DNS name against the certificate's subjectAltName entries.
///
/// Wildcards are only honored as the complete leftmost label (`*.example.com`),
/// matching exactly one label, per RFC 6125 and the CA/Browser Forum baseline.
/// The common name is never consulted when a SAN exists, and this product
/// requires a SAN for TLS server certificates.
pub fn matches_dns(cert: &Certificate<'_>, hostname: &str) -> bool {
    if cert.extensions.dns_names.is_empty() {
        return false;
    }
    let hostname = hostname.to_ascii_lowercase();
    if hostname.is_empty() || !hostname.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')) {
        return false;
    }
    cert.extensions.dns_names.iter().any(|pattern| match_pattern(pattern, &hostname))
}

fn match_pattern(pattern: &str, hostname: &str) -> bool {
    if hostname.contains('*') {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let Some((label, rest)) = hostname.split_once('.')
        else {
            return false;
        };
        !label.is_empty() && rest == suffix && !suffix.contains("*")
    }
    else {
        pattern == hostname
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_single_label() {
        assert!(match_pattern("*.wxtoken.work", "api.wxtoken.work"));
        assert!(!match_pattern("*.wxtoken.work", "wxtoken.work"));
        assert!(!match_pattern("*.wxtoken.work", "a.b.wxtoken.work"));
        assert!(!match_pattern("*.wxtoken.work", "*.wxtoken.work"));
    }

    #[test]
    fn exact_and_case_insensitive() {
        assert!(match_pattern("wxtoken.work", "wxtoken.work"));
        assert!(match_pattern("wxtoken.work", "WXTOKEN.WORK".to_ascii_lowercase().as_str()));
        assert!(!match_pattern("wxtoken.work", "example.work"));
    }

    #[test]
    fn leftmost_only() {
        assert!(!match_pattern("a.*.wxtoken.work", "a.b.wxtoken.work"));
    }
}
