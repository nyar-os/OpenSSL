//! base64url, JWK thumbprints, and ES256 JWS construction for ACME requests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use signature::Signer;

use crate::errors::{Error, ErrorCode, Result};

/// base64url without padding, as required by RFC 8555 §6.3.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The SHA-256 JWK thumbprint of an already canonical JWK string (RFC 8555 §8.1, RFC 7638).
pub fn jwk_thumbprint(canonical_jwk: &str) -> String {
    b64url(&Sha256::digest(canonical_jwk.as_bytes()))
}

/// The ES256 account key used for JWS signatures and dns-01 key authorizations.
#[derive(Debug, Clone)]
pub struct AccountKey {
    signing: SigningKey,
}

impl AccountKey {
    /// Generate a fresh P-256 account key from the system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self { signing: crate::csr::generate_p256_key() }
    }

    /// Adopt an existing P-256 signing key.
    #[must_use]
    pub fn from_signing_key(signing: SigningKey) -> Self {
        Self { signing }
    }

    /// The JWK object with only the required members `crv`, `kty`, `x`, `y`.
    fn jwk_value(&self) -> Value {
        let point = self.signing.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut members = Map::new();
        members.insert("crv".to_owned(), Value::String("P-256".to_owned()));
        members.insert("kty".to_owned(), Value::String("EC".to_owned()));
        members.insert("x".to_owned(), Value::String(b64url(&bytes[1..33])));
        members.insert("y".to_owned(), Value::String(b64url(&bytes[33..65])));
        Value::Object(members)
    }

    /// The canonical JWK used for the thumbprint: required members only, lexicographic order.
    #[must_use]
    pub fn canonical_jwk(&self) -> String {
        self.jwk_value().to_string()
    }

    /// The account key fingerprint: `base64url(SHA-256(canonical JWK))`.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        jwk_thumbprint(&self.canonical_jwk())
    }

    /// The dns-01 key authorization string `token '.' thumbprint` for one challenge token.
    #[must_use]
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }
}

/// How a JWS identifies the ACME account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountRef {
    /// Self-certify with the embedded JWK, used before the account exists.
    Jwk,
    /// Reference the created account by its URL.
    Kid(String),
}

/// Build the flattened JWS JSON document for one ACME request.
///
/// `payload_json` is the raw JSON body, or the empty string for a POST-as-GET.
pub fn build_jws(key: &AccountKey, account: &AccountRef, url: &str, nonce: &str, payload_json: &str) -> Result<String> {
    let mut protected = Map::new();
    protected.insert("alg".to_owned(), Value::String("ES256".to_owned()));
    protected.insert("aud".to_owned(), Value::String(url.to_owned()));
    match account {
        AccountRef::Jwk => {
            protected.insert("jwk".to_owned(), key.jwk_value());
        }
        AccountRef::Kid(kid) => {
            protected.insert("kid".to_owned(), Value::String(kid.clone()));
        }
    }
    protected.insert("nonce".to_owned(), Value::String(nonce.to_owned()));
    protected.insert("url".to_owned(), Value::String(url.to_owned()));

    let protected = b64url(Value::Object(protected).to_string().as_bytes());
    let payload = b64url(payload_json.as_bytes());
    let signature: Signature = key.signing.sign(format!("{protected}.{payload}").as_bytes());

    let mut document = Map::new();
    document.insert("protected".to_owned(), Value::String(protected));
    document.insert("payload".to_owned(), Value::String(payload));
    document.insert("signature".to_owned(), Value::String(b64url(&signature.to_bytes())));
    serde_json::to_string(&Value::Object(document)).map_err(|error| Error::new(ErrorCode::Internal, error.to_string()))
}
