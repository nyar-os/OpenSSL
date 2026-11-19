//! TLS 1.3 X25519 key exchange and the RFC 8446 §7.1 key schedule.

use super::{TlsError, TlsResult};
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Nonce},
};
use core::fmt;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

/// An X25519 client key pair kept across a HelloRetryRequest.
pub struct KeyPair {
    secret: StaticSecret,
    public: [u8; 32],
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("KeyPair").field("public", &self.public).finish()
    }
}

impl KeyPair {
    /// Generate a fresh ephemeral pair from the system CSPRNG.
    pub fn generate() -> TlsResult<Self> {
        let mut bytes = [0u8; 32];
        boost_random::Secure::system().fill(&mut bytes).map_err(TlsError::Entropy)?;
        let secret = StaticSecret::from(bytes);
        let public = XPublicKey::from(&secret);
        Ok(Self { secret, public: public.to_bytes() })
    }

    /// The public value sent in `key_share`.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The 32-byte ECDH shared secret.
    pub fn shared(&self, peer: &[u8; 32]) -> [u8; 32] {
        self.secret.diffie_hellman(&XPublicKey::from(*peer)).to_bytes()
    }
}

/// X25519 on raw bytes, for vector testing.
pub fn shared_from(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret).diffie_hellman(&XPublicKey::from(*peer)).to_bytes()
}

/// HKDF-Extract with the given salt.
pub fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

/// `Derive-Secret` from RFC 8446.
pub fn derive_secret(secret: &[u8], label: &str, context: &[u8]) -> [u8; 32] {
    let out = expand_label(secret, label, context, 32);
    out.as_slice().try_into().expect("32 bytes")
}

/// `HKDF-Expand-Label` from RFC 8446 §7.1.
pub fn expand_label(secret: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(3 + full_label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("secret is a valid PRK");
    let mut out = vec![0u8; length];
    hkdf.expand(&info, &mut out).expect("expansion length is valid");
    out
}

/// One direction of the AEAD record protection state.
#[derive(Debug, Clone, Copy)]
pub struct TrafficKey {
    key: [u8; 16],
    iv: [u8; 12],
    sequence: u64,
}

impl TrafficKey {
    /// Derive the key and IV from a traffic secret.
    pub fn from_secret(secret: &[u8]) -> Self {
        let key_bytes = expand_label(secret, "key", &[], 16);
        let iv_bytes = expand_label(secret, "iv", &[], 12);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        key.copy_from_slice(&key_bytes);
        iv.copy_from_slice(&iv_bytes);
        Self { key, iv, sequence: 0 }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.sequence.to_be_bytes();
        for (index, byte) in seq.iter().enumerate() {
            nonce[4 + index] ^= byte;
        }
        self.sequence += 1;
        nonce
    }

    /// Encrypt one record payload, returning the ciphertext with tag appended.
    pub fn seal(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte key");
        let nonce = self.next_nonce();
        let nonce = Nonce::<Aes128Gcm>::from(nonce);
        cipher.encrypt(&nonce, aes_gcm::aead::Payload { msg: plaintext, aad }).expect("AES-GCM encrypt")
    }

    /// Decrypt one record payload.
    pub fn open(&mut self, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let cipher = Aes128Gcm::new_from_slice(&self.key).expect("16-byte key");
        let nonce = self.next_nonce();
        let nonce = Nonce::<Aes128Gcm>::from(nonce);
        cipher.decrypt(&nonce, aes_gcm::aead::Payload { msg: ciphertext, aad }).ok()
    }

    /// Reset the sequence counter after a key update.
    pub fn advance(&mut self, new_secret: &[u8]) {
        *self = Self::from_secret(new_secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn expand_label_is_deterministic() {
        let secret = [7u8; 32];
        let first = derive_secret(&secret, "finished", &[0u8; 32]);
        let again = derive_secret(&secret, "finished", &[0u8; 32]);
        assert_eq!(hex(&first), hex(&again));
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn expand_label_lengths_and_contexts() {
        let secret = [1u8; 32];
        assert_eq!(expand_label(&secret, "key", &[], 16).len(), 16);
        assert_eq!(expand_label(&secret, "iv", &[], 12).len(), 12);
        let with_context = derive_secret(&secret, "c hs traffic", b"hash");
        let other = derive_secret(&secret, "c hs traffic", b"other");
        assert_ne!(with_context, other);
    }

    #[test]
    fn x25519_shared_secret_is_symmetric() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        assert_eq!(a.shared(b.public()), b.shared(a.public()));
    }

    #[test]
    fn traffic_key_seal_open_round_trip() {
        let secret = [42u8; 32];
        let mut client = TrafficKey::from_secret(&secret);
        let mut server = TrafficKey::from_secret(&secret);
        let aad = [0x17u8, 0x03, 0x03, 0x00, 0x05];
        let sealed = client.seal(b"hello", &aad);
        let opened = server.open(&sealed, &aad).expect("open");
        assert_eq!(opened, b"hello");
    }

    #[test]
    fn sequence_nonce_advances() {
        let secret = [9u8; 32];
        let mut key = TrafficKey::from_secret(&secret);
        let aad = [0x16u8, 0x03, 0x03, 0x00, 0x01];
        let first = key.seal(b"a", &aad);
        let second = key.seal(b"a", &aad);
        assert_ne!(first, second, "nonce must advance per record");
    }
}
