//! The TLS record layer: framing, AEAD protection, and fragmentation.

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use super::{
    error::{TlsError, TlsResult},
    kx::TrafficKey,
};

/// Maximum plaintext bytes per record (RFC 8446 §5.2).
pub const MAX_FRAGMENT: usize = 16_384;
/// AEAD tag length for TLS_AES_128_GCM_SHA256.
const TAG_LEN: usize = 16;

/// A buffered TCP wire that reads and writes TLS records.
#[derive(Debug)]
pub struct Wire {
    stream: TcpStream,
    pending: Vec<u8>,
}

impl Wire {
    /// Wrap a connected stream.
    pub const fn new(stream: TcpStream) -> Self {
        Self { stream, pending: Vec::new() }
    }

    fn fill(&mut self, need: usize) -> TlsResult<()> {
        while self.pending.len() < need {
            let mut chunk = [0u8; 8_192];
            let read = self.stream.read(&mut chunk)?;
            if read == 0 {
                if self.pending.is_empty() {
                    return Err(TlsError::Eof);
                }
                return Err(TlsError::Protocol("connection closed mid-record".to_string()));
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
        Ok(())
    }

    /// Read one record, returning its type and content.
    pub fn read_record(&mut self) -> TlsResult<(u8, Vec<u8>)> {
        self.fill(5)?;
        let record_type = self.pending[0];
        let length = usize::from(u16::from_be_bytes([self.pending[3], self.pending[4]]));
        if length > MAX_FRAGMENT + TAG_LEN + 1 {
            return Err(TlsError::Protocol(format!("oversized record length {length}")));
        }
        self.fill(5 + length)?;
        let body = self.pending[5..5 + length].to_vec();
        self.pending.drain(..5 + length);
        Ok((record_type, body))
    }

    /// Write one plaintext record.
    pub fn write_record(&mut self, record_type: u8, body: &[u8]) -> TlsResult<()> {
        self.write_record_version(record_type, 0x03, 0x03, body)
    }

    /// Write one plaintext record with an explicit legacy record version.
    pub fn write_record_version(&mut self, record_type: u8, major: u8, minor: u8, body: &[u8]) -> TlsResult<()> {
        let mut frame = Vec::with_capacity(5 + body.len());
        frame.extend_from_slice(&[record_type, major, minor]);
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(body);
        self.stream.write_all(&frame)?;
        Ok(())
    }

    /// Write one encrypted record with the inner content type appended.
    pub fn write_encrypted(&mut self, key: &mut TrafficKey, inner_type: u8, body: &[u8]) -> TlsResult<()> {
        let mut plaintext = Vec::with_capacity(body.len() + 1);
        plaintext.extend_from_slice(body);
        plaintext.push(inner_type);
        // The AAD carries the transmitted record length: plaintext plus the AEAD tag.
        let sealed_length = plaintext.len() + TAG_LEN;
        let aad = [0x17u8, 0x03, 0x03, (sealed_length as u16 >> 8) as u8, sealed_length as u16 as u8];
        let sealed = key.seal(&plaintext, &aad);
        self.write_record(0x17, &sealed)
    }

    /// Read one encrypted record, decrypt it, and return the inner type plus payload.
    pub fn read_encrypted(&mut self, key: &mut TrafficKey) -> TlsResult<(u8, Vec<u8>)> {
        let (record_type, body) = self.read_record()?;
        if record_type == 0x14 && body.len() == 1 && body[0] == 0x01 {
            return self.read_encrypted(key);
        }
        if record_type != 0x17 {
            return Err(TlsError::Protocol(format!("unexpected record type {record_type} after encryption")));
        }
        let aad = [0x17u8, 0x03, 0x03, (body.len() as u16 >> 8) as u8, body.len() as u16 as u8];
        let opened = key.open(&body, &aad).ok_or_else(|| TlsError::Protocol("record authentication failed".to_string()))?;
        let inner_type = *opened.last().ok_or_else(|| TlsError::Protocol("empty encrypted record".to_string()))?;
        Ok((inner_type, opened[..opened.len() - 1].to_vec()))
    }

    /// Flush the socket.
    pub fn flush(&mut self) -> TlsResult<()> {
        self.stream.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::kx::TrafficKey;
    use std::net::TcpListener;

    #[test]
    fn encrypted_round_trip_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let secret = [3u8; 32];
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut wire = Wire::new(stream);
            let mut key = TrafficKey::from_secret(&secret);
            let (inner, body) = wire.read_encrypted(&mut key).expect("read");
            (inner, body)
        });
        let mut wire = Wire::new(TcpStream::connect(address).expect("connect"));
        let mut key = TrafficKey::from_secret(&secret);
        wire.write_encrypted(&mut key, 0x17, b"payload").expect("write");
        wire.flush().expect("flush");
        let (inner, body) = handle.join().expect("join");
        assert_eq!(inner, 0x17);
        assert_eq!(body, b"payload");
    }
}
