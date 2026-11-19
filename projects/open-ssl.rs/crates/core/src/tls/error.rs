use core::fmt;

/// Why a TLS connection or handshake failed.
#[derive(Debug)]
pub enum TlsError {
    /// Transport failure.
    Io(std::io::Error),
    /// The peer closed the TCP connection at a clean record boundary without
    /// `close_notify`. Reads surface this as end of stream.
    Eof,
    /// The peer violated the protocol or used an unsupported construct.
    Protocol(String),
    /// The peer sent a fatal alert.
    Alert(u8),
    /// Certificate chain or hostname validation failed.
    Certificate(String),
    /// A required primitive is not supported by this build.
    Unsupported(String),
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "tls transport error: {error}"),
            Self::Eof => write!(formatter, "tls connection closed at record boundary"),
            Self::Protocol(detail) => write!(formatter, "tls protocol error: {detail}"),
            Self::Alert(code) => write!(formatter, "tls alert from peer: {code}"),
            Self::Certificate(detail) => write!(formatter, "tls certificate error: {detail}"),
            Self::Unsupported(detail) => write!(formatter, "tls unsupported: {detail}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<std::io::Error> for TlsError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<data_binary_asn1::DerError> for TlsError {
    fn from(error: data_binary_asn1::DerError) -> Self {
        Self::Protocol(error.to_string())
    }
}

/// The result type shared by the `tls` module.
pub type TlsResult<T> = core::result::Result<T, TlsError>;
