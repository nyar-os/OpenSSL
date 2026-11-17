use super::*;

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::new(ErrorCode::Io, value.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::new(ErrorCode::Internal, value.to_string())
    }
}

impl From<boost_net::NetError> for Error {
    fn from(value: boost_net::NetError) -> Self {
        Self::new(ErrorCode::Network, value.to_string())
    }
}
