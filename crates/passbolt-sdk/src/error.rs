use thiserror::Error;

// ── Module-level error types ─────────────────────────────────────────────────

/// Transport-level errors from the HTTP layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Request timed out: {0}")]
    Timeout(String),
}

/// Authentication errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("Login failed: {0}")]
    LoginFailed(String),

    #[error("MFA required")]
    MfaRequired,

    #[error("MFA verification failed after {attempts} attempt(s): {message}")]
    MfaFailed { attempts: u32, message: String },

    #[error("Session expired")]
    SessionExpired,

    #[error("Server identity mismatch: {0}")]
    ServerIdentityMismatch(String),

    #[error("Post-login key cross-check failed")]
    KeyCrossCheckFailed,
}

/// Cryptographic operation errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Failed to parse PGP key: {0}")]
    KeyParse(String),

    #[error("PGP decryption failed: {0}")]
    Decrypt(String),

    #[error("PGP encryption failed: {0}")]
    Encrypt(String),
}

/// Structured API error with optional validation details.
#[derive(Debug, Error)]
#[error("API error ({status}): {message}")]
pub struct ApiError {
    pub status: u16,
    pub message: String,
    pub validation_errors: Option<serde_json::Value>,
}

// ── Aggregator ───────────────────────────────────────────────────────────────

/// SDK-level error type for all Passbolt operations.
///
/// `#[non_exhaustive]` ensures downstream callers use wildcard patterns,
/// allowing us to add variants without breaking API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PassboltError {
    #[error(transparent)]
    Transport(#[from] TransportError),

    #[error(transparent)]
    Auth(#[from] AuthError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Api(#[from] ApiError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("{0}")]
    Other(String),
}

/// Transition helper: convert any `anyhow::Error` into `PassboltError::Other`.
impl From<anyhow::Error> for PassboltError {
    fn from(err: anyhow::Error) -> Self {
        Self::Other(format!("{err:#}"))
    }
}
