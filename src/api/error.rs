use thiserror::Error;

/// SDK-level error type for all Passbolt operations.
///
/// `#[non_exhaustive]` ensures downstream callers use wildcard patterns,
/// allowing us to add variants without breaking API.
// Some variants are reserved for future SDK use and will be populated
// as the anyhow→PassboltError migration progresses across all modules.
#[derive(Debug, Error)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum PassboltError {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },

    #[error("Login failed: {0}")]
    LoginFailed(String),

    #[error("MFA required")]
    MfaRequired,

    #[error("MFA verification failed after {attempts} attempt(s): {message}")]
    MfaFailed { attempts: u32, message: String },

    #[error("Server identity mismatch: {0}")]
    ServerIdentityMismatch(String),

    #[error("Failed to parse PGP key: {0}")]
    PgpKeyParse(String),

    #[error("PGP decryption failed: {0}")]
    PgpDecrypt(String),

    #[error("PGP encryption failed: {0}")]
    PgpEncrypt(String),

    #[error("Post-login key cross-check failed")]
    KeyCrossCheckFailed,

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
        PassboltError::Other(format!("{err:#}"))
    }
}
