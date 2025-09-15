use crate::error::PassboltError;

/// Trait for providing MFA TOTP codes during authentication.
///
/// Synchronous because both interactive (rpassword) and non-interactive
/// (TOTP generation) implementations are CPU-only.
pub trait MfaProvider: Send + Sync {
    fn get_totp_code(&self) -> Result<String, PassboltError>;
}
