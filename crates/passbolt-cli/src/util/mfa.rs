use std::time::{SystemTime, UNIX_EPOCH};

use passbolt_sdk::error::PassboltError;
use passbolt_sdk::MfaProvider;

/// Interactive MFA: prompts the user via terminal.
pub struct TerminalMfaProvider;

impl MfaProvider for TerminalMfaProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        rpassword::prompt_password("TOTP code: ")
            .map_err(|e| PassboltError::Other(format!("Failed to read TOTP code: {e}")))
    }
}

/// Non-interactive MFA: generates TOTP from a base32 secret.
pub struct AutoTotpProvider {
    pub secret: String,
    pub offset_secs: i64,
}

impl MfaProvider for AutoTotpProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        generate_totp(&self.secret, self.offset_secs)
    }
}

/// Generate a TOTP code from a base32 secret + optional clock offset.
fn generate_totp(secret: &str, offset_secs: i64) -> Result<String, PassboltError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| PassboltError::Other(format!("Invalid TOTP secret (must be base32): {e}")))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| PassboltError::Other(format!("Failed to create TOTP: {e}")))?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PassboltError::Other(format!("System clock error: {e}")))?
        .as_secs();

    // Safe: now_secs (epoch seconds) fits in i64 until year 292 billion
    #[allow(clippy::cast_possible_wrap)]
    let now_signed = now_secs as i64;
    #[allow(clippy::cast_sign_loss)]
    let adjusted = now_signed.saturating_add(offset_secs).max(0) as u64;
    Ok(totp.generate(adjusted))
}
