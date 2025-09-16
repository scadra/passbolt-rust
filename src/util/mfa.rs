// Passbolt ~ Open source password manager for teams
// Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::error::PassboltError;

/// Trait for providing MFA TOTP codes during authentication.
///
/// Synchronous because both interactive (rpassword) and non-interactive
/// (TOTP generation) implementations are CPU-only.
pub trait MfaProvider: Send + Sync {
    fn get_totp_code(&self) -> Result<String, PassboltError>;
}

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

    let adjusted = (now_secs as i64 + offset_secs) as u64;
    Ok(totp.generate(adjusted))
}
