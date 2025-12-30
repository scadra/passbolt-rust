// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use std::time::{SystemTime, UNIX_EPOCH};

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::error::PassboltError;
use passbolt_sdk::MfaProvider;
use totp_rs::{Algorithm, Secret, TOTP};

pub const NON_INTERACTIVE_TOTP: &str = "non-interactive-totp";

/// Non-interactive MFA: generates the TOTP code from a base32 secret.
pub struct TotpSecretProvider {
    secret: String,
    offset_seconds: i64,
}

impl TotpSecretProvider {
    /// Provider for the `non-interactive-totp` mode, `None` for any other mode.
    pub fn from_config(config: &SdkConfig) -> Option<Self> {
        (config.mfa_mode == NON_INTERACTIVE_TOTP).then(|| Self {
            secret: config.mfa_totp_token.clone(),
            offset_seconds: config.mfa_totp_offset,
        })
    }

    fn code_at(&self, unix_seconds: u64) -> Result<String, PassboltError> {
        let secret_bytes = Secret::Encoded(self.secret.clone())
            .to_bytes()
            .map_err(|error| {
                PassboltError::Other(format!("Invalid TOTP secret (must be base32): {error}"))
            })?;
        let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
            .map_err(|error| PassboltError::Other(format!("Failed to create TOTP: {error}")))?;
        Ok(totp.generate(unix_seconds))
    }
}

impl MfaProvider for TotpSecretProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        let now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PassboltError::Other(format!("System clock error: {error}")))?
            .as_secs();
        let adjusted_seconds = if self.offset_seconds >= 0 {
            now_seconds.saturating_add(self.offset_seconds.unsigned_abs())
        } else {
            now_seconds.saturating_sub(self.offset_seconds.unsigned_abs())
        };
        self.code_at(adjusted_seconds)
    }
}

impl Drop for TotpSecretProvider {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 SHA1 seed "12345678901234567890" in base32.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn provider(secret: &str) -> TotpSecretProvider {
        TotpSecretProvider {
            secret: secret.into(),
            offset_seconds: 0,
        }
    }

    #[test]
    fn test_code_at_matches_rfc_6238_vector() {
        let code = provider(RFC_SECRET).code_at(59).unwrap();

        assert_eq!(code, "287082");
    }

    #[test]
    fn test_code_at_rejects_non_base32_secret() {
        let error = provider("not base32!").code_at(59).unwrap_err();

        assert!(error.to_string().contains("base32"), "{error}");
    }

    #[test]
    fn test_get_totp_code_returns_six_digits() {
        let code = provider(RFC_SECRET).get_totp_code().unwrap();

        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|character| character.is_ascii_digit()));
    }
}
