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

use passbolt_sdk::error::PassboltError;
use passbolt_sdk::MfaProvider;

/// Interactive MFA: prompts the user via terminal.
pub struct TerminalMfaProvider;

impl MfaProvider for TerminalMfaProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        rpassword::prompt_password("TOTP code: ")
            .map_err(|error| PassboltError::Other(format!("Failed to read TOTP code: {error}")))
    }
}

/// Non-interactive MFA: generates TOTP from a base32 secret.
pub struct AutoTotpProvider {
    pub secret: String,
    pub offset_secs: i64,
}

impl MfaProvider for AutoTotpProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PassboltError::Other(format!("System clock error: {error}")))?
            .as_secs();
        generate_totp(&self.secret, self.offset_secs, now)
    }
}

/// Generate the TOTP code of a base32 secret at `now` (epoch seconds) shifted by `offset_secs`.
fn generate_totp(secret: &str, offset_secs: i64, now: u64) -> Result<String, PassboltError> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|error| {
            PassboltError::Other(format!("Invalid TOTP secret (must be base32): {error}"))
        })?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|error| PassboltError::Other(format!("Failed to create TOTP: {error}")))?;

    let adjusted = now.saturating_add_signed(offset_secs);
    Ok(totp.generate(adjusted))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 SHA-1 seed "12345678901234567890", base32-encoded.
    const RFC_6238_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[rstest::rstest]
    #[case(59, "287082")]
    #[case(1_111_111_109, "081804")]
    #[case(1_111_111_111, "050471")]
    #[case(1_234_567_890, "005924")]
    #[case(2_000_000_000, "279037")]
    #[case(20_000_000_000, "353130")]
    fn test_generate_totp_matches_the_rfc_6238_vectors(#[case] now: u64, #[case] expected: &str) {
        assert_eq!(generate_totp(RFC_6238_SECRET, 0, now).unwrap(), expected);
    }

    #[test]
    fn test_generate_totp_applies_a_positive_offset() {
        assert_eq!(
            generate_totp(RFC_6238_SECRET, 1_111_111_109 - 59, 59).unwrap(),
            "081804"
        );
    }

    #[test]
    fn test_generate_totp_applies_a_negative_offset() {
        assert_eq!(
            generate_totp(RFC_6238_SECRET, -(1_111_111_109 - 59), 1_111_111_109).unwrap(),
            "287082"
        );
    }

    #[test]
    fn test_generate_totp_rejects_a_secret_that_is_not_base32() {
        let error = generate_totp("not base32!", 0, 59).unwrap_err();

        assert!(error.to_string().contains("base32"), "{error}");
    }
}
