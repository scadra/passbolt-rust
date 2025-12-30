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

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    secret: String,
    offset_secs: i64,
    retry_delay: Duration,
    asked: AtomicBool,
}

impl AutoTotpProvider {
    pub const fn new(secret: String, offset_secs: i64, retry_delay: Duration) -> Self {
        Self {
            secret,
            offset_secs,
            retry_delay,
            asked: AtomicBool::new(false),
        }
    }
}

impl MfaProvider for AutoTotpProvider {
    fn get_totp_code(&self) -> Result<String, PassboltError> {
        if self.asked.swap(true, Ordering::Relaxed) {
            std::thread::sleep(self.retry_delay);
        }
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

    // Unchecked: 80-bit secrets (Google Authenticator's default) are below the RFC's 128-bit advice.
    let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes);

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
    fn test_auto_totp_provider_waits_only_before_a_retry() {
        let retry_delay = Duration::from_millis(200);
        let provider = AutoTotpProvider::new(RFC_6238_SECRET.into(), 0, retry_delay);

        let started = std::time::Instant::now();
        provider.get_totp_code().unwrap();
        assert!(started.elapsed() < retry_delay);
        provider.get_totp_code().unwrap();
        assert!(started.elapsed() >= retry_delay);
    }

    #[test]
    fn test_generate_totp_rejects_a_secret_that_is_not_base32() {
        let error = generate_totp("not base32!", 0, 59).unwrap_err();

        assert!(error.to_string().contains("base32"), "{error}");
    }
}
