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

use percent_encoding::percent_decode_str;
use serde_json::Value;
use zeroize::Zeroize;

use crate::crypto::{decrypt_message, PrivateKey};
use crate::error::{AuthError, CryptoError, PassboltError};
use crate::http::HttpClient;
use crate::mfa::MfaProvider;

/// Result of a successful login — CSRF token and user ID.
pub struct AuthTokens {
    pub csrf_token: String,
    pub user_id: String,
}

impl Drop for AuthTokens {
    fn drop(&mut self) {
        self.csrf_token.zeroize();
        self.user_id.zeroize();
    }
}

/// MFA configuration (CLI-oriented).
///
/// SDK consumers that don't use the config file can pass `MfaProvider` directly.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct MfaConfig {
    pub mode: String,
    pub totp_token: secrecy::SecretString,
    pub totp_offset: i64,
    pub retrys: u32,
}

/// Perform the full Passbolt GPG challenge-response login (cookie-based).
pub async fn login<H: HttpClient>(
    http: &H,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
    mfa_provider: Option<&dyn MfaProvider>,
    max_attempts: u32,
) -> Result<AuthTokens, PassboltError> {
    let url = format!("{base_url}/auth/login.json");

    // Step 1: send fingerprint, receive encrypted challenge in header
    let init_body = serde_json::json!({
        "gpg_auth": { "keyid": private_key.fingerprint }
    });
    let json_bytes = serde_json::to_vec(&init_body)?;

    let response = http.post(&url, &[], &json_bytes).await?;

    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);

    if response.status >= 400 {
        let message = body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown error");
        return Err(AuthError::LoginFailed(format!(
            "Login initiation failed ({}): {message}",
            response.status
        ))
        .into());
    }

    // Extract challenge from response header
    let challenge_encoded = response
        .header("X-GPGAuth-User-Auth-Token")
        .ok_or_else(|| {
            AuthError::LoginFailed("Server did not return X-GPGAuth-User-Auth-Token header".into())
        })?
        .to_string();

    let encrypted_challenge = decode_auth_token_header(&challenge_encoded)?;

    // Step 2: decrypt the challenge
    let decrypted =
        decrypt_message(&encrypted_challenge, &private_key.key, passphrase).map_err(|error| {
            AuthError::LoginFailed(format!("Failed to decrypt server challenge: {error}"))
        })?;
    let token = String::from_utf8(decrypted)
        .map_err(|error| {
            AuthError::LoginFailed(format!("Decrypted challenge is not valid UTF-8: {error}"))
        })?
        .trim()
        .to_owned();

    // Step 3: send decrypted token to complete auth
    let verify_body = serde_json::json!({
        "gpg_auth": {
            "keyid": private_key.fingerprint,
            "user_token_result": token
        }
    });
    let verify_bytes = serde_json::to_vec(&verify_body)?;

    let verify_response = http.post(&url, &[], &verify_bytes).await?;

    // Handle MFA challenge (403)
    if verify_response.status == 403 {
        let mfa_body: Value = serde_json::from_slice(&verify_response.body).unwrap_or(Value::Null);
        let is_mfa = mfa_body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .is_none_or(|message| message.to_lowercase().contains("mfa"));

        if is_mfa {
            if let Some(provider) = mfa_provider {
                return handle_mfa_login(http, base_url, provider, max_attempts).await;
            }
            return Err(AuthError::MfaRequired.into());
        }
        let message = mfa_body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Forbidden");
        return Err(AuthError::LoginFailed(format!("Login failed (403): {message}")).into());
    }

    if verify_response.status >= 400 {
        let error_body: Value =
            serde_json::from_slice(&verify_response.body).unwrap_or(Value::Null);
        let message = error_body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown error");
        return Err(AuthError::LoginFailed(format!(
            "Login verification failed ({}): {message}",
            verify_response.status
        ))
        .into());
    }

    extract_auth_tokens(&verify_response)
}

/// Inverse of PHP `quotemeta(urlencode($armored))`, how the server sends the challenge.
fn decode_auth_token_header(encoded: &str) -> Result<String, AuthError> {
    let unquoted = encoded.replace('\\', "").replace('+', " ");
    percent_decode_str(&unquoted)
        .decode_utf8()
        .map(Into::into)
        .map_err(|error| {
            AuthError::LoginFailed(format!("Invalid X-GPGAuth-User-Auth-Token header: {error}"))
        })
}

/// Handle MFA by using the provided `MfaProvider` to obtain TOTP codes.
async fn handle_mfa_login<H: HttpClient>(
    http: &H,
    base_url: &str,
    provider: &dyn MfaProvider,
    max_attempts: u32,
) -> Result<AuthTokens, PassboltError> {
    let mfa_url = format!("{base_url}/mfa/verify/totp.json");

    for attempt in 0..max_attempts {
        let code = provider.get_totp_code()?;

        let body =
            serde_json::to_vec(&serde_json::json!({ "totp": code, "remember_device": false }))?;

        let response = http.post(&mfa_url, &[], &body).await?;

        if response.status < 400 {
            return extract_auth_tokens(&response);
        }

        let response_body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        let message = response_body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("MFA failed");

        if attempt + 1 >= max_attempts {
            return Err(AuthError::MfaFailed {
                attempts: max_attempts,
                message: message.to_string(),
            }
            .into());
        }
    }

    unreachable!()
}

/// Extract CSRF token and `user_id` from a successful login/MFA response.
fn extract_auth_tokens(response: &crate::http::HttpResponse) -> Result<AuthTokens, PassboltError> {
    let csrf_from_header = response.header("X-CSRF-Token").map(str::to_owned);

    // Check for csrfToken cookie in our custom set-cookie-name headers
    let csrf_from_cookie = response
        .headers_by_name("set-cookie-name")
        .iter()
        .find(|cookie| cookie.starts_with("csrfToken="))
        .map(|cookie| cookie.strip_prefix("csrfToken=").unwrap_or("").to_owned());

    let body: Value = serde_json::from_slice(&response.body)?;

    let csrf_from_body = body
        .pointer("/body/csrfToken")
        .and_then(|value| value.as_str())
        .map(str::to_owned);

    let csrf_token = csrf_from_header
        .or(csrf_from_cookie)
        .or(csrf_from_body)
        .unwrap_or_default();

    let user_id = body
        .pointer("/body/user/id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_owned();

    Ok(AuthTokens {
        csrf_token,
        user_id,
    })
}

/// Verify server identity via GET /auth/verify.json.
pub async fn verify_server<H: HttpClient>(
    http: &H,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
) -> Result<(String, String), PassboltError> {
    let url = format!("{base_url}/auth/verify.json");
    let response = http.get(&url, &[]).await?;

    let body: Value = serde_json::from_slice(&response.body)?;

    let fingerprint = body
        .pointer("/body/fingerprint")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AuthError::LoginFailed("Server did not return fingerprint".into()))?
        .to_string();

    let encrypted_challenge = body
        .pointer("/body/challenge")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();

    let decrypted_token = if encrypted_challenge.is_empty() {
        String::new()
    } else {
        let decrypted = decrypt_message(&encrypted_challenge, &private_key.key, passphrase)
            .map_err(|error| CryptoError::Decrypt(format!("server verify challenge: {error}")))?;
        String::from_utf8(decrypted)
            .map_err(|error| {
                PassboltError::Other(format!("Server verify token is not valid UTF-8: {error}"))
            })?
            .trim()
            .to_string()
    };

    Ok((fingerprint, decrypted_token))
}

/// Check stored server identity tokens before login.
pub async fn check_server_identity<H: HttpClient>(
    http: &H,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
    stored_fingerprint: &str,
    stored_token: &str,
) -> Result<(), PassboltError> {
    if stored_fingerprint.is_empty() && stored_token.is_empty() {
        return Ok(());
    }

    let (fingerprint, plain_token) = verify_server(http, base_url, private_key, passphrase).await?;

    if !stored_fingerprint.is_empty() && fingerprint != stored_fingerprint {
        return Err(AuthError::ServerIdentityMismatch(format!(
            "expected {stored_fingerprint}, got {fingerprint}"
        ))
        .into());
    }

    if !stored_token.is_empty() && !plain_token.is_empty() && plain_token != stored_token {
        return Err(
            AuthError::ServerIdentityMismatch("server verify token mismatch".into()).into(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::quotemeta_space("BEGIN\\+PGP\\+MESSAGE", "BEGIN PGP MESSAGE")]
    #[case::quotemeta_dot("Version%3A\\+1\\.0", "Version: 1.0")]
    #[case::base64_plus("ab%2Bcd%2F%3D", "ab+cd/=")]
    #[case::literal_backslash("a%5Cb", "a\\b")]
    #[case::newline("line1%0Aline2", "line1\nline2")]
    fn test_decode_auth_token_header(#[case] header: &str, #[case] expected: &str) {
        assert_eq!(decode_auth_token_header(header).unwrap(), expected);
    }

    #[test]
    fn test_decode_auth_token_header_invalid_utf8() {
        assert!(decode_auth_token_header("%FF").is_err());
    }
}
