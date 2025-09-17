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
use reqwest::{Client, Response};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::api::crypto::{decrypt_message, PrivateKey};
use crate::api::error::PassboltError;
use crate::util::mfa::MfaProvider;

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

/// MFA configuration passed into the login flow.
///
/// `ZeroizeOnDrop` ensures the TOTP secret is wiped from memory after use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MfaConfig {
    /// "interactive-totp" | "non-interactive-totp" | "none"
    pub mode: String,
    /// Base32 TOTP secret (for non-interactive mode)
    pub totp_token: secrecy::SecretString,
    /// Clock offset in seconds
    pub totp_offset: i64,
    /// Number of retry attempts
    pub retrys: u32,
}

/// Result of parsing MfaConfig into a provider + retry count.
pub struct MfaSettings {
    pub provider: Option<Box<dyn MfaProvider>>,
    pub max_attempts: u32,
}

impl MfaConfig {
    /// Convert MfaConfig into a MfaProvider + max_attempts for the auth flow.
    pub fn into_settings(self) -> MfaSettings {
        use secrecy::ExposeSecret;
        let provider: Option<Box<dyn MfaProvider>> = match self.mode.as_str() {
            "none" => None,
            "non-interactive-totp" => Some(Box::new(crate::util::mfa::AutoTotpProvider {
                secret: self.totp_token.expose_secret().to_string(),
                offset_secs: self.totp_offset,
            })),
            _ => Some(Box::new(crate::util::mfa::TerminalMfaProvider)),
        };
        MfaSettings {
            provider,
            max_attempts: self.retrys.max(1),
        }
    }
}

/// Perform the full Passbolt GPG challenge-response login (cookie-based).
///
/// Protocol:
/// 1. POST /auth/login.json  { gpg_auth: { keyid } }
///    → Response header X-GPGAuth-User-Auth-Token: <URL-encoded encrypted challenge>
/// 2. URL-decode the header, decrypt with user private key
/// 3. POST /auth/login.json  { gpg_auth: { keyid, user_token_result: <decrypted> } }
///    → Server sets passbolt_session cookie + CSRF token
/// 4. If 403 and MFA required → handle TOTP then retry
pub async fn login(
    client: &Client,
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

    let resp = client
        .post(&url)
        .json(&init_body)
        .send()
        .await
        .map_err(|e| PassboltError::Http(format!("Failed to connect to Passbolt server: {e}")))?;

    let status = resp.status();

    // Extract header before consuming body
    let challenge_raw = resp
        .headers()
        .get("X-GPGAuth-User-Auth-Token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let body: Value = resp.json().await.unwrap_or(Value::Null);

    if !status.is_success() {
        let msg = body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(PassboltError::LoginFailed(format!(
            "Login initiation failed ({status}): {msg}"
        )));
    }

    let challenge_encoded = challenge_raw.ok_or_else(|| {
        PassboltError::LoginFailed("Server did not return X-GPGAuth-User-Auth-Token header".into())
    })?;

    // Percent-decode the header value; also convert `+` to space (form-encoding).
    let encrypted_challenge = percent_decode_str(&challenge_encoded)
        .decode_utf8_lossy()
        .replace('+', " ");

    // Step 2: decrypt the challenge
    let decrypted =
        decrypt_message(&encrypted_challenge, &private_key.key, passphrase).map_err(|e| {
            PassboltError::LoginFailed(format!("Failed to decrypt server challenge: {e}"))
        })?;
    let token = String::from_utf8(decrypted)
        .map_err(|e| {
            PassboltError::LoginFailed(format!("Decrypted challenge is not valid UTF-8: {e}"))
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

    let verify_resp = client
        .post(&url)
        .json(&verify_body)
        .send()
        .await
        .map_err(|e| PassboltError::Http(format!("Failed to send token verification: {e}")))?;

    let verify_status = verify_resp.status();

    // Handle MFA challenge (403)
    if verify_status == reqwest::StatusCode::FORBIDDEN {
        let mfa_body: Value = verify_resp.json().await.unwrap_or(Value::Null);
        let is_mfa = mfa_body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .map(|m| m.to_lowercase().contains("mfa"))
            .unwrap_or(true); // assume MFA if we get 403

        if is_mfa {
            if let Some(provider) = mfa_provider {
                return handle_mfa_login(client, base_url, provider, max_attempts).await;
            }
            return Err(PassboltError::MfaRequired);
        }
        let msg = mfa_body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .unwrap_or("Forbidden");
        return Err(PassboltError::LoginFailed(format!(
            "Login failed (403): {msg}"
        )));
    }

    if !verify_status.is_success() {
        let err_body: Value = verify_resp.json().await.unwrap_or(Value::Null);
        let msg = err_body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        return Err(PassboltError::LoginFailed(format!(
            "Login verification failed ({verify_status}): {msg}"
        )));
    }

    extract_auth_tokens(verify_resp).await
}

/// Handle MFA by using the provided `MfaProvider` to obtain TOTP codes.
async fn handle_mfa_login(
    client: &Client,
    base_url: &str,
    provider: &dyn MfaProvider,
    max_attempts: u32,
) -> Result<AuthTokens, PassboltError> {
    let mfa_url = format!("{base_url}/mfa/verify/totp.json");

    for attempt in 0..max_attempts {
        let code = provider.get_totp_code()?;

        let resp = client
            .post(&mfa_url)
            .json(&serde_json::json!({ "totp": code, "remember_device": false }))
            .send()
            .await
            .map_err(|e| PassboltError::Http(format!("Failed to send MFA verification: {e}")))?;

        let status = resp.status();
        if status.is_success() {
            return extract_auth_tokens(resp).await;
        }

        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let msg = body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .unwrap_or("MFA failed");

        if attempt + 1 < max_attempts {
            eprintln!("MFA attempt {} failed: {msg}. Retrying...", attempt + 1);
        } else {
            return Err(PassboltError::MfaFailed {
                attempts: max_attempts,
                message: msg.to_string(),
            });
        }
    }

    unreachable!()
}

/// Extract CSRF token and user_id from a successful login/MFA response.
async fn extract_auth_tokens(resp: Response) -> Result<AuthTokens, PassboltError> {
    // CSRF token: check X-CSRF-Token header first, then cookies, then body
    let csrf_from_header = resp
        .headers()
        .get("X-CSRF-Token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let csrf_from_cookie = resp
        .cookies()
        .find(|c| c.name() == "csrfToken")
        .map(|c| c.value().to_owned());

    let body: Value = resp
        .json()
        .await
        .map_err(|e| PassboltError::Http(format!("Failed to parse login response: {e}")))?;

    let csrf_from_body = body
        .pointer("/body/csrfToken")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let csrf_token = csrf_from_header
        .or(csrf_from_cookie)
        .or(csrf_from_body)
        .unwrap_or_default();

    let user_id = body
        .pointer("/body/user/id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();

    Ok(AuthTokens {
        csrf_token,
        user_id,
    })
}

/// Verify server identity via GET /auth/verify.json.
///
/// Returns (fingerprint, decrypted_challenge_token).
/// Used by the `verify` subcommand to establish initial trust.
pub async fn verify_server(
    client: &Client,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
) -> Result<(String, String), PassboltError> {
    let url = format!("{base_url}/auth/verify.json");
    let resp = client.get(&url).send().await.map_err(|e| {
        PassboltError::Http(format!("Failed to connect for server verification: {e}"))
    })?;

    let body: Value = resp
        .json()
        .await
        .map_err(|e| PassboltError::Http(format!("Failed to parse server verify response: {e}")))?;

    let fingerprint = body
        .pointer("/body/fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PassboltError::LoginFailed("Server did not return fingerprint".into()))?
        .to_string();

    let enc_challenge = body
        .pointer("/body/challenge")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let decrypted_token = if !enc_challenge.is_empty() {
        let dec = decrypt_message(&enc_challenge, &private_key.key, passphrase)
            .map_err(|e| PassboltError::PgpDecrypt(format!("server verify challenge: {e}")))?;
        String::from_utf8(dec)
            .map_err(|e| {
                PassboltError::Other(format!("Server verify token is not valid UTF-8: {e}"))
            })?
            .trim()
            .to_string()
    } else {
        String::new()
    };

    Ok((fingerprint, decrypted_token))
}

/// Check stored server identity tokens before login.
///
/// `stored_fingerprint` = cfg.server_verify_enc_token (confusingly named but stores fingerprint)
/// `stored_token` = cfg.server_verify_token (decrypted challenge stored from last verify)
pub async fn check_server_identity(
    client: &Client,
    base_url: &str,
    private_key: &PrivateKey,
    passphrase: &str,
    stored_fingerprint: &str,
    stored_token: &str,
) -> Result<(), PassboltError> {
    if stored_fingerprint.is_empty() && stored_token.is_empty() {
        return Ok(()); // no stored tokens → skip check
    }

    let (fingerprint, plain_token) =
        verify_server(client, base_url, private_key, passphrase).await?;

    if !stored_fingerprint.is_empty() && fingerprint != stored_fingerprint {
        return Err(PassboltError::ServerIdentityMismatch(format!(
            "expected {stored_fingerprint}, got {fingerprint}"
        )));
    }

    if !stored_token.is_empty() && !plain_token.is_empty() && plain_token != stored_token {
        return Err(PassboltError::ServerIdentityMismatch(
            "server verify token mismatch".into(),
        ));
    }

    Ok(())
}
