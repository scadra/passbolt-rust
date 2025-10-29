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

// WASM is single-threaded — futures don't need Send, and wasm_bindgen requires owned params.
#![allow(clippy::future_not_send, clippy::needless_pass_by_value)]

//! Passbolt SDK — WASM binding for browser extensions.
//!
//! Exports `PassboltSession` for authenticated API operations and
//! stateless crypto functions for progressive openpgp.js replacement.

mod http;

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::error::PassboltError;
use passbolt_sdk::types::{SecretData, TotpData};
use passbolt_sdk::PassboltSdk;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::http::WasmHttpClient;

type Client = PassboltSdk<WasmHttpClient>;

// ── Error conversion ─────────────────────────────────────────────────────────

fn to_js_error(e: PassboltError) -> JsError {
    JsError::new(&e.to_string())
}

fn to_js_value<T: serde::Serialize>(val: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(val).map_err(|error| JsError::new(&error.to_string()))
}

/// Decrypted secret as exposed to JS.
///
/// `SecretData.raw` is not serialized by the SDK, so the password of a
/// "password-string" resource is folded into `password` here.
#[derive(Serialize)]
struct JsSecretData {
    password: Option<String>,
    description: Option<String>,
    totp: Option<TotpData>,
}

impl From<SecretData> for JsSecretData {
    fn from(secret: SecretData) -> Self {
        Self {
            password: secret.password.or(secret.raw),
            description: secret.description,
            totp: secret.totp,
        }
    }
}

fn build_sdk_config(
    server_url: String,
    private_key_armored: String,
    passphrase: String,
) -> SdkConfig {
    SdkConfig {
        server_url,
        private_key_armored,
        passphrase: secrecy::SecretString::from(passphrase),
        mfa_mode: String::new(),
        mfa_totp_token: String::new(),
        mfa_totp_offset: 0,
        mfa_retrys: 0,
        tls_skip_verify: false,
        tls_client_cert: String::new(),
        tls_client_private_key: String::new(),
        proxy: String::new(),
        server_verify_enc_token: String::new(),
        server_verify_token: String::new(),
    }
}

// ── PassboltSession ──────────────────────────────────────────────────────────

/// Authenticated Passbolt session for CRUD operations.
///
/// Usage from JS:
/// ```js
/// const session = await PassboltSession.login(serverUrl, privateKey, passphrase);
/// const resources = await session.listResources();
/// await session.logout();
/// ```
#[wasm_bindgen]
pub struct PassboltSession {
    client: Client,
}

#[wasm_bindgen]
impl PassboltSession {
    /// Authenticate against a Passbolt server and return a session.
    #[wasm_bindgen]
    pub async fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
    ) -> Result<Self, JsError> {
        let http = WasmHttpClient::new();
        let config = build_sdk_config(server_url, private_key_armored, passphrase);

        let client = Client::login(http, &config, None, 3)
            .await
            .map_err(to_js_error)?;

        Ok(Self { client })
    }

    /// Terminate the server-side session.
    #[wasm_bindgen]
    pub async fn logout(&self) {
        self.client.logout().await;
    }

    /// Check if the session is still valid.
    #[wasm_bindgen(js_name = "checkAuth")]
    pub async fn check_auth(&self) -> Result<bool, JsError> {
        self.client.check_auth_status().await.map_err(to_js_error)
    }

    // ── Resources ────────────────────────────────────────────────────────

    /// List all resources (with secrets and permissions).
    #[wasm_bindgen(js_name = "listResources")]
    pub async fn list_resources(&self, search: Option<String>) -> Result<JsValue, JsError> {
        let query = passbolt_sdk::ResourceQuery {
            search,
            ..Default::default()
        };
        let resources = self
            .client
            .get_resources(query)
            .await
            .map_err(to_js_error)?;
        to_js_value(&resources)
    }

    /// Get a single resource by ID.
    #[wasm_bindgen(js_name = "getResource")]
    pub async fn get_resource(&self, id: String) -> Result<JsValue, JsError> {
        let resource = self.client.get_resource(&id).await.map_err(to_js_error)?;
        to_js_value(&resource)
    }

    /// Decrypt a resource's secret. Returns the plaintext secret data as JSON.
    #[wasm_bindgen(js_name = "decryptResourceSecret")]
    pub async fn decrypt_resource_secret(&self, resource_js: JsValue) -> Result<JsValue, JsError> {
        let resource: passbolt_sdk::types::Resource =
            serde_wasm_bindgen::from_value(resource_js)
                .map_err(|error| JsError::new(&format!("Invalid resource: {error}")))?;
        let secret = self
            .client
            .decrypt_resource_secret(&resource)
            .await
            .map_err(to_js_error)?;
        to_js_value(&JsSecretData::from(secret))
    }

    /// Delete a resource.
    #[wasm_bindgen(js_name = "deleteResource")]
    pub async fn delete_resource(&self, id: String) -> Result<(), JsError> {
        self.client.delete_resource(&id).await.map_err(to_js_error)
    }

    // ── Folders ──────────────────────────────────────────────────────────

    /// List all folders.
    #[wasm_bindgen(js_name = "listFolders")]
    pub async fn list_folders(&self) -> Result<JsValue, JsError> {
        let folders = self
            .client
            .get_folders(passbolt_sdk::FolderQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&folders)
    }

    /// Get a single folder by ID.
    #[wasm_bindgen(js_name = "getFolder")]
    pub async fn get_folder(&self, id: String) -> Result<JsValue, JsError> {
        let folder = self.client.get_folder(&id).await.map_err(to_js_error)?;
        to_js_value(&folder)
    }

    // ── Users ────────────────────────────────────────────────────────────

    /// List all users.
    #[wasm_bindgen(js_name = "listUsers")]
    pub async fn list_users(&self) -> Result<JsValue, JsError> {
        let users = self
            .client
            .get_users(passbolt_sdk::UserQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&users)
    }

    /// Get the currently logged-in user.
    #[wasm_bindgen(js_name = "getMe")]
    pub async fn get_me(&self) -> Result<JsValue, JsError> {
        let me = self.client.get_me().await.map_err(to_js_error)?;
        to_js_value(&me)
    }

    // ── Groups ───────────────────────────────────────────────────────────

    /// List all groups.
    #[wasm_bindgen(js_name = "listGroups")]
    pub async fn list_groups(&self) -> Result<JsValue, JsError> {
        let groups = self
            .client
            .get_groups(passbolt_sdk::GroupQuery::default())
            .await
            .map_err(to_js_error)?;
        to_js_value(&groups)
    }

    // ── Tags ─────────────────────────────────────────────────────────────

    /// List all tags.
    #[wasm_bindgen(js_name = "getTags")]
    pub async fn get_tags(&self) -> Result<JsValue, JsError> {
        let tags = self.client.get_tags().await.map_err(to_js_error)?;
        to_js_value(&tags)
    }

    // ── Comments ─────────────────────────────────────────────────────────

    /// Get comments for a resource.
    #[wasm_bindgen(js_name = "getComments")]
    pub async fn get_comments(&self, resource_id: String) -> Result<JsValue, JsError> {
        let comments = self
            .client
            .get_comments(&resource_id)
            .await
            .map_err(to_js_error)?;
        to_js_value(&comments)
    }

    /// Create a comment on a resource.
    #[wasm_bindgen(js_name = "createComment")]
    pub async fn create_comment(
        &self,
        resource_id: String,
        content: String,
        parent_id: Option<String>,
    ) -> Result<JsValue, JsError> {
        let comment = self
            .client
            .create_comment(&resource_id, &content, parent_id.as_deref())
            .await
            .map_err(to_js_error)?;
        to_js_value(&comment)
    }

    // ── Sharing ──────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) for sharing.
    #[wasm_bindgen(js_name = "searchAros")]
    pub async fn search_aros(&self, search: String) -> Result<JsValue, JsError> {
        let aros = self
            .client
            .search_aros(&search)
            .await
            .map_err(to_js_error)?;
        to_js_value(&aros)
    }

    // ── HIBP ─────────────────────────────────────────────────────────────

    /// Check if a password has been exposed in data breaches.
    /// Returns the number of times found (0 = not breached).
    #[wasm_bindgen(js_name = "checkPasswordPwned")]
    pub async fn check_password_pwned(&self, password: String) -> Result<u64, JsError> {
        self.client
            .check_password_pwned(&password)
            .await
            .map_err(to_js_error)
    }
}

// ── Stateless crypto functions ───────────────────────────────────────────────

/// Decrypt a PGP-armored message with a private key.
/// For progressive openpgp.js replacement.
#[wasm_bindgen(js_name = "decryptMessage")]
pub fn decrypt_message(
    armored_message: &str,
    private_key_armored: &str,
    passphrase: &str,
) -> Result<Vec<u8>, JsError> {
    let key = passbolt_sdk::crypto::parse_private_key(private_key_armored)
        .map_err(|error| JsError::new(&error.to_string()))?;
    passbolt_sdk::crypto::decrypt_message(armored_message, &key.key, passphrase)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Encrypt a plaintext message for one or more PGP public keys.
/// Returns the PGP-armored ciphertext.
#[wasm_bindgen(js_name = "encryptMessage")]
pub fn encrypt_message(
    plaintext: &[u8],
    public_keys_armored: Vec<String>,
) -> Result<String, JsError> {
    let parsed: Result<Vec<_>, _> = public_keys_armored
        .iter()
        .map(|armored_key| passbolt_sdk::crypto::parse_public_key(armored_key))
        .collect();
    let keys = parsed.map_err(|error| JsError::new(&error.to_string()))?;
    let key_refs: Vec<_> = keys.iter().collect();
    passbolt_sdk::crypto::encrypt_message(plaintext, &key_refs)
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[wasm_bindgen(js_name = "getKeyFingerprint")]
pub fn get_key_fingerprint(private_key_armored: &str) -> Result<String, JsError> {
    let key = passbolt_sdk::crypto::parse_private_key(private_key_armored)
        .map_err(|error| JsError::new(&error.to_string()))?;
    Ok(key.fingerprint.clone())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use secrecy::ExposeSecret;
    use serde_json::json;

    use super::*;

    const SERVER_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_public.asc");

    fn secret(password: Option<&str>, raw: Option<&str>) -> SecretData {
        SecretData {
            password: password.map(String::from),
            raw: raw.map(String::from),
            ..SecretData::default()
        }
    }

    #[rstest]
    #[case::password_string(None, Some("raw password"), Some("raw password"))]
    #[case::json_secret(Some("json password"), None, Some("json password"))]
    #[case::password_wins_over_raw(Some("json password"), Some("raw"), Some("json password"))]
    #[case::empty(None, None, None)]
    fn test_js_secret_data_password_falls_back_to_raw(
        #[case] password: Option<&str>,
        #[case] raw: Option<&str>,
        #[case] expected: Option<&str>,
    ) {
        let js_secret = JsSecretData::from(secret(password, raw));

        assert_eq!(js_secret.password.as_deref(), expected);
    }

    #[test]
    fn test_js_secret_data_serializes_password_of_password_string_resource() {
        let js_secret = JsSecretData::from(secret(None, Some("raw password")));

        let serialized = serde_json::to_value(&js_secret).unwrap();

        assert_eq!(
            serialized,
            json!({ "password": "raw password", "description": null, "totp": null })
        );
    }

    #[test]
    fn test_js_secret_data_keeps_description_and_totp() {
        let secret_data: SecretData = serde_json::from_value(json!({
            "password": "pw",
            "description": "note",
            "totp": { "secret_key": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30, "issuer": null }
        }))
        .unwrap();

        let serialized = serde_json::to_value(JsSecretData::from(secret_data)).unwrap();

        assert_eq!(serialized["description"], "note");
        assert_eq!(serialized["totp"]["secret_key"], "JBSWY3DPEHPK3PXP");
        assert_eq!(serialized["totp"]["digits"], 6);
    }

    #[test]
    fn test_build_sdk_config_copies_credentials_without_mfa_or_tls_bypass() {
        let config = build_sdk_config(
            "https://passbolt.test".into(),
            "armored key".into(),
            "secret passphrase".into(),
        );

        assert_eq!(config.server_url, "https://passbolt.test");
        assert_eq!(config.private_key_armored, "armored key");
        assert_eq!(config.passphrase.expose_secret(), "secret passphrase");
        assert_eq!(config.mfa_mode, "");
        assert!(!config.tls_skip_verify);
        assert_eq!(config.proxy, "");
    }

    #[test]
    fn test_encrypt_then_decrypt_message_round_trips() {
        let armored = encrypt_message(b"top secret", vec![SERVER_PUBLIC.into()]).unwrap();

        let plaintext = decrypt_message(&armored, SERVER_PRIVATE, "").unwrap();

        assert_eq!(plaintext, b"top secret");
    }

    #[test]
    fn test_get_key_fingerprint_is_uppercase_hex() {
        let fingerprint = get_key_fingerprint(SERVER_PRIVATE).unwrap();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| matches!(character, '0'..='9' | 'A'..='F')));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    const SERVER_PRIVATE: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/server_private.asc");
    const BETTY_PUBLIC: &str =
        include_str!("../../passbolt-sdk/tests/fixtures/keys/betty_public.asc");

    #[wasm_bindgen_test]
    fn test_decrypt_message_with_wrong_key_is_error() {
        let armored = encrypt_message(b"for betty", vec![BETTY_PUBLIC.into()]).unwrap();

        let result = decrypt_message(&armored, SERVER_PRIVATE, "");

        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn test_js_secret_data_exposes_raw_password_to_js() {
        let secret = SecretData {
            raw: Some("raw password".into()),
            ..SecretData::default()
        };

        let value = to_js_value(&JsSecretData::from(secret)).unwrap();

        let password = js_sys::Reflect::get(&value, &"password".into()).unwrap();
        assert_eq!(password.as_string().as_deref(), Some("raw password"));
    }
}
