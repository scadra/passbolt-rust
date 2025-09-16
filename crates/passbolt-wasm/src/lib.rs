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
use passbolt_sdk::PassboltSdk;
use wasm_bindgen::prelude::*;

use crate::http::WasmHttpClient;

type Client = PassboltSdk<WasmHttpClient>;

// ── Error conversion ─────────────────────────────────────────────────────────

fn to_js_error(e: PassboltError) -> JsError {
    JsError::new(&e.to_string())
}

fn to_js_value<T: serde::Serialize>(val: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(val).map_err(|e| JsError::new(&e.to_string()))
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
        let cfg = SdkConfig {
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
        };

        let client = Client::login(http, &cfg, None, 3)
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
                .map_err(|e| JsError::new(&format!("Invalid resource: {e}")))?;
        let secret = self
            .client
            .decrypt_resource_secret(&resource)
            .await
            .map_err(to_js_error)?;
        to_js_value(&secret)
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
        .map_err(|e| JsError::new(&e.to_string()))?;
    passbolt_sdk::crypto::decrypt_message(armored_message, &key.key, passphrase)
        .map_err(|e| JsError::new(&e.to_string()))
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
        .map(|k| passbolt_sdk::crypto::parse_public_key(k))
        .collect();
    let keys = parsed.map_err(|e| JsError::new(&e.to_string()))?;
    let key_refs: Vec<_> = keys.iter().collect();
    passbolt_sdk::crypto::encrypt_message(plaintext, &key_refs)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[wasm_bindgen(js_name = "getKeyFingerprint")]
pub fn get_key_fingerprint(private_key_armored: &str) -> Result<String, JsError> {
    let key = passbolt_sdk::crypto::parse_private_key(private_key_armored)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.fingerprint.clone())
}
