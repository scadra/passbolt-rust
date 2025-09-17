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

// UniFFI requires owned types at the FFI boundary (no &str, &[u8] across FFI).
// Sync block_on wrappers are intentional; consumers dispatch from background threads.
#![allow(clippy::future_not_send, clippy::needless_pass_by_value)]

//! Passbolt SDK — Multi-language FFI bindings via `UniFFI`.
//!
//! Generates native bindings for Python, Kotlin (Android), Swift (iOS),
//! C#, and Ruby from a single Rust crate.
//!
//! ## Quick start (Python)
//! ```python
//! from passbolt_ffi import PassboltClient
//!
//! client = PassboltClient.login("https://passbolt.example.com", private_key, passphrase)
//! resources = client.list_resources(None, False, False)
//! client.logout()
//! ```

mod error;
mod types;

uniffi::setup_scaffolding!();

use std::sync::{Arc, LazyLock};

use passbolt_sdk::config::SdkConfig;
use passbolt_sdk::platform::native::{NativeHttpClient, NativeHttpConfig};
use passbolt_sdk::PassboltSdk;

use crate::error::PassboltFfiError;
use crate::types::{
    FfiAro, FfiComment, FfiFavorite, FfiFolder, FfiFolderQuery, FfiFolderTreeNode, FfiGroup,
    FfiGroupDeleteDryRun, FfiPasswordExpirySettings, FfiPermission, FfiResource, FfiResourceQuery,
    FfiSecretData, FfiTag, FfiUser, FfiUserDeleteDryRun, FfiUserQuery,
};

type Client = PassboltSdk<NativeHttpClient>;

/// Global tokio runtime for executing async SDK operations.
static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime")
});

// ── PassboltClient ──────────────────────────────────────────────────────────

/// Authenticated Passbolt client for CRUD operations.
///
/// All methods are synchronous at the FFI boundary; they block internally
/// on the tokio runtime. Call from background threads on mobile platforms.
#[derive(uniffi::Object)]
pub struct PassboltClient {
    inner: Client,
}

#[uniffi::export]
impl PassboltClient {
    // ── Auth ────────────────────────────────────────────────────────────

    /// Authenticate against a Passbolt server and return a client session.
    #[uniffi::constructor]
    pub fn login(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
    ) -> Result<Arc<Self>, PassboltFfiError> {
        Self::login_with_options(
            server_url,
            private_key_armored,
            passphrase,
            false,
            None,
            None,
        )
    }

    /// Authenticate with advanced TLS/proxy options.
    #[uniffi::constructor]
    pub fn login_with_options(
        server_url: String,
        private_key_armored: String,
        passphrase: String,
        tls_skip_verify: bool,
        proxy: Option<String>,
        mfa_totp_token: Option<String>,
    ) -> Result<Arc<Self>, PassboltFfiError> {
        RUNTIME.block_on(async {
            let http_cfg = NativeHttpConfig {
                tls_skip_verify,
                client_cert_pem: None,
                client_key_pem: None,
                proxy_url: proxy.clone(),
            };
            let http = NativeHttpClient::new(&http_cfg).map_err(|e| PassboltFfiError::Config {
                message: e.to_string(),
            })?;

            let cfg = SdkConfig {
                server_url,
                private_key_armored,
                passphrase: secrecy::SecretString::from(passphrase),
                mfa_mode: if mfa_totp_token.is_some() {
                    "non-interactive-totp".into()
                } else {
                    String::new()
                },
                mfa_totp_token: mfa_totp_token.unwrap_or_default(),
                mfa_totp_offset: 0,
                mfa_retrys: 3,
                tls_skip_verify,
                tls_client_cert: String::new(),
                tls_client_private_key: String::new(),
                proxy: proxy.unwrap_or_default(),
                server_verify_enc_token: String::new(),
                server_verify_token: String::new(),
            };

            let client = Client::login(http, &cfg, None, 3)
                .await
                .map_err(PassboltFfiError::from)?;

            Ok(Arc::new(Self { inner: client }))
        })
    }

    /// Terminate the server-side session.
    pub fn logout(&self) {
        RUNTIME.block_on(self.inner.logout());
    }

    /// Check if the session is still valid.
    pub fn check_auth(&self) -> Result<bool, PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.check_auth_status())
            .map_err(Into::into)
    }

    // ── Resources ───────────────────────────────────────────────────────

    /// List resources with optional search and filters.
    pub fn list_resources(
        &self,
        search: Option<String>,
        favorites_only: bool,
        owned_by_me: bool,
    ) -> Result<Vec<FfiResource>, PassboltFfiError> {
        let query = FfiResourceQuery {
            search,
            favorites_only,
            owned_by_me,
        };
        let resources = RUNTIME
            .block_on(self.inner.get_resources(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(resources.into_iter().map(FfiResource::from).collect())
    }

    /// Get a single resource by ID.
    pub fn get_resource(&self, id: String) -> Result<FfiResource, PassboltFfiError> {
        let resource = RUNTIME
            .block_on(self.inner.get_resource(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiResource::from(resource))
    }

    /// Get multiple resources by IDs.
    pub fn get_resources_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<FfiResource>, PassboltFfiError> {
        let resources = RUNTIME
            .block_on(self.inner.get_resources_by_ids(&ids))
            .map_err(PassboltFfiError::from)?;
        Ok(resources.into_iter().map(FfiResource::from).collect())
    }

    /// Decrypt a resource's secret. Pass the resource obtained from `get_resource`.
    pub fn decrypt_resource_secret(
        &self,
        resource_id: String,
    ) -> Result<FfiSecretData, PassboltFfiError> {
        RUNTIME.block_on(async {
            let resource = self
                .inner
                .get_resource(&resource_id)
                .await
                .map_err(PassboltFfiError::from)?;
            let secret = self
                .inner
                .decrypt_resource_secret(&resource)
                .await
                .map_err(PassboltFfiError::from)?;
            Ok(FfiSecretData::from(secret))
        })
    }

    /// Delete a resource.
    pub fn delete_resource(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_resource(&id))
            .map_err(Into::into)
    }

    /// Bulk delete resources.
    pub fn delete_resources(&self, ids: Vec<String>) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_resources(&ids))
            .map_err(Into::into)
    }

    /// Get permissions for a resource.
    pub fn get_resource_permissions(
        &self,
        id: String,
    ) -> Result<Vec<FfiPermission>, PassboltFfiError> {
        let perms = RUNTIME
            .block_on(self.inner.get_resource_permissions(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(perms.into_iter().map(FfiPermission::from).collect())
    }

    // ── Folders ─────────────────────────────────────────────────────────

    /// List all folders.
    pub fn list_folders(&self, search: Option<String>) -> Result<Vec<FfiFolder>, PassboltFfiError> {
        let query = FfiFolderQuery { search };
        let folders = RUNTIME
            .block_on(self.inner.get_folders(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(folders.into_iter().map(FfiFolder::from).collect())
    }

    /// Get a single folder by ID.
    pub fn get_folder(&self, id: String) -> Result<FfiFolder, PassboltFfiError> {
        let folder = RUNTIME
            .block_on(self.inner.get_folder(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiFolder::from(folder))
    }

    /// Delete a folder.
    pub fn delete_folder(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_folder(&id))
            .map_err(Into::into)
    }

    /// Build a folder tree from the flat folder list.
    pub fn get_folder_tree(&self) -> Result<Vec<FfiFolderTreeNode>, PassboltFfiError> {
        let folders = RUNTIME
            .block_on(self.inner.get_folders(passbolt_sdk::FolderQuery::default()))
            .map_err(PassboltFfiError::from)?;
        let tree = passbolt_sdk::build_folder_tree(&folders);
        Ok(tree.into_iter().map(FfiFolderTreeNode::from).collect())
    }

    // ── Users ───────────────────────────────────────────────────────────

    /// List all users.
    pub fn list_users(
        &self,
        search: Option<String>,
        group_id: Option<String>,
        admin_only: bool,
    ) -> Result<Vec<FfiUser>, PassboltFfiError> {
        let query = FfiUserQuery {
            search,
            group_id,
            admin_only,
        };
        let users = RUNTIME
            .block_on(self.inner.get_users(query.into()))
            .map_err(PassboltFfiError::from)?;
        Ok(users.into_iter().map(FfiUser::from).collect())
    }

    /// Get the currently logged-in user.
    pub fn get_me(&self) -> Result<FfiUser, PassboltFfiError> {
        let user = RUNTIME
            .block_on(self.inner.get_me())
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUser::from(user))
    }

    /// Get a user by ID.
    pub fn get_user(&self, id: String) -> Result<FfiUser, PassboltFfiError> {
        let user = RUNTIME
            .block_on(self.inner.get_user(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUser::from(user))
    }

    /// Delete a user.
    pub fn delete_user(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_user(&id))
            .map_err(Into::into)
    }

    /// Preview the impact of deleting a user.
    pub fn delete_user_dry_run(&self, id: String) -> Result<FfiUserDeleteDryRun, PassboltFfiError> {
        let result = RUNTIME
            .block_on(self.inner.delete_user_dry_run(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiUserDeleteDryRun::from(result))
    }

    // ── Groups ──────────────────────────────────────────────────────────

    /// List all groups.
    pub fn list_groups(&self) -> Result<Vec<FfiGroup>, PassboltFfiError> {
        let groups = RUNTIME
            .block_on(self.inner.get_groups(passbolt_sdk::GroupQuery::default()))
            .map_err(PassboltFfiError::from)?;
        Ok(groups.into_iter().map(FfiGroup::from).collect())
    }

    /// Get a group by ID.
    pub fn get_group(&self, id: String) -> Result<FfiGroup, PassboltFfiError> {
        let group = RUNTIME
            .block_on(self.inner.get_group(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiGroup::from(group))
    }

    /// Delete a group.
    pub fn delete_group(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_group(&id))
            .map_err(Into::into)
    }

    /// Preview the impact of deleting a group.
    pub fn delete_group_dry_run(
        &self,
        id: String,
    ) -> Result<FfiGroupDeleteDryRun, PassboltFfiError> {
        let result = RUNTIME
            .block_on(self.inner.delete_group_dry_run(&id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiGroupDeleteDryRun::from(result))
    }

    // ── Tags ────────────────────────────────────────────────────────────

    /// List all tags.
    pub fn get_tags(&self) -> Result<Vec<FfiTag>, PassboltFfiError> {
        let tags = RUNTIME
            .block_on(self.inner.get_tags())
            .map_err(PassboltFfiError::from)?;
        Ok(tags.into_iter().map(FfiTag::from).collect())
    }

    /// Add a tag to a resource.
    pub fn add_tag_to_resource(
        &self,
        resource_id: String,
        slug: String,
    ) -> Result<FfiTag, PassboltFfiError> {
        let tag = RUNTIME
            .block_on(self.inner.add_tag_to_resource(&resource_id, &slug))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiTag::from(tag))
    }

    /// Delete a tag.
    pub fn delete_tag(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_tag(&id))
            .map_err(Into::into)
    }

    // ── Comments ────────────────────────────────────────────────────────

    /// Get comments for a resource.
    pub fn get_comments(&self, resource_id: String) -> Result<Vec<FfiComment>, PassboltFfiError> {
        let comments = RUNTIME
            .block_on(self.inner.get_comments(&resource_id))
            .map_err(PassboltFfiError::from)?;
        Ok(comments.into_iter().map(FfiComment::from).collect())
    }

    /// Create a comment on a resource.
    pub fn create_comment(
        &self,
        resource_id: String,
        content: String,
        parent_id: Option<String>,
    ) -> Result<FfiComment, PassboltFfiError> {
        let comment = RUNTIME
            .block_on(
                self.inner
                    .create_comment(&resource_id, &content, parent_id.as_deref()),
            )
            .map_err(PassboltFfiError::from)?;
        Ok(FfiComment::from(comment))
    }

    /// Delete a comment.
    pub fn delete_comment(&self, id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.delete_comment(&id))
            .map_err(Into::into)
    }

    // ── Sharing ─────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) for sharing.
    pub fn search_aros(&self, search: String) -> Result<Vec<FfiAro>, PassboltFfiError> {
        let aros = RUNTIME
            .block_on(self.inner.search_aros(&search))
            .map_err(PassboltFfiError::from)?;
        Ok(aros.into_iter().map(FfiAro::from).collect())
    }

    // ── Favorites ───────────────────────────────────────────────────────

    /// Add a resource to favorites.
    pub fn add_favorite(&self, resource_id: String) -> Result<FfiFavorite, PassboltFfiError> {
        let fav = RUNTIME
            .block_on(self.inner.add_favorite(&resource_id))
            .map_err(PassboltFfiError::from)?;
        Ok(FfiFavorite::from(fav))
    }

    /// Remove a favorite.
    pub fn remove_favorite(&self, favorite_id: String) -> Result<(), PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.remove_favorite(&favorite_id))
            .map_err(Into::into)
    }

    // ── Password Expiry ─────────────────────────────────────────────────

    /// Get password expiry settings.
    pub fn get_password_expiry_settings(
        &self,
    ) -> Result<FfiPasswordExpirySettings, PassboltFfiError> {
        let settings = RUNTIME
            .block_on(self.inner.get_password_expiry_settings())
            .map_err(PassboltFfiError::from)?;
        Ok(FfiPasswordExpirySettings::from(settings))
    }

    // ── HIBP ────────────────────────────────────────────────────────────

    /// Check if a password has been exposed in data breaches.
    /// Returns the number of times found (0 = not breached).
    pub fn check_password_pwned(&self, password: String) -> Result<u64, PassboltFfiError> {
        RUNTIME
            .block_on(self.inner.check_password_pwned(&password))
            .map_err(Into::into)
    }

    // ── Session info ────────────────────────────────────────────────────

    /// Get the current user's ID.
    pub fn user_id(&self) -> String {
        self.inner.user_id.clone()
    }

    /// Get the server base URL.
    pub fn base_url(&self) -> String {
        self.inner.base_url.clone()
    }
}

// ── Stateless crypto functions ──────────────────────────────────────────────

/// Decrypt a PGP-armored message with a private key.
#[uniffi::export]
pub fn decrypt_message(
    armored_message: String,
    private_key_armored: String,
    passphrase: String,
) -> Result<Vec<u8>, PassboltFfiError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|e| {
        PassboltFfiError::Crypto {
            message: e.to_string(),
        }
    })?;
    passbolt_sdk::crypto::decrypt_message(&armored_message, &key.key, &passphrase).map_err(|e| {
        PassboltFfiError::Crypto {
            message: e.to_string(),
        }
    })
}

/// Encrypt a plaintext message for one or more PGP public keys.
/// Returns the PGP-armored ciphertext.
#[uniffi::export]
pub fn encrypt_message(
    plaintext: Vec<u8>,
    public_keys_armored: Vec<String>,
) -> Result<String, PassboltFfiError> {
    let parsed: Result<Vec<_>, _> = public_keys_armored
        .iter()
        .map(|k| passbolt_sdk::crypto::parse_public_key(k))
        .collect();
    let keys = parsed.map_err(|e| PassboltFfiError::Crypto {
        message: e.to_string(),
    })?;
    let key_refs: Vec<_> = keys.iter().collect();
    passbolt_sdk::crypto::encrypt_message(&plaintext, &key_refs).map_err(|e| {
        PassboltFfiError::Crypto {
            message: e.to_string(),
        }
    })
}

/// Parse a PGP private key and return its fingerprint (hex uppercase).
#[uniffi::export]
pub fn get_key_fingerprint(private_key_armored: String) -> Result<String, PassboltFfiError> {
    let key = passbolt_sdk::crypto::parse_private_key(&private_key_armored).map_err(|e| {
        PassboltFfiError::Crypto {
            message: e.to_string(),
        }
    })?;
    Ok(key.fingerprint.clone())
}
