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

use std::collections::HashMap;
use std::sync::Arc;

use pgp::types::SecretKeyTrait;
use pgp::SignedSecretKey;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use std::sync::{OnceLock, RwLock};

use serde_json::Value;

use crate::auth::{self, AuthTokens};
use crate::config::SdkConfig;
use crate::crypto::{self, PrivateKey};
use crate::error::{ApiError, AuthError, CryptoError, PassboltError};
use crate::http::{HttpClient, HttpResponse};
use crate::mfa::MfaProvider;
#[allow(clippy::wildcard_imports)] // too many types to enumerate explicitly
use crate::types::*;

/// Main Passbolt SDK client, generic over the HTTP backend.
pub struct PassboltSdk<H: HttpClient> {
    http: H,
    pub base_url: String,
    csrf_token: RwLock<String>,
    pub(crate) private_key: PrivateKey,
    pub(crate) passphrase: SecretString,
    pub user_id: String,
    /// Cached v5 metadata private key (fetched at most once per session).
    metadata_private_key: OnceLock<Option<SignedSecretKey>>,
}

/// Fetch the org-wide metadata private key from the API.
///
/// Free function (not a method) so it can be called from an `OnceCell` init
/// closure without conflicting with the borrow of `self.metadata_private_key`.
async fn fetch_metadata_key<H: HttpClient>(
    http: &H,
    base_url: &str,
    user_id: &str,
    private_key: &pgp::SignedSecretKey,
    passphrase: &str,
) -> Result<Option<pgp::SignedSecretKey>, PassboltError> {
    let url = format!("{base_url}/metadata/keys.json?contain[metadata_private_keys]=1");
    let response = http.get(&url, &[]).await?;

    let body: Value = serde_json::from_slice(&response.body)?;

    if response.status >= 400 {
        let message = body
            .pointer("/header/message")
            .and_then(|value| value.as_str())
            .unwrap_or("Unknown error");
        return Err(ApiError {
            status: response.status,
            message: message.to_string(),
            validation_errors: None,
        }
        .into());
    }

    let data = body.get("body").cloned().unwrap_or(body);
    let keys: Vec<MetadataKey> = serde_json::from_value(data)?;

    for metadata_key in &keys {
        for share in &metadata_key.metadata_private_keys {
            if share.user_id.as_deref() == Some(user_id) {
                let plaintext = crypto::decrypt_message(&share.data, private_key, passphrase)
                    .map_err(|error| {
                        CryptoError::Decrypt(format!(
                            "Failed to decrypt metadata private key share: {error}"
                        ))
                    })?;
                let armored = String::from_utf8(plaintext).map_err(|error| {
                    PassboltError::Other(format!("Metadata key is not valid UTF-8: {error}"))
                })?;
                let key = crypto::parse_private_key(&armored)?;
                return Ok(Some(key.key.clone()));
            }
        }
    }

    Ok(None)
}

/// `id` unchanged if it is a hyphenated UUID, the only form safe to put in a URL path.
fn uuid_segment(id: &str) -> Result<&str, PassboltError> {
    if id.len() == 36 && uuid::Uuid::try_parse(id).is_ok() {
        Ok(id)
    } else {
        Err(PassboltError::InvalidArgument(format!(
            "{id:?} is not a UUID"
        )))
    }
}

/// Refuse a server URL that would send the session in clear text.
fn check_server_url(server_url: &str) -> Result<(), PassboltError> {
    let url = url::Url::parse(server_url)
        .map_err(|error| PassboltError::Config(format!("invalid server_address: {error}")))?;
    match url.scheme() {
        "https" => Ok(()),
        // A local server (docker, end-to-end tests) is often plain HTTP;
        // its traffic never leaves the machine.
        "http" if is_loopback(&url) => Ok(()),
        scheme => Err(PassboltError::Config(format!(
            "server_address must use https, not {scheme}"
        ))),
    }
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

impl<H: HttpClient> PassboltSdk<H> {
    /// Create a new SDK client with a pre-built HTTP backend and authenticate.
    pub async fn login(
        http: H,
        sdk_config: &SdkConfig,
        mfa_provider: Option<&dyn MfaProvider>,
        max_attempts: u32,
    ) -> Result<Self, PassboltError> {
        if sdk_config.server_url.is_empty() {
            return Err(PassboltError::Config(
                "server_address is not configured".into(),
            ));
        }
        check_server_url(&sdk_config.server_url)?;

        let private_key = crypto::parse_private_key(&sdk_config.private_key_armored)?;
        let passphrase = sdk_config.passphrase.clone();
        let base_url = sdk_config.server_url.trim_end_matches('/').to_string();

        // Pre-login server identity check
        if !sdk_config.server_verify_enc_token.is_empty()
            || !sdk_config.server_verify_token.is_empty()
        {
            auth::check_server_identity(
                &http,
                &base_url,
                &private_key,
                passphrase.expose_secret(),
                &sdk_config.server_verify_enc_token,
                &sdk_config.server_verify_token,
            )
            .await?;
        }

        let mut tokens: AuthTokens = auth::login(
            &http,
            &base_url,
            &private_key,
            passphrase.expose_secret(),
            mfa_provider,
            max_attempts,
        )
        .await?;

        let mut client = Self {
            http,
            base_url,
            csrf_token: RwLock::new(std::mem::take(&mut tokens.csrf_token)),
            private_key,
            passphrase,
            user_id: std::mem::take(&mut tokens.user_id),
            metadata_private_key: OnceLock::new(),
        };

        // Login is exempt from CSRF: the token cookie comes with this first GET.
        client.user_id = client.fetch_current_user().await?;
        if client.csrf_token().is_empty() {
            return Err(
                AuthError::LoginFailed("the server did not provide a CSRF token".into()).into(),
            );
        }
        Ok(client)
    }

    /// Current user id, from `GET /users/me.json` (post-login verify).
    async fn fetch_current_user(&self) -> Result<String, PassboltError> {
        let url = format!("{}/users/me.json?contain[gpgkey]=1", self.base_url);
        let response = self.http_get(&url).await?;
        let current_user: User = self.parse_response(&response).map_err(|error| {
            PassboltError::from(AuthError::LoginFailed(format!(
                "Failed to fetch current user info: {error}"
            )))
        })?;

        // Cross-check: encrypt a probe with the server's copy of our public key,
        // then decrypt it with our private key.
        let armored_key = current_user
            .gpg_key
            .as_ref()
            .and_then(|gpg_key| gpg_key.armored_key.as_deref())
            .ok_or(AuthError::KeyCrossCheckFailed)?;
        let probe = b"passbolt-key-check";
        let decrypted_probe = crypto::parse_public_key(armored_key)
            .and_then(|public_key| crypto::encrypt_message(probe, &[&public_key]))
            .and_then(|encrypted_probe| {
                crypto::decrypt_message(
                    &encrypted_probe,
                    &self.private_key.key,
                    self.passphrase.expose_secret(),
                )
            })
            .map_err(|_| AuthError::KeyCrossCheckFailed)?;
        if decrypted_probe != probe {
            return Err(AuthError::KeyCrossCheckFailed.into());
        }

        Ok(current_user.id)
    }

    /// Terminate the server-side session.
    pub async fn logout(&self) {
        let url = format!("{}/auth/logout.json", self.base_url);
        let csrf_token = self.csrf_token();
        let _ = self
            .http
            .post(&url, &[("X-CSRF-Token", csrf_token.as_str())], &[])
            .await;
    }

    /// Check if the current session is still authenticated.
    ///
    /// Returns `true` if the session is valid, `false` if expired/unauthenticated.
    /// Callers can use this for keep-alive or session refresh logic.
    pub async fn check_auth_status(&self) -> Result<bool, PassboltError> {
        let url = format!("{}/auth/is-authenticated.json", self.base_url);
        let response = self.http_get(&url).await?;
        Ok(response.status < 400)
    }

    // ── Internal HTTP helpers ─────────────────────────────────────────────────

    /// Token to send as `X-CSRF-Token`: the `csrfToken` cookie, whichever request set it.
    pub fn csrf_token(&self) -> String {
        self.http
            .cookie(&self.base_url, "csrfToken")
            .unwrap_or_else(|| self.csrf_token.read().unwrap().clone())
    }

    fn remember_csrf_cookie(&self, response: &HttpResponse) {
        if let Some(token) = auth::csrf_cookie(response) {
            *self.csrf_token.write().unwrap() = token;
        }
    }

    async fn http_get(&self, url: &str) -> Result<HttpResponse, PassboltError> {
        let response = self.http.get(url, &[]).await?;
        self.remember_csrf_cookie(&response);
        Ok(response)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let response = self.http_get(&url).await?;
        self.parse_response(&response)
    }

    async fn get_with_query<T, K, V>(
        &self,
        path: &str,
        params: &[(K, V)],
    ) -> Result<T, PassboltError>
    where
        T: DeserializeOwned,
        K: AsRef<str> + Sync,
        V: AsRef<str> + Sync,
    {
        // Build URL with query string
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            let query_pairs: Vec<String> = params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            key.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                        percent_encoding::utf8_percent_encode(
                            value.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                    )
                })
                .collect();
            url.push_str(&query_pairs.join("&"));
        }

        let response = self.http_get(&url).await?;
        self.parse_response(&response)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let csrf_token = self.csrf_token();
        let json_body = serde_json::to_vec(body)?;
        let response = self
            .http
            .post(&url, &[("X-CSRF-Token", csrf_token.as_str())], &json_body)
            .await?;
        self.remember_csrf_cookie(&response);
        self.parse_response(&response)
    }

    async fn put_request<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<T, PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let csrf_token = self.csrf_token();
        let json_body = serde_json::to_vec(body)?;
        let response = self
            .http
            .put(&url, &[("X-CSRF-Token", csrf_token.as_str())], &json_body)
            .await?;
        self.remember_csrf_cookie(&response);
        self.parse_response(&response)
    }

    async fn delete_request(&self, path: &str) -> Result<(), PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let csrf_token = self.csrf_token();
        let response = self
            .http
            .delete(&url, &[("X-CSRF-Token", csrf_token.as_str())])
            .await?;
        self.remember_csrf_cookie(&response);

        if response.status >= 400 {
            let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            let message = body
                .pointer("/header/message")
                .and_then(|value| value.as_str())
                .unwrap_or("Unknown error");
            return Err(ApiError {
                status: response.status,
                message: format!("DELETE {path} failed: {message}"),
                validation_errors: None,
            }
            .into());
        }
        Ok(())
    }

    async fn delete_request_with_body(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<(), PassboltError> {
        let url = format!("{}{path}", self.base_url);
        let csrf_token = self.csrf_token();
        let json_body = serde_json::to_vec(body)?;
        let response = self
            .http
            .delete_with_body(&url, &[("X-CSRF-Token", csrf_token.as_str())], &json_body)
            .await?;
        self.remember_csrf_cookie(&response);

        if response.status >= 400 {
            let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            let message = body
                .pointer("/header/message")
                .and_then(|value| value.as_str())
                .unwrap_or("Unknown error");
            return Err(ApiError {
                status: response.status,
                message: format!("DELETE {path} failed: {message}"),
                validation_errors: None,
            }
            .into());
        }
        Ok(())
    }

    #[allow(clippy::unused_self)] // keeps API consistent; may use self for logging later
    fn parse_response<T: DeserializeOwned>(
        &self,
        response: &HttpResponse,
    ) -> Result<T, PassboltError> {
        let body: Value = serde_json::from_slice(&response.body)?;

        if response.status >= 400 {
            let message = body
                .pointer("/header/message")
                .and_then(|value| value.as_str())
                .unwrap_or("Unknown error");
            let validation_errors = body.get("body").cloned();
            return Err(ApiError {
                status: response.status,
                message: message.to_string(),
                validation_errors,
            }
            .into());
        }

        let data = body.get("body").cloned().unwrap_or(body);
        serde_json::from_value(data).map_err(PassboltError::from)
    }

    /// Fetch a paginated list endpoint.
    ///
    /// - If `pagination.page` is `Some(p)`, fetch only that page.
    /// - If `pagination.page` is `None`, auto-paginate all pages (max 100 safety limit).
    async fn get_paginated<T: DeserializeOwned>(
        &self,
        path: &str,
        base_params: &[(&str, String)],
        pagination: &PaginationParams,
    ) -> Result<Vec<T>, PassboltError> {
        let mut all_params: Vec<(&str, String)> = base_params.to_vec();

        if let Some(limit) = pagination.limit {
            all_params.push(("api-version", "v2".into()));
            all_params.push(("limit", limit.to_string()));
        }

        // Single-page mode
        if let Some(page) = pagination.page {
            all_params.push(("page", page.to_string()));
            return self.get_with_query(path, &all_params).await;
        }

        // Auto-paginate mode (safety limit)
        let max_pages: u32 = 100;
        let mut results: Vec<T> = Vec::new();

        for page in 1..=max_pages {
            let mut page_params = all_params.clone();
            page_params.push(("page", page.to_string()));

            let url = self.build_query_url(path, &page_params);
            let response = self.http_get(&url).await?;
            let body: Value = serde_json::from_slice(&response.body)?;

            if response.status >= 400 {
                let message = body
                    .pointer("/header/message")
                    .and_then(|value| value.as_str())
                    .unwrap_or("Unknown error");
                return Err(ApiError {
                    status: response.status,
                    message: message.to_string(),
                    validation_errors: None,
                }
                .into());
            }

            let data = body.get("body").cloned().unwrap_or_else(|| body.clone());
            let page_items: Vec<T> = serde_json::from_value(data)?;
            let page_count = page_items.len();
            results.extend(page_items);

            // Check pagination info from response header
            let pagination_info = body
                .pointer("/header/pagination")
                .and_then(|value| serde_json::from_value::<PaginationInfo>(value.clone()).ok());

            if let Some(info) = pagination_info {
                let limit = info.limit.unwrap_or(20);
                if page_count < limit as usize || results.len() >= info.count as usize {
                    break;
                }
            } else {
                // No pagination header — single page response
                break;
            }
        }

        Ok(results)
    }

    fn build_query_url<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        params: &[(K, V)],
    ) -> String {
        let mut url = format!("{}{path}", self.base_url);
        if !params.is_empty() {
            let separator = if url.contains('?') { '&' } else { '?' };
            url.push(separator);
            let query_pairs: Vec<String> = params
                .iter()
                .map(|(key, value)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            key.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                        percent_encoding::utf8_percent_encode(
                            value.as_ref(),
                            percent_encoding::NON_ALPHANUMERIC,
                        ),
                    )
                })
                .collect();
            url.push_str(&query_pairs.join("&"));
        }
        url
    }

    // ── v5 Metadata key ────────────────────────────────────────────────────────

    /// Fetch the org-wide metadata private key and cache it for the session.
    pub async fn ensure_metadata_key(&self) -> Result<Option<&SignedSecretKey>, PassboltError> {
        if let Some(cached_key) = self.metadata_private_key.get() {
            return Ok(cached_key.as_ref());
        }

        let result = fetch_metadata_key(
            &self.http,
            &self.base_url,
            &self.user_id,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )
        .await?;

        // If another caller already set it, that's fine — both fetches are idempotent.
        let _ = self.metadata_private_key.set(result);
        Ok(self.metadata_private_key.get().unwrap().as_ref())
    }

    /// Decrypt the PGP-armored `metadata` field of a v5 resource.
    pub async fn decrypt_resource_metadata(
        &self,
        resource: &Resource,
    ) -> Result<Option<ResourceMetadata>, PassboltError> {
        let Some(armored) = resource.armored_metadata() else {
            return Ok(None);
        };

        let plaintext = match resource.metadata_key_type.as_deref() {
            Some("user_key") => crypto::decrypt_message(
                armored,
                &self.private_key.key,
                self.passphrase.expose_secret(),
            )
            .map_err(|error| {
                CryptoError::Decrypt(format!("resource metadata (user_key): {error}"))
            })?,
            _ => match self.ensure_metadata_key().await? {
                Some(key) => crypto::decrypt_message(armored, key, self.passphrase.expose_secret())
                    .map_err(|error| {
                        CryptoError::Decrypt(format!("resource metadata (shared_key): {error}"))
                    })?,
                None => return Ok(None),
            },
        };

        let text = String::from_utf8(plaintext).map_err(|error| {
            PassboltError::Other(format!("Resource metadata is not valid UTF-8: {error}"))
        })?;
        let metadata = serde_json::from_str::<ResourceMetadata>(&text)?;
        Ok(Some(metadata))
    }

    // ── Batch decrypt (native only — requires tokio JoinSet) ────────────────

    /// Decrypt secrets for a batch of resources in parallel.
    #[cfg(feature = "native")]
    pub async fn decrypt_secrets_batch(
        &self,
        resources: &[Resource],
        workers: usize,
    ) -> Result<HashMap<String, SecretData>, PassboltError> {
        use tokio::task::JoinSet;

        let concurrency = if workers == 0 {
            std::thread::available_parallelism().map_or(4, std::num::NonZero::get)
        } else {
            workers
        }
        .max(1);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let pgp_key = Arc::new(self.private_key.key.clone());
        let passphrase = Arc::new(self.passphrase.clone());

        let mut tasks: JoinSet<(String, SecretData)> = JoinSet::new();

        for resource in resources {
            let encrypted = resource
                .secrets
                .first()
                .and_then(|secret| secret.data.clone())
                .unwrap_or_default();
            let id = resource.id.clone();
            let key = Arc::clone(&pgp_key);
            let task_passphrase = Arc::clone(&passphrase);
            let permit = Arc::clone(&semaphore)
                .acquire_owned()
                .await
                .map_err(|error| PassboltError::Other(format!("Semaphore error: {error}")))?;

            tasks.spawn_blocking(move || {
                let _permit = permit;
                let secret = if encrypted.is_empty() {
                    SecretData::default()
                } else {
                    crypto::decrypt_message(&encrypted, &key, task_passphrase.expose_secret())
                        .map_or_else(
                            |_| SecretData::default(),
                            |plaintext| {
                                let text = String::from_utf8(plaintext).unwrap_or_default();
                                serde_json::from_str::<SecretData>(&text).unwrap_or_else(|_| {
                                    SecretData {
                                        password: Some(text.clone()),
                                        raw: Some(text),
                                        ..Default::default()
                                    }
                                })
                            },
                        )
                };
                (id, secret)
            });
        }

        let mut secrets = HashMap::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok((id, secret)) = result {
                secrets.insert(id, secret);
            }
        }

        Ok(secrets)
    }

    /// Decrypt v5 metadata for a batch of resources.
    pub async fn decrypt_metadata_batch(
        &self,
        resources: &[Resource],
    ) -> HashMap<String, ResourceMetadata> {
        let mut metadatas = HashMap::new();
        for resource in resources {
            if resource.is_v5() {
                if let Ok(Some(metadata)) = self.decrypt_resource_metadata(resource).await {
                    metadatas.insert(resource.id.clone(), metadata);
                }
            }
        }
        metadatas
    }

    // ── Crypto accessors ────────────────────────────────────────────────────

    /// Get a reference-counted clone of the PGP private key for parallel tasks.
    pub fn pgp_key_arc(&self) -> Arc<pgp::SignedSecretKey> {
        Arc::new(self.private_key.key.clone())
    }

    /// Get a reference-counted clone of the passphrase for parallel tasks.
    pub fn passphrase_arc(&self) -> Arc<SecretString> {
        Arc::new(self.passphrase.clone())
    }

    // ── Resources ──────────────────────────────────────────────────────────────

    pub async fn get_resources(
        &self,
        options: ResourceQuery,
    ) -> Result<Vec<Resource>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[secret]", "1".into()),
            ("contain[favorite]", "1".into()),
        ];

        for group_id in options.group_ids {
            params.push(("filter[is-shared-with-group][]", group_id));
        }
        for folder_id in options.folder_ids {
            params.push(("filter[has-parent][]", folder_id));
        }

        if options.favorites_only {
            params.push(("filter[is-favorite]", "1".into()));
        }
        if options.owned_by_me {
            params.push(("filter[is-owned-by-me]", "1".into()));
        }
        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }

        self.get_paginated("/resources.json", &params, &options.pagination)
            .await
    }

    pub async fn get_resource(&self, id: &str) -> Result<Resource, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!(
            "/resources/{id}.json?contain[permission]=1&contain[secret]=1"
        ))
        .await
    }

    pub async fn create_resource(
        &self,
        payload: &CreateResourcePayload,
    ) -> Result<Resource, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/resources.json", &body).await
    }

    pub async fn update_resource(
        &self,
        id: &str,
        payload: &UpdateResourcePayload,
    ) -> Result<Resource, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/resources/{id}.json"), &body)
            .await
    }

    pub async fn delete_resource(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/resources/{id}.json")).await
    }

    pub async fn get_resource_permissions(
        &self,
        id: &str,
    ) -> Result<Vec<Permission>, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/permissions/resource/{id}.json")).await
    }

    /// Fetch and decrypt a resource secret.
    pub async fn decrypt_resource_secret(
        &self,
        resource: &Resource,
    ) -> Result<SecretData, PassboltError> {
        let secret_data = if let Some(secret) = resource.secrets.first() {
            secret.data.clone().unwrap_or_default()
        } else {
            let secrets: Vec<Secret> = self
                .get(&format!(
                    "/secrets/resource/{}.json",
                    uuid_segment(&resource.id)?
                ))
                .await?;
            secrets
                .first()
                .and_then(|secret| secret.data.clone())
                .unwrap_or_default()
        };

        if secret_data.is_empty() {
            return Ok(SecretData::default());
        }

        let plaintext = crypto::decrypt_message(
            &secret_data,
            &self.private_key.key,
            self.passphrase.expose_secret(),
        )
        .map_err(|error| CryptoError::Decrypt(format!("resource secret: {error}")))?;

        let text = String::from_utf8(plaintext)
            .map_err(|error| PassboltError::Other(format!("Secret is not valid UTF-8: {error}")))?;

        Ok(
            serde_json::from_str::<SecretData>(&text).unwrap_or_else(|_| SecretData {
                password: Some(text.clone()),
                raw: Some(text),
                ..Default::default()
            }),
        )
    }

    /// Encrypt a secret for the given user IDs.
    pub async fn encrypt_secret_for_users(
        &self,
        secret_json: &str,
        user_ids: &[String],
    ) -> Result<Vec<SecretPayload>, PassboltError> {
        let mut payloads = Vec::new();

        for user_id in user_ids {
            let user: User = self
                .get(&format!(
                    "/users/{}.json?contain[gpgkey]=1",
                    uuid_segment(user_id)?
                ))
                .await?;
            let armored_key = user
                .gpg_key
                .as_ref()
                .and_then(|gpg_key| gpg_key.armored_key.as_deref())
                .ok_or_else(|| PassboltError::NotFound(format!("User {user_id} has no GPG key")))?;

            let public_key = crypto::parse_public_key(armored_key)?;
            let encrypted = crypto::encrypt_message(secret_json.as_bytes(), &[&public_key])?;

            payloads.push(SecretPayload {
                user_id: user_id.clone(),
                data: encrypted,
            });
        }

        Ok(payloads)
    }

    // ── Folders ───────────────────────────────────────────────────────────────

    pub async fn get_folders(&self, options: FolderQuery) -> Result<Vec<Folder>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![("contain[permissions]", "1".into())];

        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }
        if let Some(group_id) = options.group_id {
            params.push(("filter[is-shared-with-group]", group_id));
        }
        if let Some(parent_folder_id) = options.parent_folder_id {
            params.push(("filter[has-parent]", parent_folder_id));
        }

        self.get_paginated("/folders.json", &params, &options.pagination)
            .await
    }

    pub async fn get_folder(&self, id: &str) -> Result<Folder, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/folders/{id}.json?contain[permissions]=1"))
            .await
    }

    pub async fn create_folder(
        &self,
        payload: &CreateFolderPayload,
    ) -> Result<Folder, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/folders.json", &body).await
    }

    pub async fn update_folder(
        &self,
        id: &str,
        payload: &UpdateFolderPayload,
    ) -> Result<Folder, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/folders/{id}.json"), &body)
            .await
    }

    pub async fn delete_folder(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/folders/{id}.json")).await
    }

    pub async fn get_folder_permissions(&self, id: &str) -> Result<Vec<Permission>, PassboltError> {
        let id = uuid_segment(id)?;
        let folder: Folder = self
            .get(&format!("/folders/{id}.json?contain[permissions]=1"))
            .await?;
        Ok(folder.permissions)
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    pub async fn get_users(&self, options: UserQuery) -> Result<Vec<User>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[role]", "1".into()),
            ("contain[gpgkey]", "1".into()),
            ("contain[groups_users]", "1".into()),
        ];

        if let Some(search) = options.search {
            params.push(("filter[search]", search));
        }
        if let Some(group_id) = options.group_id {
            params.push(("filter[is-in-group]", group_id));
        }
        if let Some(resource_id) = options.resource_id {
            params.push(("filter[has-access]", resource_id));
        }
        if options.admin_only {
            params.push(("filter[is-admin]", "1".into()));
        }

        self.get_paginated("/users.json", &params, &options.pagination)
            .await
    }

    pub async fn get_user(&self, id: &str) -> Result<User, PassboltError> {
        let id = if id == "me" { id } else { uuid_segment(id)? };
        self.get(&format!(
            "/users/{id}.json?contain[role]=1&contain[gpgkey]=1"
        ))
        .await
    }

    pub async fn create_user(&self, payload: &CreateUserPayload) -> Result<User, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/users.json", &body).await
    }

    pub async fn update_user(
        &self,
        id: &str,
        payload: &UpdateUserPayload,
    ) -> Result<User, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/users/{id}.json"), &body).await
    }

    pub async fn delete_user(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/users/{id}.json")).await
    }

    pub async fn get_me(&self) -> Result<User, PassboltError> {
        self.get("/users/me.json?contain[role]=1&contain[gpgkey]=1")
            .await
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    pub async fn get_groups(&self, options: GroupQuery) -> Result<Vec<Group>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![("contain[groups_users]", "1".into())];

        if let Some(user_id) = options.user_id {
            params.push(("filter[has-users]", user_id));
        }
        if let Some(manager_id) = options.manager_id {
            params.push(("filter[has-managers]", manager_id));
        }

        self.get_paginated("/groups.json", &params, &options.pagination)
            .await
    }

    pub async fn get_group(&self, id: &str) -> Result<Group, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/groups/{id}.json?contain[groups_users]=1"))
            .await
    }

    pub async fn create_group(&self, payload: &CreateGroupPayload) -> Result<Group, PassboltError> {
        let body = serde_json::to_value(payload)?;
        self.post("/groups.json", &body).await
    }

    pub async fn update_group(
        &self,
        id: &str,
        payload: &UpdateGroupPayload,
    ) -> Result<Group, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        self.put_request(&format!("/groups/{id}.json"), &body).await
    }

    pub async fn delete_group(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/groups/{id}.json")).await
    }

    // ── Favorites ─────────────────────────────────────────────────────────────

    pub async fn add_favorite(&self, resource_id: &str) -> Result<Favorite, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let body = serde_json::json!({});
        self.post(&format!("/favorites/resource/{resource_id}.json"), &body)
            .await
    }

    pub async fn remove_favorite(&self, favorite_id: &str) -> Result<(), PassboltError> {
        let favorite_id = uuid_segment(favorite_id)?;
        self.delete_request(&format!("/favorites/{favorite_id}.json"))
            .await
    }

    // ── Sharing ───────────────────────────────────────────────────────────────

    pub async fn share_resource(
        &self,
        id: &str,
        payload: &SharePayload,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        let _: Value = self
            .put_request(&format!("/share/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    pub async fn share_folder(
        &self,
        id: &str,
        payload: &SharePayload,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::to_value(payload)?;
        let _: Value = self
            .put_request(&format!("/share/folder/{id}.json"), &body)
            .await?;
        Ok(())
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    pub async fn get_role_id_by_name(&self, role_name: &str) -> Result<String, PassboltError> {
        let roles: Vec<serde_json::Value> = self.get("/roles.json").await?;
        roles
            .iter()
            .find(|role| role["name"].as_str() == Some(role_name))
            .and_then(|role| role["id"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| PassboltError::NotFound(format!("Role not found: {role_name}")))
    }

    // ── Resource types ────────────────────────────────────────────────────────

    pub async fn get_resource_type_id_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<String>, PassboltError> {
        let types: Vec<ResourceType> = self.get("/resource-types.json").await?;
        Ok(types
            .into_iter()
            .find(|resource_type| resource_type.slug == slug)
            .map(|resource_type| resource_type.id))
    }

    // ── Move ──────────────────────────────────────────────────────────────────

    pub async fn move_resource(
        &self,
        id: &str,
        folder_parent_id: Option<&str>,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self
            .put_request(&format!("/move/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    pub async fn move_folder(
        &self,
        id: &str,
        folder_parent_id: Option<&str>,
    ) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self
            .put_request(&format!("/move/folder/{id}.json"), &body)
            .await?;
        Ok(())
    }

    // ── Bulk Delete ──────────────────────────────────────────────────────────

    /// Delete multiple resources at once.
    pub async fn delete_resources(&self, ids: &[String]) -> Result<(), PassboltError> {
        let body = serde_json::json!({ "ids": ids });
        self.delete_request_with_body("/resources.json", &body)
            .await
    }

    // ── Find Resources by IDs ────────────────────────────────────────────────

    /// Fetch multiple resources by their IDs in a single request.
    pub async fn get_resources_by_ids(
        &self,
        ids: &[String],
    ) -> Result<Vec<Resource>, PassboltError> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[secret]", "1".into()),
        ];
        for id in ids {
            params.push(("filter[has-id][]", id.clone()));
        }
        let pagination = PaginationParams::default();
        self.get_paginated("/resources.json", &params, &pagination)
            .await
    }

    // ── Search AROs ──────────────────────────────────────────────────────────

    /// Search for users and groups (AROs) matching a search term.
    pub async fn search_aros(&self, search: &str) -> Result<Vec<Aro>, PassboltError> {
        self.get_with_query("/share/search-aros.json", &[("filter[search]", search)])
            .await
    }

    // ── Tags ─────────────────────────────────────────────────────────────────

    /// List all tags.
    pub async fn get_tags(&self) -> Result<Vec<Tag>, PassboltError> {
        self.get("/tags.json").await
    }

    /// Add a tag to a resource. Creates the tag if it doesn't exist.
    pub async fn add_tag_to_resource(
        &self,
        resource_id: &str,
        slug: &str,
    ) -> Result<Tag, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let body = serde_json::json!({ "slug": slug });
        self.post(&format!("/tags/{resource_id}.json"), &body).await
    }

    /// Replace all tags on a resource.
    pub async fn update_resource_tags(
        &self,
        resource_id: &str,
        tags: &[String],
    ) -> Result<Vec<Tag>, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let body: Value = tags
            .iter()
            .map(|slug| serde_json::json!({ "slug": slug }))
            .collect::<Vec<_>>()
            .into();
        self.put_request(&format!("/resources/{resource_id}/tags.json"), &body)
            .await
    }

    /// Update a tag's slug.
    pub async fn update_tag(&self, id: &str, slug: &str) -> Result<Tag, PassboltError> {
        let id = uuid_segment(id)?;
        let body = serde_json::json!({ "slug": slug });
        self.put_request(&format!("/tags/{id}.json"), &body).await
    }

    /// Delete a tag.
    pub async fn delete_tag(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/tags/{id}.json")).await
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    /// List comments for a resource.
    pub async fn get_comments(&self, resource_id: &str) -> Result<Vec<Comment>, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        self.get(&format!(
            "/comments/resource/{resource_id}.json?contain[creator]=1"
        ))
        .await
    }

    /// Create a comment on a resource.
    pub async fn create_comment(
        &self,
        resource_id: &str,
        content: &str,
        parent_id: Option<&str>,
    ) -> Result<Comment, PassboltError> {
        let resource_id = uuid_segment(resource_id)?;
        let mut body = serde_json::json!({ "content": content });
        if let Some(parent_id) = parent_id {
            body["parent_id"] = serde_json::json!(parent_id);
        }
        self.post(&format!("/comments/resource/{resource_id}.json"), &body)
            .await
    }

    /// Delete a comment.
    pub async fn delete_comment(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/comments/{id}.json")).await
    }

    // ── Password Expiry Settings ─────────────────────────────────────────────

    /// Get the password expiry settings.
    pub async fn get_password_expiry_settings(
        &self,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        self.get("/password-expiry/settings.json").await
    }

    /// Create or update password expiry settings.
    pub async fn save_password_expiry_settings(
        &self,
        settings: &PasswordExpirySettings,
    ) -> Result<PasswordExpirySettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/password-expiry/settings.json", &body).await
    }

    /// Delete password expiry settings.
    pub async fn delete_password_expiry_settings(&self, id: &str) -> Result<(), PassboltError> {
        let id = uuid_segment(id)?;
        self.delete_request(&format!("/password-expiry/settings/{id}.json"))
            .await
    }

    // ── HIBP Password Breach Check ───────────────────────────────────────────

    /// Check if a password has been exposed in data breaches (HIBP k-anonymity).
    ///
    /// Returns the number of times the password was found (0 = not breached).
    pub async fn check_password_pwned(&self, password: &str) -> Result<u64, PassboltError> {
        crate::pwned::check_pwned(&self.http, password).await
    }

    // ── Delete Dry-Run ───────────────────────────────────────────────────────

    /// Preview the impact of deleting a user (admin).
    ///
    /// Returns counts of resources/folders where the user is sole owner,
    /// and groups where they are sole manager.
    pub async fn delete_user_dry_run(&self, id: &str) -> Result<UserDeleteDryRun, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/users/{id}/dry-run.json")).await
    }

    /// Preview the impact of deleting a group.
    ///
    /// Returns counts of resources/folders where the group is sole accessor.
    pub async fn delete_group_dry_run(&self, id: &str) -> Result<GroupDeleteDryRun, PassboltError> {
        let id = uuid_segment(id)?;
        self.get(&format!("/groups/{id}/dry-run.json")).await
    }

    // ── Metadata Settings ────────────────────────────────────────────────────

    /// Get metadata types settings (which versions are allowed).
    pub async fn get_metadata_types_settings(
        &self,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        self.get("/metadata/types/settings.json").await
    }

    /// Save metadata types settings (admin).
    pub async fn save_metadata_types_settings(
        &self,
        settings: &MetadataTypesSettings,
    ) -> Result<MetadataTypesSettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/metadata/types/settings.json", &body).await
    }

    /// Get metadata keys settings.
    pub async fn get_metadata_keys_settings(&self) -> Result<MetadataKeysSettings, PassboltError> {
        self.get("/metadata/keys/settings.json").await
    }

    /// Save metadata keys settings (admin).
    pub async fn save_metadata_keys_settings(
        &self,
        settings: &MetadataKeysSettings,
    ) -> Result<MetadataKeysSettings, PassboltError> {
        let body = serde_json::to_value(settings)?;
        self.post("/metadata/keys/settings.json", &body).await
    }

    /// Share metadata private key(s) with users.
    ///
    /// Each entry contains the metadata key ID, user ID, and the private key
    /// encrypted for that user's public key.
    pub async fn share_metadata_private_keys(
        &self,
        entries: &[MetadataPrivateKeyPayload],
    ) -> Result<(), PassboltError> {
        let body = serde_json::to_value(entries)?;
        let _: Value = self.post("/metadata/keys/private.json", &body).await?;
        Ok(())
    }

    /// Encrypt metadata for a v5 resource.
    ///
    /// Returns the PGP-armored encrypted metadata string.
    pub fn encrypt_metadata(
        &self,
        metadata: &ResourceMetadata,
        is_personal: bool,
    ) -> Result<(String, Option<String>), PassboltError> {
        let json = serde_json::to_string(metadata)?;
        if is_personal {
            // Encrypt with user's own public key (sign the unsigned key first)
            let mut rng = rand::thread_rng();
            let unsigned_public_key = self.private_key.key.public_key();
            let signed_public_key = unsigned_public_key
                .sign(&mut rng, &self.private_key.key, || {
                    self.passphrase.expose_secret().to_string()
                })
                .map_err(|error| CryptoError::Encrypt(format!("sign public key: {error}")))?;
            let armored = crypto::encrypt_message(json.as_bytes(), &[&signed_public_key])
                .map_err(|error| CryptoError::Encrypt(format!("metadata (user_key): {error}")))?;
            Ok((armored, None))
        } else {
            // Requires a shared metadata key — caller must ensure it's available
            Err(PassboltError::Other(
                "Shared metadata encryption requires metadata key; use encrypt_metadata_with_key"
                    .into(),
            ))
        }
    }

    /// Encrypt metadata using a specific public key (for shared metadata keys).
    pub fn encrypt_metadata_with_key(
        &self,
        metadata: &ResourceMetadata,
        public_key: &pgp::SignedPublicKey,
        metadata_key_id: &str,
    ) -> Result<(String, String), PassboltError> {
        let json = serde_json::to_string(metadata)?;
        let armored = crypto::encrypt_message(json.as_bytes(), &[public_key])
            .map_err(|error| CryptoError::Encrypt(format!("metadata (shared_key): {error}")))?;
        Ok((armored, metadata_key_id.to_string()))
    }
}

// ── Query option structs ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ResourceQuery {
    pub favorites_only: bool,
    pub owned_by_me: bool,
    pub group_ids: Vec<String>,
    pub folder_ids: Vec<String>,
    pub search: Option<String>,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct FolderQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub parent_folder_id: Option<String>,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct UserQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub resource_id: Option<String>,
    pub admin_only: bool,
    pub pagination: PaginationParams,
}

#[derive(Debug, Default)]
pub struct GroupQuery {
    pub user_id: Option<String>,
    pub manager_id: Option<String>,
    pub pagination: PaginationParams,
}
