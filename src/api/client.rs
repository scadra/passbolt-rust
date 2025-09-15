use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use pgp::SignedSecretKey;
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::OnceCell;

use crate::api::{
    auth::{self, AuthTokens, MfaConfig},
    crypto::{self, PrivateKey},
    http,
    types::*,
};
use crate::config::{Config, SdkConfig};

/// Main Passbolt API client.
pub struct PassboltClient {
    pub client: Client,
    pub base_url: String,
    /// CSRF token received at login, sent as X-CSRF-Token on mutating requests.
    pub csrf_token: String,
    pub(crate) private_key: PrivateKey,
    /// Passphrase for the PGP private key; wrapped in `SecretString` to prevent
    /// accidental logging and to zeroize on drop.
    pub(crate) passphrase: SecretString,
    pub user_id: String,
    /// Cached v5 metadata private key (fetched at most once per session).
    metadata_private_key: OnceCell<Option<SignedSecretKey>>,
}

/// Fetch the org-wide metadata private key from the API.
///
/// Free function (not a method) so it can be called from an `OnceCell` init
/// closure without conflicting with the borrow of `self.metadata_private_key`.
async fn fetch_metadata_key(
    client: &reqwest::Client,
    base_url: &str,
    user_id: &str,
    private_key: &pgp::SignedSecretKey,
    passphrase: &str,
) -> Result<Option<pgp::SignedSecretKey>> {
    let url = format!("{base_url}/metadata/keys.json?contain[metadata_private_keys]=1");
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    let body: Value = resp.json().await.context("Failed to parse JSON response")?;

    if !status.is_success() {
        let msg = body
            .pointer("/header/message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        bail!("API error ({status}): {msg}");
    }

    let data = body.get("body").cloned().unwrap_or(body);
    let keys: Vec<MetadataKey> =
        serde_json::from_value(data).context("Failed to deserialize metadata keys")?;

    for mk in &keys {
        for share in &mk.metadata_private_keys {
            if share.user_id.as_deref() == Some(user_id) {
                let plaintext = crypto::decrypt_message(&share.data, private_key, passphrase)
                    .context("Failed to decrypt metadata private key share")?;
                let armored =
                    String::from_utf8(plaintext).context("Metadata key is not valid UTF-8")?;
                let key = crypto::parse_private_key(&armored)?;
                return Ok(Some(key.key.clone()));
            }
        }
    }

    Ok(None)
}

impl PassboltClient {
    /// Create a new client and authenticate using CLI `Config`.
    ///
    /// Convenience wrapper that converts `Config` → `SdkConfig` then delegates.
    pub async fn login(cfg: &Config) -> Result<Self> {
        let sdk_cfg = cfg.to_sdk_config()?;
        Self::login_with_sdk_config(sdk_cfg).await
    }

    /// Create a new client and authenticate with the server using `SdkConfig`.
    pub async fn login_with_sdk_config(sdk_cfg: SdkConfig) -> Result<Self> {
        let cert_bytes = if !sdk_cfg.tls_client_cert.is_empty() {
            Some(sdk_cfg.tls_client_cert.as_bytes())
        } else {
            None
        };
        let key_bytes = if !sdk_cfg.tls_client_private_key.is_empty() {
            Some(sdk_cfg.tls_client_private_key.as_bytes())
        } else {
            None
        };

        let proxy = if sdk_cfg.proxy.is_empty() {
            None
        } else {
            Some(sdk_cfg.proxy.as_str())
        };
        let client = http::build_client(sdk_cfg.tls_skip_verify, cert_bytes, key_bytes, proxy)
            .context("Failed to build HTTP client")?;

        if sdk_cfg.server_url.is_empty() {
            bail!("server_address is not configured. Run `passbolt configure` first.");
        }

        let private_key = crypto::parse_private_key(&sdk_cfg.private_key_armored)?;

        let passphrase = sdk_cfg.passphrase.clone();
        let base_url = sdk_cfg.server_url.trim_end_matches('/').to_string();

        // Pre-login server identity check (if tokens are stored from `verify` command)
        if !sdk_cfg.server_verify_enc_token.is_empty() || !sdk_cfg.server_verify_token.is_empty() {
            auth::check_server_identity(
                &client,
                &base_url,
                &private_key,
                passphrase.expose_secret(),
                &sdk_cfg.server_verify_enc_token,
                &sdk_cfg.server_verify_token,
            )
            .await
            .context("Server identity check failed")?;
        }

        let mfa = MfaConfig {
            mode: sdk_cfg.mfa_mode.clone(),
            totp_token: SecretString::from(sdk_cfg.mfa_totp_token.clone()),
            totp_offset: sdk_cfg.mfa_totp_offset,
            retrys: sdk_cfg.mfa_retrys,
        };
        let mfa_settings = mfa.into_settings();

        let mut tokens: AuthTokens = auth::login(
            &client,
            &base_url,
            &private_key,
            passphrase.expose_secret(),
            mfa_settings.provider.as_deref(),
            mfa_settings.max_attempts,
        )
        .await?;

        // Use user_id from token if available, otherwise fetch from /users/me.json.
        // mem::take moves the fields out (no heap allocation) and leaves empty strings
        // in tokens, which are then zeroized by AuthTokens's Drop impl.
        let csrf_token = std::mem::take(&mut tokens.csrf_token);
        let mut user_id = std::mem::take(&mut tokens.user_id);

        let mut passbolt_client = PassboltClient {
            client,
            base_url,
            csrf_token,
            private_key,
            passphrase,
            user_id: String::new(),
            metadata_private_key: OnceCell::new(),
        };

        if user_id.is_empty() {
            user_id = passbolt_client.fetch_user_id().await?;
        }

        passbolt_client.user_id = user_id;

        Ok(passbolt_client)
    }

    /// Fetch current user ID via GET /users/me.json (post-login verify).
    async fn fetch_user_id(&self) -> Result<String> {
        let me: User = self
            .get("/users/me.json?contain[gpgkey]=1")
            .await
            .context("Failed to fetch current user info")?;

        // Cross-check: encrypt random bytes with server's copy of our public key,
        // then decrypt with our private key. Detects server-side key substitution.
        if let Some(gpg_key) = &me.gpg_key {
            if let Some(armored) = &gpg_key.armored_key {
                if let Ok(pub_key) = crypto::parse_public_key(armored) {
                    let probe = b"passbolt-key-check";
                    if let Ok(enc) = crypto::encrypt_message(probe, &[&pub_key]) {
                        if let Ok(dec) = crypto::decrypt_message(
                            &enc,
                            &self.private_key.key,
                            self.passphrase.expose_secret(),
                        ) {
                            if dec != probe {
                                bail!(
                                    "Post-login key check failed: server public key does not \
                                     match local private key"
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(me.id)
    }

    /// Terminate the server-side session.
    pub async fn logout(&self) {
        let url = format!("{}/auth/logout.json", self.base_url);
        // Best-effort; ignore errors (session may already be expired)
        let _ = self.client.get(&url).send().await;
    }

    // ── Internal HTTP helpers ─────────────────────────────────────────────────

    /// Inject the CSRF token header on mutating requests.
    fn csrf_header(&self) -> (&'static str, &str) {
        ("X-CSRF-Token", self.csrf_token.as_str())
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;

        self.parse_response(resp).await
    }

    async fn get_with_query<T, K, V>(&self, path: &str, params: &[(K, V)]) -> Result<T>
    where
        T: DeserializeOwned,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let url = format!("{}{path}", self.base_url);
        let mut builder = self.client.get(&url);
        for (k, v) in params {
            builder = builder.query(&[(k.as_ref(), v.as_ref())]);
        }
        let resp = builder.send().await.with_context(|| format!("GET {url}"))?;

        self.parse_response(resp).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        let (csrf_key, csrf_val) = self.csrf_header();
        let resp = self
            .client
            .post(&url)
            .header(csrf_key, csrf_val)
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;

        self.parse_response(resp).await
    }

    async fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        let (csrf_key, csrf_val) = self.csrf_header();
        let resp = self
            .client
            .put(&url)
            .header(csrf_key, csrf_val)
            .json(body)
            .send()
            .await
            .with_context(|| format!("PUT {url}"))?;

        self.parse_response(resp).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let url = format!("{}{path}", self.base_url);
        let (csrf_key, csrf_val) = self.csrf_header();
        let resp = self
            .client
            .delete(&url)
            .header(csrf_key, csrf_val)
            .send()
            .await
            .with_context(|| format!("DELETE {url}"))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            let msg = body
                .pointer("/header/message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            bail!("DELETE {path} failed ({status}): {msg}");
        }
        Ok(())
    }

    async fn parse_response<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body: Value = resp.json().await.context("Failed to parse JSON response")?;

        if !status.is_success() {
            let msg = body
                .pointer("/header/message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            bail!("API error ({status}): {msg}");
        }

        let data = body.get("body").cloned().unwrap_or(body);

        serde_json::from_value(data).context("Failed to deserialize API response")
    }

    // ── v5 Metadata key ────────────────────────────────────────────────────────

    /// Fetch the org-wide metadata private key and cache it for the session.
    pub async fn ensure_metadata_key(&self) -> Result<Option<&SignedSecretKey>> {
        let client = &self.client;
        let base_url = &self.base_url;
        let user_id = &self.user_id;
        let priv_key = &self.private_key.key;
        let pass = self.passphrase.expose_secret();

        let val = self
            .metadata_private_key
            .get_or_try_init(|| async move {
                fetch_metadata_key(client, base_url, user_id, priv_key, pass).await
            })
            .await?;
        Ok(val.as_ref())
    }

    /// Decrypt the PGP-armored `metadata` field of a v5 resource.
    ///
    /// Returns `Ok(None)` when the resource has no metadata, or when the
    /// metadata key is unavailable. Logs nothing — callers decide how to handle.
    pub async fn decrypt_resource_metadata(
        &self,
        r: &Resource,
    ) -> Result<Option<ResourceMetadata>> {
        let armored = match r.armored_metadata() {
            Some(a) => a,
            None => return Ok(None),
        };

        let plaintext = match r.metadata_key_type.as_deref() {
            Some("user_key") => crypto::decrypt_message(
                armored,
                &self.private_key.key,
                self.passphrase.expose_secret(),
            )
            .context("Failed to decrypt resource metadata (user_key)")?,
            _ => match self.ensure_metadata_key().await? {
                Some(key) => crypto::decrypt_message(armored, key, self.passphrase.expose_secret())
                    .context("Failed to decrypt resource metadata (shared_key)")?,
                None => return Ok(None),
            },
        };

        let text = String::from_utf8(plaintext).context("Resource metadata is not valid UTF-8")?;
        let meta = serde_json::from_str::<ResourceMetadata>(&text)
            .context("Failed to parse resource metadata JSON")?;
        Ok(Some(meta))
    }

    // ── Batch decrypt ─────────────────────────────────────────────────────────

    /// Decrypt secrets for a batch of resources in parallel.
    ///
    /// Returns a map of resource_id → SecretData.
    pub async fn decrypt_secrets_batch(
        &self,
        resources: &[Resource],
        workers: usize,
    ) -> Result<HashMap<String, SecretData>> {
        use std::sync::Arc;
        use tokio::task::JoinSet;

        let concurrency = if workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            workers
        }
        .max(1);
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let pgp_key = Arc::new(self.private_key.key.clone());
        let passphrase = Arc::new(self.passphrase.clone());

        let mut set: JoinSet<(String, SecretData)> = JoinSet::new();

        for r in resources {
            let encrypted = r
                .secrets
                .first()
                .and_then(|s| s.data.clone())
                .unwrap_or_default();
            let id = r.id.clone();
            let key = Arc::clone(&pgp_key);
            let pass = Arc::clone(&passphrase);
            let permit = Arc::clone(&sem).acquire_owned().await?;

            set.spawn_blocking(move || {
                let _permit = permit;
                let secret = if encrypted.is_empty() {
                    SecretData::default()
                } else {
                    match crypto::decrypt_message(&encrypted, &key, pass.expose_secret()) {
                        Ok(plaintext) => {
                            let text = String::from_utf8(plaintext).unwrap_or_default();
                            serde_json::from_str::<SecretData>(&text).unwrap_or_else(|_| {
                                SecretData {
                                    password: Some(text.clone()),
                                    raw: Some(text),
                                    ..Default::default()
                                }
                            })
                        }
                        Err(_) => SecretData::default(),
                    }
                };
                (id, secret)
            });
        }

        let mut secrets = HashMap::new();
        while let Some(result) = set.join_next().await {
            if let Ok((id, secret)) = result {
                secrets.insert(id, secret);
            }
        }

        Ok(secrets)
    }

    /// Decrypt v5 metadata for a batch of resources.
    ///
    /// Returns a map of resource_id → ResourceMetadata (only for v5 resources
    /// where decryption succeeded).
    pub async fn decrypt_metadata_batch(
        &self,
        resources: &[Resource],
    ) -> HashMap<String, ResourceMetadata> {
        let mut metadatas = HashMap::new();
        for r in resources {
            if r.is_v5() {
                match self.decrypt_resource_metadata(r).await {
                    Ok(Some(meta)) => {
                        metadatas.insert(r.id.clone(), meta);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("[warn] Cannot decrypt metadata for '{}': {e}", r.name);
                    }
                }
            }
        }
        metadatas
    }

    // ── Crypto accessors ────────────────────────────────────────────────────

    /// Get a reference-counted clone of the PGP private key for parallel tasks.
    pub fn pgp_key_arc(&self) -> std::sync::Arc<pgp::SignedSecretKey> {
        std::sync::Arc::new(self.private_key.key.clone())
    }

    /// Get a reference-counted clone of the passphrase for parallel tasks.
    pub fn passphrase_arc(&self) -> std::sync::Arc<SecretString> {
        std::sync::Arc::new(self.passphrase.clone())
    }

    // ── Resources ──────────────────────────────────────────────────────────────

    pub async fn get_resources(&self, opts: ResourceQuery) -> Result<Vec<Resource>> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[permission]", "1".into()),
            ("contain[secret]", "1".into()),
            ("contain[favorite]", "1".into()),
        ];

        for s in opts.group_ids {
            params.push(("filter[is-shared-with-group][]", s));
        }
        for s in opts.folder_ids {
            params.push(("filter[has-parent][]", s));
        }

        if opts.favorites_only {
            params.push(("filter[is-favorite]", "1".into()));
        }
        if opts.owned_by_me {
            params.push(("filter[is-owned-by-me]", "1".into()));
        }

        self.get_with_query("/resources.json", &params).await
    }

    pub async fn get_resource(&self, id: &str) -> Result<Resource> {
        self.get(&format!(
            "/resources/{id}.json?contain[permission]=1&contain[secret]=1"
        ))
        .await
    }

    pub async fn create_resource(&self, payload: &CreateResourcePayload) -> Result<Resource> {
        let body = serde_json::to_value(payload)?;
        self.post("/resources.json", &body).await
    }

    pub async fn update_resource(
        &self,
        id: &str,
        payload: &UpdateResourcePayload,
    ) -> Result<Resource> {
        let body = serde_json::to_value(payload)?;
        self.put(&format!("/resources/{id}.json"), &body).await
    }

    pub async fn delete_resource(&self, id: &str) -> Result<()> {
        self.delete(&format!("/resources/{id}.json")).await
    }

    pub async fn get_resource_permissions(&self, id: &str) -> Result<Vec<Permission>> {
        self.get(&format!("/permissions/resource/{id}.json")).await
    }

    /// Fetch and decrypt a resource secret.
    pub async fn decrypt_resource_secret(&self, resource: &Resource) -> Result<SecretData> {
        let secret_data = if let Some(s) = resource.secrets.first() {
            s.data.clone().unwrap_or_default()
        } else {
            let secrets: Vec<Secret> = self
                .get(&format!("/secrets/resource/{}.json", resource.id))
                .await
                .context("Failed to fetch resource secret")?;
            secrets
                .first()
                .and_then(|s| s.data.clone())
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
        .context("Failed to decrypt resource secret")?;

        let text = String::from_utf8(plaintext).context("Secret is not valid UTF-8")?;

        if let Ok(data) = serde_json::from_str::<SecretData>(&text) {
            Ok(data)
        } else {
            Ok(SecretData {
                password: Some(text.clone()),
                raw: Some(text),
                ..Default::default()
            })
        }
    }

    /// Encrypt a secret for the given user IDs.
    pub async fn encrypt_secret_for_users(
        &self,
        secret_json: &str,
        user_ids: &[String],
    ) -> Result<Vec<SecretPayload>> {
        let mut payloads = Vec::new();

        for uid in user_ids {
            let user: User = self
                .get(&format!("/users/{uid}.json?contain[gpgkey]=1"))
                .await?;
            let armored_key = user
                .gpg_key
                .as_ref()
                .and_then(|k| k.armored_key.as_deref())
                .context("User has no GPG key")?;

            let pub_key = crypto::parse_public_key(armored_key)?;
            let encrypted = crypto::encrypt_message(secret_json.as_bytes(), &[&pub_key])?;

            payloads.push(SecretPayload {
                user_id: uid.clone(),
                data: encrypted,
            });
        }

        Ok(payloads)
    }

    // ── Folders ───────────────────────────────────────────────────────────────

    pub async fn get_folders(&self, opts: FolderQuery) -> Result<Vec<Folder>> {
        let mut params: Vec<(&str, String)> = vec![("contain[permissions]", "1".into())];

        if let Some(s) = opts.search {
            params.push(("filter[search]", s));
        }
        if let Some(g) = opts.group_id {
            params.push(("filter[is-shared-with-group]", g));
        }
        if let Some(f) = opts.parent_folder_id {
            params.push(("filter[has-parent]", f));
        }

        self.get_with_query("/folders.json", &params).await
    }

    pub async fn get_folder(&self, id: &str) -> Result<Folder> {
        self.get(&format!("/folders/{id}.json?contain[permissions]=1"))
            .await
    }

    pub async fn create_folder(&self, payload: &CreateFolderPayload) -> Result<Folder> {
        let body = serde_json::to_value(payload)?;
        self.post("/folders.json", &body).await
    }

    pub async fn update_folder(&self, id: &str, payload: &UpdateFolderPayload) -> Result<Folder> {
        let body = serde_json::to_value(payload)?;
        self.put(&format!("/folders/{id}.json"), &body).await
    }

    pub async fn delete_folder(&self, id: &str) -> Result<()> {
        self.delete(&format!("/folders/{id}.json")).await
    }

    pub async fn get_folder_permissions(&self, id: &str) -> Result<Vec<Permission>> {
        self.get(&format!("/permissions/folder/{id}.json")).await
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    pub async fn get_users(&self, opts: UserQuery) -> Result<Vec<User>> {
        let mut params: Vec<(&str, String)> = vec![
            ("contain[role]", "1".into()),
            ("contain[gpgkey]", "1".into()),
            ("contain[groups_users]", "1".into()),
        ];

        if let Some(s) = opts.search {
            params.push(("filter[search]", s));
        }
        if let Some(g) = opts.group_id {
            params.push(("filter[is-in-group]", g));
        }
        if let Some(r) = opts.resource_id {
            params.push(("filter[has-access]", r));
        }
        if opts.admin_only {
            params.push(("filter[is-admin]", "1".into()));
        }

        self.get_with_query("/users.json", &params).await
    }

    pub async fn get_user(&self, id: &str) -> Result<User> {
        self.get(&format!(
            "/users/{id}.json?contain[role]=1&contain[gpgkey]=1"
        ))
        .await
    }

    pub async fn create_user(&self, payload: &CreateUserPayload) -> Result<User> {
        let body = serde_json::to_value(payload)?;
        self.post("/users.json", &body).await
    }

    pub async fn update_user(&self, id: &str, payload: &UpdateUserPayload) -> Result<User> {
        let body = serde_json::to_value(payload)?;
        self.put(&format!("/users/{id}.json"), &body).await
    }

    pub async fn delete_user(&self, id: &str) -> Result<()> {
        self.delete(&format!("/users/{id}.json")).await
    }

    pub async fn get_me(&self) -> Result<User> {
        self.get("/users/me.json?contain[role]=1&contain[gpgkey]=1")
            .await
    }

    // ── Groups ────────────────────────────────────────────────────────────────

    pub async fn get_groups(&self, opts: GroupQuery) -> Result<Vec<Group>> {
        let mut params: Vec<(&str, String)> = vec![("contain[groups_users]", "1".into())];

        if let Some(u) = opts.user_id {
            params.push(("filter[has-users]", u));
        }
        if let Some(m) = opts.manager_id {
            params.push(("filter[has-managers]", m));
        }

        self.get_with_query("/groups.json", &params).await
    }

    pub async fn get_group(&self, id: &str) -> Result<Group> {
        self.get(&format!("/groups/{id}.json?contain[groups_users]=1"))
            .await
    }

    pub async fn create_group(&self, payload: &CreateGroupPayload) -> Result<Group> {
        let body = serde_json::to_value(payload)?;
        self.post("/groups.json", &body).await
    }

    pub async fn update_group(&self, id: &str, payload: &UpdateGroupPayload) -> Result<Group> {
        let body = serde_json::to_value(payload)?;
        self.put(&format!("/groups/{id}.json"), &body).await
    }

    pub async fn delete_group(&self, id: &str) -> Result<()> {
        self.delete(&format!("/groups/{id}.json")).await
    }

    // ── Sharing ───────────────────────────────────────────────────────────────

    pub async fn share_resource(&self, id: &str, payload: &SharePayload) -> Result<()> {
        let body = serde_json::to_value(payload)?;
        let _: Value = self
            .put(&format!("/share/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    pub async fn share_folder(&self, id: &str, payload: &SharePayload) -> Result<()> {
        let body = serde_json::to_value(payload)?;
        let _: Value = self.put(&format!("/share/folder/{id}.json"), &body).await?;
        Ok(())
    }

    // ── Roles ─────────────────────────────────────────────────────────────────

    pub async fn get_role_id_by_name(&self, role_name: &str) -> Result<String> {
        let roles: Vec<serde_json::Value> = self.get("/roles.json").await?;
        roles
            .iter()
            .find(|r| r["name"].as_str() == Some(role_name))
            .and_then(|r| r["id"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| anyhow::anyhow!("Role not found: {role_name}"))
    }

    // ── Resource types ────────────────────────────────────────────────────────

    /// Fetch all resource types and return the ID for the given slug, if found.
    pub async fn get_resource_type_id_by_slug(&self, slug: &str) -> Result<Option<String>> {
        let types: Vec<ResourceType> = self.get("/resource-types.json").await?;
        Ok(types.into_iter().find(|t| t.slug == slug).map(|t| t.id))
    }

    // ── Move ──────────────────────────────────────────────────────────────────

    pub async fn move_resource(&self, id: &str, folder_parent_id: Option<&str>) -> Result<()> {
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self
            .put(&format!("/move/resource/{id}.json"), &body)
            .await?;
        Ok(())
    }

    pub async fn move_folder(&self, id: &str, folder_parent_id: Option<&str>) -> Result<()> {
        let payload = MovePayload {
            folder_parent_id: folder_parent_id.map(String::from),
        };
        let body = serde_json::to_value(&payload)?;
        let _: Value = self.put(&format!("/move/folder/{id}.json"), &body).await?;
        Ok(())
    }
}

// ── Query option structs ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct ResourceQuery {
    pub favorites_only: bool,
    pub owned_by_me: bool,
    /// Filter by group IDs (empty = no filter)
    pub group_ids: Vec<String>,
    /// Filter by folder IDs (empty = no filter)
    pub folder_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct FolderQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub parent_folder_id: Option<String>,
}

#[derive(Debug, Default)]
pub struct UserQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub resource_id: Option<String>,
    pub admin_only: bool,
}

#[derive(Debug, Default)]
pub struct GroupQuery {
    pub user_id: Option<String>,
    pub manager_id: Option<String>,
}
