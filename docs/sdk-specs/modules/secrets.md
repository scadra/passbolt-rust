# Secrets Module

## Overview

The Secrets module handles finding, decrypting, and parsing resource secrets. Each resource has one encrypted secret per user who has access. Secrets contain the sensitive data (passwords, TOTP keys, descriptions) encrypted with each recipient's public PGP key.

**Current JS references:**
- `service/secret/findSecretService.js` - Fetch encrypted secrets from API
- `service/secret/decryptAndParseResourceSecretService.js` - Decrypt and parse secrets
- `service/secret/findAndDecryptSecretService.js` - Combined find + decrypt
- `service/crypto/decryptSecretsService.js` - Bulk decrypt secrets
- `service/secret/secretRevisionService.js` - Secret revision history
- `model/entity/secret/` - Secret entities
- `service/api/secret/secretService.js` - Secret API client
- `event/secretEvents.js` - Secret event handlers

## Secret Structure

A secret is a PGP-encrypted JSON string. The JSON structure depends on the resource type:

### Password String
```json
{
  "password": "my-secret-password"
}
```

### Password and Description
```json
{
  "password": "my-secret-password",
  "description": "Login for production server"
}
```

### Password, Description, and TOTP
```json
{
  "password": "my-secret-password",
  "description": "Two-factor enabled account",
  "totp": {
    "secret_key": "JBSWY3DPEHPK3PXP",
    "period": 30,
    "digits": 6,
    "algorithm": "SHA1"
  }
}
```

### Standalone TOTP
```json
{
  "totp": {
    "secret_key": "JBSWY3DPEHPK3PXP",
    "period": 30,
    "digits": 6,
    "algorithm": "SHA1"
  }
}
```

## Find Secret

**Current JS reference:** `findSecretService.js`

- `GET /secrets/resource/<resource_id>.json`
- Returns the encrypted secret (PGP armored message) for the current user

## Decrypt and Parse

**Current JS reference:** `decryptAndParseResourceSecretService.js`

### Flow

1. Fetch the encrypted secret from API
2. Decrypt the user's private key with passphrase
3. Decrypt the PGP message with the private key
4. Parse the JSON content
5. Validate against the resource type schema

### Bulk Decryption

**Current JS reference:** `decryptSecretsService.js`

For performance, multiple secrets can be decrypted in bulk:
1. Decrypt the private key once
2. Decrypt all secrets using the same unlocked private key
3. Uses concurrent execution (`ExecuteConcurrentlyService`) with batching

## Password Breach Check (Pwned)

**Current JS reference:** `service/secret/pownedService.js` (via `event/pownedPasswordEvents.js`)

Checks if a password has been exposed in known data breaches using the Have I Been Pwned API:

### Flow

1. SHA-1 hash the password
2. Send first 5 characters of hash to `GET https://api.pwnedpasswords.com/range/<prefix>`
3. Check if the remaining hash suffix appears in the response
4. Return the number of times the password was found (0 = safe)

This uses k-anonymity: the full hash is never sent to the API.

**Rate limiting**: The HIBP API has a rate limit of ~1500 requests/minute for unauthenticated clients. For bulk password checks (e.g., checking all passwords in a vault), the SDK should:
- Throttle requests to stay under the limit (e.g., max 20 concurrent requests with 50ms delay between batches)
- Return partial results on rate limit (HTTP 429) rather than failing the entire operation
- Expose a `check_pwned_bulk` method that handles batching internally

## Password Expiry

**Current JS references:** `service/api/passwordExpiry/passwordExpiryResourceService.js`, `service/api/passwordExpiry/passwordExpirySettingsService.js`

- Organization-level settings define expiry policies
- Resources can have an `expired` date

### Password Expiry Endpoints

#### Update Resource Expiry

```
POST /password-expiry/resources.json
Body: {
  "resource_id": "<uuid>",
  "expired": "2024-12-31T00:00:00Z" | null
}
Response: {
  "id": "<uuid>",
  "resource_id": "<uuid>",
  "expired": "2024-12-31T00:00:00Z",
  "created": "...",
  "modified": "..."
}
```

Set `expired` to `null` to clear the expiry.

#### Get Expiry Settings

```
GET /password-expiry/settings.json
Response: {
  "id": "<uuid>",
  "default_expiry_period_days": 90,
  "policy_override": false,
  "automatic_expiry": true,
  "automatic_update": false
}
```

#### Save Expiry Settings (Admin)

```
POST /password-expiry/settings.json
Body: {
  "default_expiry_period_days": 90,
  "policy_override": false,
  "automatic_expiry": true,
  "automatic_update": false
}
```

#### Delete Expiry Settings (Admin)

```
DELETE /password-expiry/settings/<id>.json
```

### Expiry Policies

- **Automatic expiry**: Passwords expire after N days from creation/modification
- **Automatic update**: When a password is updated, the expiry date is reset
- **Expiry on share**: When a password is shared with a new user, the expiry date is set
- **Policy override**: If true, users can override the organization-wide expiry policy
- **Manual expiry**: Users can manually set/clear expiry dates on individual resources

## Secret Revisions

**Current JS references:** `service/api/secretRevision/resourceSecretRevisionApiService.js`, `service/api/secretRevision/secretRevisionsSettingsApiService.js`

### Get Revisions for a Resource

```
GET /secret-revisions/resource/<resource_id>.json
Contains: creator, creator.profile, owner_accessors, owner_accessors.profile, secret
Response: {
  "header": { "status": "success", "servertime": "..." },
  "body": [
    {
      "id": "<uuid>",
      "resource_id": "<uuid>",
      "user_id": "<uuid>",
      "created": "2024-03-04T15:20:30Z",
      "modified": "2024-03-04T15:20:30Z",
      "creator": { "id": "...", "profile": { ... } },
      "secret": { "id": "...", "data": "<encrypted PGP message>" }
    }
  ]
}
```

The `secret` contain option includes the actual encrypted secret data for that revision, allowing decryption and viewing of historical values.

### Revision Settings

```
GET /secret-revisions/settings.json
Response: { "id": "...", "enabled": true, "retention_days": 90, ... }

POST /secret-revisions/settings.json
Body: { "enabled": true, "retention_days": 90 }

DELETE /secret-revisions/settings.json
```

## Proposed Rust API

```rust
pub struct SecretsClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> SecretsClient<T, S> {
    /// Find and return the encrypted secret for a resource
    pub async fn find_by_resource_id(&self, resource_id: &Uuid) -> Result<EncryptedSecret, SecretError>;

    /// Find and decrypt the secret for a resource
    pub async fn find_and_decrypt(
        &self,
        resource_id: &Uuid,
        passphrase: &str,
    ) -> Result<SecretData, SecretError>;

    /// Decrypt an already-fetched encrypted secret
    pub fn decrypt(
        &self,
        encrypted: &EncryptedSecret,
        resource_type_id: &Uuid,
        passphrase: &str,
    ) -> Result<SecretData, SecretError>;

    /// Bulk decrypt multiple secrets
    pub fn decrypt_all(
        &self,
        secrets: &[(EncryptedSecret, Uuid)],  // (secret, resource_type_id)
        passphrase: &str,
    ) -> Result<Vec<SecretData>, SecretError>;

    /// Encrypt a secret for a list of recipients
    pub fn encrypt_for_recipients(
        &self,
        secret: &SecretData,
        recipient_keys: &[(Uuid, PublicKey)],
        passphrase: &str,
    ) -> Result<Vec<EncryptedSecretForUser>, SecretError>;

    /// Check if a password has been pwned
    pub async fn check_pwned(&self, password: &str) -> Result<u64, SecretError>;
}

/// Password expiry client
pub struct PasswordExpiryClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> PasswordExpiryClient<T, S> {
    /// Get password expiry settings
    pub async fn get_settings(&self) -> Result<PasswordExpirySettings, SecretError>;

    /// Save password expiry settings (admin)
    pub async fn save_settings(&self, settings: PasswordExpirySettings) -> Result<(), SecretError>;

    /// Delete password expiry settings (admin)
    pub async fn delete_settings(&self) -> Result<(), SecretError>;
}

/// Secret revisions client
pub struct SecretRevisionsClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> SecretRevisionsClient<T, S> {
    /// Find all revisions for a resource
    pub async fn find_all_by_resource_id(
        &self,
        resource_id: &Uuid,
    ) -> Result<Vec<SecretRevision>, SecretError>;

    /// Get revision settings
    pub async fn find_settings(&self) -> Result<SecretRevisionSettings, SecretError>;

    /// Save revision settings (admin)
    pub async fn save_settings(&self, settings: SecretRevisionSettings) -> Result<(), SecretError>;
}

// --- Data Types ---

pub struct EncryptedSecret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub resource_id: Uuid,
    pub data: String,  // PGP armored message
}

pub struct EncryptedSecretForUser {
    pub user_id: Uuid,
    pub data: String,  // PGP armored message
}

pub struct PasswordExpirySettings {
    pub id: Option<Uuid>,
    pub default_expiry_period_days: Option<u32>,
    pub policy_override: bool,
    pub automatic_expiry: bool,
    pub automatic_update: bool,
}

pub struct SecretRevisionSettings {
    pub id: Option<Uuid>,
    pub enabled: bool,
    pub retention_days: Option<u32>,
}

pub struct SecretRevision {
    pub id: Uuid,
    pub resource_id: Uuid,
    pub created: DateTime<Utc>,
    pub created_by: Uuid,
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found for resource: {resource_id}")]
    NotFound { resource_id: Uuid },
    #[error("Failed to parse secret: {0}")]
    ParseFailed(String),
    #[error("Invalid secret schema for resource type: {resource_type_id}")]
    InvalidSchema { resource_type_id: Uuid },
    #[error("Passphrase required but not cached")]
    PassphraseRequired,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Transport(#[from] TransportError),
}
```

## Dependencies

- **Crypto module**: For PGP encrypt/decrypt
- **Transport trait**: For API calls + HIBP API
- **Resources module**: For resource type resolution
