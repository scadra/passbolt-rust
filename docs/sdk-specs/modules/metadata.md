# Metadata Module

## Overview

The Metadata module manages encrypted resource/folder metadata (v5 format). In v4, metadata (name, URL, description) is stored in cleartext. In v5, metadata is encrypted with shared metadata keys, providing zero-knowledge security for resource names and URLs.

**Current JS references:**
- `service/metadata/encryptMetadataService.js` - Encrypt metadata
- `service/metadata/decryptMetadataService.js` - Decrypt metadata
- `service/metadata/findMetadataKeysService.js` - Find metadata keys
- `service/metadata/findMetadataSettingsService.js` - Metadata settings
- `service/metadata/getOrFindMetadataKeysService.js` - Cache-first metadata keys
- `service/metadata/saveMetadataKeysSettingsService.js` - Save settings
- `controller/metadata/` - Metadata controllers
- `controller/rotateMetadataKey/` - Key rotation controllers
- `model/entity/metadata/` - Metadata entities
- Event handlers in `event/` for `passbolt.metadata.*` events

## Metadata v4 vs v5

### v4 (Legacy - Cleartext)

Metadata stored directly on the resource:
```json
{
  "name": "GitHub Login",
  "username": "user@example.com",
  "uri": "https://github.com",
  "description": "My GitHub account"
}
```

### v5 (Encrypted)

Metadata encrypted as a PGP message:
```json
{
  "metadata": "<PGP encrypted JSON>",
  "metadata_key_id": "<uuid>",
  "metadata_key_type": "user_key|shared_key"
}
```

Decrypted metadata content:
```json
{
  "object_type": "PASSBOLT_RESOURCE_METADATA",
  "name": "GitHub Login",
  "username": "user@example.com",
  "uris": ["https://github.com"],
  "description": "My GitHub account",
  "resource_type_id": "<uuid>"
}
```

## Metadata Keys

### Types

- **User key**: The resource metadata is encrypted with a user's personal PGP key. Only that user can decrypt. Used for personal (non-shared) resources.
- **Shared key**: A dedicated metadata key shared among users. The metadata key's private part is encrypted for each user who needs access.

### Metadata Key Entity

```json
{
  "id": "<uuid>",
  "fingerprint": "...",
  "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "metadata_private_keys": [
    {
      "id": "<uuid>",
      "metadata_key_id": "<uuid>",
      "user_id": "<uuid>",
      "data": "<PGP encrypted private key>"
    }
  ]
}
```

### Key Hierarchy

```
Metadata Shared Key (PGP key pair)
├── Public part: stored in cleartext (used to encrypt metadata)
└── Private part: encrypted separately for each user
    ├── User A: encrypted with User A's public key
    ├── User B: encrypted with User B's public key
    └── User C: encrypted with User C's public key
```

## Share Metadata Private Key

**Current JS reference:** `service/metadata/shareMetadataKeyPrivateService.js`, `service/api/metadata/metadataPrivateKeyApiService.js`

When a new user needs access to metadata encrypted with a shared key, an admin must share the metadata private key with them. The private key is decrypted by the admin, then re-encrypted for the target user's public key.

### Endpoint

```
POST /metadata/keys/private.json
Body: [
  {
    "metadata_key_id": "<uuid>",
    "user_id": "<uuid>",
    "data": "<PGP encrypted private key (armored)>"
  },
  ...
]
Response: 200 OK
```

Multiple entries can be sent in a single request for batch sharing.

```
PUT /metadata/keys/private/<id>.json
Body: {
  "metadata_key_id": "<uuid>",
  "user_id": "<uuid>",
  "data": "<PGP encrypted private key (armored)>"
}
Response: Updated MetadataPrivateKey entity
```

**Important**: The `data` field must contain an encrypted (not decrypted) metadata private key. The API rejects plaintext private keys.

### Sharing Flow

1. **Find users missing metadata keys**: Check `user.missingMetadataKeysIds` from `GET /users.json`
2. **For each missing key**:
   a. Decrypt the metadata private key with the admin's private key
   b. If the original key was signed by the current user, include the admin's private key for signing
   c. Encrypt the metadata private key with the target user's public key
   d. Add to the batch payload
3. **POST the batch** to `/metadata/keys/private.json`
4. **Update local user cache** to remove shared key IDs from `missingMetadataKeysIds`

### Access Control

- Only **admin** users can share metadata private keys
- The admin must have access to the metadata private key (it must be encrypted for them)

## Encrypt Metadata

**Current JS reference:** `service/metadata/encryptMetadataService.js`

### Flow

1. Determine the metadata key to use:
   - If personal resource: use the user's own PGP key
   - If shared resource: use the shared metadata key
2. Serialize metadata to JSON
3. Encrypt with the metadata key's public key
4. Optionally sign with the user's private key

### Session Key Optimization

For bulk operations (sharing, migration), session keys are used:
1. Encrypt metadata once to get the session key
2. Use the session key to encrypt the same metadata for other recipients
3. Avoids redundant encryption of the same plaintext

## Decrypt Metadata

**Current JS reference:** `service/metadata/decryptMetadataService.js`

### Flow

1. Determine which key was used (`metadata_key_type`)
2. If `user_key`: decrypt with user's private key
3. If `shared_key`:
   a. Find the metadata private key encrypted for the current user
   b. Decrypt the metadata private key with user's private key
   c. Use the decrypted metadata key to decrypt the metadata
4. Parse the JSON content
5. Validate the metadata structure

## Key Rotation

**Current JS references:** `controller/rotateMetadataKey/`

Key rotation replaces the shared metadata key. All metadata encrypted with the old key must be re-encrypted with the new key.

### Flow

1. **Generate new metadata key pair**
2. **Encrypt the new private key for all users** who need access
3. **Re-encrypt all metadata** that used the old key:
   - Decrypt with old key
   - Encrypt with new key
   - Batch updates to server
4. **Mark old key as rotated** (not deleted, for audit trail)

This is a long-running operation with progress tracking.

### Resume Support

Key rotation can be interrupted (browser closed, network error). The `resume-rotate-metadata-key` event allows continuing from where it stopped.

## v4 to v5 Migration

### Resource Version Detection

A resource is v4 or v5 based on its `resource_type_id`. The resource type slug determines the version:

- **v4 slugs**: `password-string`, `password-and-description`, `password-description-totp`, `totp`
- **v5 slugs**: Any slug starting with `v5-` (e.g., `v5-default`, `v5-password-string`, `v5-default-totp`, `v5-totp`, `v5-custom-fields`, `v5-standalone-note`)

```rust
impl ResourceType {
    pub fn is_v5(&self) -> bool {
        self.slug.starts_with("v5")
    }
}
```

### v4 → v5 Resource Type Mapping

| v4 Slug | v5 Slug |
|---------|---------|
| `password-string` | `v5-password-string` |
| `password-and-description` | `v5-default` |
| `password-description-totp` | `v5-default-totp` |
| `totp` | `v5-totp` |

### Metadata Key Type Decision Tree

When encrypting metadata for a v5 resource, the SDK must choose between `user_key` and `shared_key`:

```
IF resource.is_personal() AND metadata_settings.allow_usage_of_personal_keys:
    metadata_key_type = "user_key"
    metadata_key_id = None
    encrypt_with = user's public key
    sign_with = [user's private key]
ELSE:
    metadata_key_type = "shared_key"
    metadata_key_id = latest metadata key ID
    encrypt_with = shared metadata public key
    sign_with = [user's private key, metadata private key]
```

**Personal resource detection** (in order of precedence):
1. If `personal` property is explicitly set on the resource, use that value
2. Otherwise: personal if the resource has exactly 1 permission AND that permission's ARO is `User`
3. Otherwise: not personal (shared)

### Migration During Sharing (Personal → Shared Metadata)

**Current JS reference:** `service/share/shareResourceService.js` (`updatePersonalMetadataToSharedMetadata`)

When a personal v5 resource is shared with other users, its metadata must be re-encrypted from `user_key` to `shared_key`. This happens automatically during the share flow:

```
For each resource being shared:
  1. Skip if not a v5 resource type
  2. Skip if metadata already encrypted with shared_key
  3. Skip if not receiving new permissions in this share operation
  4. Set resource.personal = false
  5. Re-encrypt metadata with the shared metadata key
  6. PUT updated resource to API
```

This migration is performed concurrently (up to 5 at a time) with progress reporting.

### Bulk Migration Endpoint (Admin)

```
POST /metadata/upgrade/resources.json
Body: [<ResourcesCollection with updated resource_type_id and encrypted metadata>]
Contains: permissions
Filters: is-shared
Response: Next batch of resources still needing migration
```

### Enable Encrypted Metadata

**Current JS reference:** controllers for `passbolt.metadata.enable*`

Two paths:
1. **New instance**: Enable encrypted metadata from the start
2. **Existing instance**: Migrate existing cleartext metadata to encrypted

### Migration Flow (Existing Instance)

1. Admin enables encrypted metadata in settings
2. Generate shared metadata key
3. Encrypt the metadata key's private part for all users
4. For each existing v4 resource:
   - Read cleartext metadata
   - Map v4 resource type to v5 equivalent
   - Encrypt metadata with the appropriate key (user_key for personal, shared_key for shared)
   - Update resource to v5 format via `POST /metadata/upgrade/resources.json`
5. Update metadata types settings to require v5

### Settings

- **Metadata Types Settings**: Which metadata versions are allowed (`v4`, `v5`, or both)
- **Metadata Keys Settings**: Configuration for metadata key management (including `allow_usage_of_personal_keys`)
- **Getting Started Settings**: Onboarding state for metadata setup

## Proposed Rust API

```rust
pub struct MetadataClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> MetadataClient<T, S> {
    // --- Key Management ---

    /// Find all non-deleted metadata keys
    pub async fn find_all_metadata_keys(&self) -> Result<Vec<MetadataKey>, MetadataError>;

    /// Get or find metadata keys (cache-first)
    pub async fn get_or_find_metadata_keys(&self) -> Result<Vec<MetadataKey>, MetadataError>;

    /// Generate a new metadata key pair
    pub async fn generate_metadata_key(&self) -> Result<MetadataKey, MetadataError>;

    /// Create and save a new metadata key
    pub async fn create_key(&self, passphrase: &str) -> Result<MetadataKey, MetadataError>;

    /// Share a metadata private key with a user
    pub async fn share_private_key_with_user(
        &self,
        metadata_key_id: &Uuid,
        user_id: &Uuid,
        passphrase: &str,
    ) -> Result<(), MetadataError>;

    // --- Encrypt/Decrypt ---

    /// Encrypt metadata for a resource
    pub fn encrypt_metadata(
        &self,
        metadata: &ResourceMetadata,
        key: &MetadataEncryptionKey,
        signing_key: &DecryptedPrivateKey,
    ) -> Result<String, MetadataError>;

    /// Decrypt metadata from a resource
    pub fn decrypt_metadata(
        &self,
        encrypted_metadata: &str,
        key_type: MetadataKeyType,
        metadata_key_id: Option<&Uuid>,
        passphrase: &str,
    ) -> Result<ResourceMetadata, MetadataError>;

    // --- Key Rotation ---

    /// Rotate the metadata key (long-running)
    pub async fn rotate_key(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    /// Resume an interrupted key rotation
    pub async fn resume_rotate_key(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    // --- Settings ---

    /// Get metadata types settings
    pub async fn find_metadata_types_settings(&self) -> Result<MetadataTypesSettings, MetadataError>;

    /// Get or find metadata types settings (cache-first)
    pub async fn get_or_find_metadata_types_settings(&self) -> Result<MetadataTypesSettings, MetadataError>;

    /// Save metadata types settings (admin)
    pub async fn save_metadata_types_settings(&self, settings: MetadataTypesSettings) -> Result<(), MetadataError>;

    /// Get metadata keys settings
    pub async fn find_metadata_keys_settings(&self) -> Result<MetadataKeysSettings, MetadataError>;

    /// Save metadata keys settings (admin)
    pub async fn save_metadata_keys_settings(&self, settings: MetadataKeysSettings) -> Result<(), MetadataError>;

    // --- Migration ---

    /// Enable encrypted metadata for an existing instance
    pub async fn enable_for_existing_instance(&self, passphrase: &str, progress: &dyn ProgressReporter) -> Result<(), MetadataError>;

    /// Keep cleartext metadata for existing instance (opt-out)
    pub async fn keep_cleartext_for_existing_instance(&self) -> Result<(), MetadataError>;
}

// --- Data Types ---

pub struct MetadataKey {
    pub id: Uuid,
    pub fingerprint: String,
    pub armored_key: String,  // public key
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub metadata_private_keys: Vec<MetadataPrivateKey>,
}

pub struct MetadataPrivateKey {
    pub id: Uuid,
    pub metadata_key_id: Uuid,
    pub user_id: Uuid,
    pub data: String,  // PGP encrypted private key
}

pub struct ResourceMetadata {
    pub object_type: String,  // "PASSBOLT_RESOURCE_METADATA"
    pub name: String,
    pub username: Option<String>,
    pub uris: Vec<String>,
    pub description: Option<String>,
    pub resource_type_id: Uuid,
}

pub enum MetadataKeyType {
    UserKey,
    SharedKey,
}

pub enum MetadataEncryptionKey {
    UserKey(PublicKey),
    SharedKey { public_key: PublicKey, key_id: Uuid },
}

pub struct MetadataTypesSettings {
    pub default_resource_types: String,  // "v4", "v5"
    pub default_folder_type: String,
    pub default_tag_type: String,
    pub default_comment_type: String,
    pub allow_creation_of_v5_resources: bool,
    pub allow_creation_of_v5_folders: bool,
    pub allow_creation_of_v5_tags: bool,
    pub allow_creation_of_v5_comments: bool,
    pub allow_creation_of_v4_resources: bool,
    pub allow_creation_of_v4_folders: bool,
    pub allow_creation_of_v4_tags: bool,
    pub allow_creation_of_v4_comments: bool,
}

pub struct MetadataKeysSettings {
    pub allow_usage_of_personal_keys: bool,
    pub zero_knowledge_key_share: bool,
}

/// Progress reporting trait for long-running operations
pub trait ProgressReporter: Send + Sync {
    fn report(&self, step: &str, current: u64, total: u64);
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("Metadata key not found: {id}")]
    KeyNotFound { id: Uuid },
    #[error("No metadata private key found for current user")]
    PrivateKeyNotAvailable,
    #[error("Metadata decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid metadata format: {0}")]
    InvalidFormat(String),
    #[error("Key rotation in progress")]
    RotationInProgress,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

## Dependencies

- **Crypto module**: For all PGP operations on metadata keys and content
- **Resources module**: For accessing resources during migration/rotation
- **Users module**: For distributing metadata private keys
- **Transport trait**: For API calls to `/metadata/*`
- **Storage trait**: For caching metadata keys and settings
