# Resources Module

## Overview

The Resources module handles CRUD operations on password resources (the core data type in Passbolt). Each resource has metadata (name, URL, description) and one or more encrypted secrets. Resources can be organized in folders and shared with users/groups.

**Current JS references:**
- `service/resource/resourceCreateService.js` - Create resources
- `service/resource/findResourcesService.js` - Find/list resources
- `service/resource/getOrFindResourcesService.js` - Get from cache or fetch
- `controller/resource/resourceUpdateController.js` - Update resources
- `service/resource/deleteResourceService.js` - Delete resources
- `service/resource/moveResourcesService.js` - Move resources between folders
- `controller/favorite/favoriteResourceController.js` - Favorites
- `model/entity/resource/` - Resource entities
- `service/local_storage/resourceLocalStorage.js` - Local cache
- `event/resourceEvents.js` - Resource event handlers

## Resource Types

Resources are typed, defining what fields are available in the secret and metadata:

**Current JS reference:** `model/entity/resourceType/`

| Type Slug | Description | Secret Contains |
|-----------|-------------|-----------------|
| `password-string` | Simple password | `{ password }` |
| `password-and-description` | Password + description in secret | `{ password, description }` |
| `password-description-totp` | Password + description + TOTP | `{ password, description, totp }` |
| `totp` | Standalone TOTP | `{ totp }` |
| `v5-password-string` | v5 password (encrypted metadata) | `{ password }` |
| `v5-default` | v5 default (encrypted metadata) | `{ password, description }` |
| `v5-totp-standalone` | v5 TOTP (encrypted metadata) | `{ totp }` |
| `v5-default-with-totp` | v5 password + TOTP (encrypted metadata) | `{ password, description, totp }` |

v4 types store name/URL/description in cleartext metadata. v5 types encrypt metadata.

## Create Resource

**Current JS reference:** `resourceCreateService.js`

### Flow

1. Validate resource data against resource type schema
2. If v5 type: encrypt metadata with metadata key
3. Encrypt secret for the current user's public key
4. `POST /resources.json` with resource data + encrypted secret
5. Update local storage cache

### API Payload

```json
{
  "name": "Example",                    // v4 only (cleartext)
  "username": "user@example.com",       // v4 only
  "uri": "https://example.com",         // v4 only
  "description": "...",                 // v4 only (if not in secret)
  "resource_type_id": "<uuid>",
  "folder_parent_id": "<uuid|null>",
  "metadata": "<encrypted>",            // v5 only
  "metadata_key_id": "<uuid>",          // v5 only
  "metadata_key_type": "user_key|shared_key", // v5 only
  "secrets": [{
    "user_id": "<current_user_uuid>",
    "data": "<PGP encrypted secret JSON>"
  }]
}
```

## Find Resources

**Current JS reference:** `findResourcesService.js`, `getOrFindResourcesService.js`

- `GET /resources.json` with contain/filter/order options
- Contains: `secret`, `permission`, `permissions`, `creator`, `modifier`, `favorite`, `tag`
- Filters: `has-id`, `has-parent-folder-id`, `is-favorite`, `is-shared-with-group`, `is-owned-by-me`, `has-tag`
- Results cached in local storage (`ResourceLocalStorage`)
- `getOrFind` pattern: return from local cache if fresh, otherwise fetch from API

## Update Resource

**Current JS reference:** `controller/resource/resourceUpdateController.js`

### Flow

1. Validate updated fields
2. If secret changed: re-encrypt for all users who have access
3. If v5: re-encrypt metadata if needed
4. `PUT /resources/<id>.json`
5. Update local storage

When the secret changes, all existing permissions determine who needs the new encrypted secret.

## Delete Resource

**Current JS reference:** `service/resource/deleteResourceService.js`

- `DELETE /resources/<id>.json`
- Supports bulk delete: `DELETE /resources.json` with `{ ids: [...] }`
- Updates local storage cache

## Move Resources

**Current JS reference:** `service/resource/moveResourcesService.js`

- `PUT /move/resource/<id>.json`
- **Payload**: `{ "folder_parent_id": "<uuid>" | null }`
- **Response**: 200 OK with standard success envelope
- Moving to a folder may require re-sharing if the destination folder has different permissions
- May trigger re-encryption of secrets for new recipients

## Favorites

**Current JS references:** `controller/favorite/`

- Add favorite: `POST /favorites/resource/<id>.json`
- Remove favorite: `DELETE /favorites/<favorite_id>.json`
- Local cache tracking

## Local Storage Cache

**Current JS reference:** `service/local_storage/resourceLocalStorage.js`

Resources are cached in `browser.storage.local` under key `passbolt-resources`. The cache:
- Is synced on login and periodically
- Supports partial updates (add/update/remove single resources)
- Uses navigator.locks for concurrency control

## Proposed Rust API

```rust
pub struct ResourcesClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> ResourcesClient<T, S> {
    /// Create a new resource
    pub async fn create(&self, params: CreateResourceParams) -> Result<Resource, ResourceError>;

    /// Find resources with filters
    pub async fn find(&self, options: FindResourcesOptions) -> Result<Vec<Resource>, ResourceError>;

    /// Find a single resource by ID with details
    pub async fn find_details(&self, id: &Uuid) -> Result<Resource, ResourceError>;

    /// Get from cache or find from API
    pub async fn get_or_find(&self, options: FindResourcesOptions) -> Result<Vec<Resource>, ResourceError>;

    /// Update an existing resource
    pub async fn update(&self, id: &Uuid, params: UpdateResourceParams) -> Result<Resource, ResourceError>;

    /// Delete a resource
    pub async fn delete(&self, id: &Uuid) -> Result<(), ResourceError>;

    /// Delete multiple resources
    pub async fn delete_all(&self, ids: &[Uuid]) -> Result<(), ResourceError>;

    /// Move resources to a folder
    pub async fn move_to_folder(&self, ids: &[Uuid], folder_id: Option<Uuid>) -> Result<(), ResourceError>;

    /// Add a resource to favorites
    pub async fn add_favorite(&self, id: &Uuid) -> Result<Favorite, ResourceError>;

    /// Remove from favorites
    pub async fn remove_favorite(&self, favorite_id: &Uuid) -> Result<(), ResourceError>;

    /// Update the local storage cache
    pub async fn update_local_storage(&self) -> Result<(), ResourceError>;

    /// Set password expiry date
    pub async fn set_expiration_date(
        &self,
        id: &Uuid,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), ResourceError>;
}

// --- Data Types ---

pub struct CreateResourceParams {
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub description: Option<String>,
    pub resource_type_id: Uuid,
    pub folder_parent_id: Option<Uuid>,
    pub secret: SecretData,
    pub passphrase: String,  // To decrypt private key for signing
}

pub struct UpdateResourceParams {
    pub name: Option<String>,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub description: Option<String>,
    pub secret: Option<SecretData>,
    pub passphrase: Option<String>,
}

pub struct FindResourcesOptions {
    pub contain: ResourceContain,
    pub filters: ResourceFilters,
    pub orders: Vec<ResourceOrder>,
    pub pagination: Option<PaginationParams>,
}

/// Controls which related data to include in the response (API `contain` parameter)
pub struct ResourceContain {
    /// Include the current user's permission on the resource
    pub permission: bool,
    /// Include all permissions on the resource
    pub permissions: bool,
    /// Include the encrypted secret
    pub secret: bool,
    /// Include the creator user profile
    pub creator: bool,
    /// Include the modifier user profile
    pub modifier: bool,
    /// Include favorite status
    pub favorite: bool,
    /// Include tags
    pub tag: bool,
}

impl Default for ResourceContain {
    fn default() -> Self {
        Self {
            permission: false,
            permissions: false,
            secret: false,
            creator: false,
            modifier: false,
            favorite: false,
            tag: false,
        }
    }
}

/// Filters for resource queries (API `filter` parameter)
pub struct ResourceFilters {
    /// Filter by specific resource IDs
    pub has_id: Option<Vec<Uuid>>,
    /// Filter by parent folder
    pub has_parent_folder_id: Option<Option<Uuid>>,  // None = root, Some(id) = specific folder
    /// Only favorites
    pub is_favorite: Option<bool>,
    /// Shared with a specific group
    pub is_shared_with_group: Option<Uuid>,
    /// Owned by current user
    pub is_owned_by_me: Option<bool>,
    /// Has a specific tag
    pub has_tag: Option<String>,
}

impl Default for ResourceFilters {
    fn default() -> Self {
        Self {
            has_id: None,
            has_parent_folder_id: None,
            is_favorite: None,
            is_shared_with_group: None,
            is_owned_by_me: None,
            has_tag: None,
        }
    }
}

/// Sort order for resource queries (API `order` parameter)
pub enum ResourceOrder {
    NameAsc,
    NameDesc,
    CreatedAsc,
    CreatedDesc,
    ModifiedAsc,
    ModifiedDesc,
    UriAsc,
    UriDesc,
    UsernameAsc,
    UsernameDesc,
}

pub struct Resource {
    pub id: Uuid,
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub description: Option<String>,
    pub resource_type_id: Uuid,
    pub folder_parent_id: Option<Uuid>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub created_by: Uuid,
    pub modified_by: Uuid,
    pub favorite: Option<Favorite>,
    pub permission: Option<Permission>,
    pub personal: bool,
    // v5 fields
    pub metadata: Option<EncryptedMetadata>,
    pub metadata_key_id: Option<Uuid>,
    pub metadata_key_type: Option<MetadataKeyType>,
}

/// Encrypted metadata for v5 resources (opaque to the Resource struct)
pub struct EncryptedMetadata {
    /// The PGP-encrypted metadata JSON string
    pub data: String,
}

/// The favorite association
pub struct Favorite {
    pub id: Uuid,
    pub created: DateTime<Utc>,
}

pub enum SecretData {
    PasswordString { password: String },
    PasswordAndDescription { password: String, description: String },
    PasswordDescriptionTotp { password: String, description: String, totp: TotpData },
    Totp { totp: TotpData },
}

pub struct TotpData {
    pub secret_key: String,
    pub period: u32,       // default 30
    pub digits: u8,        // default 6
    pub algorithm: String, // SHA1, SHA256, SHA512
}
```

## Cross-Module Type References

The following types used in this module are defined in other modules:
- `Permission` - See [sharing.md](./sharing.md)
- `MetadataKeyType` - See [metadata.md](./metadata.md)
- `PaginationParams` - See [architecture.md](../architecture.md)

## Error Types

```rust
#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Resource not found: {id}")]
    NotFound { id: Uuid },
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Resource type not found: {id}")]
    ResourceTypeNotFound { id: Uuid },
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Passphrase required but not cached")]
    PassphraseRequired,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```
