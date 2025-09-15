# Sharing Module

## Overview

The Sharing module manages resource and folder sharing between users and groups. Sharing involves two concerns: changing permissions (who can access) and re-encrypting secrets (so new recipients can decrypt).

**Current JS references:**
- `service/share/shareResourceService.js` - Share resources
- `service/share/shareFoldersService.js` - Share folders
- `model/entity/permission/` - Permission entities
- `model/entity/permission/change/permissionChangesCollection.js` - Permission change tracking
- `service/api/share/shareService.js` - Share API client
- `event/shareEvents.js` - Share event handlers
- `event/permissionEvents.js` - Permission event handlers

## Permission Model

**Current JS reference:** `model/entity/permission/`

### Permission Entity

```json
{
  "id": "<uuid>",
  "aco": "Resource|Folder",
  "aco_foreign_key": "<resource_or_folder_uuid>",
  "aro": "User|Group",
  "aro_foreign_key": "<user_or_group_uuid>",
  "type": 1|7|15
}
```

### Permission Types

| Value | Name | Description |
|-------|------|-------------|
| 1 | Read | Can view the resource/folder |
| 7 | Update | Can view and edit |
| 15 | Owner | Full control (can share, delete) |

### ACO (Access Control Object)

The thing being shared: `Resource` or `Folder`.

### ARO (Access Request Object)

Who receives the permission: `User` or `Group`.

## Share Resources

**Current JS reference:** `service/share/shareResourceService.js`

### Flow (from `shareAll` method)

1. **Validate inputs**: Resource IDs, permission changes collection, passphrase
2. **Calculate needed secrets**: Determine which users need new encrypted secrets
   - New users being granted access need the secret encrypted for their public key
   - Users being removed don't need new secrets
3. **Decrypt secrets**: Decrypt the current user's copy of each resource's secret
4. **Sync keyring**: Ensure public keys are available for all new recipients
5. **Encrypt secrets for new users**: For each resource, encrypt the plaintext secret with each new recipient's public key
6. **Handle v5 metadata**: If resource uses encrypted metadata, re-encrypt metadata for new recipients
7. **Submit changes**: `PUT /share/resource/<id>.json` with permissions + new encrypted secrets
8. **Update local storage**: Refresh the resource cache

### API Payload

```json
{
  "permissions": [
    {
      "id": "<existing_perm_id>",       // for update/delete
      "aro": "User|Group",
      "aro_foreign_key": "<uuid>",
      "type": 15,                        // for create/update
      "delete": true                     // for deletion
    }
  ],
  "secrets": [
    {
      "user_id": "<uuid>",
      "resource_id": "<uuid>",
      "data": "<PGP encrypted secret>"
    }
  ]
}
```

### Permission Changes Collection

Tracks three types of changes:
- **Created**: New permissions (new users/groups gaining access)
- **Updated**: Changed permission level (e.g., Read → Owner)
- **Deleted**: Removed permissions (revoking access)

## Share Folders

**Current JS reference:** `service/share/shareFoldersService.js`

Sharing a folder cascades to all resources and subfolders within it.

### Flow

1. **Get folder contents**: Recursively collect all resources and subfolders in the tree
2. **Calculate cascading permissions**: Apply the new permissions to all children
3. **Calculate needed secrets**: For each resource in the tree, determine which users need new encrypted secrets
4. **Bulk encrypt**: Encrypt all needed secrets
5. **Submit**: `PUT /share/folder/<id>.json` with all permission changes and encrypted secrets
6. **Update local storage**

## Re-encryption Workflow

This is the critical crypto operation during sharing:

```
1. For each resource being shared:
   a. Fetch the encrypted secret (already encrypted for current user)
   b. Decrypt with current user's private key
   c. For each NEW recipient:
      - Get recipient's public key from keyring
      - Encrypt the plaintext secret with recipient's public key
      - Add to the secrets payload
2. Submit all permission changes + new encrypted secrets in one API call
```

### Performance Optimizations

The current JS implementation uses:
- `ExecuteConcurrentlyService` for parallel encryption
- Session keys for bulk metadata re-encryption
- Batched API calls

## Search AROs

**Current JS reference:** via `event/shareEvents.js`

- `GET /share/search-aros.json?search=<term>` - Search users and groups for sharing autocomplete
- Returns mixed list of users and groups matching the search term

## Proposed Rust API

```rust
pub struct SharingClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> SharingClient<T, S> {
    /// Share resources with permission changes
    /// Handles re-encryption of secrets for new recipients
    pub async fn share_resources(
        &self,
        resource_ids: &[Uuid],
        permission_changes: PermissionChanges,
        passphrase: &str,
    ) -> Result<(), SharingError>;

    /// Share a folder (cascades to all contents)
    pub async fn share_folder(
        &self,
        folder_id: &Uuid,
        permission_changes: PermissionChanges,
        passphrase: &str,
    ) -> Result<(), SharingError>;

    /// Search for users and groups to share with
    pub async fn search_aros(&self, search: &str) -> Result<Vec<Aro>, SharingError>;

    /// Get permissions for a resource or folder
    pub async fn find_permissions(
        &self,
        aco_type: AcoType,
        aco_id: &Uuid,
    ) -> Result<Vec<Permission>, SharingError>;

    /// Get all resources shared with a specific group
    pub async fn find_resources_shared_with_group(
        &self,
        group_id: &Uuid,
    ) -> Result<Vec<Uuid>, SharingError>;
}

// --- Data Types ---

pub struct Permission {
    pub id: Uuid,
    pub aco: AcoType,
    pub aco_foreign_key: Uuid,
    pub aro: AroType,
    pub aro_foreign_key: Uuid,
    pub permission_type: PermissionType,
}

pub enum AcoType {
    Resource,
    Folder,
}

pub enum AroType {
    User,
    Group,
}

#[repr(u8)]
pub enum PermissionType {
    Read = 1,
    Update = 7,
    Owner = 15,
}

pub struct PermissionChanges {
    pub created: Vec<PermissionChange>,
    pub updated: Vec<PermissionChange>,
    pub deleted: Vec<PermissionChange>,
}

pub struct PermissionChange {
    pub id: Option<Uuid>,         // existing permission ID (for update/delete)
    pub aro: AroType,
    pub aro_foreign_key: Uuid,
    pub permission_type: Option<PermissionType>,  // for create/update
}

pub enum Aro {
    User(UserAro),
    Group(GroupAro),
}

pub struct UserAro {
    pub id: Uuid,
    pub username: String,
    pub profile: UserProfile,
    pub gpg_key: Option<GpgKeyInfo>,
}

pub struct GroupAro {
    pub id: Uuid,
    pub name: String,
    pub members_count: u32,
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum SharingError {
    #[error("Cannot share: missing public key for user {user_id}")]
    MissingPublicKey { user_id: Uuid },
    #[error("Cannot share: at least one owner required")]
    NoOwnerRemaining,
    #[error("Insufficient permissions to share")]
    InsufficientPermissions,
    #[error("Encryption failed during sharing: {0}")]
    EncryptionFailed(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
```

## Dependencies

- **Crypto module**: For keyring access, encrypt/decrypt
- **Resources module**: For fetching resources to re-encrypt
- **Folders module**: For traversing folder trees during folder sharing
- **Transport trait**: For API calls to `/share/*`
