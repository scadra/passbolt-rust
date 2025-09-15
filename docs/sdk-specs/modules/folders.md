# Folders Module

## Overview

The Folders module handles hierarchical organization of resources. Folders support nesting (parent-child), individual permissions, and permission inheritance on move operations.

**Current JS references:**
- `controller/folder/folderCreateController.js` - Create folders
- `controller/folder/folderUpdateController.js` - Update folders
- `controller/folder/folderDeleteController.js` - Delete folders
- `controller/folder/folderMoveController.js` - Move folders
- `service/folder/findFolderDetailsService.js` - Find folder details
- `service/folder/moveOneFolderService.js` - Move a single folder (with permission recalculation)
- `service/local_storage/folderLocalStorage.js` - Local cache
- `model/entity/folder/` - Folder entities
- `event/folderEvents.js` - Folder event handlers

## Folder Entity

```json
{
  "id": "<uuid>",
  "name": "My Folder",
  "folder_parent_id": "<uuid|null>",
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "created_by": "<uuid>",
  "modified_by": "<uuid>",
  "personal": true,
  "permission": { /* current user's permission */ },
  "permissions": [ /* all permissions */ ],
  "children_resources": [ /* contained resources */ ],
  "children_folders": [ /* contained subfolders */ ]
}
```

## Create Folder

- `POST /folders.json` with `{ name, folder_parent_id }`
- If created in a shared folder, inherits the parent's permissions
- Updates local cache

## Update Folder

- `PUT /folders/<id>.json` with `{ name }`
- Only the name can be updated directly (move is a separate operation)

## Delete Folder

- `DELETE /folders/<id>.json`
- Cascade option: delete contents or move to root
- Supports `cascade: true` to delete all children
- When `cascade: false` (default), children are moved to root level

## Move Folder

**Current JS reference:** `service/folder/moveOneFolderService.js`

Moving a folder is the most complex operation because it may require permission changes.

### Flow

1. `PUT /move/folder/<id>.json`
   - **Payload**: `{ "folder_parent_id": "<uuid>" | null }`
   - **Response**: 200 OK with standard success envelope
2. If the destination folder has different permissions:
   - Calculate permission changes needed
   - New users who gain access need encrypted secrets for all resources in the moved folder tree
   - Users who lose access have permissions removed
3. Re-encrypt secrets for new recipients (cascading through all resources in the subtree)
4. Share changes are applied via the sharing API
5. Update local storage

### Simulate Endpoint

**There is no dedicated simulate endpoint for folder moves.** Permission changes are calculated entirely client-side. (For comparison, resources have `POST /share/simulate/resource/<id>.json` for share simulation.)

The folder move flow calculates permissions locally, presents changes to the user for confirmation, then applies them.

### Permission Recalculation Algorithm

**Current JS reference:** `service/move/moveOneFolderService.js`, `model/entity/permission/permissionsCollection.js`

When moving folder A from parent P into destination folder D:

```
Step 1: Remove parent's permissions
   remaining = diff(current_permissions, parent_P_permissions)
   → Removes permissions that came from the old parent

Step 2: Add destination's permissions
   inherited = clone(destination_D_permissions, for_aco=folder_A)
   → Creates new permission entries from destination folder

Step 3: Combine with maximum rule
   new_permissions = sum(remaining, inherited)
   → For each user/group, keeps the HIGHEST permission level

Step 4: Special case - moving to root
   If destination is root (null), ensure the current user
   retains OWNER (15) permission

Step 5: Calculate delta
   changes = diff(current_permissions, new_permissions)
   → Produces list of added/removed/modified permissions
```

### Maximum Permission Rule

Permission types have a numeric hierarchy:
- `PERMISSION_READ = 1`
- `PERMISSION_UPDATE = 7`
- `PERMISSION_OWNER = 15`

When combining permissions from multiple sources (individual + group + inherited), the **highest value wins**. The `addOrReplace` operation:
1. Find existing permission for the same ARO (user/group)
2. If new permission has **lower or equal** type → keep existing (no-op)
3. If new permission has **higher** type → replace with the higher permission

**Example**: User A has `Read (1)` on folder from individual permission and `Update (7)` via group membership → result is `Update (7)`.

### Permission Changes on Move

When moving folder A into folder B:
- Users with access to B but not A → **gain access** (inherited from B, need secret re-encryption for all resources in A's subtree)
- Users with access to A but not B → **keep their permissions** (no removal on move, permissions are additive)
- Users with access to both → **keep the highest** permission from either source
- The moved folder and all its children (subfolders + resources) receive the recalculated permissions

## Folder Hierarchy

Folders form a tree:
- Root level: `folder_parent_id = null`
- Nested: `folder_parent_id = <parent_uuid>`
- No circular references allowed
- Depth is not explicitly limited but practically bounded

### Building the Tree

The local cache stores a flat list. The tree structure is computed client-side by:
1. Indexing folders by ID
2. Grouping by `folder_parent_id`
3. Recursively building children arrays

## Local Storage Cache

**Current JS reference:** `service/local_storage/folderLocalStorage.js`

- Stored under key `passbolt-folders`
- Synced on login and periodically
- Uses navigator.locks for concurrency

## Proposed Rust API

```rust
pub struct FoldersClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> FoldersClient<T, S> {
    /// Create a new folder
    pub async fn create(&self, params: CreateFolderParams) -> Result<Folder, FolderError>;

    /// Find folder details by ID
    pub async fn find_details(&self, id: &Uuid) -> Result<Folder, FolderError>;

    /// Update a folder (name only)
    pub async fn update(&self, id: &Uuid, name: &str) -> Result<Folder, FolderError>;

    /// Delete a folder
    pub async fn delete(&self, id: &Uuid, cascade: bool) -> Result<(), FolderError>;

    /// Move a folder to a new parent
    /// This may trigger permission changes and secret re-encryption
    pub async fn move_to(
        &self,
        id: &Uuid,
        folder_parent_id: Option<Uuid>,
        passphrase: &str,
    ) -> Result<(), FolderError>;

    /// Update local storage cache from API
    pub async fn update_local_storage(&self) -> Result<(), FolderError>;

    /// Build folder tree from flat list
    pub fn build_tree(&self, folders: &[Folder]) -> Vec<FolderTreeNode>;
}

// --- Data Types ---

pub struct CreateFolderParams {
    pub name: String,
    pub folder_parent_id: Option<Uuid>,
}

pub struct Folder {
    pub id: Uuid,
    pub name: String,
    pub folder_parent_id: Option<Uuid>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub created_by: Uuid,
    pub modified_by: Uuid,
    pub personal: bool,
    pub permission: Option<Permission>,
    pub permissions: Option<Vec<Permission>>,
}

pub struct FolderTreeNode {
    pub folder: Folder,
    pub children_folders: Vec<FolderTreeNode>,
    pub children_resources: Vec<Uuid>,  // resource IDs
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum FolderError {
    #[error("Folder not found: {id}")]
    NotFound { id: Uuid },
    #[error("Cannot move folder: circular reference detected")]
    CircularReference,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Sharing(#[from] SharingError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

## Dependencies

- **Sharing module**: For permission changes during move
- **Secrets module**: For re-encryption during move
- **Transport trait**: For API calls to `/folders/*`
- **Storage trait**: For local folder cache
