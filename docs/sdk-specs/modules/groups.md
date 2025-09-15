# Groups Module

## Overview

The Groups module manages user groups for simplified sharing. When a resource is shared with a group, all group members gain access. Adding/removing group members triggers re-encryption of all resources shared with that group.

**Current JS references:**
- `controller/group/groupCreateController.js` - Create groups
- `controller/group/groupUpdateController.js` - Update groups
- `controller/group/groupDeleteController.js` - Delete groups
- `service/api/group/groupService.js` - Group API client
- `service/local_storage/groupLocalStorage.js` - Group cache
- `model/entity/group/` - Group entities
- `model/entity/group/groupsUsersCollection.js` - Group membership collection
- `event/groupEvents.js` - Group event handlers

## Group Entity

```json
{
  "id": "<uuid>",
  "name": "Engineering Team",
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "created_by": "<uuid>",
  "modified_by": "<uuid>",
  "groups_users": [
    {
      "id": "<uuid>",
      "group_id": "<uuid>",
      "user_id": "<uuid>",
      "is_admin": true,
      "user": { /* user entity */ }
    }
  ],
  "my_group_user": {
    "id": "<uuid>",
    "is_admin": false
  }
}
```

## Create Group

- `POST /groups.json`
- Payload: `{ name, groups_users: [{ user_id, is_admin }] }`
- At least one group admin is required
- No secret re-encryption needed at creation (no resources shared yet)

## Update Group

**This is the most complex operation** because changing members affects all shared resources.

### Flow

1. **Compute member changes**: Added members, removed members, changed admin status
2. **Find affected resources**: All resources shared with this group via `GET /resources.json?filter[is-shared-with-group]=<group_id>`
3. **For added members**:
   - Fetch encrypted secrets for all affected resources
   - Decrypt with current user's private key
   - Encrypt for each new member's public key
4. **Submit update**: `PUT /groups/<id>.json` with member changes + new encrypted secrets
5. **For removed members**: Server handles permission cleanup (no client-side re-encryption needed since they had access before)

### API Payload (Update)

```json
{
  "name": "New Name",
  "groups_users": [
    { "user_id": "<uuid>", "is_admin": true },           // add member
    { "id": "<existing_id>", "is_admin": false },          // update role
    { "id": "<existing_id>", "delete": true }              // remove member
  ],
  "secrets": [
    {
      "resource_id": "<uuid>",
      "user_id": "<new_member_uuid>",
      "data": "<PGP encrypted secret>"
    }
  ]
}
```

### Re-encryption During Member Addition

```
For each resource shared with the group:
  1. Fetch current user's encrypted secret
  2. Decrypt with current user's private key + passphrase
  3. For each NEW group member:
     a. Get their public key from keyring
     b. Encrypt the plaintext secret with their public key
     c. Add to secrets payload
```

### Permission Conflict Resolution

When a new group member already has individual access to a resource shared with the group:

- **Individual permission exists**: The server maintains both the individual and group-based permissions independently
- **Effective permission**: The user's effective access is the **maximum** of their individual permission and the group permission (same maximum rule as folder moves)
- **No re-encryption needed**: If the user already has access (via individual permission), no new secret encryption is needed for that resource — the user already has a decrypted copy
- **The `secrets` payload in the update request** should only include encrypted secrets for users who have **no existing access** to the resource (neither individual nor via another group)

**Example**: User A has `Read (1)` individually on Resource X. Group G (which User A is being added to) has `Update (7)` on Resource X. After adding User A to Group G:
- User A's effective permission on Resource X is `Update (7)` (maximum)
- No new secret encryption is needed for User A on Resource X (they already have access)

## Delete Group

- `DELETE /groups/<id>.json`
- Dry-run available: `DELETE /groups/<id>/dry-run.json`
- Checks for resources that would become orphaned (sole group permission)
- Resources solely shared with this group may need ownership transfer

## Find Groups

- `GET /groups.json` - List all groups
- Contains: `groups_users`, `my_group_user`, `users`
- Filters: `has-users`, `has-managers`
- `find_my_groups` - Filtered to groups the current user belongs to
- Cached in `GroupLocalStorage`

## Proposed Rust API

```rust
pub struct GroupsClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    crypto: Arc<CryptoService>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> GroupsClient<T, S> {
    /// Create a new group
    pub async fn create(&self, params: CreateGroupParams) -> Result<Group, GroupError>;

    /// Update a group (name and/or members)
    /// Handles re-encryption of secrets for new members
    pub async fn update(
        &self,
        id: &Uuid,
        params: UpdateGroupParams,
        passphrase: &str,
    ) -> Result<Group, GroupError>;

    /// Delete a group
    pub async fn delete(&self, id: &Uuid) -> Result<(), GroupError>;

    /// Delete dry-run: check the impact
    pub async fn delete_dry_run(&self, id: &Uuid) -> Result<GroupDeleteDryRun, GroupError>;

    /// Find all groups
    pub async fn find_all(&self) -> Result<Vec<Group>, GroupError>;

    /// Find groups the current user belongs to
    pub async fn find_my_groups(&self) -> Result<Vec<Group>, GroupError>;

    /// Update local storage cache
    pub async fn update_local_storage(&self) -> Result<(), GroupError>;
}

// --- Data Types ---

pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub created_by: Uuid,
    pub modified_by: Uuid,
    pub groups_users: Option<Vec<GroupUser>>,
    pub my_group_user: Option<GroupUser>,
}

pub struct GroupUser {
    pub id: Uuid,
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub is_admin: bool,
    pub user: Option<User>,
}

pub struct CreateGroupParams {
    pub name: String,
    pub members: Vec<GroupMemberParam>,
}

pub struct UpdateGroupParams {
    pub name: Option<String>,
    pub members_added: Vec<GroupMemberParam>,
    pub members_updated: Vec<GroupMemberUpdateParam>,
    pub members_removed: Vec<Uuid>,  // group_user IDs to remove
}

pub struct GroupMemberParam {
    pub user_id: Uuid,
    pub is_admin: bool,
}

pub struct GroupMemberUpdateParam {
    pub group_user_id: Uuid,
    pub is_admin: bool,
}

pub struct GroupDeleteDryRun {
    pub resources_sole_group_count: u32,
    pub folders_sole_group_count: u32,
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum GroupError {
    #[error("Group not found: {id}")]
    NotFound { id: Uuid },
    #[error("Group must have at least one admin")]
    NoAdminRemaining,
    #[error("Cannot delete: group is sole accessor for resources")]
    SoleAccessorConflict,
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

## Dependencies

- **Crypto module**: For keyring access, encrypt/decrypt during member changes
- **Secrets module**: For re-encryption when adding members
- **Sharing module**: For finding resources shared with the group
- **Transport trait**: For API calls to `/groups/*`
- **Storage trait**: For local group cache
