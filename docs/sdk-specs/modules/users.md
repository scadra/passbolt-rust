# Users Module

## Overview

The Users module manages user accounts, profiles, avatars, roles, and role-based access control (RBAC). Users are the primary identity type in Passbolt: each user has a GPG key pair, a profile, and role-based permissions.

**Current JS references:**
- `controller/user/userCreateController.js` - Create users
- `controller/user/userDeleteController.js` - Delete users
- `controller/user/userUpdateController.js` - Update users
- `controller/user/getUserController.js` - Get logged-in user
- `service/api/user/userService.js` - User API client
- `service/local_storage/userLocalStorage.js` - User cache
- `service/role/roleService.js` - Role management
- `service/rbac/rbacService.js` - RBAC
- `model/entity/user/` - User entities
- `event/userEvents.js` - User event handlers
- `event/roleEvents.js` - Role event handlers

## User Entity

```json
{
  "id": "<uuid>",
  "username": "user@example.com",
  "active": true,
  "deleted": false,
  "disabled": null,
  "created": "2024-01-01T00:00:00Z",
  "modified": "2024-01-01T00:00:00Z",
  "last_logged_in": "2024-06-01T00:00:00Z",
  "role_id": "<uuid>",
  "role": { "id": "<uuid>", "name": "user|admin" },
  "profile": {
    "id": "<uuid>",
    "user_id": "<uuid>",
    "first_name": "Ada",
    "last_name": "Lovelace",
    "avatar": {
      "id": "<uuid>",
      "url": {
        "medium": "/avatars/...",
        "small": "/avatars/..."
      }
    }
  },
  "gpgkey": {
    "id": "<uuid>",
    "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----...",
    "fingerprint": "...",
    "key_id": "..."
  },
  "groups_users": [
    { "id": "<uuid>", "group_id": "<uuid>", "is_admin": false }
  ]
}
```

## Operations

### Get All Users

- `GET /users.json` with contain/filter options
- Contains: `profile`, `gpgkey`, `groups_users`, `role`, `last_logged_in`
- Filters: `has-groups`, `has-access`, `is-admin`, `search`
- Cached in `UserLocalStorage`

### Get Logged-in User

- `GET /users/me.json`
- Returns the current authenticated user with full profile

### Create User (Admin)

- `POST /users.json`
- Creates a new user account (sends invitation email)
- Payload: `{ username, profile: { first_name, last_name }, role_id }`

### Update User

- `PUT /users/<id>.json`
- Updatable fields: `profile.first_name`, `profile.last_name`, `role_id` (admin only)

### Update Avatar

- `POST /users/<id>/avatar.json` (multipart form data)
- Upload a new profile picture

### Delete User (Admin)

- `DELETE /users/<id>.json`
- Dry-run available: `DELETE /users/<id>/dry-run.json` to check impact
- Transfer ownership option for resources/folders owned by the deleted user

### Resend Invite

- `POST /users/<id>/resend-invite.json`
- Re-sends the setup invitation email (admin only)

### Update Private Key

- `PUT /users/<id>/private-key.json`
- Updates the user's private key (used during key rotation)

### Update Security Token

- `PUT /users/me/security-token.json`
- Updates the visual security token (color + text shown during auth to prevent phishing)

## Roles

**Current JS reference:** `service/role/roleService.js`

Two built-in roles:
- **user**: Standard user (can manage own resources, share, use groups)
- **admin**: Administrator (can manage users, settings, policies)

- `GET /roles.json` - List all roles
- Cached in `RoleLocalStorage`

## RBAC (Role-Based Access Control)

**Current JS reference:** `service/rbac/rbacService.js`

Fine-grained permissions layered on top of roles:

- `GET /rbacs/me.json` - Get current user's RBAC permissions
- Returns a map of `{ ui_action: "allow|deny" }`
- Controls UI-level features (e.g., can user access folders, tags, mobile transfer, etc.)

### RBAC Actions

Known UI actions controlled by RBAC:

| Action | Description |
|--------|-------------|
| `Folders.use` | Can use folder organization |
| `Tags.use` | Can use tagging |
| `Share.viewList` | Can view the sharing dialog |
| `Mobile.transfer` | Can initiate mobile transfer |
| `Desktop.export` | Can export to desktop app |
| `PasswordPolicies.viewAll` | Can view password policies |
| `PasswordExpiry.viewAll` | Can view password expiry settings |
| `Users.viewWorkspace` | Can access the users workspace |
| `Secrets.preview` | Can preview a secret without copying |
| `Resources.import` | Can import resources |
| `Resources.export` | Can export resources |

**Note:** The RBAC action list is server-defined and may grow with new features. The SDK treats actions as opaque strings and does not hardcode the list. The `RbacPermissions` struct uses a `HashMap<String, RbacAction>` for forward-compatibility.

## Account Setup Flow

**Current JS references:** `controller/setup/`, `event/setupEvents.js`, `model/setup/setupModel.js`, `model/entity/account/accountSetupEntity.js`

Account setup is the first-time user registration flow. The user receives an invitation email with a setup URL containing a `userId` and `authenticationToken`.

### Setup Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/setup/start/<user_id>/<token>.json` | Fetch user metadata and policies |
| POST | `/setup/complete/<user_id>.json` | Complete setup with generated keys |
| GET | `/auth/verify.json` | Fetch server's public GPG key |

### Setup Flow

```
1. Start Setup
   GET /setup/start/{userId}/{token}
   Response: {
     user: { id, username, profile, locale, account_recovery_user_setting },
     account_recovery_organization_policy: { ... },
     user_passphrase_policy: { ... }
   }

2. Fetch Server Public Key
   GET /auth/verify
   Response: { armored_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----..." }

3. User Interaction Steps (client-side)
   a. Set locale preference
   b. Generate GPG key pair (or import existing private key)
   c. Verify passphrase (if importing key)
   d. Download recovery kit
   e. Configure account recovery preference (approved/rejected)
   f. Set security token (color + 3-char code)

4. Complete Setup
   POST /setup/complete/{userId}
   Body: {
     "authentication_token": { "token": "<uuid>" },
     "gpgkey": { "armored_key": "<user public key>" },
     "locale": "en-US",
     "account_recovery_user_setting": {
       "status": "approved|rejected"
     }
   }
   Response: 200 OK

5. Store Account Locally
   - Save AccountEntity to local storage (domain, user_id, keys, security_token)

6. Sign In
   - Standard GPG challenge-response login with new keys
```

### AccountKit Entity

The AccountKit is a portable account backup containing all cryptographic material needed to restore an account:

```rust
pub struct AccountKit {
    pub domain: String,
    pub user_id: Uuid,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub user_private_armored_key: String,  // max 50,000 chars
    pub user_public_armored_key: String,
    pub server_public_armored_key: String,
    pub security_token: SecurityToken,
}
```

## Account Recovery Flow

**Current JS references:** `controller/recover/`, `event/recoverEvents.js`, `model/entity/account/accountRecoverEntity.js`

Account recovery is used when a user loses access to their account (lost device, reinstalled extension). The user receives a recovery URL with a `userId` and `authenticationToken`.

### Recovery Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/setup/recover/start/<user_id>/<token>.json` | Fetch user metadata for recovery |
| POST | `/setup/recover/complete/<user_id>.json` | Complete recovery with imported keys |
| POST | `/setup/recover/abort/<user_id>.json` | Abort recovery and request help |
| POST | `/account-recovery/requests.json` | Create account recovery request (org-assisted) |
| GET | `/account-recovery/organization-policies.json` | Get organization recovery policy |
| POST | `/account-recovery/responses.json` | Admin responds to recovery request |

### Recovery Flow (Self-Service)

```
1. Start Recovery
   GET /setup/recover/start/{userId}/{token}
   Response: {
     user: { id, username, profile, locale, account_recovery_user_setting },
     user_passphrase_policy: { ... }
   }

2. Fetch Server Public Key
   GET /auth/verify
   Response: { armored_key: "..." }

3. User Imports Private Key
   a. Import existing private key (armored PGP)
   b. Verify passphrase against imported key
   c. Set security token

4. Complete Recovery
   POST /setup/recover/complete/{userId}
   Body: {
     "authentication_token": { "token": "<uuid>" },
     "gpgkey": { "armored_key": "<user public key>" },
     "locale": "en-US"
   }
   Response: 200 OK

5. Store Account Locally + Sign In
```

### Recovery Flow (Organization-Assisted)

When the user has lost their private key AND had previously approved account recovery:

```
1-2. Same as self-service (start + fetch server key)

3. Generate Recovery Request Key
   - Generate a new temporary GPG key pair

4. Create Account Recovery Request
   POST /account-recovery/requests
   Body: {
     "authentication_token": { "token": "<uuid>" },
     "fingerprint": "<40-hex-chars>",
     "user_id": "<uuid>",
     "armored_key": "<new public key>"
   }
   Response: { "id": "<request_uuid>", "status": "pending", ... }

5. Wait for Admin Approval
   - Admin reviews and approves via POST /account-recovery/responses
   - Admin decrypts the user's private key using the organization recovery key
   - Admin re-encrypts for the recovery request key

6. User Retrieves Approved Recovery
   - Gets recovered private key
   - Completes standard recovery flow
```

### Abort Recovery

If the user cannot complete recovery:

```
POST /setup/recover/abort/{userId}
Body: { "authentication_token": { "token": "<uuid>" } }
```

This notifies the organization that the user needs manual intervention.

## Proposed Rust API

```rust
pub struct UsersClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    account: AccountInfo,
}

impl<T: Transport, S: Storage> UsersClient<T, S> {
    /// Get all users
    pub async fn find_all(&self, options: FindUsersOptions) -> Result<Vec<User>, UserError>;

    /// Get the currently logged-in user
    pub async fn find_logged_in_user(&self) -> Result<User, UserError>;

    /// Create a new user (admin)
    pub async fn create(&self, params: CreateUserParams) -> Result<User, UserError>;

    /// Update a user
    pub async fn update(&self, id: &Uuid, params: UpdateUserParams) -> Result<User, UserError>;

    /// Update a user's avatar
    pub async fn update_avatar(&self, id: &Uuid, image_data: &[u8]) -> Result<(), UserError>;

    /// Delete a user (admin), with dry-run option
    pub async fn delete(&self, id: &Uuid) -> Result<(), UserError>;

    /// Delete dry-run: check the impact before deleting
    pub async fn delete_dry_run(&self, id: &Uuid) -> Result<DeleteDryRun, UserError>;

    /// Resend invitation email (admin)
    pub async fn resend_invite(&self, id: &Uuid) -> Result<(), UserError>;

    /// Update user's security token
    pub async fn update_security_token(&self, token: SecurityToken) -> Result<(), UserError>;

    /// Update local storage cache
    pub async fn update_local_storage(&self) -> Result<(), UserError>;
}

/// Role client
pub struct RolesClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> RolesClient<T, S> {
    /// Get all roles
    pub async fn get_all(&self) -> Result<Vec<Role>, UserError>;

    /// Update local storage
    pub async fn update_local_storage(&self) -> Result<(), UserError>;
}

/// RBAC client
pub struct RbacClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> RbacClient<T, S> {
    /// Get current user's RBAC permissions
    pub async fn find_me(&self) -> Result<RbacPermissions, UserError>;
}

// --- Data Types ---

pub struct User {
    pub id: Uuid,
    pub username: String,
    pub active: bool,
    pub deleted: bool,
    pub disabled: Option<DateTime<Utc>>,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub last_logged_in: Option<DateTime<Utc>>,
    pub role_id: Uuid,
    pub role: Option<Role>,
    pub profile: Option<UserProfile>,
    pub gpg_key: Option<GpgKeyInfo>,
    pub groups_users: Option<Vec<GroupUser>>,
}

pub struct UserProfile {
    pub id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub avatar: Option<Avatar>,
}

pub struct Avatar {
    pub id: Uuid,
    pub url_medium: String,
    pub url_small: String,
}

pub struct Role {
    pub id: Uuid,
    pub name: String,  // "user" or "admin"
}

pub struct SecurityToken {
    pub color: String,
    pub text_color: String,
    pub code: String,  // 3-character code
}

pub struct CreateUserParams {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub role_id: Uuid,
}

pub struct UpdateUserParams {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role_id: Option<Uuid>,
}

/// Options for finding/listing users
pub struct FindUsersOptions {
    pub contain: UserContain,
    pub filters: UserFilters,
    pub pagination: Option<PaginationParams>,
}

/// Controls which related data to include in user responses
pub struct UserContain {
    /// Include user profile (first_name, last_name, avatar)
    pub profile: bool,
    /// Include the user's GPG public key
    pub gpgkey: bool,
    /// Include group memberships
    pub groups_users: bool,
    /// Include the user's role
    pub role: bool,
    /// Include last_logged_in timestamp
    pub last_logged_in: bool,
}

impl Default for UserContain {
    fn default() -> Self {
        Self {
            profile: true,
            gpgkey: false,
            groups_users: false,
            role: false,
            last_logged_in: false,
        }
    }
}

/// Filters for user queries
pub struct UserFilters {
    /// Filter users who belong to specific groups
    pub has_groups: Option<Vec<Uuid>>,
    /// Filter users who have access to a specific resource/folder
    pub has_access: Option<Uuid>,
    /// Filter by admin role
    pub is_admin: Option<bool>,
    /// Free-text search (matches username, first_name, last_name)
    pub search: Option<String>,
}

impl Default for UserFilters {
    fn default() -> Self {
        Self {
            has_groups: None,
            has_access: None,
            is_admin: None,
            search: None,
        }
    }
}

/// Account setup client
pub struct SetupClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> SetupClient<T, S> {
    /// Start setup: fetch user metadata and policies
    pub async fn start(&self, user_id: &Uuid, token: &Uuid) -> Result<SetupInfo, SetupError>;

    /// Complete setup: submit generated keys and preferences
    pub async fn complete(&self, user_id: &Uuid, params: CompleteSetupParams) -> Result<(), SetupError>;
}

/// Account recovery client
pub struct RecoverClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
}

impl<T: Transport, S: Storage> RecoverClient<T, S> {
    /// Start recovery: fetch user metadata
    pub async fn start(&self, user_id: &Uuid, token: &Uuid) -> Result<RecoverInfo, SetupError>;

    /// Complete recovery: submit imported keys
    pub async fn complete(&self, user_id: &Uuid, params: CompleteRecoverParams) -> Result<(), SetupError>;

    /// Abort recovery and request help
    pub async fn abort(&self, user_id: &Uuid, token: &Uuid) -> Result<(), SetupError>;

    /// Create an account recovery request (org-assisted)
    pub async fn create_recovery_request(&self, params: RecoveryRequestParams) -> Result<RecoveryRequest, SetupError>;
}

// --- Setup/Recovery Data Types ---

pub struct SetupInfo {
    pub user: User,
    pub account_recovery_organization_policy: Option<AccountRecoveryPolicy>,
    pub user_passphrase_policies: Option<UserPassphrasePolicies>,
}

pub struct RecoverInfo {
    pub user: User,
    pub user_passphrase_policies: Option<UserPassphrasePolicies>,
}

pub struct CompleteSetupParams {
    pub authentication_token: Uuid,
    pub user_public_armored_key: String,
    pub locale: Option<String>,
    pub account_recovery_user_setting: Option<AccountRecoveryUserSetting>,
}

pub struct CompleteRecoverParams {
    pub authentication_token: Uuid,
    pub user_public_armored_key: String,
    pub locale: Option<String>,
}

pub struct RecoveryRequestParams {
    pub authentication_token: Uuid,
    pub user_id: Uuid,
    pub fingerprint: String,
    pub armored_key: String,  // public key for recovery
}

pub struct RecoveryRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub status: String,  // "pending", "approved", "rejected"
}

pub struct AccountRecoveryPolicy {
    pub policy: String,  // "mandatory", "opt-in", "opt-out", "disabled"
}

pub struct AccountRecoveryUserSetting {
    pub status: String,  // "approved", "rejected"
}

pub struct UserPassphrasePolicies {
    pub entropy_minimum: Option<u32>,
    pub external_dictionary_check: bool,
}

pub struct DeleteDryRun {
    pub resources_sole_owner_count: u32,
    pub folders_sole_owner_count: u32,
    pub groups_sole_manager_count: u32,
}

pub struct RbacPermissions {
    pub permissions: HashMap<String, RbacAction>,
}

pub enum RbacAction {
    Allow,
    Deny,
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found: {id}")]
    NotFound { id: Uuid },
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Cannot delete: user is sole owner of resources")]
    SoleOwnerConflict,
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

#[derive(Error, Debug)]
pub enum SetupError {
    #[error("Invalid authentication token")]
    InvalidToken,
    #[error("Setup already completed")]
    AlreadyCompleted,
    #[error("Recovery request not found or expired")]
    RecoveryRequestNotFound,
    #[error("Account recovery not enabled for this user")]
    RecoveryNotEnabled,
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
```
