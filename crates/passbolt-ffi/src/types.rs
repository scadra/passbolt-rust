use chrono::{DateTime, Utc};
use passbolt_sdk::types;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn to_iso(dt: Option<DateTime<Utc>>) -> Option<String> {
    dt.map(|d| d.to_rfc3339())
}

// ── Core domain types ───────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiResource {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
    pub uri: Option<String>,
    pub description: Option<String>,
    pub folder_parent_id: Option<String>,
    pub resource_type_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub personal: Option<bool>,
    pub favorite: Option<FfiFavorite>,
    pub secrets: Vec<FfiSecret>,
    pub permissions: Vec<FfiPermission>,
    pub expired: Option<String>,
}

impl From<types::Resource> for FfiResource {
    fn from(r: types::Resource) -> Self {
        Self {
            id: r.id,
            name: r.name,
            username: r.username,
            uri: r.uri,
            description: r.description,
            folder_parent_id: r.folder_parent_id,
            resource_type_id: r.resource_type_id,
            created: to_iso(r.created),
            modified: to_iso(r.modified),
            created_by: r.created_by,
            modified_by: r.modified_by,
            personal: r.personal,
            favorite: r.favorite.map(FfiFavorite::from),
            secrets: r.secrets.into_iter().map(FfiSecret::from).collect(),
            permissions: r.permissions.into_iter().map(FfiPermission::from).collect(),
            expired: to_iso(r.expired),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFolder {
    pub id: String,
    pub name: String,
    pub folder_parent_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub personal: Option<bool>,
    pub permissions: Vec<FfiPermission>,
}

impl From<types::Folder> for FfiFolder {
    fn from(f: types::Folder) -> Self {
        Self {
            id: f.id,
            name: f.name,
            folder_parent_id: f.folder_parent_id,
            created: to_iso(f.created),
            modified: to_iso(f.modified),
            created_by: f.created_by,
            modified_by: f.modified_by,
            personal: f.personal,
            permissions: f.permissions.into_iter().map(FfiPermission::from).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUser {
    pub id: String,
    pub username: Option<String>,
    pub role_id: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub active: Option<bool>,
    pub deleted: Option<bool>,
    pub profile: Option<FfiUserProfile>,
    pub role: Option<FfiRole>,
    pub gpg_key: Option<FfiGpgKey>,
    // groups_users excluded to break User ↔ GroupUser cycle
}

impl From<types::User> for FfiUser {
    fn from(u: types::User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            role_id: u.role_id,
            created: to_iso(u.created),
            modified: to_iso(u.modified),
            active: u.active,
            deleted: u.deleted,
            profile: u.profile.map(FfiUserProfile::from),
            role: u.role.map(FfiRole::from),
            gpg_key: u.gpg_key.map(FfiGpgKey::from),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroup {
    pub id: String,
    pub name: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub deleted: Option<bool>,
    pub groups_users: Vec<FfiGroupUser>,
}

impl From<types::Group> for FfiGroup {
    fn from(g: types::Group) -> Self {
        Self {
            id: g.id,
            name: g.name,
            created: to_iso(g.created),
            modified: to_iso(g.modified),
            created_by: g.created_by,
            modified_by: g.modified_by,
            deleted: g.deleted,
            groups_users: g.groups_users.into_iter().map(FfiGroupUser::from).collect(),
        }
    }
}

// ── Nested types ────────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiPermission {
    pub id: Option<String>,
    pub aco: Option<String>,
    pub aco_foreign_key: Option<String>,
    pub aro: Option<String>,
    pub aro_foreign_key: Option<String>,
    pub permission_type: Option<i32>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub user: Option<FfiUser>,
    pub group: Option<FfiGroup>,
}

impl From<types::Permission> for FfiPermission {
    fn from(p: types::Permission) -> Self {
        Self {
            id: p.id,
            aco: p.aco,
            aco_foreign_key: p.aco_foreign_key,
            aro: p.aro,
            aro_foreign_key: p.aro_foreign_key,
            permission_type: p.permission_type,
            created: to_iso(p.created),
            modified: to_iso(p.modified),
            user: p.user.map(|u| FfiUser::from(*u)),
            group: p.group.map(|g| FfiGroup::from(*g)),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiSecret {
    pub id: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub data: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

impl From<types::Secret> for FfiSecret {
    fn from(s: types::Secret) -> Self {
        Self {
            id: s.id,
            resource_id: s.resource_id,
            user_id: s.user_id,
            data: s.data,
            created: to_iso(s.created),
            modified: to_iso(s.modified),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiSecretData {
    pub password: Option<String>,
    pub description: Option<String>,
    pub totp: Option<FfiTotpData>,
    pub raw: Option<String>,
}

impl From<types::SecretData> for FfiSecretData {
    fn from(s: types::SecretData) -> Self {
        Self {
            password: s.password,
            description: s.description,
            totp: s.totp.map(FfiTotpData::from),
            raw: s.raw,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiTotpData {
    pub secret_key: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
    pub issuer: Option<String>,
}

impl From<types::TotpData> for FfiTotpData {
    fn from(t: types::TotpData) -> Self {
        Self {
            secret_key: t.secret_key,
            algorithm: t.algorithm,
            digits: t.digits,
            period: t.period,
            issuer: t.issuer,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUserProfile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

impl From<types::UserProfile> for FfiUserProfile {
    fn from(p: types::UserProfile) -> Self {
        Self {
            first_name: p.first_name,
            last_name: p.last_name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGpgKey {
    pub id: Option<String>,
    pub user_id: Option<String>,
    pub armored_key: Option<String>,
    pub bits: Option<u32>,
    pub fingerprint: Option<String>,
    pub key_created: Option<String>,
}

impl From<types::GpgKey> for FfiGpgKey {
    fn from(k: types::GpgKey) -> Self {
        Self {
            id: k.id,
            user_id: k.user_id,
            armored_key: k.armored_key,
            bits: k.bits,
            fingerprint: k.fingerprint,
            key_created: to_iso(k.key_created),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroupUser {
    pub id: Option<String>,
    pub group_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: Option<bool>,
    pub created: Option<String>,
    // `user` excluded to break cycle: User ↔ GroupUser
}

impl From<types::GroupUser> for FfiGroupUser {
    fn from(gu: types::GroupUser) -> Self {
        Self {
            id: gu.id,
            group_id: gu.group_id,
            user_id: gu.user_id,
            is_admin: gu.is_admin,
            created: to_iso(gu.created),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiRole {
    pub id: Option<String>,
    pub name: Option<String>,
}

impl From<types::Role> for FfiRole {
    fn from(r: types::Role) -> Self {
        Self {
            id: r.id,
            name: r.name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFavorite {
    pub id: Option<String>,
    pub foreign_model: Option<String>,
    pub foreign_key: Option<String>,
    pub created: Option<String>,
}

impl From<types::Favorite> for FfiFavorite {
    fn from(f: types::Favorite) -> Self {
        Self {
            id: f.id,
            foreign_model: f.foreign_model,
            foreign_key: f.foreign_key,
            created: to_iso(f.created),
        }
    }
}

// ── Feature types ───────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiTag {
    pub id: String,
    pub slug: String,
    pub is_shared: Option<bool>,
    pub created: Option<String>,
    pub modified: Option<String>,
}

impl From<types::Tag> for FfiTag {
    fn from(t: types::Tag) -> Self {
        Self {
            id: t.id,
            slug: t.slug,
            is_shared: t.is_shared,
            created: to_iso(t.created),
            modified: to_iso(t.modified),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiComment {
    pub id: String,
    pub parent_id: Option<String>,
    pub foreign_key: Option<String>,
    pub foreign_model: Option<String>,
    pub content: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub created_by: Option<String>,
    pub modified_by: Option<String>,
    pub creator: Option<FfiUser>,
}

impl From<types::Comment> for FfiComment {
    fn from(c: types::Comment) -> Self {
        Self {
            id: c.id,
            parent_id: c.parent_id,
            foreign_key: c.foreign_key,
            foreign_model: c.foreign_model,
            content: c.content,
            created: to_iso(c.created),
            modified: to_iso(c.modified),
            created_by: c.created_by,
            modified_by: c.modified_by,
            creator: c.creator.map(|u| FfiUser::from(*u)),
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiAro {
    pub id: String,
    pub aro_type: Option<String>,
    pub username: Option<String>,
    pub profile: Option<FfiUserProfile>,
    pub name: Option<String>,
}

impl From<types::Aro> for FfiAro {
    fn from(a: types::Aro) -> Self {
        Self {
            id: a.id,
            aro_type: a.aro_type,
            username: a.username,
            profile: a.profile.map(FfiUserProfile::from),
            name: a.name,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiPasswordExpirySettings {
    pub id: Option<String>,
    pub default_expiry_period_days: Option<u32>,
    pub policy_override: Option<bool>,
    pub automatic_expiry: Option<bool>,
    pub automatic_update: Option<bool>,
}

impl From<types::PasswordExpirySettings> for FfiPasswordExpirySettings {
    fn from(s: types::PasswordExpirySettings) -> Self {
        Self {
            id: s.id,
            default_expiry_period_days: s.default_expiry_period_days,
            policy_override: s.policy_override,
            automatic_expiry: s.automatic_expiry,
            automatic_update: s.automatic_update,
        }
    }
}

#[derive(uniffi::Record)]
#[allow(clippy::struct_field_names)]
pub struct FfiUserDeleteDryRun {
    pub resources_sole_owner_count: u32,
    pub folders_sole_owner_count: u32,
    pub groups_sole_manager_count: u32,
}

impl From<types::UserDeleteDryRun> for FfiUserDeleteDryRun {
    fn from(d: types::UserDeleteDryRun) -> Self {
        Self {
            resources_sole_owner_count: d.resources_sole_owner_count,
            folders_sole_owner_count: d.folders_sole_owner_count,
            groups_sole_manager_count: d.groups_sole_manager_count,
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiGroupDeleteDryRun {
    pub resources_sole_group_count: u32,
    pub folders_sole_group_count: u32,
}

impl From<types::GroupDeleteDryRun> for FfiGroupDeleteDryRun {
    fn from(d: types::GroupDeleteDryRun) -> Self {
        Self {
            resources_sole_group_count: d.resources_sole_group_count,
            folders_sole_group_count: d.folders_sole_group_count,
        }
    }
}

// ── Query types (FFI → SDK) ────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiResourceQuery {
    pub search: Option<String>,
    pub favorites_only: bool,
    pub owned_by_me: bool,
}

impl From<FfiResourceQuery> for passbolt_sdk::ResourceQuery {
    fn from(q: FfiResourceQuery) -> Self {
        Self {
            search: q.search,
            favorites_only: q.favorites_only,
            owned_by_me: q.owned_by_me,
            ..Default::default()
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiFolderQuery {
    pub search: Option<String>,
}

impl From<FfiFolderQuery> for passbolt_sdk::FolderQuery {
    fn from(q: FfiFolderQuery) -> Self {
        Self {
            search: q.search,
            ..Default::default()
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiUserQuery {
    pub search: Option<String>,
    pub group_id: Option<String>,
    pub admin_only: bool,
}

impl From<FfiUserQuery> for passbolt_sdk::UserQuery {
    fn from(q: FfiUserQuery) -> Self {
        Self {
            search: q.search,
            group_id: q.group_id,
            admin_only: q.admin_only,
            ..Default::default()
        }
    }
}

// ── Folder tree ─────────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct FfiFolderTreeNode {
    pub folder: FfiFolder,
    pub children: Vec<FfiFolderTreeNode>,
}

impl From<types::FolderTreeNode> for FfiFolderTreeNode {
    fn from(n: types::FolderTreeNode) -> Self {
        Self {
            folder: FfiFolder::from(n.folder),
            children: n.children.into_iter().map(Self::from).collect(),
        }
    }
}
