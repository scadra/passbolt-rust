use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ─── Pagination ──────────────────────────────────────────────────────────────

/// Pagination parameters for list queries.
#[derive(Debug, Clone, Default)]
pub struct PaginationParams {
    /// Request a specific page (1-indexed). If `None`, auto-paginate all pages.
    pub page: Option<u32>,
    /// Items per page. Server default if `None`.
    pub limit: Option<u32>,
}

/// Pagination metadata returned by the API.
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationInfo {
    pub count: u32,
    pub page: u32,
    pub limit: Option<u32>,
}

// ─── Resource ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub folder_parent_id: Option<String>,
    #[serde(default)]
    pub resource_type_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub personal: Option<bool>,
    #[serde(default)]
    pub favorite: Option<Favorite>,
    #[serde(default)]
    pub secrets: Vec<Secret>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// v5: PGP-armored metadata string; v4: null/absent.
    #[serde(rename = "metadata", default)]
    pub metadata_armored: Option<serde_json::Value>,
    #[serde(default)]
    pub metadata_key_id: Option<String>,
    #[serde(default)]
    pub metadata_key_type: Option<String>,
    #[serde(default)]
    pub expired: Option<DateTime<Utc>>,
}

impl Resource {
    /// Returns `true` for v5 resources (metadata is PGP-encrypted).
    #[must_use]
    pub const fn is_v5(&self) -> bool {
        self.metadata_key_id.is_some()
    }

    /// Return the PGP-armored metadata string for v5 resources.
    #[must_use]
    pub fn armored_metadata(&self) -> Option<&str> {
        self.metadata_armored.as_ref()?.as_str()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Favorite {
    pub id: Option<String>,
    pub foreign_model: Option<String>,
    pub foreign_key: Option<String>,
    pub created: Option<DateTime<Utc>>,
}

// ─── v5 Metadata key API ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataKey {
    pub id: String,
    #[serde(default)]
    pub metadata_private_keys: Vec<MetadataPrivateKeyShare>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPrivateKeyShare {
    #[serde(default)]
    pub user_id: Option<String>,
    /// PGP MESSAGE encrypted with the user's public key.
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetadata {
    pub object_type: Option<String>,
    pub name: Option<String>,
    pub username: Option<String>,
    pub uris: Option<Vec<ResourceUri>>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUri {
    pub uri: Option<String>,
    pub match_field: Option<String>,
}

// ─── Secret ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Option<String>,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub data: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

/// Plaintext secret data after decryption.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretData {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub totp: Option<TotpData>,
    /// Raw secret when `resource_type` is password-string
    #[serde(skip)]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpData {
    pub secret_key: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
    pub issuer: Option<String>,
}

// ─── ResourceType ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceType {
    pub id: String,
    pub slug: String,
    pub name: Option<String>,
    pub definition: Option<serde_json::Value>,
}

// ─── Folder ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub folder_parent_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub personal: Option<bool>,
    #[serde(default)]
    pub permissions: Vec<Permission>,
}

// ─── User ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: Option<String>,
    pub role_id: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub deleted: Option<bool>,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub role: Option<Role>,
    #[serde(default)]
    pub gpg_key: Option<GpgKey>,
    #[serde(default)]
    pub groups_users: Vec<GroupUser>,
}

impl User {
    #[must_use]
    pub fn first_name(&self) -> &str {
        self.profile
            .as_ref()
            .and_then(|p| p.first_name.as_deref())
            .unwrap_or("")
    }

    #[must_use]
    pub fn last_name(&self) -> &str {
        self.profile
            .as_ref()
            .and_then(|p| p.last_name.as_deref())
            .unwrap_or("")
    }

    #[must_use]
    pub fn role_name(&self) -> &str {
        self.role
            .as_ref()
            .and_then(|r| r.name.as_deref())
            .unwrap_or("")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgKey {
    pub id: Option<String>,
    pub user_id: Option<String>,
    pub armored_key: Option<String>,
    pub bits: Option<u32>,
    pub fingerprint: Option<String>,
    pub key_created: Option<DateTime<Utc>>,
}

// ─── Group ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub deleted: Option<bool>,
    #[serde(default)]
    pub groups_users: Vec<GroupUser>,
    #[serde(default)]
    pub my_group_user: Option<GroupUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupUser {
    pub id: Option<String>,
    pub group_id: Option<String>,
    pub user_id: Option<String>,
    pub is_admin: Option<bool>,
    pub created: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user: Option<Box<User>>,
}

// ─── Permission ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Option<String>,
    pub aco: Option<String>,
    pub aco_foreign_key: Option<String>,
    pub aro: Option<String>,
    pub aro_foreign_key: Option<String>,
    #[serde(rename = "type")]
    pub permission_type: Option<i32>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user: Option<Box<User>>,
    #[serde(default)]
    pub group: Option<Box<Group>>,
}

impl Permission {
    #[must_use]
    pub const fn type_name(&self) -> &str {
        match self.permission_type {
            Some(1) => "Read",
            Some(7) => "Update",
            Some(15) => "Owner",
            _ => "Unknown",
        }
    }
}

// ─── Share ────────────────────────────────────────────────────────────────────

/// ACO (Access Control Object) type used in share requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareChange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub aro: String,
    pub aro_foreign_key: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub permission_type: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<bool>,
}

// ─── Create/Update payloads ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CreateResourcePayload {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
    pub secrets: Vec<SecretPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateResourcePayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SecretPayload>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct SecretPayload {
    pub user_id: String,
    pub data: String,
}

#[derive(Debug, Serialize)]
pub struct CreateFolderPayload {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateFolderPayload {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateUserPayload {
    pub username: String,
    pub role_id: Option<String>,
    pub profile: CreateUserProfile,
}

#[derive(Debug, Serialize)]
pub struct CreateUserProfile {
    pub first_name: String,
    pub last_name: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<UpdateUserProfile>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateGroupPayload {
    pub name: String,
    pub groups_users: Vec<GroupUserPayload>,
}

#[derive(Debug, Serialize)]
pub struct UpdateGroupPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups_users: Option<Vec<GroupUserPayload>>,
}

#[derive(Debug, Serialize)]
pub struct GroupUserPayload {
    pub user_id: String,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct MovePayload {
    pub folder_parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SharePayload {
    pub permissions: Vec<ShareChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<SecretPayload>>,
}

/// Build a list of share permission changes for users and groups.
#[must_use]
pub fn build_share_changes(
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Vec<ShareChange> {
    user_ids
        .iter()
        .map(|uid| ShareChange {
            id: None,
            aro: "User".into(),
            aro_foreign_key: uid.clone(),
            permission_type: Some(permission_type),
            delete: None,
        })
        .chain(group_ids.iter().map(|gid| ShareChange {
            id: None,
            aro: "Group".into(),
            aro_foreign_key: gid.clone(),
            permission_type: Some(permission_type),
            delete: None,
        }))
        .collect()
}

/// Build revoke changes from existing permissions for the given user/group IDs.
///
/// The Passbolt API requires the existing permission `id` and `delete: true` to revoke.
#[must_use]
pub fn build_revoke_changes(
    existing_perms: &[Permission],
    user_ids: &[String],
    group_ids: &[String],
) -> Vec<ShareChange> {
    existing_perms
        .iter()
        .filter(|p| {
            let fk = p.aro_foreign_key.as_deref().unwrap_or("");
            user_ids.iter().any(|u| u == fk) || group_ids.iter().any(|g| g == fk)
        })
        .filter_map(|p| {
            let id = p.id.clone()?;
            Some(ShareChange {
                id: Some(id),
                aro: p.aro.clone().unwrap_or_default(),
                aro_foreign_key: p.aro_foreign_key.clone().unwrap_or_default(),
                permission_type: None,
                delete: Some(true),
            })
        })
        .collect()
}

// ─── Tag ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub slug: String,
    #[serde(default)]
    pub is_shared: Option<bool>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
}

// ─── Comment ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub id: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub foreign_key: Option<String>,
    #[serde(default)]
    pub foreign_model: Option<String>,
    pub content: String,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub modified_by: Option<String>,
    #[serde(default)]
    pub creator: Option<Box<User>>,
}

// ─── ARO (Access Request Object) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aro {
    pub id: String,
    #[serde(rename = "type", default)]
    pub aro_type: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub profile: Option<UserProfile>,
    #[serde(default)]
    pub name: Option<String>,
}

// ─── Password Expiry Settings ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordExpirySettings {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub default_expiry_period_days: Option<u32>,
    #[serde(default)]
    pub policy_override: Option<bool>,
    #[serde(default)]
    pub automatic_expiry: Option<bool>,
    #[serde(default)]
    pub automatic_update: Option<bool>,
}

// ─── Delete Dry-Run ──────────────────────────────────────────────────────────

/// Impact preview for deleting a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeleteDryRun {
    #[serde(default)]
    pub resources_sole_owner_count: u32,
    #[serde(default)]
    pub folders_sole_owner_count: u32,
    #[serde(default)]
    pub groups_sole_manager_count: u32,
}

/// Impact preview for deleting a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDeleteDryRun {
    #[serde(default)]
    pub resources_sole_group_count: u32,
    #[serde(default)]
    pub folders_sole_group_count: u32,
}

// ─── Metadata Settings ───────────────────────────────────────────────────────

/// Controls which metadata versions are allowed for creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataTypesSettings {
    #[serde(default)]
    pub default_resource_types: Option<String>,
    #[serde(default)]
    pub default_folder_type: Option<String>,
    #[serde(default)]
    pub default_tag_type: Option<String>,
    #[serde(default)]
    pub default_comment_type: Option<String>,
    #[serde(default)]
    pub allow_creation_of_v5_resources: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_folders: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_tags: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v5_comments: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_resources: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_folders: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_tags: Option<bool>,
    #[serde(default)]
    pub allow_creation_of_v4_comments: Option<bool>,
}

/// Controls metadata key behaviour (personal vs shared keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataKeysSettings {
    #[serde(default)]
    pub allow_usage_of_personal_keys: Option<bool>,
    #[serde(default)]
    pub zero_knowledge_key_share: Option<bool>,
}

// ─── Metadata Private Key Sharing ────────────────────────────────────────────

/// Payload for sharing a metadata private key with a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataPrivateKeyPayload {
    pub metadata_key_id: String,
    pub user_id: String,
    /// PGP-encrypted metadata private key (armored), encrypted for the target user.
    pub data: String,
}

// ─── Folder Tree ─────────────────────────────────────────────────────────────

/// A node in a folder hierarchy tree.
#[derive(Debug, Clone)]
pub struct FolderTreeNode {
    pub folder: Folder,
    pub children: Vec<FolderTreeNode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── build_share_changes ─────────────────────────────────────────────────

    #[test]
    fn test_users_only() {
        let users = vec!["u1".into(), "u2".into()];
        let changes = build_share_changes(&users, &[], 7);
        assert_eq!(changes.len(), 2);
        assert!(changes.iter().all(|c| c.aro == "User"));
        assert!(changes.iter().all(|c| c.permission_type == Some(7)));
        assert!(changes.iter().all(|c| c.delete.is_none()));
    }

    #[test]
    fn test_groups_only() {
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&[], &groups, 1);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].aro, "Group");
        assert_eq!(changes[0].aro_foreign_key, "g1");
        assert_eq!(changes[0].permission_type, Some(1));
    }

    #[test]
    fn test_mixed_users_and_groups() {
        let users = vec!["u1".into()];
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&users, &groups, 15);
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].aro, "User");
        assert_eq!(changes[1].aro, "Group");
    }

    #[test]
    fn test_permission_type_propagated() {
        let users = vec!["u1".into(), "u2".into()];
        let groups = vec!["g1".into()];
        let changes = build_share_changes(&users, &groups, 7);
        assert!(changes.iter().all(|c| c.permission_type == Some(7)));
    }

    // ─── build_revoke_changes ─────────────────────────────────────────────────

    fn make_perm(id: &str, aro: &str, aro_foreign_key: &str) -> Permission {
        Permission {
            id: Some(id.into()),
            aco: None,
            aco_foreign_key: None,
            aro: Some(aro.into()),
            aro_foreign_key: Some(aro_foreign_key.into()),
            permission_type: Some(7),
            created: None,
            modified: None,
            user: None,
            group: None,
        }
    }

    #[test]
    fn test_revoke_user() {
        let perms = vec![make_perm("perm-1", "User", "u1")];
        let changes = build_revoke_changes(&perms, &["u1".into()], &[]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, Some("perm-1".into()));
        assert_eq!(changes[0].delete, Some(true));
        assert!(changes[0].permission_type.is_none());
    }

    #[test]
    fn test_revoke_unknown_ignored() {
        let perms = vec![make_perm("perm-1", "User", "u1")];
        let changes = build_revoke_changes(&perms, &["u99".into()], &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_revoke_group() {
        let perms = vec![make_perm("perm-2", "Group", "g1")];
        let changes = build_revoke_changes(&perms, &[], &["g1".into()]);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].aro, "Group");
        assert_eq!(changes[0].delete, Some(true));
    }

    #[test]
    fn test_revoke_perm_without_id_skipped() {
        let perm = Permission {
            id: None,
            aco: None,
            aco_foreign_key: None,
            aro: Some("User".into()),
            aro_foreign_key: Some("u1".into()),
            permission_type: Some(7),
            created: None,
            modified: None,
            user: None,
            group: None,
        };
        let changes = build_revoke_changes(&[perm], &["u1".into()], &[]);
        assert!(changes.is_empty());
    }
}
