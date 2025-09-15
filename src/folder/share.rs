use crate::api::client::PassboltClient;
use crate::api::types::{build_revoke_changes, build_share_changes, SharePayload};
use anyhow::Result;

/// Share a folder with a list of users and/or groups.
///
/// `permission_type == -1` means revoke: existing permissions for the given
/// users/groups are fetched and marked for deletion.
pub async fn share_folder(
    client: &PassboltClient,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<()> {
    if permission_type == -1 {
        let existing = client.get_folder_permissions(id).await?;
        let permissions = build_revoke_changes(&existing, user_ids, group_ids);
        if permissions.is_empty() {
            anyhow::bail!("No matching permissions found to revoke for the given users/groups");
        }
        let payload = SharePayload {
            permissions,
            secrets: None,
        };
        return client.share_folder(id, &payload).await;
    }

    let permissions = build_share_changes(user_ids, group_ids, permission_type);

    let payload = SharePayload {
        permissions,
        secrets: None,
    };

    client.share_folder(id, &payload).await
}
