// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use std::collections::BTreeSet;

use crate::client::{FolderQuery, PassboltSdk, ResourceQuery};
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::resource::share::{aros, change_permissions, merge_changes};
use crate::types::{build_revoke_changes, Folder, Permission, SharePayload};

const OWNER: i32 = 15;

/// Share a folder with users and groups, or revoke their access (`permission_type == -1`).
///
/// Existing permissions are updated, not duplicated, as go-passbolt does. With `with_content`,
/// the change also goes to the sub-folders and resources the user owns, as the browser
/// extension does; a branch stops at a folder the user does not own.
pub async fn share_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
    with_content: bool,
) -> Result<(), PassboltError> {
    let existing = client.get_folder_permissions(id).await?;
    let changed =
        change_folder(client, id, &existing, user_ids, group_ids, permission_type).await?;
    if !changed && permission_type == -1 {
        return Err(PassboltError::InvalidArgument(
            "No matching permissions found to revoke for the given users/groups".into(),
        ));
    }
    if !with_content {
        return Ok(());
    }

    let folders = client.get_folders(FolderQuery::default()).await?;
    let owned_folders = owned_descendants(id, &folders);
    for folder in folders
        .iter()
        .filter(|folder| owned_folders.contains(&folder.id))
    {
        change_folder(
            client,
            &folder.id,
            &folder.permissions,
            user_ids,
            group_ids,
            permission_type,
        )
        .await?;
    }

    let mut parent_ids: Vec<String> = owned_folders.into_iter().collect();
    parent_ids.push(id.to_string());
    let resources = client
        .get_resources(ResourceQuery {
            folder_ids: parent_ids,
            ..ResourceQuery::default()
        })
        .await?;
    for resource in resources
        .iter()
        .filter(|resource| is_owner(resource.permission.as_ref()))
    {
        change_permissions(client, &resource.id, user_ids, group_ids, permission_type).await?;
    }
    Ok(())
}

/// Share one folder; `false` when its permissions are already as asked.
async fn change_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    existing: &[Permission],
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<bool, PassboltError> {
    let permissions = if permission_type == -1 {
        build_revoke_changes(existing, user_ids, group_ids)
    } else {
        merge_changes(existing, aros(user_ids, group_ids), permission_type)
    };
    if permissions.is_empty() {
        return Ok(false);
    }
    let payload = SharePayload {
        permissions,
        secrets: None,
    };
    client.share_folder(id, &payload).await?;
    Ok(true)
}

/// The folders below `root` the user owns, a branch stopping at the first one they do not own.
fn owned_descendants(root: &str, folders: &[Folder]) -> BTreeSet<String> {
    let mut owned = BTreeSet::new();
    let mut parents = vec![root.to_string()];
    while let Some(parent) = parents.pop() {
        for child in folders
            .iter()
            .filter(|folder| folder.folder_parent_id.as_deref() == Some(parent.as_str()))
        {
            // A cycle in the parent links must not loop forever.
            if is_owner(child.permission.as_ref())
                && child.id != root
                && owned.insert(child.id.clone())
            {
                parents.push(child.id.clone());
            }
        }
    }
    owned
}

fn is_owner(permission: Option<&Permission>) -> bool {
    permission.and_then(|permission| permission.permission_type) == Some(OWNER)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn folder(id: &str, parent: Option<&str>, permission_type: i32) -> Folder {
        serde_json::from_value(json!({
            "id": id,
            "name": id,
            "folder_parent_id": parent,
            "created": null,
            "modified": null,
            "permission": {"type": permission_type}
        }))
        .unwrap()
    }

    #[test]
    fn test_owned_descendants_stop_at_a_folder_not_owned() {
        let folders = [
            folder("child", Some("root"), OWNER),
            folder("grandchild", Some("child"), OWNER),
            folder("read-only", Some("root"), 1),
            folder("below-read-only", Some("read-only"), OWNER),
            folder("elsewhere", None, OWNER),
        ];

        let owned = owned_descendants("root", &folders);

        assert_eq!(owned, BTreeSet::from(["child".into(), "grandchild".into()]));
    }

    #[test]
    fn test_owned_descendants_end_on_a_cycle() {
        let folders = [folder("a", Some("b"), OWNER), folder("b", Some("a"), OWNER)];

        assert_eq!(
            owned_descendants("a", &folders),
            BTreeSet::from(["b".into()])
        );
    }
}
