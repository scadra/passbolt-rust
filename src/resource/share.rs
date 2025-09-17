// Passbolt ~ Open source password manager for teams
// Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use anyhow::Result;

use crate::api::client::PassboltClient;
use crate::api::types::{build_revoke_changes, build_share_changes, SharePayload};

/// Share a resource with a list of users and/or groups.
///
/// `permission_type == -1` means revoke: existing permissions for the given
/// users/groups are fetched and marked for deletion.  No re-encryption needed.
pub async fn share_resource(
    client: &PassboltClient,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<()> {
    if permission_type == -1 {
        let existing = client.get_resource_permissions(id).await?;
        let permissions = build_revoke_changes(&existing, user_ids, group_ids);
        if permissions.is_empty() {
            anyhow::bail!("No matching permissions found to revoke for the given users/groups");
        }
        let payload = SharePayload {
            permissions,
            secrets: None,
        };
        return client.share_resource(id, &payload).await;
    }

    let permissions = build_share_changes(user_ids, group_ids, permission_type);

    // We need to re-encrypt the secret for new users
    let resource = client.get_resource(id).await?;
    let secret_data = client.decrypt_resource_secret(&resource).await?;

    let secret_json = serde_json::to_string(&secret_data)?;

    let mut secret_payloads = Vec::new();
    for uid in user_ids {
        let encrypted = client
            .encrypt_secret_for_users(&secret_json, &[uid.clone()])
            .await?;
        secret_payloads.extend(encrypted);
    }

    let payload = SharePayload {
        permissions,
        secrets: if secret_payloads.is_empty() {
            None
        } else {
            Some(secret_payloads)
        },
    };

    client.share_resource(id, &payload).await
}
