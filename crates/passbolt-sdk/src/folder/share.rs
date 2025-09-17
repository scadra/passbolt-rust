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

use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{build_revoke_changes, build_share_changes, SharePayload};

/// Share a folder with a list of users and/or groups.
///
/// `permission_type == -1` means revoke: existing permissions for the given
/// users/groups are fetched and marked for deletion.
pub async fn share_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    user_ids: &[String],
    group_ids: &[String],
    permission_type: i32,
) -> Result<(), PassboltError> {
    if permission_type == -1 {
        let existing = client.get_folder_permissions(id).await?;
        let permissions = build_revoke_changes(&existing, user_ids, group_ids);
        if permissions.is_empty() {
            return Err(PassboltError::InvalidArgument(
                "No matching permissions found to revoke for the given users/groups".into(),
            ));
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
