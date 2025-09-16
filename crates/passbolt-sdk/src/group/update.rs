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
use crate::types::{Group, GroupUserPayload, UpdateGroupPayload};

pub async fn update_group<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    name: Option<&str>,
    add_members: &[String],
    add_managers: &[String],
    remove_members: &[String],
) -> Result<Group, PassboltError> {
    let mut groups_users = crate::group::build_group_members(add_managers, add_members);

    for uid in remove_members {
        groups_users.push(GroupUserPayload {
            user_id: uid.clone(),
            is_admin: false,
            delete: Some(true),
        });
    }

    let payload = UpdateGroupPayload {
        name: name.map(String::from),
        groups_users: if groups_users.is_empty() {
            None
        } else {
            Some(groups_users)
        },
    };

    client.update_group(id, &payload).await
}
