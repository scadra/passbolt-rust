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

use crate::api::client::PassboltClient;
use crate::api::types::{CreateGroupPayload, Group};
use anyhow::Result;

pub async fn create_group(
    client: &PassboltClient,
    name: &str,
    member_ids: &[String],
    manager_ids: &[String],
) -> Result<Group> {
    let groups_users = crate::group::build_group_members(manager_ids, member_ids);

    let payload = CreateGroupPayload {
        name: name.to_string(),
        groups_users,
    };

    client.create_group(&payload).await
}
