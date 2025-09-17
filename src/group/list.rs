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

use crate::api::client::{GroupQuery, PassboltClient};
use crate::api::types::Group;
use crate::group::filter::filter_groups;
use crate::util::filter::Filter;
use anyhow::Result;

pub async fn list_groups(
    client: &PassboltClient,
    user_id: Option<String>,
    manager_id: Option<String>,
    filters: &[Filter],
) -> Result<Vec<Group>> {
    let query = GroupQuery {
        user_id,
        manager_id,
    };
    let groups = client.get_groups(query).await?;
    Ok(filter_groups(groups, filters))
}
