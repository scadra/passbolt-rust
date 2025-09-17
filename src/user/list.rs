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

use crate::api::client::{PassboltClient, UserQuery};
use crate::api::types::User;
use crate::user::filter::filter_users;
use crate::util::filter::Filter;
use anyhow::Result;

pub async fn list_users(
    client: &PassboltClient,
    search: Option<String>,
    group_id: Option<String>,
    resource_id: Option<String>,
    admin_only: bool,
    filters: &[Filter],
) -> Result<Vec<User>> {
    let query = UserQuery {
        search,
        group_id,
        resource_id,
        admin_only,
    };
    let users = client.get_users(query).await?;
    Ok(filter_users(users, filters))
}
