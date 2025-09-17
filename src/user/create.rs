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
use crate::api::types::{CreateUserPayload, CreateUserProfile, User};
use anyhow::Result;

pub async fn create_user(
    client: &PassboltClient,
    username: &str,
    first_name: &str,
    last_name: &str,
    role: &str,
) -> Result<User> {
    // Look up role ID by name; propagate error so a misspelled role fails loudly.
    let role_id = Some(client.get_role_id_by_name(role).await?);

    let payload = CreateUserPayload {
        username: username.to_string(),
        role_id,
        profile: CreateUserProfile {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        },
    };

    client.create_user(&payload).await
}
