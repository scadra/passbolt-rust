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

use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{CreateUserPayload, CreateUserProfile, User};

pub async fn create_user<H: HttpClient>(
    client: &PassboltSdk<H>,
    username: &str,
    first_name: &str,
    last_name: &str,
    role: &str,
) -> Result<User, PassboltError> {
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
