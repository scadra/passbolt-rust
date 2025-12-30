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
use crate::types::{UpdateUserPayload, UpdateUserProfile, User};

pub async fn update_user<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    role: Option<&str>,
) -> Result<User, PassboltError> {
    // As go-passbolt: the API takes the role id, found by the role name.
    let role_id = match role {
        Some(role) => Some(client.get_role_id_by_name(role).await?),
        None => None,
    };

    let profile = if first_name.is_some() || last_name.is_some() {
        Some(UpdateUserProfile {
            first_name: first_name.map(String::from),
            last_name: last_name.map(String::from),
        })
    } else {
        None
    };

    let payload = UpdateUserPayload { role_id, profile };
    client.update_user(id, &payload).await
}
