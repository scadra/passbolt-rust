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
use crate::types::{CreateFolderPayload, Folder};

pub async fn create_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    name: &str,
    folder_parent_id: Option<&str>,
) -> Result<Folder, PassboltError> {
    let payload = CreateFolderPayload {
        name: name.to_string(),
        folder_parent_id: folder_parent_id.map(String::from),
    };
    client.create_folder(&payload).await
}
