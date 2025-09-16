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
use crate::api::types::{CreateFolderPayload, Folder};
use anyhow::Result;

pub async fn create_folder(
    client: &PassboltClient,
    name: &str,
    folder_parent_id: Option<&str>,
) -> Result<Folder> {
    let payload = CreateFolderPayload {
        name: name.to_string(),
        folder_parent_id: folder_parent_id.map(String::from),
    };
    client.create_folder(&payload).await
}
