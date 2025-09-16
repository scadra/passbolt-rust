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

use anyhow::Result;

use crate::api::client::{PassboltClient, ResourceQuery};
use crate::api::types::Resource;
use crate::resource::filter::filter_resources;
use crate::util::filter::Filter;

pub async fn list_resources(
    client: &PassboltClient,
    favorites_only: bool,
    owned_by_me: bool,
    group_ids: Vec<String>,
    folder_ids: Vec<String>,
    search: Option<String>,
    filters: &[Filter],
) -> Result<Vec<Resource>> {
    let query = ResourceQuery {
        favorites_only,
        owned_by_me,
        group_ids,
        folder_ids,
    };
    let resources = client.get_resources(query).await?;
    let resources = if let Some(ref term) = search {
        let term_lower = term.to_lowercase();
        resources
            .into_iter()
            .filter(|r| r.name.to_lowercase().contains(&term_lower))
            .collect()
    } else {
        resources
    };
    Ok(filter_resources(resources, filters))
}
