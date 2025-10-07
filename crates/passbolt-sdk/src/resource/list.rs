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

use crate::client::{PassboltSdk, ResourceQuery};
use crate::filter::Filter;
use crate::http::HttpClient;
use crate::resource::filter::filter_resources;
use crate::types::Resource;

pub async fn list_resources<H: HttpClient>(
    client: &PassboltSdk<H>,
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
        search: search.clone(),
        ..Default::default()
    };
    let mut resources = client.get_resources(query).await?;
    // The server ignores the search filter (v5 names are encrypted): match the name here.
    if let Some(search) = search {
        let needle = search.to_lowercase();
        resources.retain(|resource| resource.name.to_lowercase().contains(&needle));
    }
    Ok(filter_resources(resources, filters))
}
