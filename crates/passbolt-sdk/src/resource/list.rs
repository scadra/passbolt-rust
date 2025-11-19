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

use crate::client::{PassboltSdk, ResourceQuery};
use crate::error::PassboltError;
use crate::filter::Filter;
use crate::http::HttpClient;
use crate::resource::filter::filter_resources;
use crate::resource::view::ResourceView;

/// List resources with their v5 metadata decrypted, and their secrets with `secret_workers`
/// (decryption threads, 0 for one per CPU).
///
/// `query.search` and `filters` apply to the decrypted fields: the server cannot search
/// encrypted v5 names.
pub async fn list_resources<H: HttpClient>(
    client: &PassboltSdk<H>,
    query: ResourceQuery,
    filters: &[Filter],
    secret_workers: Option<usize>,
) -> Result<Vec<ResourceView>, PassboltError> {
    let search = query.search.clone();
    let resources = client.get_resources(query).await?;
    let resource_types = client.resource_types().await?;
    let mut metadatas = client.decrypt_metadata_batch(&resources).await?;
    let mut secrets = match secret_workers {
        Some(workers) => {
            client
                .decrypt_secret_texts_batch(&resources, workers)
                .await?
        }
        None => std::collections::HashMap::default(),
    };
    let mut views = Vec::with_capacity(resources.len());
    for resource in resources {
        let id = resource.id.clone();
        let mut view = ResourceView::new(resource, metadatas.remove(&id), &resource_types)?;
        if let Some(secret) = secrets.remove(&id) {
            view = view.with_secret(&secret)?;
        }
        views.push(view);
    }
    if let Some(search) = search {
        let needle = search.to_lowercase();
        views.retain(|view| view.name.to_lowercase().contains(&needle));
    }
    Ok(filter_resources(views, filters))
}
