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
        search,
        ..Default::default()
    };
    let resources = client.get_resources(query).await?;
    Ok(filter_resources(resources, filters))
}
