use anyhow::Result;

use crate::client::{GroupQuery, PassboltSdk};
use crate::filter::Filter;
use crate::group::filter::filter_groups;
use crate::http::HttpClient;
use crate::types::Group;

pub async fn list_groups<H: HttpClient>(
    client: &PassboltSdk<H>,
    user_id: Option<String>,
    manager_id: Option<String>,
    filters: &[Filter],
) -> Result<Vec<Group>> {
    let query = GroupQuery {
        user_id,
        manager_id,
        ..Default::default()
    };
    let groups = client.get_groups(query).await?;
    Ok(filter_groups(groups, filters))
}
