use crate::api::client::{GroupQuery, PassboltClient};
use crate::api::types::Group;
use crate::group::filter::filter_groups;
use crate::util::filter::Filter;
use anyhow::Result;

pub async fn list_groups(
    client: &PassboltClient,
    user_id: Option<String>,
    manager_id: Option<String>,
    filters: &[Filter],
) -> Result<Vec<Group>> {
    let query = GroupQuery {
        user_id,
        manager_id,
    };
    let groups = client.get_groups(query).await?;
    Ok(filter_groups(groups, filters))
}
