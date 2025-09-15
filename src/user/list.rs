use crate::api::client::{PassboltClient, UserQuery};
use crate::api::types::User;
use crate::user::filter::filter_users;
use crate::util::filter::Filter;
use anyhow::Result;

pub async fn list_users(
    client: &PassboltClient,
    search: Option<String>,
    group_id: Option<String>,
    resource_id: Option<String>,
    admin_only: bool,
    filters: &[Filter],
) -> Result<Vec<User>> {
    let query = UserQuery {
        search,
        group_id,
        resource_id,
        admin_only,
    };
    let users = client.get_users(query).await?;
    Ok(filter_users(users, filters))
}
