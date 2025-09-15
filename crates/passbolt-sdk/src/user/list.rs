use anyhow::Result;

use crate::client::{PassboltSdk, UserQuery};
use crate::filter::Filter;
use crate::http::HttpClient;
use crate::types::User;
use crate::user::filter::filter_users;

pub async fn list_users<H: HttpClient>(
    client: &PassboltSdk<H>,
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
        ..Default::default()
    };
    let users = client.get_users(query).await?;
    Ok(filter_users(users, filters))
}
