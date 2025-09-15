use crate::api::client::PassboltClient;
use crate::api::types::{UpdateUserPayload, UpdateUserProfile, User};
use anyhow::Result;

pub async fn update_user(
    client: &PassboltClient,
    id: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    role: Option<&str>,
) -> Result<User> {
    let role_id = role.map(str::to_string);

    let profile = if first_name.is_some() || last_name.is_some() {
        Some(UpdateUserProfile {
            first_name: first_name.map(String::from),
            last_name: last_name.map(String::from),
        })
    } else {
        None
    };

    let payload = UpdateUserPayload { role_id, profile };
    client.update_user(id, &payload).await
}
