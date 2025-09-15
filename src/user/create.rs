use crate::api::client::PassboltClient;
use crate::api::types::{CreateUserPayload, CreateUserProfile, User};
use anyhow::Result;

pub async fn create_user(
    client: &PassboltClient,
    username: &str,
    first_name: &str,
    last_name: &str,
    role: &str,
) -> Result<User> {
    // Look up role ID by name; propagate error so a misspelled role fails loudly.
    let role_id = Some(client.get_role_id_by_name(role).await?);

    let payload = CreateUserPayload {
        username: username.to_string(),
        role_id,
        profile: CreateUserProfile {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
        },
    };

    client.create_user(&payload).await
}
