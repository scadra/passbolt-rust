use crate::api::client::PassboltClient;
use crate::api::types::{CreateGroupPayload, Group};
use anyhow::Result;

pub async fn create_group(
    client: &PassboltClient,
    name: &str,
    member_ids: &[String],
    manager_ids: &[String],
) -> Result<Group> {
    let groups_users = crate::group::build_group_members(manager_ids, member_ids);

    let payload = CreateGroupPayload {
        name: name.to_string(),
        groups_users,
    };

    client.create_group(&payload).await
}
