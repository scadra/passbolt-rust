use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{CreateGroupPayload, Group};

pub async fn create_group<H: HttpClient>(
    client: &PassboltSdk<H>,
    name: &str,
    member_ids: &[String],
    manager_ids: &[String],
) -> Result<Group, PassboltError> {
    let groups_users = crate::group::build_group_members(manager_ids, member_ids);

    let payload = CreateGroupPayload {
        name: name.to_string(),
        groups_users,
    };

    client.create_group(&payload).await
}
