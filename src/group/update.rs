use crate::api::client::PassboltClient;
use crate::api::types::{Group, GroupUserPayload, UpdateGroupPayload};
use anyhow::Result;

pub async fn update_group(
    client: &PassboltClient,
    id: &str,
    name: Option<&str>,
    add_members: &[String],
    add_managers: &[String],
    remove_members: &[String],
) -> Result<Group> {
    let mut groups_users = crate::group::build_group_members(add_managers, add_members);

    for uid in remove_members {
        groups_users.push(GroupUserPayload {
            user_id: uid.clone(),
            is_admin: false,
            delete: Some(true),
        });
    }

    let payload = UpdateGroupPayload {
        name: name.map(String::from),
        groups_users: if groups_users.is_empty() {
            None
        } else {
            Some(groups_users)
        },
    };

    client.update_group(id, &payload).await
}
