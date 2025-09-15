use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{Group, GroupUserPayload, UpdateGroupPayload};

pub async fn update_group<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    name: Option<&str>,
    add_members: &[String],
    add_managers: &[String],
    remove_members: &[String],
) -> Result<Group, PassboltError> {
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
