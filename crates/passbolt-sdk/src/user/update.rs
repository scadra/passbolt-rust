use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{UpdateUserPayload, UpdateUserProfile, User};

pub async fn update_user<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    first_name: Option<&str>,
    last_name: Option<&str>,
    role: Option<&str>,
) -> Result<User, PassboltError> {
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
