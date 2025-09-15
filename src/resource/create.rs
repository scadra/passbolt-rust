use anyhow::Result;
use serde_json::Value;

use crate::api::client::PassboltClient;
use crate::api::types::{CreateResourcePayload, TotpData};

/// Create a new resource with an encrypted secret.
// Many required arguments — matches the Passbolt API resource fields.
#[allow(clippy::too_many_arguments)]
pub async fn create_resource(
    client: &PassboltClient,
    name: &str,
    username: Option<&str>,
    uri: Option<&str>,
    description: Option<&str>,
    password: Option<&str>,
    folder_parent_id: Option<&str>,
    expiry: Option<Value>,
    totp: Option<TotpData>,
) -> Result<crate::api::types::Resource> {
    // Determine resource type slug and build secret JSON accordingly
    let (resource_type_slug, secret_data) = match (&totp, password) {
        (Some(totp_data), Some(pwd)) => {
            // Password + TOTP
            let data = serde_json::json!({
                "password": pwd,
                "description": description.unwrap_or(""),
                "totp": totp_data
            });
            ("password-description-totp", data)
        }
        (Some(totp_data), None) => {
            // TOTP only
            let data = serde_json::json!({ "totp": totp_data });
            ("totp", data)
        }
        (None, Some(pwd)) => {
            // Password + description (default)
            let data = serde_json::json!({
                "password": pwd,
                "description": description.unwrap_or("")
            });
            ("password-and-description", data)
        }
        (None, None) => {
            anyhow::bail!("Either --password or --totp-key must be provided");
        }
    };

    let secret_json = serde_json::to_string(&secret_data)?;

    // Look up the resource_type_id for this slug (best-effort; None = server default)
    let resource_type_id = client
        .get_resource_type_id_by_slug(resource_type_slug)
        .await
        .ok()
        .flatten();

    // Encrypt for current user only (they can share later)
    let me_id = client.get_me().await?.id;
    let secrets = client
        .encrypt_secret_for_users(&secret_json, &[me_id])
        .await?;

    let payload = CreateResourcePayload {
        name: name.to_string(),
        username: username.map(String::from),
        uri: uri.map(String::from),
        description: None, // stored in encrypted secret
        folder_parent_id: folder_parent_id.map(String::from),
        resource_type_id,
        secrets,
        expired: expiry.and_then(|v| v.as_str().map(String::from)),
    };

    client.create_resource(&payload).await
}
