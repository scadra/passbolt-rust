// Passbolt ~ Open source password manager for teams
// Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{Resource, TotpData, UpdateResourcePayload};
use serde_json::Value;

/// Update a resource. Re-encrypts the secret when password or TOTP fields change.
// Many optional arguments — matches the Passbolt API resource fields.
#[allow(clippy::too_many_arguments)]
pub async fn update_resource<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
    name: Option<&str>,
    username: Option<&str>,
    uri: Option<&str>,
    description: Option<&str>,
    new_password: Option<&str>,
    expiry: Option<Value>,
    totp_key: Option<&str>,
    totp_algorithm: Option<&str>,
    totp_digits: Option<u32>,
    totp_period: Option<u64>,
    totp_issuer: Option<&str>,
    remove_totp: bool,
) -> Result<Resource, PassboltError> {
    let needs_secret_update = new_password.is_some()
        || totp_key.is_some()
        || totp_algorithm.is_some()
        || totp_digits.is_some()
        || totp_period.is_some()
        || totp_issuer.is_some()
        || remove_totp;

    let secrets = if needs_secret_update {
        // Fetch existing resource to get current users who have access
        let resource = client.get_resource(id).await?;

        // Get all users who can access this resource
        let permissions = client.get_resource_permissions(id).await?;
        let user_ids: Vec<String> = permissions
            .iter()
            .filter(|permission| permission.aro.as_deref() == Some("User"))
            .filter_map(|permission| permission.aro_foreign_key.clone())
            .collect();

        // Decrypt current secret to preserve existing data
        let current_secret = client.decrypt_resource_secret(&resource).await?;

        let password = new_password
            .map(String::from)
            .or_else(|| current_secret.password.clone())
            .unwrap_or_default();

        let description = description
            .map(String::from)
            .or_else(|| current_secret.description.clone())
            .unwrap_or_default();

        // Determine new TOTP state
        let new_totp: Option<TotpData> = if remove_totp {
            None
        } else if totp_key.is_some() {
            // Build a new TotpData; merge with existing values if partially specified
            let existing = current_secret.totp.as_ref();
            Some(TotpData {
                secret_key: totp_key.map(String::from),
                algorithm: totp_algorithm
                    .map(String::from)
                    .or_else(|| existing.and_then(|totp| totp.algorithm.clone()))
                    .or_else(|| Some("SHA1".to_string())),
                digits: totp_digits
                    .or_else(|| existing.and_then(|totp| totp.digits))
                    .or(Some(6)),
                period: totp_period
                    .or_else(|| existing.and_then(|totp| totp.period))
                    .or(Some(30)),
                issuer: totp_issuer
                    .map(String::from)
                    .or_else(|| existing.and_then(|totp| totp.issuer.clone())),
            })
        } else if totp_algorithm.is_some()
            || totp_digits.is_some()
            || totp_period.is_some()
            || totp_issuer.is_some()
        {
            // Partial TOTP field update — merge with existing TOTP
            current_secret.totp.as_ref().map(|existing| TotpData {
                secret_key: existing.secret_key.clone(),
                algorithm: totp_algorithm
                    .map(String::from)
                    .or_else(|| existing.algorithm.clone()),
                digits: totp_digits.or(existing.digits),
                period: totp_period.or(existing.period),
                issuer: totp_issuer
                    .map(String::from)
                    .or_else(|| existing.issuer.clone()),
            })
        } else {
            // Preserve existing TOTP unchanged
            current_secret.totp.clone()
        };

        let mut secret_data = serde_json::json!({
            "password": password,
            "description": description
        });
        if let Some(totp) = new_totp {
            secret_data["totp"] = serde_json::to_value(totp)?;
        }
        let secret_json = serde_json::to_string(&secret_data)?;

        let encrypted = client
            .encrypt_secret_for_users(&secret_json, &user_ids)
            .await?;
        Some(encrypted)
    } else {
        None
    };

    let expired = expiry.map(|value| if value.is_null() { Value::Null } else { value });

    let payload = UpdateResourcePayload {
        name: name.map(String::from),
        username: username.map(String::from),
        uri: uri.map(String::from),
        description: None,
        resource_type_id: None,
        secrets,
        expired,
    };

    client.update_resource(id, &payload).await
}
