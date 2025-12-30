// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

#[cfg(feature = "totp")]
use anyhow::Context;
use anyhow::Result;

use crate::client::PassboltSdk;
use crate::http::HttpClient;
use crate::resource::view::ResourceView;
use crate::types::{Permission, Resource, SecretData};

/// Fetch a resource by ID.
pub async fn get_resource<H: HttpClient>(client: &PassboltSdk<H>, id: &str) -> Result<Resource> {
    Ok(client.get_resource(id).await?)
}

/// Fetch and decrypt a resource's secret.
pub async fn get_resource_secret<H: HttpClient>(
    client: &PassboltSdk<H>,
    resource: &Resource,
) -> Result<SecretData> {
    Ok(client.decrypt_resource_secret(resource).await?)
}

/// Fetch a resource with its v5 metadata and its secret decrypted.
pub async fn get_resource_view<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
) -> Result<ResourceView> {
    let resource = client.get_resource(id).await?;
    let metadata = client.decrypt_resource_metadata(&resource).await?;
    let secret = client.decrypt_resource_secret_text(&resource).await?;
    let resource_types = client.resource_types().await?;
    let view = ResourceView::new(resource, metadata, &resource_types)?;
    Ok(match secret {
        Some(secret) => view.with_secret(&secret)?,
        None => view,
    })
}

/// Fetch permissions for a resource.
pub async fn get_resource_permissions<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
) -> Result<Vec<Permission>> {
    Ok(client.get_resource_permissions(id).await?)
}

/// Decrypt a resource's TOTP secret and generate the current code.
/// Returns (code, `seconds_remaining`).
#[cfg(feature = "totp")]
pub async fn get_totp_code<H: HttpClient>(
    client: &PassboltSdk<H>,
    id: &str,
) -> Result<(String, u64)> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let resource = client.get_resource(id).await?;
    let secret_data = client.decrypt_resource_secret(&resource).await?;

    let totp_data = secret_data
        .totp
        .context("Resource has no TOTP data (not a TOTP resource type)")?;

    let secret_key = totp_data.secret_key.as_deref().unwrap_or("").to_uppercase();
    let algorithm_name = totp_data.algorithm.as_deref().unwrap_or("SHA1");
    let digits = totp_data.digits.unwrap_or(6) as usize;
    let period = totp_data.period.unwrap_or(30);

    let algorithm = match algorithm_name.to_uppercase().as_str() {
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };

    let secret_bytes = Secret::Encoded(secret_key)
        .to_bytes()
        .context("Invalid TOTP secret key (bad base32)")?;

    // Unchecked: 80-bit secrets (Google Authenticator's default) are below the RFC's 128-bit advice.
    let totp = TOTP::new_unchecked(algorithm, digits, 1, period, secret_bytes);

    let code = totp
        .generate_current()
        .context("Failed to generate TOTP code")?;
    let ttl = totp.ttl().context("Failed to compute TOTP TTL")?;

    Ok((code, ttl))
}
