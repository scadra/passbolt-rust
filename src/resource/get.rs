use anyhow::{Context, Result};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::api::client::PassboltClient;
use crate::api::types::{Permission, Resource, SecretData};

/// Fetch a resource by ID.
pub async fn get_resource(client: &PassboltClient, id: &str) -> Result<Resource> {
    client.get_resource(id).await
}

/// Fetch and decrypt a resource's secret.
pub async fn get_resource_secret(
    client: &PassboltClient,
    resource: &Resource,
) -> Result<SecretData> {
    client.decrypt_resource_secret(resource).await
}

/// Fetch permissions for a resource.
pub async fn get_resource_permissions(
    client: &PassboltClient,
    id: &str,
) -> Result<Vec<Permission>> {
    client.get_resource_permissions(id).await
}

/// Decrypt a resource's TOTP secret and generate the current code.
/// Returns (code, seconds_remaining).
pub async fn get_totp_code(client: &PassboltClient, id: &str) -> Result<(String, u64)> {
    let resource = client.get_resource(id).await?;
    let secret_data = client.decrypt_resource_secret(&resource).await?;

    let totp_data = secret_data
        .totp
        .context("Resource has no TOTP data (not a TOTP resource type)")?;

    let secret_key = totp_data.secret_key.as_deref().unwrap_or("").to_uppercase();
    let algo_str = totp_data.algorithm.as_deref().unwrap_or("SHA1");
    let digits = totp_data.digits.unwrap_or(6) as usize;
    let period = totp_data.period.unwrap_or(30);

    let algorithm = match algo_str.to_uppercase().as_str() {
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };

    let secret_bytes = Secret::Encoded(secret_key)
        .to_bytes()
        .context("Invalid TOTP secret key (bad base32)")?;

    let totp = TOTP::new(algorithm, digits, 1, period, secret_bytes)
        .context("Failed to build TOTP generator")?;

    let code = totp
        .generate_current()
        .context("Failed to generate TOTP code")?;
    let ttl = totp.ttl().context("Failed to compute TOTP TTL")?;

    Ok((code, ttl))
}
