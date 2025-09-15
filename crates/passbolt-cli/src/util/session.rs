use anyhow::Result;

use crate::config::Config;

pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

/// Build a client from the loaded config, performing login.
pub async fn get_client(cfg: &Config) -> Result<Client> {
    let sdk_cfg = cfg.to_sdk_config()?;

    let http_cfg = passbolt_sdk::NativeHttpConfig {
        tls_skip_verify: sdk_cfg.tls_skip_verify,
        client_cert_pem: if sdk_cfg.tls_client_cert.is_empty() {
            None
        } else {
            Some(sdk_cfg.tls_client_cert.as_bytes().to_vec())
        },
        client_key_pem: if sdk_cfg.tls_client_private_key.is_empty() {
            None
        } else {
            Some(sdk_cfg.tls_client_private_key.as_bytes().to_vec())
        },
        proxy_url: if sdk_cfg.proxy.is_empty() {
            None
        } else {
            Some(sdk_cfg.proxy.clone())
        },
    };

    let http = passbolt_sdk::NativeHttpClient::new(&http_cfg)?;

    // Build MFA provider from config
    let mfa_provider: Option<Box<dyn passbolt_sdk::MfaProvider>> = match sdk_cfg.mfa_mode.as_str() {
        "none" => None,
        "non-interactive-totp" => Some(Box::new(crate::util::mfa::AutoTotpProvider {
            secret: sdk_cfg.mfa_totp_token.clone(),
            offset_secs: sdk_cfg.mfa_totp_offset,
        })),
        _ => Some(Box::new(crate::util::mfa::TerminalMfaProvider)),
    };

    let max_attempts = sdk_cfg.mfa_retrys.max(1);

    let client =
        passbolt_sdk::PassboltSdk::login(http, &sdk_cfg, mfa_provider.as_deref(), max_attempts)
            .await?;

    Ok(client)
}
