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

use anyhow::Result;

use crate::config::Config;

pub type Client = passbolt_sdk::PassboltSdk<passbolt_sdk::NativeHttpClient>;

/// Build a client from the loaded config, performing login.
pub async fn get_client(config: &Config) -> Result<Client> {
    let sdk_config = config.to_sdk_config()?;

    let http_config = passbolt_sdk::NativeHttpConfig {
        tls_skip_verify: sdk_config.tls_skip_verify,
        client_cert_pem: if sdk_config.tls_client_cert.is_empty() {
            None
        } else {
            Some(sdk_config.tls_client_cert.as_bytes().to_vec())
        },
        client_key_pem: if sdk_config.tls_client_private_key.is_empty() {
            None
        } else {
            Some(sdk_config.tls_client_private_key.as_bytes().to_vec())
        },
        proxy_url: if sdk_config.proxy.is_empty() {
            None
        } else {
            Some(sdk_config.proxy.clone())
        },
    };

    let http = passbolt_sdk::NativeHttpClient::new(&http_config)?;

    // Build MFA provider from config
    let mfa_provider: Option<Box<dyn passbolt_sdk::MfaProvider>> =
        match sdk_config.mfa_mode.as_str() {
            "none" => None,
            "non-interactive-totp" => Some(Box::new(crate::util::mfa::AutoTotpProvider {
                secret: sdk_config.mfa_totp_token.clone(),
                offset_secs: sdk_config.mfa_totp_offset,
            })),
            _ => Some(Box::new(crate::util::mfa::TerminalMfaProvider)),
        };

    let max_attempts = sdk_config.mfa_retrys.max(1);

    let client =
        passbolt_sdk::PassboltSdk::login(http, &sdk_config, mfa_provider.as_deref(), max_attempts)
            .await?;

    Ok(client)
}
