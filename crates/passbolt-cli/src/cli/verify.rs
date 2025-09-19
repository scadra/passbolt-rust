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
use clap::Args;

use crate::config::Config;

#[derive(Args, Debug)]
pub struct VerifyArgs {}

pub async fn run(_args: &VerifyArgs, config: &mut Config) -> Result<()> {
    let private_key = passbolt_sdk::crypto::parse_private_key(&config.private_key_text()?)?;

    // Build a temporary HTTP client just for verification
    let http_config = passbolt_sdk::NativeHttpConfig {
        tls_skip_verify: config.tls_skip_verify,
        client_cert_pem: None,
        client_key_pem: None,
        proxy_url: if config.proxy.is_empty() {
            None
        } else {
            Some(config.proxy.clone())
        },
    };
    let http = passbolt_sdk::NativeHttpClient::new(&http_config)?;

    let (fingerprint, token) = passbolt_sdk::auth::verify_server(
        &http,
        &config.server_address,
        &private_key,
        &config.user_password,
    )
    .await?;

    config.server_verify_token = token;
    config.server_verify_enc_token.clone_from(&fingerprint);
    config.save()?;

    println!("Server verified. Fingerprint: {fingerprint}");
    println!("Tokens persisted to config.");

    Ok(())
}
