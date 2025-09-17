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

use crate::api::crypto;
use crate::config::Config;

#[derive(Args, Debug)]
pub struct VerifyArgs {}

pub async fn run(_args: &VerifyArgs, cfg: &mut Config) -> Result<()> {
    let private_key = crypto::parse_private_key(&cfg.private_key_text()?)?;

    let proxy = if cfg.proxy.is_empty() {
        None
    } else {
        Some(cfg.proxy.as_str())
    };
    let client = crate::api::http::build_client(cfg.tls_skip_verify, None, None, proxy)?;

    let (fingerprint, token) = crate::api::auth::verify_server(
        &client,
        &cfg.server_address,
        &private_key,
        &cfg.user_password,
    )
    .await?;

    cfg.server_verify_token = token;
    cfg.server_verify_enc_token = fingerprint.clone();
    cfg.save()?;

    println!("Server verified. Fingerprint: {fingerprint}");
    println!("Tokens persisted to config.");

    Ok(())
}
