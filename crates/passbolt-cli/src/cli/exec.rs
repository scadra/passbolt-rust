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

use anyhow::{bail, Context, Result};
use clap::Args;
use std::collections::HashMap;

use crate::Client;

const PASSBOLT_SCHEME: &str = "passbolt://";

#[derive(Args, Debug)]
pub struct ExecArgs {
    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Execute a command with `passbolt://UUID` env vars replaced by decrypted passwords.
///
/// The session is closed before the command starts.
pub async fn run(args: &ExecArgs, client: &Client) -> Result<()> {
    if args.command.is_empty() {
        bail!("No command specified");
    }

    // Scan env for passbolt:// URLs and resolve them
    let mut extra_env: HashMap<String, String> = HashMap::new();

    // Collect env vars first, then drop the iterator (std::env::Vars is not Send)
    let env_snapshot: Vec<(String, String)> = std::env::vars().collect();

    for (key, value) in env_snapshot {
        if let Some(resource_id) = value.strip_prefix(PASSBOLT_SCHEME) {
            let view = passbolt_sdk::resource::get::get_resource_view(client, resource_id)
                .await
                .with_context(|| format!("Cannot read resource {resource_id}"))?;
            let Some(password) = view.password else {
                bail!("Resource {resource_id} has no password to put in {key}");
            };
            extra_env.insert(key, password);
        }
    }

    // As go-passbolt-cli: the session must not stay open while the command runs.
    client.logout().await;

    let program = &args.command[0];
    let program_args = &args.command[1..];

    let mut command = std::process::Command::new(program);
    command.args(program_args);

    for (name, value) in &extra_env {
        command.env(name, value);
    }

    let status = command
        .status()
        .with_context(|| format!("Failed to execute: {program}"))?;

    std::process::exit(status.code().unwrap_or(1));
}
