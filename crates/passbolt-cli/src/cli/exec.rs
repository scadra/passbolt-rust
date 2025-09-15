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

/// Execute a command with `passbolt://UUID` env vars replaced by decrypted secrets.
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
            let resource = client
                .get_resource(resource_id)
                .await
                .with_context(|| format!("Resource not found: {resource_id}"))?;

            let secret = client
                .decrypt_resource_secret(&resource)
                .await
                .with_context(|| format!("Cannot decrypt resource: {resource_id}"))?;

            let password = secret.password.or(secret.raw).unwrap_or_default();

            extra_env.insert(key, password);
        }
    }

    let program = &args.command[0];
    let program_args = &args.command[1..];

    let mut cmd = std::process::Command::new(program);
    cmd.args(program_args);

    for (k, v) in &extra_env {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute: {program}"))?;

    std::process::exit(status.code().unwrap_or(1));
}
