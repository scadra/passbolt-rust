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
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::util::password::read_password;
use crate::Client;

#[derive(Args, Debug)]
pub struct ExportArgs {
    #[command(subcommand)]
    pub format: ExportFormat,
}

#[derive(Subcommand, Debug)]
pub enum ExportFormat {
    /// Export to `KeePass` KDBX format
    Keepass {
        /// Output file path
        #[arg(short = 'o', long)]
        output: PathBuf,
        /// `KeePass` master password (prompted if not provided)
        #[arg(long)]
        password: Option<String>,
        /// Export only this folder and its sub-folders (by ID); default: export all
        #[arg(short = 'f', long)]
        folder_id: Option<String>,
    },
}

pub async fn run(args: &ExportArgs, client: &Client, workers: usize) -> Result<()> {
    match &args.format {
        ExportFormat::Keepass {
            output,
            password,
            folder_id,
        } => {
            use secrecy::ExposeSecret;

            let master_password = if let Some(provided_password) = password {
                provided_password.clone()
            } else {
                let secret = read_password("KeePass master password: ")?;
                secret.expose_secret().to_string()
            };

            crate::keepass::export::export_keepass(
                client,
                output,
                &master_password,
                folder_id.as_deref(),
                workers,
            )
            .await?;
        }
    }
    Ok(())
}
