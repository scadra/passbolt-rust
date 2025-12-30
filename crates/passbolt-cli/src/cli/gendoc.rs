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

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, CommandFactory};

use crate::cli::root::Cli;

#[derive(Args, Debug)]
pub struct GendocArgs {
    /// Output format: markdown | man
    #[arg(short = 't', long, default_value = "markdown", value_parser = ["markdown", "man"])]
    pub doc_type: String,

    /// Directory to write output files into (created if absent)
    #[arg(short = 'o', long, default_value = ".")]
    pub output_dir: PathBuf,
}

pub fn run_gendoc(args: &GendocArgs) -> Result<()> {
    std::fs::create_dir_all(&args.output_dir)?;
    match args.doc_type.as_str() {
        "man" => generate_man_pages(&args.output_dir),
        _ => generate_markdown(&args.output_dir),
    }
}

fn generate_markdown(output_dir: &Path) -> Result<()> {
    let content = clap_markdown::help_markdown::<Cli>();
    let path = output_dir.join("passbolt.md");
    std::fs::write(&path, content)?;
    println!("Written: {}", path.display());
    Ok(())
}

fn generate_man_pages(output_dir: &Path) -> Result<()> {
    let command = Cli::command();
    let root_name = command.get_name().to_string();
    generate_man_recursive(&command, output_dir, &[root_name])
}

fn generate_man_recursive(
    command: &clap::Command,
    output_dir: &Path,
    ancestors: &[String],
) -> Result<()> {
    let name = ancestors.join("-");
    let man = clap_mangen::Man::new(command.clone());
    let mut rendered = Vec::new();
    man.render(&mut rendered)?;
    let path = output_dir.join(format!("{name}.1"));
    std::fs::write(&path, &rendered)?;
    println!("Written: {}", path.display());

    for subcommand in command.get_subcommands() {
        if subcommand.get_name() == "help" {
            continue;
        }
        let mut subcommand_ancestors = ancestors.to_vec();
        subcommand_ancestors.push(subcommand.get_name().to_string());
        generate_man_recursive(subcommand, output_dir, &subcommand_ancestors)?;
    }
    Ok(())
}
