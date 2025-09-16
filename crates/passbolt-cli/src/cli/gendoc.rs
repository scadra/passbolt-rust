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

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Args, CommandFactory};

use crate::cli::root::Cli;

#[derive(Args, Debug)]
pub struct GendocArgs {
    /// Output format: markdown | man
    #[arg(short = 't', long, default_value = "markdown")]
    pub doc_type: String,

    /// Directory to write output files into (created if absent)
    #[arg(short = 'o', long, default_value = ".")]
    pub output_dir: PathBuf,
}

pub fn run_gendoc(args: &GendocArgs) -> Result<()> {
    std::fs::create_dir_all(&args.output_dir)?;
    match args.doc_type.as_str() {
        "man" => generate_man_pages(&args.output_dir),
        "markdown" => generate_markdown(&args.output_dir),
        other => {
            eprintln!("Unknown doc type '{other}', use 'markdown' or 'man'");
            generate_markdown(&args.output_dir)
        }
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
    let cmd = Cli::command();
    let root_name = cmd.get_name().to_string();
    generate_man_recursive(&cmd, output_dir, &[root_name])
}

fn generate_man_recursive(
    cmd: &clap::Command,
    output_dir: &Path,
    ancestors: &[String],
) -> Result<()> {
    let name = ancestors.join("-");
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    man.render(&mut buf)?;
    let path = output_dir.join(format!("{name}.1"));
    std::fs::write(&path, &buf)?;
    println!("Written: {}", path.display());

    for subcmd in cmd.get_subcommands() {
        if subcmd.get_name() == "help" {
            continue;
        }
        let mut sub_ancestors = ancestors.to_vec();
        sub_ancestors.push(subcmd.get_name().to_string());
        generate_man_recursive(subcmd, output_dir, &sub_ancestors)?;
    }
    Ok(())
}
