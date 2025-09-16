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
use secrecy::SecretString;
use std::io::{self, IsTerminal};

/// Read a password from stdin or interactively from the terminal.
/// If stdin is not a terminal (piped), read the first line from stdin.
/// Otherwise prompt with `rpassword`.
pub fn read_password(prompt: &str) -> Result<SecretString> {
    if !io::stdin().is_terminal() {
        // Stdin is piped — read a line
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("Cannot read stdin: {e}"))?;
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        return Ok(SecretString::new(trimmed.into()));
    }

    let pass = rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("Cannot read password: {e}"))?;
    Ok(SecretString::new(pass.into()))
}
