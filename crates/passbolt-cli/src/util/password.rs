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

use anyhow::Result;
use secrecy::SecretString;
use std::io::{self, IsTerminal};

/// Read a password from stdin or interactively from the terminal.
/// If stdin is not a terminal (piped), read the first line from stdin.
/// Otherwise prompt with `rpassword`.
///
/// An empty password is an error: an empty or closed stdin must not become a password.
pub fn read_password(prompt: &str) -> Result<SecretString> {
    let password = read_line(prompt)?;
    non_empty(password)
}

fn non_empty(password: String) -> Result<SecretString> {
    if password.is_empty() {
        anyhow::bail!("Empty password: give one, or pass it with its option");
    }
    Ok(SecretString::new(password.into()))
}

fn read_line(prompt: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        // Stdin is piped — read a line
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .map_err(|error| anyhow::anyhow!("Cannot read stdin: {error}"))?;
        let trimmed = line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string();
        return Ok(trimmed);
    }

    rpassword::prompt_password(prompt)
        .map_err(|error| anyhow::anyhow!("Cannot read password: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_non_empty_refuses_an_empty_password() {
        assert!(non_empty(String::new()).is_err());
    }

    #[test]
    fn test_non_empty_keeps_the_password() {
        assert_eq!(non_empty("p".into()).unwrap().expose_secret(), "p");
    }
}
