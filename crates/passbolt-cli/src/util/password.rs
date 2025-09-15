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
