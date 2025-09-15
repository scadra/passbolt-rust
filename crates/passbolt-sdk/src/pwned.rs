use sha1::{Digest, Sha1};

use crate::error::PassboltError;
use crate::http::HttpClient;

/// Check if a password has been exposed in data breaches using HIBP k-anonymity.
///
/// Hashes the password with SHA-1, sends the first 5 hex chars to the HIBP API,
/// then checks if the remaining suffix appears in the response.
/// Returns the number of times the password was found (0 = not breached).
pub async fn check_pwned<H: HttpClient>(http: &H, password: &str) -> Result<u64, PassboltError> {
    let hash = hex::encode(Sha1::digest(password.as_bytes())).to_uppercase();
    let prefix = &hash[..5];
    let suffix = &hash[5..];

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let resp = http.get(&url, &[]).await?;

    if resp.status >= 400 {
        return Err(PassboltError::Other(format!(
            "HIBP API returned status {}",
            resp.status
        )));
    }

    let body = String::from_utf8(resp.body)
        .map_err(|e| PassboltError::Other(format!("HIBP response is not valid UTF-8: {e}")))?;

    for line in body.lines() {
        // Format: <SUFFIX>:<COUNT>
        if let Some((line_suffix, count_str)) = line.split_once(':') {
            if line_suffix.trim() == suffix {
                return count_str
                    .trim()
                    .parse::<u64>()
                    .map_err(|e| PassboltError::Other(format!("Failed to parse HIBP count: {e}")));
            }
        }
    }

    Ok(0)
}
