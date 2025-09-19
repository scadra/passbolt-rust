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

use anyhow::{bail, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

/// Parse an expiry string into a JSON value suitable for the API.
///
/// Accepted formats:
/// - RFC3339 date/time:   `"2025-12-31T00:00:00Z"`
/// - Duration from now:   `"7d"`, `"48h"`, `"30m"`
/// - Clear expiry:        `"none"` / `""`
pub fn parse_expiry(input: &str) -> Result<Value> {
    let input = input.trim();

    if input.is_empty() || input.eq_ignore_ascii_case("none") {
        return Ok(Value::Null);
    }

    // Try RFC3339 first
    if let Ok(expires_at) = input.parse::<DateTime<Utc>>() {
        return Ok(Value::String(expires_at.to_rfc3339()));
    }

    // Duration from now: 7d, 48h, 30m
    let to_delta = match input.chars().last() {
        Some('d') => Duration::try_days,
        Some('h') => Duration::try_hours,
        Some('m') => Duration::try_minutes,
        _ => bail!(
            "Unrecognised expiry format: {input}  \
             (use RFC3339, a duration like '7d'/'48h'/'30m', or 'none')"
        ),
    };
    let amount: i64 = input[..input.len() - 1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid expiry duration: {input}"))?;
    let expires_at = to_delta(amount)
        .and_then(|delta| Utc::now().checked_add_signed(delta))
        .ok_or_else(|| anyhow::anyhow!("Expiry duration out of range: {input}"))?;

    Ok(Value::String(expires_at.to_rfc3339()))
}
