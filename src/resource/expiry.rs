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
pub fn parse_expiry(s: &str) -> Result<Value> {
    let s = s.trim();

    if s.is_empty() || s.eq_ignore_ascii_case("none") {
        return Ok(Value::Null);
    }

    // Try RFC3339 first
    if let Ok(dt) = s.parse::<DateTime<Utc>>() {
        return Ok(Value::String(dt.to_rfc3339()));
    }

    // Try duration suffix
    let now = Utc::now();
    let dt = if let Some(n) = s.strip_suffix('d') {
        let days: i64 = n
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid expiry duration: {s}"))?;
        now + Duration::days(days)
    } else if let Some(n) = s.strip_suffix('h') {
        let hours: i64 = n
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid expiry duration: {s}"))?;
        now + Duration::hours(hours)
    } else if let Some(n) = s.strip_suffix('m') {
        let mins: i64 = n
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid expiry duration: {s}"))?;
        now + Duration::minutes(mins)
    } else {
        bail!(
            "Unrecognised expiry format: {s}  \
             (use RFC3339, a duration like '7d'/'48h'/'30m', or 'none')"
        );
    };

    Ok(Value::String(dt.to_rfc3339()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_none() {
        assert_eq!(parse_expiry("none").unwrap(), Value::Null);
        assert_eq!(parse_expiry("").unwrap(), Value::Null);
    }

    #[test]
    fn test_days() {
        let v = parse_expiry("7d").unwrap();
        assert!(v.is_string());
    }

    #[test]
    fn test_rfc3339() {
        let v = parse_expiry("2099-01-01T00:00:00Z").unwrap();
        let s = v.as_str().unwrap();
        // chrono normalises Z → +00:00; both are valid RFC3339
        assert!(s.starts_with("2099-01-01T00:00:00"));
    }
}
