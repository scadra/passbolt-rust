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
    let response = http.get(&url, &[]).await?;

    if response.status >= 400 {
        return Err(PassboltError::Other(format!(
            "HIBP API returned status {}",
            response.status
        )));
    }

    let body = String::from_utf8(response.body).map_err(|error| {
        PassboltError::Other(format!("HIBP response is not valid UTF-8: {error}"))
    })?;

    for line in body.lines() {
        // Format: <SUFFIX>:<COUNT>
        if let Some((line_suffix, count_str)) = line.split_once(':') {
            if line_suffix.trim() == suffix {
                return count_str.trim().parse::<u64>().map_err(|error| {
                    PassboltError::Other(format!("Failed to parse HIBP count: {error}"))
                });
            }
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unused_async_trait_impl)] // synchronous stub behind an async trait

    use std::sync::Mutex;

    use rstest::rstest;

    use super::*;
    use crate::error::TransportError;
    use crate::http::HttpResponse;

    /// SHA-1 of "password": `5BAA6` + `1E4C9B93F3F0682250B6CF8331B7EE68FD8`.
    const PASSWORD_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    /// Answers every GET with `status` and `body`, and records the URLs.
    struct RangeApiStub {
        status: u16,
        body: String,
        urls: Mutex<Vec<String>>,
    }

    impl RangeApiStub {
        fn new(status: u16, body: &str) -> Self {
            Self {
                status,
                body: body.to_string(),
                urls: Mutex::default(),
            }
        }
    }

    impl HttpClient for RangeApiStub {
        async fn get(
            &self,
            url: &str,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse, TransportError> {
            self.urls.lock().unwrap().push(url.to_string());
            Ok(HttpResponse {
                status: self.status,
                headers: Vec::new(),
                body: self.body.clone().into_bytes(),
            })
        }

        async fn post(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _body: &[u8],
        ) -> Result<HttpResponse, TransportError> {
            unreachable!("the range API is only read")
        }

        async fn put(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
            _body: &[u8],
        ) -> Result<HttpResponse, TransportError> {
            unreachable!("the range API is only read")
        }

        async fn delete(
            &self,
            _url: &str,
            _headers: &[(&str, &str)],
        ) -> Result<HttpResponse, TransportError> {
            unreachable!("the range API is only read")
        }
    }

    #[tokio::test]
    async fn test_check_pwned_sends_only_the_hash_prefix() {
        let http = RangeApiStub::new(200, "");

        check_pwned(&http, "password").await.unwrap();

        assert_eq!(
            *http.urls.lock().unwrap(),
            ["https://api.pwnedpasswords.com/range/5BAA6"]
        );
    }

    #[tokio::test]
    async fn test_check_pwned_returns_the_count_of_the_matching_suffix() {
        let body =
            format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{PASSWORD_SUFFIX}:9545824\r\n");
        let http = RangeApiStub::new(200, &body);

        let count = check_pwned(&http, "password").await.unwrap();

        assert_eq!(count, 9_545_824);
    }

    #[tokio::test]
    async fn test_check_pwned_absent_suffix_is_zero() {
        let http = RangeApiStub::new(200, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n");

        let count = check_pwned(&http, "password").await.unwrap();

        assert_eq!(count, 0);
    }

    #[rstest]
    #[case::too_many_requests(429)]
    #[case::server_error(503)]
    #[tokio::test]
    async fn test_check_pwned_error_status_is_an_error(#[case] status: u16) {
        let http = RangeApiStub::new(status, "");

        let error = check_pwned(&http, "password").await.unwrap_err();

        assert!(error.to_string().contains(&status.to_string()), "{error}");
    }

    #[tokio::test]
    async fn test_check_pwned_invalid_count_is_an_error() {
        let http = RangeApiStub::new(200, &format!("{PASSWORD_SUFFIX}:many"));

        let error = check_pwned(&http, "password").await.unwrap_err();

        assert!(matches!(error, PassboltError::Other(_)), "{error:?}");
    }
}
