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

use crate::error::TransportError;

/// HTTP response abstraction for the SDK.
///
/// Decouples from reqwest so the SDK can be used with different HTTP
/// backends (native, WASM fetch, etc.).
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Get the first header value matching the given name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.to_lowercase() == lower)
            .map(|(_, header_value)| header_value.as_str())
    }

    /// Get all header values matching the given name (case-insensitive).
    #[must_use]
    pub fn headers_by_name(&self, name: &str) -> Vec<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .filter(|(header_name, _)| header_name.to_lowercase() == lower)
            .map(|(_, header_value)| header_value.as_str())
            .collect()
    }
}

/// Async HTTP client abstraction.
///
/// Uses `async_fn_in_trait` (stable since Rust 1.75).
#[allow(async_fn_in_trait)]
pub trait HttpClient: Send + Sync {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError>;

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError>;

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError>;

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError>;

    /// Current value of cookie `name` for `url`, for backends with a cookie jar.
    fn cookie(&self, url: &str, name: &str) -> Option<String> {
        let _ = (url, name);
        None
    }

    /// Send a DELETE request with a JSON body.
    ///
    /// Some Passbolt endpoints (e.g. bulk delete) require a body on DELETE.
    /// Default implementation returns an error; backends should override.
    #[allow(clippy::unused_async)] // must be async as trait method; default impl has no awaits
    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let _ = (url, headers, body);
        Err(TransportError::Http(
            "DELETE with body not supported by this HTTP backend".into(),
        ))
    }
}
