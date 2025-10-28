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

use js_sys::{Array, Uint8Array};
use passbolt_sdk::error::TransportError;
use passbolt_sdk::http::{HttpClient, HttpResponse};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestCredentials, RequestInit, RequestMode, Response};

#[wasm_bindgen]
extern "C" {
    /// The global `fetch`, available in windows and in workers (MV3 service worker)
    /// alike, unlike `web_sys::window()`.
    #[wasm_bindgen(js_name = fetch)]
    fn global_fetch(request: &Request) -> js_sys::Promise;
}

const DEFAULT_HEADERS: [(&str, &str); 2] = [
    ("Content-Type", "application/json"),
    ("Accept", "application/json"),
];

/// JSON defaults followed by the caller's headers; a caller header replaces a
/// default of the same name (case-insensitive), as `Headers.set` does.
fn build_request_headers<'header>(
    headers: &[(&'header str, &'header str)],
) -> Vec<(&'header str, &'header str)> {
    let mut merged: Vec<(&str, &str)> = Vec::with_capacity(DEFAULT_HEADERS.len() + headers.len());
    for &(name, value) in DEFAULT_HEADERS.iter().chain(headers) {
        if let Some(existing) = merged
            .iter_mut()
            .find(|(existing_name, _)| existing_name.eq_ignore_ascii_case(name))
        {
            *existing = (name, value);
        } else {
            merged.push((name, value));
        }
    }
    merged
}

/// Browser-native HTTP client using `fetch()` with cookie credentials.
pub struct WasmHttpClient;

impl WasmHttpClient {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    async fn fetch(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, TransportError> {
        let request_init = RequestInit::new();
        request_init.set_method(method);
        request_init.set_credentials(RequestCredentials::Include);
        request_init.set_mode(RequestMode::Cors);

        let request_headers = Headers::new().map_err(|error| js_err("Headers::new", &error))?;
        for (name, value) in build_request_headers(headers) {
            request_headers
                .set(name, value)
                .map_err(|error| js_err(&format!("set header {name}"), &error))?;
        }
        request_init.set_headers(&request_headers);

        // Set body if present
        if let Some(bytes) = body {
            let body_array = Uint8Array::from(bytes);
            request_init.set_body(&body_array);
        }

        let request = Request::new_with_str_and_init(url, &request_init)
            .map_err(|error| js_err("Request::new", &error))?;

        let response_value = JsFuture::from(global_fetch(&request))
            .await
            .map_err(|error| js_err(&format!("{method} {url}"), &error))?;

        let response: Response = response_value
            .dyn_into()
            .map_err(|_| TransportError::Http("Response is not a Response object".into()))?;

        let status = response.status();

        // Extract response headers
        let response_headers = response.headers();
        let mut header_vec: Vec<(String, String)> = Vec::new();

        // Iterate through headers using js_sys
        let entries = js_sys::try_iter(&response_headers).ok().flatten();
        if let Some(entry_iterator) = entries {
            for entry in entry_iterator.flatten() {
                let pair: Array = entry.into();
                let key = pair.get(0).as_string().unwrap_or_default();
                let value = pair.get(1).as_string().unwrap_or_default();
                header_vec.push((key, value));
            }
        }

        // Read body as bytes
        let body_promise = response
            .array_buffer()
            .map_err(|error| js_err("arrayBuffer()", &error))?;
        let body_value = JsFuture::from(body_promise)
            .await
            .map_err(|error| js_err("read body", &error))?;
        let body_bytes = Uint8Array::new(&body_value).to_vec();

        Ok(HttpResponse {
            status,
            headers: header_vec,
            body: body_bytes,
        })
    }
}

impl HttpClient for WasmHttpClient {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("GET", url, headers, None).await
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("POST", url, headers, Some(body)).await
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("PUT", url, headers, Some(body)).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("DELETE", url, headers, None).await
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        self.fetch("DELETE", url, headers, Some(body)).await
    }
}

fn js_err(context: &str, err: &JsValue) -> TransportError {
    let message = err
        .as_string()
        .or_else(|| js_sys::JSON::stringify(err).ok().map(String::from))
        .unwrap_or_else(|| format!("{err:?}"));
    TransportError::Network(format!("{context}: {message}"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn test_build_request_headers_without_caller_headers_is_json_defaults() {
        let headers = build_request_headers(&[]);

        assert_eq!(headers, DEFAULT_HEADERS.to_vec());
    }

    #[test]
    fn test_build_request_headers_appends_caller_headers() {
        let headers = build_request_headers(&[("X-CSRF-Token", "token")]);

        assert_eq!(
            headers,
            vec![
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
                ("X-CSRF-Token", "token"),
            ]
        );
    }

    #[rstest]
    #[case::same_case("Content-Type")]
    #[case::other_case("content-type")]
    fn test_build_request_headers_caller_replaces_default(#[case] name: &str) {
        let headers = build_request_headers(&[(name, "text/plain")]);

        assert_eq!(
            headers,
            vec![(name, "text/plain"), ("Accept", "application/json")]
        );
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    async fn test_get_fetches_without_a_window() {
        let client = WasmHttpClient::new();

        let response = client
            .get("data:application/json,%7B%22ok%22%3Atrue%7D", &[])
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.body, br#"{"ok":true}"#);
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"));
    }
}
