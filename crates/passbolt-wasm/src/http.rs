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

        // Set headers
        let request_headers = Headers::new().map_err(|error| js_err("Headers::new", &error))?;
        request_headers
            .set("Content-Type", "application/json")
            .map_err(|error| js_err("set Content-Type", &error))?;
        request_headers
            .set("Accept", "application/json")
            .map_err(|error| js_err("set Accept", &error))?;
        for &(name, value) in headers {
            request_headers
                .set(name, value)
                .map_err(|error| js_err("set header", &error))?;
        }
        request_init.set_headers(&request_headers);

        // Set body if present
        if let Some(bytes) = body {
            let body_array = Uint8Array::from(bytes);
            request_init.set_body(&body_array);
        }

        let request = Request::new_with_str_and_init(url, &request_init)
            .map_err(|error| js_err("Request::new", &error))?;

        let window = web_sys::window()
            .ok_or_else(|| TransportError::Http("No global window object available".into()))?;

        let response_value = JsFuture::from(window.fetch_with_request(&request))
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
