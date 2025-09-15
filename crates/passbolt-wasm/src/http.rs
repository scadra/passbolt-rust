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
        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_credentials(RequestCredentials::Include);
        opts.set_mode(RequestMode::Cors);

        // Set headers
        let h = Headers::new().map_err(|e| js_err("Headers::new", &e))?;
        h.set("Content-Type", "application/json")
            .map_err(|e| js_err("set Content-Type", &e))?;
        h.set("Accept", "application/json")
            .map_err(|e| js_err("set Accept", &e))?;
        for &(k, v) in headers {
            h.set(k, v).map_err(|e| js_err("set header", &e))?;
        }
        opts.set_headers(&h);

        // Set body if present
        if let Some(bytes) = body {
            let uint8 = Uint8Array::from(bytes);
            opts.set_body(&uint8);
        }

        let request =
            Request::new_with_str_and_init(url, &opts).map_err(|e| js_err("Request::new", &e))?;

        let window = web_sys::window()
            .ok_or_else(|| TransportError::Http("No global window object available".into()))?;

        let resp_value = JsFuture::from(window.fetch_with_request(&request))
            .await
            .map_err(|e| js_err(&format!("{method} {url}"), &e))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| TransportError::Http("Response is not a Response object".into()))?;

        let status = resp.status();

        // Extract response headers
        let resp_headers = resp.headers();
        let mut header_vec: Vec<(String, String)> = Vec::new();

        // Iterate through headers using js_sys
        let entries = js_sys::try_iter(&resp_headers).ok().flatten();
        if let Some(iter) = entries {
            for val in iter.flatten() {
                let pair: Array = val.into();
                let key = pair.get(0).as_string().unwrap_or_default();
                let value = pair.get(1).as_string().unwrap_or_default();
                header_vec.push((key, value));
            }
        }

        // Read body as bytes
        let body_promise = resp
            .array_buffer()
            .map_err(|e| js_err("arrayBuffer()", &e))?;
        let body_value = JsFuture::from(body_promise)
            .await
            .map_err(|e| js_err("read body", &e))?;
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
    let msg = err
        .as_string()
        .or_else(|| js_sys::JSON::stringify(err).ok().map(String::from))
        .unwrap_or_else(|| format!("{err:?}"));
    TransportError::Network(format!("{context}: {msg}"))
}
