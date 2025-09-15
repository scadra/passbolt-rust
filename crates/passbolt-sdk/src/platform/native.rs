use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    Client, ClientBuilder,
};

use crate::error::{PassboltError, TransportError};
use crate::http::{HttpClient, HttpResponse};

/// HTTP client configuration for building a `NativeHttpClient`.
pub struct NativeHttpConfig {
    pub tls_skip_verify: bool,
    pub client_cert_pem: Option<Vec<u8>>,
    pub client_key_pem: Option<Vec<u8>>,
    pub proxy_url: Option<String>,
}

/// Native HTTP client backed by `reqwest`.
pub struct NativeHttpClient {
    inner: Client,
}

impl NativeHttpClient {
    /// Build a new native HTTP client from the given configuration.
    pub fn new(config: &NativeHttpConfig) -> Result<Self, PassboltError> {
        let mut builder = ClientBuilder::new()
            .use_rustls_tls()
            .cookie_store(true)
            .danger_accept_invalid_certs(config.tls_skip_verify);

        // mTLS — client certificate
        if let (Some(cert_pem), Some(key_pem)) = (
            config.client_cert_pem.as_ref(),
            config.client_key_pem.as_ref(),
        ) {
            let mut combined = Vec::from(cert_pem.as_slice());
            combined.extend_from_slice(key_pem);
            let identity = reqwest::tls::Identity::from_pem(&combined).map_err(|e| {
                TransportError::Http(format!("Failed to parse client TLS identity: {e}"))
            })?;
            builder = builder.identity(identity);
        }

        // HTTP proxy
        if let Some(url) = config.proxy_url.as_deref() {
            if !url.is_empty() {
                let proxy = reqwest::Proxy::all(url).map_err(|e| {
                    TransportError::Http(format!("Failed to configure HTTP proxy: {e}"))
                })?;
                builder = builder.proxy(proxy);
            }
        }

        // Default headers
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let inner = builder
            .default_headers(headers)
            .build()
            .map_err(|e| TransportError::Http(format!("Failed to build HTTP client: {e}")))?;

        Ok(Self { inner })
    }
}

/// Convert a `reqwest::Response` into our `HttpResponse`.
async fn into_http_response(resp: reqwest::Response) -> Result<HttpResponse, TransportError> {
    let status = resp.status().as_u16();

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Extract Set-Cookie headers for token parsing
    let mut all_headers = headers;

    // Also capture cookies from the cookie jar (if any were set)
    for cookie in resp.cookies() {
        all_headers.push((
            "set-cookie-name".to_string(),
            format!("{}={}", cookie.name(), cookie.value()),
        ));
    }

    let body = resp
        .bytes()
        .await
        .map_err(|e| TransportError::Network(format!("Failed to read response body: {e}")))?
        .to_vec();

    Ok(HttpResponse {
        status,
        headers: all_headers,
        body,
    })
}

impl HttpClient for NativeHttpClient {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.get(url);
        for &(k, v) in headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("GET {url}: {e}")))?;
        into_http_response(resp).await
    }

    async fn post(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.post(url);
        for &(k, v) in headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("POST {url}: {e}")))?;
        into_http_response(resp).await
    }

    async fn put(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.put(url);
        for &(k, v) in headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("PUT {url}: {e}")))?;
        into_http_response(resp).await
    }

    async fn delete(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.delete(url);
        for &(k, v) in headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("DELETE {url}: {e}")))?;
        into_http_response(resp).await
    }

    async fn delete_with_body(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut builder = self.inner.delete(url);
        for &(k, v) in headers {
            builder = builder.header(k, v);
        }
        let resp = builder
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| TransportError::Network(format!("DELETE {url}: {e}")))?;
        into_http_response(resp).await
    }
}
