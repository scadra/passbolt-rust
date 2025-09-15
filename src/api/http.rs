use anyhow::{Context, Result};
use reqwest::{
    header::{self, HeaderMap, HeaderValue},
    Client, ClientBuilder,
};

/// Build a configured `reqwest::Client` from TLS and proxy settings.
pub fn build_client(
    tls_skip_verify: bool,
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
    proxy_url: Option<&str>,
) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        .use_rustls_tls()
        .cookie_store(true)
        .danger_accept_invalid_certs(tls_skip_verify);

    // mTLS — client certificate
    if let (Some(cert_pem), Some(key_pem)) = (client_cert_pem, client_key_pem) {
        let mut combined = Vec::from(cert_pem);
        combined.extend_from_slice(key_pem);
        let identity = reqwest::tls::Identity::from_pem(&combined)
            .context("Failed to parse client TLS identity")?;
        builder = builder.identity(identity);
    }

    // HTTP proxy
    if let Some(url) = proxy_url {
        if !url.is_empty() {
            let proxy = reqwest::Proxy::all(url).context("Failed to configure HTTP proxy")?;
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

    builder
        .default_headers(headers)
        .build()
        .context("Failed to build HTTP client")
}
