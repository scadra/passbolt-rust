use anyhow::Result;
use clap::Args;

use crate::config::Config;

#[derive(Args, Debug)]
pub struct VerifyArgs {}

pub async fn run(_args: &VerifyArgs, cfg: &mut Config) -> Result<()> {
    let private_key = passbolt_sdk::crypto::parse_private_key(&cfg.private_key_text()?)?;

    // Build a temporary HTTP client just for verification
    let http_cfg = passbolt_sdk::NativeHttpConfig {
        tls_skip_verify: cfg.tls_skip_verify,
        client_cert_pem: None,
        client_key_pem: None,
        proxy_url: if cfg.proxy.is_empty() {
            None
        } else {
            Some(cfg.proxy.clone())
        },
    };
    let http = passbolt_sdk::NativeHttpClient::new(&http_cfg)?;

    let (fingerprint, token) = passbolt_sdk::auth::verify_server(
        &http,
        &cfg.server_address,
        &private_key,
        &cfg.user_password,
    )
    .await?;

    cfg.server_verify_token = token;
    cfg.server_verify_enc_token.clone_from(&fingerprint);
    cfg.save()?;

    println!("Server verified. Fingerprint: {fingerprint}");
    println!("Tokens persisted to config.");

    Ok(())
}
