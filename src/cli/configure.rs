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

use anyhow::{Context, Result};
use clap::Args;

use crate::config::Config;

#[derive(Args, Debug)]
pub struct ConfigureArgs {
    /// Passbolt server address
    #[arg(long, env = "PASSBOLT_SERVER_ADDRESS")]
    pub server_address: Option<String>,

    /// User PGP private key (armored inline)
    #[arg(long, env = "PASSBOLT_USER_PRIVATE_KEY")]
    pub user_private_key: Option<String>,

    /// Path to PGP private key file
    #[arg(long, env = "PASSBOLT_USER_PRIVATE_KEY_FILE")]
    pub user_private_key_file: Option<String>,

    /// Master password
    #[arg(long, env = "PASSBOLT_USER_PASSWORD")]
    pub user_password: Option<String>,

    /// MFA mode
    #[arg(long, env = "PASSBOLT_MFA_MODE")]
    pub mfa_mode: Option<String>,

    /// TOTP token
    #[arg(long, env = "PASSBOLT_MFA_TOTP_TOKEN")]
    pub mfa_totp_token: Option<String>,

    /// TLS skip verify
    #[arg(long, env = "PASSBOLT_TLS_SKIP_VERIFY")]
    pub tls_skip_verify: Option<bool>,

    /// Request timeout
    #[arg(long, env = "PASSBOLT_TIMEOUT")]
    pub timeout: Option<String>,

    /// Number of parallel workers
    #[arg(long, env = "PASSBOLT_WORKERS")]
    pub workers: Option<usize>,

    /// HTTP proxy URL (e.g. http://localhost:8080)
    #[arg(long, env = "PASSBOLT_PROXY")]
    pub proxy: Option<String>,

    /// TLS client certificate (PEM, inline)
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_CERT")]
    pub tls_client_cert: Option<String>,

    /// TLS client private key (PEM, inline)
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_PRIVATE_KEY")]
    pub tls_client_private_key: Option<String>,

    /// Path to TLS client certificate file
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_CERT_FILE")]
    pub tls_client_cert_file: Option<String>,

    /// Path to TLS client private key file
    #[arg(long, env = "PASSBOLT_TLS_CLIENT_PRIVATE_KEY_FILE")]
    pub tls_client_private_key_file: Option<String>,

    /// Number of MFA retries
    #[arg(long, env = "PASSBOLT_MFA_RETRYS")]
    pub mfa_retrys: Option<u32>,

    /// Delay between MFA retries (e.g. 10s)
    #[arg(long, env = "PASSBOLT_MFA_DELAY")]
    pub mfa_delay: Option<String>,

    /// TOTP time offset in seconds
    #[arg(long, env = "PASSBOLT_MFA_TOTP_OFFSET")]
    pub mfa_totp_offset: Option<i64>,
}

pub async fn run(args: &ConfigureArgs) -> Result<()> {
    let mut cfg = Config::load().unwrap_or_default();

    if let Some(v) = &args.server_address {
        cfg.server_address = v.clone();
    }
    if let Some(v) = &args.user_private_key {
        cfg.user_private_key = v.clone();
    }
    if let Some(v) = &args.user_private_key_file {
        cfg.user_private_key_file = v.clone();
    }
    if let Some(v) = &args.user_password {
        cfg.user_password = v.clone();
    }
    if let Some(v) = &args.mfa_mode {
        cfg.mfa_mode = v.clone();
    }
    if let Some(v) = &args.mfa_totp_token {
        cfg.mfa_totp_token = v.clone();
    }
    if let Some(v) = args.tls_skip_verify {
        cfg.tls_skip_verify = v;
    }
    if let Some(v) = &args.timeout {
        cfg.timeout = v.clone();
    }
    if let Some(v) = args.workers {
        cfg.workers = v;
    }
    if let Some(v) = &args.proxy {
        cfg.proxy = v.clone();
    }
    if let Some(v) = &args.tls_client_cert {
        cfg.tls_client_cert = v.clone();
    }
    if let Some(v) = &args.tls_client_private_key {
        cfg.tls_client_private_key = v.clone();
    }
    if let Some(path) = &args.tls_client_cert_file {
        cfg.tls_client_cert = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client cert file: {path}"))?;
    }
    if let Some(path) = &args.tls_client_private_key_file {
        cfg.tls_client_private_key = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read TLS client private key file: {path}"))?;
    }
    if let Some(v) = args.mfa_retrys {
        cfg.mfa_retrys = v;
    }
    if let Some(v) = &args.mfa_delay {
        cfg.mfa_delay = v.clone();
    }
    if let Some(v) = args.mfa_totp_offset {
        cfg.mfa_totp_offset = v;
    }

    cfg.save()?;

    let path = Config::config_path()?;
    println!("Configuration saved to {}", path.display());

    Ok(())
}
