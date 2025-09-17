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
use directories::ProjectDirs;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

const APP_QUALIFIER: &str = "";
const APP_ORG: &str = "";
const APP_NAME: &str = "passbolt";

/// Full configuration for passbolt-rs.
///
/// Derives `Zeroize`/`ZeroizeOnDrop` so that all fields — including the private
/// key armored text and passphrase — are overwritten in memory when the struct
/// is dropped.  `Debug` is intentionally absent to prevent credentials from
/// leaking through `{:?}` formatting.
#[derive(Clone, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct Config {
    pub server_address: String,
    #[serde(default)]
    pub user_private_key: String,
    #[serde(default)]
    pub user_private_key_file: String,
    #[serde(default)]
    pub user_password: String,
    /// "interactive-totp", "non-interactive-totp", "none"
    #[serde(default = "default_mfa_mode")]
    pub mfa_mode: String,
    #[serde(default)]
    pub mfa_totp_token: String,
    #[serde(default)]
    pub mfa_totp_offset: i64,
    #[serde(default = "default_mfa_retrys")]
    pub mfa_retrys: u32,
    #[serde(default = "default_mfa_delay")]
    pub mfa_delay: String,
    #[serde(default)]
    pub tls_skip_verify: bool,
    #[serde(default)]
    pub tls_client_cert: String,
    #[serde(default)]
    pub tls_client_private_key: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
    /// 0 = auto-detect (number of CPUs)
    #[serde(default)]
    pub workers: usize,
    #[serde(default)]
    pub server_verify_token: String,
    #[serde(default)]
    pub server_verify_enc_token: String,
    #[serde(default)]
    pub debug: bool,
    /// HTTP/HTTPS proxy URL (empty = no proxy)
    #[serde(default)]
    pub proxy: String,
}

fn default_mfa_mode() -> String {
    "interactive-totp".into()
}

const fn default_mfa_retrys() -> u32 {
    3
}

fn default_mfa_delay() -> String {
    "10s".into()
}

fn default_timeout() -> String {
    "1m".into()
}

impl Config {
    /// Return the configuration file path (XDG-compatible).
    pub fn config_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from(APP_QUALIFIER, APP_ORG, APP_NAME)
            .context("Cannot determine config directory")?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load config from file (if it exists) then override with env vars.
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        let mut settings = config::Config::builder();

        if path.exists() {
            settings =
                settings.add_source(config::File::from(path).format(config::FileFormat::Toml));
        }

        // Env-var overrides: PASSBOLT_SERVER_ADDRESS, etc.
        settings = settings.add_source(config::Environment::with_prefix("PASSBOLT").separator("_"));

        let cfg: Self = settings
            .build()
            .context("Failed to build config")?
            .try_deserialize()
            .context("Failed to deserialize config")?;

        Ok(cfg)
    }

    /// Save the current config to disk with restrictive permissions (0o600 on Unix).
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Cannot create config directory")?;
        }
        let toml_str = toml::to_string_pretty(self).context("Cannot serialize config")?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .context("Cannot write config file")?;
            file.write_all(toml_str.as_bytes())
                .context("Cannot write config file")?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, toml_str).context("Cannot write config file")?;
        }

        Ok(())
    }

    /// Build an `SdkConfig` from the CLI config, resolving the private key.
    pub fn to_sdk_config(&self) -> Result<passbolt_sdk::SdkConfig> {
        let private_key_armored = self.private_key_text()?;
        Ok(passbolt_sdk::SdkConfig {
            server_url: self.server_address.clone(),
            private_key_armored,
            passphrase: SecretString::from(self.user_password.clone()),
            mfa_mode: self.mfa_mode.clone(),
            mfa_totp_token: self.mfa_totp_token.clone(),
            mfa_totp_offset: self.mfa_totp_offset,
            mfa_retrys: self.mfa_retrys,
            tls_skip_verify: self.tls_skip_verify,
            tls_client_cert: self.tls_client_cert.clone(),
            tls_client_private_key: self.tls_client_private_key.clone(),
            proxy: self.proxy.clone(),
            server_verify_enc_token: self.server_verify_enc_token.clone(),
            server_verify_token: self.server_verify_token.clone(),
        })
    }

    /// Resolve the private key text: inline value or file path.
    pub fn private_key_text(&self) -> Result<String> {
        if !self.user_private_key.is_empty() {
            return Ok(self.user_private_key.clone());
        }
        if !self.user_private_key_file.is_empty() {
            return std::fs::read_to_string(&self.user_private_key_file)
                .context("Cannot read private key file");
        }
        anyhow::bail!("No private key configured (--user-private-key or --user-private-key-file)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_no_panic() {
        // Config::default() is derived via Zeroize, which zeroes all fields.
        // Serde defaults (#[serde(default = "...")]) only apply during deserialization.
        let cfg = Config::default();
        assert!(!cfg.tls_skip_verify);
        assert!(!cfg.debug);
        assert_eq!(cfg.mfa_retrys, 0); // zeroed
        assert_eq!(cfg.server_address, "");
    }

    #[test]
    fn test_toml_roundtrip() {
        let mut cfg = Config::default();
        cfg.server_address = "https://pass.example.com".into();
        cfg.user_private_key =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfakekey\n-----END PGP PRIVATE KEY BLOCK-----"
                .into();
        cfg.user_password = "hunter2".into();
        cfg.debug = true;
        cfg.mfa_retrys = 5;

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let loaded: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(loaded.server_address, "https://pass.example.com");
        assert_eq!(loaded.user_password, "hunter2");
        assert!(loaded.debug);
        assert_eq!(loaded.mfa_retrys, 5);
    }

    #[test]
    fn test_private_key_text_inline() {
        let mut cfg = Config::default();
        cfg.user_private_key = "-----BEGIN PGP PRIVATE KEY BLOCK-----".into();
        let text = cfg.private_key_text().unwrap();
        assert!(text.starts_with("-----BEGIN PGP PRIVATE KEY BLOCK-----"));
    }

    #[test]
    fn test_private_key_text_file() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "-----BEGIN PGP PRIVATE KEY BLOCK-----").unwrap();
        writeln!(file, "key-from-file").unwrap();

        let mut cfg = Config::default();
        cfg.user_private_key_file = file.path().to_string_lossy().into_owned();
        let text = cfg.private_key_text().unwrap();
        assert!(text.contains("key-from-file"));
    }

    #[test]
    fn test_private_key_text_missing() {
        let cfg = Config::default();
        assert!(cfg.private_key_text().is_err());
    }

    #[test]
    fn test_private_key_inline_takes_priority() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "from-file").unwrap();

        let mut cfg = Config::default();
        cfg.user_private_key = "inline-key".into();
        cfg.user_private_key_file = file.path().to_string_lossy().into_owned();

        let text = cfg.private_key_text().unwrap();
        assert_eq!(text, "inline-key");
    }

    #[cfg(unix)]
    #[test]
    fn test_file_written_with_mode_600() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"test = true\n").unwrap();
        drop(file);

        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
