use secrecy::SecretString;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SDK-level configuration: everything needed to connect and authenticate.
///
/// No file I/O — this is a pure data struct suitable for library consumers.
/// `ZeroizeOnDrop` ensures the private key and passphrase are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SdkConfig {
    pub server_url: String,
    pub private_key_armored: String,
    pub passphrase: SecretString,
    /// "interactive-totp" | "non-interactive-totp" | "none"
    pub mfa_mode: String,
    pub mfa_totp_token: String,
    pub mfa_totp_offset: i64,
    pub mfa_retrys: u32,
    pub tls_skip_verify: bool,
    pub tls_client_cert: String,
    pub tls_client_private_key: String,
    pub proxy: String,
    /// Stored server fingerprint (for pre-login identity check)
    pub server_verify_enc_token: String,
    /// Stored decrypted challenge token
    pub server_verify_token: String,
}
