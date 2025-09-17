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
