// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use crate::error::PassboltError;

/// Trait for providing MFA TOTP codes during authentication.
///
/// Synchronous because both interactive (rpassword) and non-interactive
/// (TOTP generation) implementations are CPU-only.
pub trait MfaProvider: Send + Sync {
    fn get_totp_code(&self) -> Result<String, PassboltError>;
}
