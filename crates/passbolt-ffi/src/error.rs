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

use std::fmt;

use passbolt_sdk::error::{ApiError, PassboltError};

/// FFI-safe error type exposed to all target languages.
#[derive(Debug, uniffi::Error)]
pub enum PassboltFfiError {
    Transport { message: String },
    Auth { message: String },
    Crypto { message: String },
    Api { status: u16, message: String },
    NotFound { message: String },
    Config { message: String },
    InvalidArgument { message: String },
    Other { message: String },
}

impl fmt::Display for PassboltFfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { message } => write!(f, "Transport error: {message}"),
            Self::Auth { message } => write!(f, "Auth error: {message}"),
            Self::Crypto { message } => write!(f, "Crypto error: {message}"),
            Self::Api { status, message } => write!(f, "API error ({status}): {message}"),
            Self::NotFound { message } => write!(f, "Not found: {message}"),
            Self::Config { message } => write!(f, "Config error: {message}"),
            Self::InvalidArgument { message } => write!(f, "Invalid argument: {message}"),
            Self::Other { message } => write!(f, "{message}"),
        }
    }
}

impl From<PassboltError> for PassboltFfiError {
    fn from(e: PassboltError) -> Self {
        match e {
            PassboltError::Transport(t) => Self::Transport {
                message: t.to_string(),
            },
            PassboltError::Auth(a) => Self::Auth {
                message: a.to_string(),
            },
            PassboltError::Crypto(c) => Self::Crypto {
                message: c.to_string(),
            },
            PassboltError::Api(ApiError {
                status, message, ..
            }) => Self::Api { status, message },
            PassboltError::NotFound(m) => Self::NotFound { message: m },
            PassboltError::Config(m) => Self::Config { message: m },
            PassboltError::InvalidArgument(m) => Self::InvalidArgument { message: m },
            _ => Self::Other {
                message: e.to_string(),
            },
        }
    }
}
