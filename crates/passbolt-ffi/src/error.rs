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
            PassboltError::Transport(transport_error) => Self::Transport {
                message: transport_error.to_string(),
            },
            PassboltError::Auth(auth_error) => Self::Auth {
                message: auth_error.to_string(),
            },
            PassboltError::Crypto(crypto_error) => Self::Crypto {
                message: crypto_error.to_string(),
            },
            PassboltError::Api(ApiError {
                status, message, ..
            }) => Self::Api { status, message },
            PassboltError::NotFound(message) => Self::NotFound { message },
            PassboltError::Config(message) => Self::Config { message },
            PassboltError::InvalidArgument(message) => Self::InvalidArgument { message },
            _ => Self::Other {
                message: e.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use passbolt_sdk::error::{AuthError, CryptoError, TransportError};
    use rstest::rstest;

    use super::*;

    fn variant_and_message(error: &PassboltFfiError) -> (&'static str, &str) {
        match error {
            PassboltFfiError::Transport { message } => ("Transport", message),
            PassboltFfiError::Auth { message } => ("Auth", message),
            PassboltFfiError::Crypto { message } => ("Crypto", message),
            PassboltFfiError::Api { message, .. } => ("Api", message),
            PassboltFfiError::NotFound { message } => ("NotFound", message),
            PassboltFfiError::Config { message } => ("Config", message),
            PassboltFfiError::InvalidArgument { message } => ("InvalidArgument", message),
            PassboltFfiError::Other { message } => ("Other", message),
        }
    }

    fn json_error() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{").unwrap_err()
    }

    #[rstest]
    #[case::transport(
        TransportError::Network("connection refused".into()).into(),
        "Transport",
        "Network error: connection refused"
    )]
    #[case::auth(AuthError::SessionExpired.into(), "Auth", "Session expired")]
    #[case::crypto(
        CryptoError::Decrypt("bad packet".into()).into(),
        "Crypto",
        "PGP decryption failed: bad packet"
    )]
    #[case::not_found(PassboltError::NotFound("resource 42".into()), "NotFound", "resource 42")]
    #[case::config(PassboltError::Config("no server".into()), "Config", "no server")]
    #[case::invalid_argument(
        PassboltError::InvalidArgument("empty id".into()),
        "InvalidArgument",
        "empty id"
    )]
    #[case::other(PassboltError::Other("unexpected".into()), "Other", "unexpected")]
    fn test_from_passbolt_error_maps_variant_and_message(
        #[case] error: PassboltError,
        #[case] expected_variant: &str,
        #[case] expected_message: &str,
    ) {
        let ffi_error = PassboltFfiError::from(error);

        assert_eq!(
            variant_and_message(&ffi_error),
            (expected_variant, expected_message)
        );
    }

    #[test]
    fn test_from_api_error_keeps_status_and_message() {
        let error = PassboltError::Api(ApiError {
            status: 403,
            message: "Forbidden".into(),
            validation_errors: None,
        });

        let ffi_error = PassboltFfiError::from(error);

        assert!(
            matches!(&ffi_error, PassboltFfiError::Api { status: 403, message } if message == "Forbidden"),
            "{ffi_error}"
        );
    }

    #[test]
    fn test_from_json_error_is_other_with_json_prefix() {
        let ffi_error = PassboltFfiError::from(PassboltError::Json(json_error()));

        let (variant, message) = variant_and_message(&ffi_error);
        assert_eq!(variant, "Other");
        assert!(message.starts_with("JSON error: "), "{message}");
    }

    #[rstest]
    #[case::transport(PassboltFfiError::Transport { message: "down".into() }, "Transport error: down")]
    #[case::api(
        PassboltFfiError::Api { status: 500, message: "boom".into() },
        "API error (500): boom"
    )]
    #[case::other(PassboltFfiError::Other { message: "plain".into() }, "plain")]
    fn test_display_formats_variant(#[case] error: PassboltFfiError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }
}
