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

use passbolt_sdk::{auth, crypto, AuthError, PassboltError, PassboltSdk};
use rstest::rstest;
use serde_json::json;

use crate::common::*;

const VERIFY_PATH: &str = "/auth/verify.json";

async fn login_error(fake: &FakePassbolt) -> PassboltError {
    match PassboltSdk::login(fake.clone(), &ada_config(), None, 3).await {
        Ok(_) => panic!("login succeeded"),
        Err(error) => error,
    }
}

async fn check_ada_server_identity(
    fake: &FakePassbolt,
    stored_fingerprint: &str,
    stored_token: &str,
) -> Result<(), PassboltError> {
    let private_key = crypto::parse_private_key(ADA.private).unwrap();
    auth::check_server_identity(
        fake,
        BASE_URL,
        &private_key,
        ADA.passphrase,
        stored_fingerprint,
        stored_token,
    )
    .await
}

fn fake_verifying_server_with_token(token: &str) -> FakePassbolt {
    let fake = FakePassbolt::new();
    let mut verify_response = data::auth_verify(&SERVER);
    verify_response["challenge"] = ADA.encrypt(token).into();
    fake.on("GET", VERIFY_PATH, verify_response);
    fake
}

#[tokio::test]
async fn login_fails_without_the_challenge_header() {
    let fake = FakePassbolt::new();
    fake.without_auth_token_header();

    let error = login_error(&fake).await;

    let PassboltError::Auth(AuthError::LoginFailed(message)) = error else {
        panic!("{error:?}")
    };
    assert!(message.contains("X-GPGAuth-User-Auth-Token"), "{message}");
    assert_eq!(fake.requests_to("POST", "/auth/login.json").len(), 1);
}

#[rstest]
#[case::server_error(500, "Internal error.")]
#[case::authentication_failed(400, "The authentication failed.")]
#[tokio::test]
async fn login_reports_a_refused_verification(#[case] status: u16, #[case] server_message: &str) {
    let fake = FakePassbolt::new();
    fake.fail_login_verification(status, server_message);

    let error = login_error(&fake).await;

    let PassboltError::Auth(AuthError::LoginFailed(message)) = error else {
        panic!("{error:?}")
    };
    assert!(
        message.contains(&status.to_string()) && message.contains(server_message),
        "{message}"
    );
}

#[tokio::test]
async fn server_identity_is_not_checked_without_stored_values() {
    let fake = FakePassbolt::new();

    check_ada_server_identity(&fake, "", "").await.unwrap();

    assert!(fake.requests_to("GET", VERIFY_PATH).is_empty());
}

#[tokio::test]
async fn server_identity_accepts_the_stored_fingerprint() {
    let fake = fake_verifying_server_with_token("server-token");

    check_ada_server_identity(&fake, &SERVER.fingerprint(), "server-token")
        .await
        .unwrap();

    assert_eq!(fake.requests_to("GET", VERIFY_PATH).len(), 1);
}

#[tokio::test]
async fn server_identity_rejects_another_fingerprint() {
    let fake = fake_verifying_server_with_token("server-token");

    let error = check_ada_server_identity(&fake, &BETTY.fingerprint(), "")
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            PassboltError::Auth(AuthError::ServerIdentityMismatch(_))
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn server_identity_rejects_another_token() {
    let fake = fake_verifying_server_with_token("server-token");

    let error = check_ada_server_identity(&fake, "", "stored-token")
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            PassboltError::Auth(AuthError::ServerIdentityMismatch(_))
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn server_identity_needs_the_server_fingerprint() {
    let fake = FakePassbolt::new();
    fake.on("GET", VERIFY_PATH, json!({}));

    let error = check_ada_server_identity(&fake, &SERVER.fingerprint(), "")
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::LoginFailed(_))),
        "{error:?}"
    );
}

#[tokio::test]
async fn login_goes_on_when_the_server_identity_matches() {
    let fake = FakePassbolt::new();
    fake.on("GET", VERIFY_PATH, data::auth_verify(&SERVER));
    let mut config = ada_config();
    config.server_verify_enc_token = SERVER.fingerprint();

    let client = PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .unwrap();

    assert_eq!(client.user_id, ADA_ID);
    assert_eq!(fake.requests_to("GET", VERIFY_PATH).len(), 1);
}

#[tokio::test]
async fn auth_status_is_true_for_a_live_session() {
    let fake = FakePassbolt::new();
    fake.on("GET", "/auth/is-authenticated.json", json!(null));
    let client = login_ada(&fake).await;

    assert!(client.check_auth_status().await.unwrap());
}

#[tokio::test]
async fn auth_status_is_false_for_an_expired_session() {
    let fake = FakePassbolt::new();
    fake.on_error("GET", "/auth/is-authenticated.json", 401);
    let client = login_ada(&fake).await;

    assert!(!client.check_auth_status().await.unwrap());
}
