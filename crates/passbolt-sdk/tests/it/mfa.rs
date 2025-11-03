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

use passbolt_sdk::{AuthError, PassboltError, PassboltSdk};

use crate::common::*;

const CODE: &str = "123456";

async fn login_with_codes(
    fake: &FakePassbolt,
    codes: &[&'static str],
) -> Result<Client, PassboltError> {
    let provider = FixedTotpCodes::new(codes);
    PassboltSdk::login(fake.clone(), &ada_config(), Some(Box::new(provider)), 3).await
}

#[tokio::test]
async fn login_completes_mfa_when_the_server_asks_for_it() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let client = login_with_codes(&fake, &[CODE]).await.unwrap();

    assert_eq!(client.user_id, ADA_ID);
    let verification = fake.body_of("POST", "/mfa/verify/totp.json");
    assert_eq!(verification["totp"], CODE);
    assert_eq!(verification["remember"], false);
}

#[tokio::test]
async fn login_without_mfa_provider_reports_mfa_required() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let error = PassboltSdk::login(fake.clone(), &ada_config(), None, 3)
        .await
        .err()
        .unwrap();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::MfaRequired)),
        "{error:?}"
    );
}

#[tokio::test]
async fn mfa_retries_a_rejected_code() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    login_with_codes(&fake, &["000000", CODE]).await.unwrap();

    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 2);
}

#[tokio::test]
async fn mfa_fails_after_the_allowed_attempts() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let error = login_with_codes(&fake, &["000000", "111111", "222222"])
        .await
        .err()
        .unwrap();

    assert!(
        matches!(
            &error,
            PassboltError::Auth(AuthError::MfaFailed { attempts: 3, message })
                if message == "The OTP is not valid."
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_expired_mfa_cookie_is_verified_again_and_the_request_replayed() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.with_directory();
    let client = login_with_codes(&fake, &[CODE, CODE]).await.unwrap();
    fake.expire_mfa();

    let me = client.get_me().await.unwrap();

    assert_eq!(me.id, ADA_ID);
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 2);
}

#[tokio::test]
async fn a_second_challenge_after_verification_is_an_error() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.ignore_mfa_verification();

    let error = login_with_codes(&fake, &[CODE]).await.err().unwrap();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::MfaFailed { .. })),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 1);
}
