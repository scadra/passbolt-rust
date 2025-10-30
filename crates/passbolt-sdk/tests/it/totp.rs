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

use passbolt_sdk::resource::{create, update};
use passbolt_sdk::types::TotpData;
use passbolt_sdk::PassboltError;
use serde_json::{json, Value};

use crate::common::*;

const PASSWORD_DESCRIPTION_TOTP: &str = "password-description-totp";
const PASSWORD_AND_DESCRIPTION: &str = "password-and-description";
const SECRET_WITH_TOTP: &str = r#"{"password":"p","description":"d","totp":{"secret_key":"OLDKEY","algorithm":"SHA256","digits":8,"period":60,"issuer":"GitHub"}}"#;
const SECRET_WITHOUT_TOTP: &str = r#"{"password":"p","description":"d"}"#;

/// TOTP arguments of `update_resource` a test sets; the rest stay `None`.
#[derive(Default)]
struct TotpChange<'a> {
    key: Option<&'a str>,
    digits: Option<u32>,
    remove: bool,
}

fn totp(secret_key: &str) -> TotpData {
    TotpData {
        secret_key: Some(secret_key.into()),
        algorithm: Some("SHA1".into()),
        digits: Some(6),
        period: Some(30),
        issuer: None,
    }
}

async fn create_github_resource(
    fake: &FakePassbolt,
    password: Option<&str>,
    totp: TotpData,
) -> Value {
    fake.with_directory();
    fake.on(
        "POST",
        "/resources.json",
        data::resource_v4(PASSWORD_DESCRIPTION_TOTP, "{}"),
    );
    let client = login_ada(fake).await;

    create::create_resource(
        &client,
        "GitHub",
        None,
        None,
        None,
        password,
        None,
        None,
        Some(totp),
    )
    .await
    .unwrap();

    fake.body_of("POST", "/resources.json")
}

fn fake_serving_totp_resource(slug: &str, secret: &str) -> FakePassbolt {
    let fake = fake_serving_resource(slug, secret, ada_owner_permissions());
    fake.on("PUT", &resource_path(), data::resource_v4(slug, secret));
    fake
}

async fn update_totp(fake: &FakePassbolt, change: TotpChange<'_>) -> Result<(), PassboltError> {
    let client = login_ada(fake).await;
    update::update_resource(
        &client,
        RESOURCE_ID,
        None,
        None,
        None,
        None,
        None,
        None,
        change.key,
        None,
        change.digits,
        None,
        None,
        change.remove,
    )
    .await
    .map(drop)
}

fn updated_secret(fake: &FakePassbolt) -> Value {
    ADA.decrypt_json(secret_of(&fake.body_of("PUT", &resource_path()), ADA_ID))
}

#[tokio::test]
async fn creating_with_a_password_and_a_totp_uses_the_totp_password_type() {
    let fake = FakePassbolt::new();

    let body = create_github_resource(&fake, Some("s3cr3t"), totp("NEWKEY")).await;

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id(PASSWORD_DESCRIPTION_TOTP)
    );
    let secret = ADA.decrypt_json(secret_of(&body, ADA_ID));
    assert_eq!(secret["password"], "s3cr3t");
    assert_eq!(secret["description"], "");
    assert_eq!(secret["totp"]["secret_key"], "NEWKEY");
}

#[tokio::test]
async fn creating_with_only_a_totp_uses_the_totp_type_without_password() {
    let fake = FakePassbolt::new();

    let body = create_github_resource(&fake, None, totp("NEWKEY")).await;

    assert_eq!(body["resource_type_id"], data::resource_type_id("totp"));
    let secret = ADA.decrypt_json(secret_of(&body, ADA_ID));
    assert!(secret.get("password").is_none(), "{secret}");
    assert_eq!(secret["totp"]["secret_key"], "NEWKEY");
}

#[tokio::test]
async fn removing_the_totp_keeps_the_password_and_description() {
    let fake = fake_serving_totp_resource(PASSWORD_DESCRIPTION_TOTP, SECRET_WITH_TOTP);

    update_totp(
        &fake,
        TotpChange {
            remove: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        updated_secret(&fake),
        json!({ "password": "p", "description": "d" })
    );
}

#[tokio::test]
async fn a_new_totp_key_gets_the_default_settings() {
    let fake = fake_serving_totp_resource(PASSWORD_AND_DESCRIPTION, SECRET_WITHOUT_TOTP);

    update_totp(
        &fake,
        TotpChange {
            key: Some("NEWKEY"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        updated_secret(&fake)["totp"],
        json!({ "secret_key": "NEWKEY", "algorithm": "SHA1", "digits": 6, "period": 30, "issuer": null })
    );
}

#[tokio::test]
async fn a_new_totp_key_keeps_the_existing_settings() {
    let fake = fake_serving_totp_resource(PASSWORD_DESCRIPTION_TOTP, SECRET_WITH_TOTP);

    update_totp(
        &fake,
        TotpChange {
            key: Some("NEWKEY"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        updated_secret(&fake)["totp"],
        json!({ "secret_key": "NEWKEY", "algorithm": "SHA256", "digits": 8, "period": 60, "issuer": "GitHub" })
    );
}

#[tokio::test]
async fn a_partial_totp_update_keeps_the_key() {
    let fake = fake_serving_totp_resource(PASSWORD_DESCRIPTION_TOTP, SECRET_WITH_TOTP);

    update_totp(
        &fake,
        TotpChange {
            digits: Some(6),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        updated_secret(&fake),
        json!({
            "password": "p",
            "description": "d",
            "totp": { "secret_key": "OLDKEY", "algorithm": "SHA256", "digits": 6, "period": 60, "issuer": "GitHub" }
        })
    );
}

#[tokio::test]
#[ignore = "SDK-TOTP-1: removing the TOTP keeps the password-description-totp resource type"]
async fn removing_the_totp_switches_to_the_password_and_description_type() {
    let fake = fake_serving_totp_resource(PASSWORD_DESCRIPTION_TOTP, SECRET_WITH_TOTP);

    update_totp(
        &fake,
        TotpChange {
            remove: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        fake.body_of("PUT", &resource_path())["resource_type_id"],
        data::resource_type_id(PASSWORD_AND_DESCRIPTION)
    );
}

#[tokio::test]
#[ignore = "SDK-TOTP-1: adding a TOTP keeps the password-and-description resource type"]
async fn adding_a_totp_switches_to_the_password_description_totp_type() {
    let fake = fake_serving_totp_resource(PASSWORD_AND_DESCRIPTION, SECRET_WITHOUT_TOTP);

    update_totp(
        &fake,
        TotpChange {
            key: Some("NEWKEY"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        fake.body_of("PUT", &resource_path())["resource_type_id"],
        data::resource_type_id(PASSWORD_DESCRIPTION_TOTP)
    );
}

#[tokio::test]
#[ignore = "SDK-TOTP-2: TOTP settings on a resource without TOTP are silently dropped"]
async fn totp_settings_without_a_totp_are_refused() {
    let fake = fake_serving_totp_resource(PASSWORD_AND_DESCRIPTION, SECRET_WITHOUT_TOTP);

    let error = update_totp(
        &fake,
        TotpChange {
            digits: Some(8),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
}
