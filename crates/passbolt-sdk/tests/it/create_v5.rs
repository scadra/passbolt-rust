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

use passbolt_sdk::resource::create::{self, NewResource};
use passbolt_sdk::types::{CustomField, TotpData};
use passbolt_sdk::PassboltError;
use rstest::rstest;
use serde_json::{json, Value};

use crate::common::*;

const ADA_GPGKEY_ID: &str = "8b6c3a10-0000-4000-8000-000000008888";
const CUSTOM_FIELD_ID: &str = "0f7b6a51-0000-4000-8000-0000000000c1";

/// Server creating v5 resources by default, with `keys` settings and the metadata key mk1.
fn v5_server(keys_settings: Value) -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.with_metadata_settings(data::metadata_types_settings(), keys_settings);
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    fake.on(
        "POST",
        "/resources.json",
        serde_json::to_value(data::resource_v5(
            &data::metadata("GitHub"),
            &ADA,
            "user_key",
            ADA_GPGKEY_ID,
        ))
        .unwrap(),
    );
    fake
}

fn github() -> NewResource {
    NewResource {
        name: "GitHub".into(),
        username: Some("ada".into()),
        uris: vec!["https://github.com".into()],
        description: Some("prod".into()),
        password: Some("s3cr3t".into()),
        ..NewResource::default()
    }
}

fn totp() -> TotpData {
    TotpData {
        secret_key: Some("JBSWY3DPEHPK3PXP".into()),
        algorithm: Some("SHA1".into()),
        digits: Some(6),
        period: Some(30),
        issuer: None,
    }
}

async fn create(fake: &FakePassbolt, new_resource: &NewResource) -> Result<Value, PassboltError> {
    let client = login_ada(fake).await;
    create::create_resource(&client, new_resource).await?;
    Ok(fake.body_of("POST", "/resources.json"))
}

async fn refused(fake: &FakePassbolt, new_resource: &NewResource) -> String {
    let error = create(fake, new_resource).await.unwrap_err();
    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/resources.json").is_empty());
    error.to_string()
}

fn ada_secret(body: &Value) -> Value {
    serde_json::from_str(&ADA.decrypt_signed(secret_of(body, ADA_ID), &[&ADA])).unwrap()
}

#[tokio::test]
async fn creates_personal_v5_metadata_signed_by_the_user() {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("v5-default")
    );
    assert_eq!(body["metadata_key_type"], "user_key");
    assert_eq!(body["metadata_key_id"], ADA_GPGKEY_ID);
    for clear_field in ["name", "username", "uri", "description"] {
        assert!(
            body.get(clear_field).is_none(),
            "{clear_field} sent in clear"
        );
    }
    let metadata: Value =
        serde_json::from_str(&ADA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&ADA]))
            .unwrap();
    assert_eq!(
        metadata,
        json!({
            "object_type": "PASSBOLT_RESOURCE_METADATA",
            "resource_type_id": data::resource_type_id("v5-default"),
            "name": "GitHub",
            "username": "ada",
            "uris": ["https://github.com"],
            "description": "prod"
        })
    );
    assert_eq!(
        ada_secret(&body),
        json!({"object_type": "PASSBOLT_SECRET_DATA", "password": "s3cr3t"})
    );
}

#[tokio::test]
async fn creates_shared_metadata_when_personal_keys_are_not_allowed() {
    let fake = v5_server(
        json!({"allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false}),
    );

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(body["metadata_key_type"], "shared_key");
    assert_eq!(body["metadata_key_id"], "mk1");
    let metadata = METADATA.decrypt_signed(body["metadata"].as_str().unwrap(), &[&METADATA, &ADA]);
    assert!(metadata.contains(r#""name":"GitHub""#), "{metadata}");
}

#[rstest]
#[case::password_and_totp(NewResource { totp: Some(totp()), ..github() }, "v5-default-with-totp")]
#[case::totp(NewResource { totp: Some(totp()), password: None, username: None, ..github() }, "v5-totp-standalone")]
#[case::pin_code(NewResource { pin_code: Some("1234".into()), ..NewResource { name: "Door".into(), ..NewResource::default() } }, "v5-pin-code")]
#[case::note(NewResource { note: Some("secret note".into()), ..NewResource { name: "Note".into(), ..NewResource::default() } }, "v5-note")]
#[tokio::test]
async fn picks_the_v5_type_matching_the_secret(
    #[case] new_resource: NewResource,
    #[case] slug: &str,
) {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(&fake, &new_resource).await.unwrap();

    assert_eq!(body["resource_type_id"], data::resource_type_id(slug));
}

#[tokio::test]
async fn splits_custom_fields_between_metadata_and_secret() {
    let fake = v5_server(data::metadata_keys_settings());
    let new_resource = NewResource {
        name: "Account".into(),
        custom_fields: vec![CustomField {
            id: CUSTOM_FIELD_ID.into(),
            field_type: "text".into(),
            metadata_key: Some("Account number".into()),
            metadata_value: None,
            secret_key: None,
            secret_value: Some("42".into()),
        }],
        ..NewResource::default()
    };

    let body = create(&fake, &new_resource).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("v5-custom-fields")
    );
    let metadata = ADA.decrypt_json(body["metadata"].as_str().unwrap());
    assert_eq!(
        metadata["custom_fields"],
        json!([{"id": CUSTOM_FIELD_ID, "type": "text", "metadata_key": "Account number"}])
    );
    assert_eq!(
        ada_secret(&body)["custom_fields"],
        json!([{"id": CUSTOM_FIELD_ID, "type": "text", "secret_value": "42"}])
    );
}

#[tokio::test]
async fn creates_a_v4_type_when_asked() {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(
        &fake,
        &NewResource {
            resource_type: Some("password-string".into()),
            description: None,
            ..github()
        },
    )
    .await
    .unwrap();

    assert_eq!(body["name"], "GitHub");
    assert_eq!(body["uri"], "https://github.com");
    assert!(body.get("metadata").is_none());
    assert_eq!(
        ADA.decrypt_signed(secret_of(&body, ADA_ID), &[&ADA]),
        "s3cr3t"
    );
}

#[rstest]
#[case::read_only_type(NewResource { resource_type: Some("v5-password-string".into()), ..github() }, "read-only")]
#[case::unknown_type(NewResource { resource_type: Some("v5-unknown".into()), ..github() }, "Unknown resource type")]
#[case::field_of_another_type(NewResource { resource_type: Some("v5-totp-standalone".into()), password: None, totp: Some(totp()), ..github() }, "username is not allowed")]
#[case::invalid_pin_code(NewResource { pin_code: Some("12ab".into()), ..NewResource { name: "Door".into(), ..NewResource::default() } }, "pin_code does not match")]
#[case::two_uris_on_v4(NewResource { resource_type: Some("password-and-description".into()), uris: vec!["a".into(), "b".into()], ..github() }, "single URI")]
#[case::nothing_secret(NewResource { password: None, ..github() }, "Nothing to keep secret")]
#[tokio::test]
async fn refuses_what_the_type_does_not_allow(
    #[case] new_resource: NewResource,
    #[case] expected: &str,
) {
    let fake = v5_server(data::metadata_keys_settings());

    let error = refused(&fake, &new_resource).await;

    assert!(error.contains(expected), "{error}");
}

#[tokio::test]
async fn refuses_v5_when_the_server_settings_forbid_it() {
    let fake = v5_server(data::metadata_keys_settings());
    let mut types_settings = data::metadata_types_settings();
    types_settings["allow_creation_of_v5_resources"] = false.into();
    fake.with_metadata_settings(types_settings, data::metadata_keys_settings());

    let error = refused(
        &fake,
        &NewResource {
            resource_type: Some("v5-default".into()),
            ..github()
        },
    )
    .await;

    assert!(error.contains("do not allow creating v5"), "{error}");
}

#[tokio::test]
async fn creates_v4_without_the_metadata_plugin() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "POST",
        "/resources.json",
        data::resource_v4("password-and-description", "{}"),
    );

    let body = create(&fake, &github()).await.unwrap();

    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id("password-and-description")
    );
    assert_eq!(body["name"], "GitHub");
}
