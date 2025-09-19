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

use std::collections::BTreeSet;

use passbolt_sdk::resource::{create, update};
use passbolt_sdk::types::Resource;
use passbolt_sdk::{ApiError, PassboltError};
use serde_json::{json, Value};

use crate::common::*;

const PASSWORD_AND_DESCRIPTION: &str = "password-and-description";

/// Fields of `update_resource` a test sets; the rest stay `None`.
#[derive(Default)]
struct UpdatedFields<'a> {
    name: Option<&'a str>,
    description: Option<&'a str>,
    password: Option<&'a str>,
}

async fn update_resource(
    client: &Client,
    fields: UpdatedFields<'_>,
) -> Result<Resource, PassboltError> {
    update::update_resource(
        client,
        RESOURCE_ID,
        fields.name,
        None,
        None,
        fields.description,
        fields.password,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    )
    .await
}

async fn create_github_resource(
    client: &Client,
    password: Option<&str>,
) -> Result<Resource, PassboltError> {
    create::create_resource(
        client,
        "GitHub",
        Some("ada"),
        None,
        Some("prod"),
        password,
        None,
        None,
        None,
    )
    .await
}

fn fake_serving_updatable_resource(slug: &str, secret: &str, permissions: Value) -> FakePassbolt {
    let fake = fake_serving_resource(slug, secret, permissions);
    fake.on("PUT", &resource_path(), data::resource_v4(slug, secret));
    fake
}

fn fake_accepting_resource_creation() -> FakePassbolt {
    let fake = FakePassbolt::new();
    fake.with_directory();
    fake.on(
        "POST",
        "/resources.json",
        data::resource_v4(PASSWORD_AND_DESCRIPTION, "{}"),
    );
    fake
}

fn decrypt_updated_secret(fake: &FakePassbolt, key: &keys::TestKey, user_id: &str) -> Value {
    key.decrypt_json(secret_of(&fake.body_of("PUT", &resource_path()), user_id))
}

#[tokio::test]
async fn decrypts_a_json_secret() {
    let client = login_ada(&FakePassbolt::new()).await;
    let resource = data::resource(
        PASSWORD_AND_DESCRIPTION,
        r#"{"password":"s3cr3t","description":"prod"}"#,
    );

    let secret = client.decrypt_resource_secret(&resource).await.unwrap();

    assert_eq!(secret.password.as_deref(), Some("s3cr3t"));
    assert_eq!(secret.description.as_deref(), Some("prod"));
}

#[tokio::test]
async fn decrypts_a_password_string_secret() {
    let client = login_ada(&FakePassbolt::new()).await;
    let resource = data::resource("password-string", "just-a-password");

    let secret = client.decrypt_resource_secret(&resource).await.unwrap();

    assert_eq!(secret.password.as_deref(), Some("just-a-password"));
}

#[tokio::test]
async fn fetches_the_secret_when_not_embedded() {
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        &format!("/secrets/resource/{RESOURCE_ID}.json"),
        json!([{ "user_id": ADA_ID, "data": ADA.encrypt(r#"{"password":"fetched"}"#) }]),
    );
    let client = login_ada(&fake).await;
    let mut resource = data::resource(PASSWORD_AND_DESCRIPTION, "{}");
    resource.secrets.clear();

    let secret = client.decrypt_resource_secret(&resource).await.unwrap();

    assert_eq!(secret.password.as_deref(), Some("fetched"));
}

#[tokio::test]
async fn api_errors_keep_the_status() {
    let fake = FakePassbolt::new();
    fake.on_error("GET", &resource_path(), 404);
    let client = login_ada(&fake).await;

    let error = client.get_resource(RESOURCE_ID).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::Api(ApiError { status: 404, .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn batch_decrypt_handles_json_and_raw_secrets() {
    let client = login_ada(&FakePassbolt::new()).await;
    let mut json_resource = data::resource(PASSWORD_AND_DESCRIPTION, r#"{"password":"one"}"#);
    json_resource.id = "json-resource".into();
    let mut raw_resource = data::resource("password-string", "two");
    raw_resource.id = "raw-resource".into();

    let secrets = client
        .decrypt_secrets_batch(&[json_resource, raw_resource], 2)
        .await
        .unwrap();

    assert_eq!(secrets["json-resource"].password.as_deref(), Some("one"));
    assert_eq!(secrets["raw-resource"].password.as_deref(), Some("two"));
}

#[tokio::test]
async fn create_encrypts_the_secret_for_the_owner() {
    let fake = fake_accepting_resource_creation();
    let client = login_ada(&fake).await;

    create_github_resource(&client, Some("s3cr3t"))
        .await
        .unwrap();

    let body = fake.body_of("POST", "/resources.json");
    assert_eq!(
        body["resource_type_id"],
        data::resource_type_id(PASSWORD_AND_DESCRIPTION)
    );
    assert_eq!(secret_user_ids(&body), BTreeSet::from([ADA_ID]));
    assert_eq!(
        ADA.decrypt_json(secret_of(&body, ADA_ID)),
        json!({ "password": "s3cr3t", "description": "prod" })
    );
}

#[tokio::test]
async fn create_keeps_the_description_out_of_clear_fields() {
    let fake = fake_accepting_resource_creation();
    let client = login_ada(&fake).await;

    create_github_resource(&client, Some("s3cr3t"))
        .await
        .unwrap();

    assert!(fake
        .body_of("POST", "/resources.json")
        .get("description")
        .is_none());
}

#[tokio::test]
async fn create_needs_a_password_or_a_totp() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;

    let error = create_github_resource(&client, None).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/resources.json").is_empty());
}

#[tokio::test]
async fn update_password_reencrypts_for_every_user_with_direct_access() {
    let permissions = json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-betty", "User", BETTY_ID, 1)
    ]);
    let fake = fake_serving_updatable_resource(
        PASSWORD_AND_DESCRIPTION,
        r#"{"password":"old","description":"keep me"}"#,
        permissions,
    );
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            password: Some("new"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        secret_user_ids(&fake.body_of("PUT", &resource_path())),
        BTreeSet::from([ADA_ID, BETTY_ID])
    );
    assert_eq!(
        decrypt_updated_secret(&fake, &BETTY, BETTY_ID),
        json!({ "password": "new", "description": "keep me" })
    );
}

#[tokio::test]
async fn update_name_leaves_secrets_alone() {
    let fake = fake_serving_updatable_resource(
        PASSWORD_AND_DESCRIPTION,
        r#"{"password":"p"}"#,
        ada_owner_permissions(),
    );
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            name: Some("Renamed"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let body = fake.body_of("PUT", &resource_path());
    assert_eq!(body["name"], "Renamed");
    assert!(body.get("secrets").is_none());
}

#[tokio::test]
async fn delete_sends_the_csrf_token() {
    let fake = FakePassbolt::new();
    fake.on("DELETE", &resource_path(), Value::Null);
    let client = login_ada(&fake).await;

    client.delete_resource(RESOURCE_ID).await.unwrap();

    assert_eq!(
        fake.requests_to("DELETE", &resource_path())[0].header("X-CSRF-Token"),
        Some(CSRF_TOKEN)
    );
}

#[tokio::test]
async fn delete_maps_a_403_to_an_api_error() {
    let fake = FakePassbolt::new();
    fake.on_error("DELETE", &resource_path(), 403);
    let client = login_ada(&fake).await;

    let error = client.delete_resource(RESOURCE_ID).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::Api(ApiError { status: 403, .. })),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "RES-3: members of a group with access do not get the new secret"]
async fn update_password_reencrypts_for_group_members() {
    let permissions = json!([
        data::permission("p-ada", "User", ADA_ID, 15),
        data::permission("p-ops", "Group", GROUP_ID, 1)
    ]);
    let fake = fake_serving_updatable_resource(
        PASSWORD_AND_DESCRIPTION,
        r#"{"password":"old"}"#,
        permissions,
    );
    fake.on("GET", "/users.json", data::users(&["ada", "carol"]));
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            password: Some("new"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let asked_who_has_access = fake
        .requests_to("GET", "/users.json")
        .iter()
        .any(|request| request.query.contains("has-access"));
    assert!(
        asked_who_has_access,
        "no GET /users.json?filter[has-access]"
    );
    assert!(secret_user_ids(&fake.body_of("PUT", &resource_path())).contains(CAROL_ID));
}

#[tokio::test]
#[ignore = "RES-4: a password-string secret is rewritten as a JSON object"]
async fn update_keeps_a_password_string_secret_as_a_string() {
    let fake = fake_serving_updatable_resource("password-string", "old", ada_owner_permissions());
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            password: Some("new"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ADA.decrypt(secret_of(&fake.body_of("PUT", &resource_path()), ADA_ID)),
        "new"
    );
}

#[tokio::test]
#[ignore = "RES-4: unknown secret fields (custom fields, object_type) are dropped"]
async fn update_keeps_unknown_secret_fields() {
    let secret = r#"{"object_type":"PASSBOLT_SECRET_DATA","password":"old","custom_fields":[{"id":"c1","secret_value":"x"}]}"#;
    let fake =
        fake_serving_updatable_resource(PASSWORD_AND_DESCRIPTION, secret, ada_owner_permissions());
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            password: Some("new"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        decrypt_updated_secret(&fake, &ADA, ADA_ID)["custom_fields"][0]["secret_value"],
        "x"
    );
}

#[tokio::test]
#[ignore = "RES-5: updating only the description is silently ignored"]
async fn update_description_reencrypts_the_secret() {
    let fake = fake_serving_updatable_resource(
        PASSWORD_AND_DESCRIPTION,
        r#"{"password":"p","description":"old"}"#,
        ada_owner_permissions(),
    );
    let client = login_ada(&fake).await;

    update_resource(
        &client,
        UpdatedFields {
            description: Some("new"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        decrypt_updated_secret(&fake, &ADA, ADA_ID)["description"],
        "new"
    );
}

#[tokio::test]
#[ignore = "RES-12: a failing /resource-types.json is ignored and the type is left to the server"]
async fn create_fails_when_resource_types_are_unavailable() {
    let fake = fake_accepting_resource_creation();
    fake.on_error("GET", "/resource-types.json", 500);
    let client = login_ada(&fake).await;

    let error = create_github_resource(&client, Some("p"))
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::Api(ApiError { status: 500, .. })),
        "{error:?}"
    );
}

#[tokio::test]
#[ignore = "RES-13: a secret that fails to decrypt comes back empty"]
async fn batch_decrypt_reports_undecryptable_secrets() {
    let client = login_ada(&FakePassbolt::new()).await;
    let mut resource = data::resource(PASSWORD_AND_DESCRIPTION, "x");
    resource.secrets[0].data = Some(BETTY.encrypt("not for ada"));

    let secrets = client.decrypt_secrets_batch(&[resource], 1).await;

    assert!(
        matches!(secrets, Err(PassboltError::Crypto(_))),
        "{secrets:?}"
    );
}

#[tokio::test]
#[ignore = "CRY-1: secrets are encrypted to the primary key, keys with an encryption subkey are unsupported"]
async fn encrypts_for_a_user_with_an_ecc_key() {
    let fake = FakePassbolt::new();
    fake.with_directory();
    let client = login_ada(&fake).await;

    let encrypted_secrets = client
        .encrypt_secret_for_users(r#"{"password":"p"}"#, &[ERIN_ID.into()])
        .await
        .unwrap();

    assert_eq!(
        ERIN.decrypt(&encrypted_secrets[0].data),
        r#"{"password":"p"}"#
    );
}
