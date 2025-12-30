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

use passbolt_sdk::types::{Resource, ResourceMetadata};
use passbolt_sdk::PassboltError;
use serde_json::json;

use crate::common::*;

async fn metadata_error(client: &Client, resource: &Resource) -> String {
    let error = client
        .decrypt_resource_metadata(resource)
        .await
        .unwrap_err();
    assert!(matches!(error, PassboltError::Crypto(_)), "{error:?}");
    error.to_string()
}

async fn decrypt_metadata(client: &Client, resource: &Resource) -> ResourceMetadata {
    client
        .decrypt_resource_metadata(resource)
        .await
        .unwrap()
        .unwrap()
}

fn shared_key_resource(name: &str) -> Resource {
    data::resource_v5(&data::metadata(name), &METADATA, "shared_key", "mk1")
}

#[tokio::test]
async fn decrypts_personal_metadata_with_the_user_key() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;
    let resource = data::resource_v5(&data::metadata("GitHub"), &ADA, "user_key", "gpgkey-ada");

    let metadata = decrypt_metadata(&client, &resource).await;

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
    assert!(fake.requests_to("GET", "/metadata/keys.json").is_empty());
}

#[tokio::test]
async fn v4_resources_have_no_metadata() {
    let client = login_ada(&FakePassbolt::new()).await;

    let metadata = client
        .decrypt_resource_metadata(&data::resource("password-string", "x"))
        .await
        .unwrap();

    assert!(metadata.is_none());
}

#[tokio::test]
async fn reads_the_uris() {
    let client = login_ada(&FakePassbolt::new()).await;
    let mut plaintext_metadata = data::metadata("GitHub");
    plaintext_metadata["uris"] = json!(["https://github.com"]);
    let resource = data::resource_v5(&plaintext_metadata, &ADA, "user_key", "gpgkey-ada");

    let metadata = decrypt_metadata(&client, &resource).await;

    assert_eq!(
        serde_json::to_value(metadata.uris).unwrap(),
        json!(["https://github.com"])
    );
}

#[tokio::test]
async fn decrypts_shared_metadata() {
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    let client = login_ada(&fake).await;

    let metadata = decrypt_metadata(&client, &shared_key_resource("GitHub")).await;

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
}

#[tokio::test]
async fn fetches_the_metadata_key_once_per_session() {
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("mk1", &METADATA)]),
    );
    let client = login_ada(&fake).await;

    decrypt_metadata(&client, &shared_key_resource("GitHub")).await;
    decrypt_metadata(&client, &shared_key_resource("GitLab")).await;

    assert_eq!(fake.requests_to("GET", "/metadata/keys.json").len(), 1);
}

#[tokio::test]
async fn uses_the_metadata_key_named_by_the_resource() {
    let fake = FakePassbolt::new();
    fake.on(
        "GET",
        "/metadata/keys.json",
        data::metadata_keys(&[("old-key", &SERVER), ("mk1", &METADATA)]),
    );
    let client = login_ada(&fake).await;

    let metadata = decrypt_metadata(&client, &shared_key_resource("GitHub")).await;

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
}

#[tokio::test]
async fn personal_metadata_without_key_id_is_v5() {
    let mut resource = data::resource_v5(&data::metadata("GitHub"), &ADA, "user_key", "");
    resource.metadata_key_id = None;

    assert!(resource.is_v5());
}

#[tokio::test]
async fn keeps_the_icon_custom_fields_and_unknown_fields() {
    let client = login_ada(&FakePassbolt::new()).await;
    let mut plaintext_metadata = data::metadata("GitHub");
    plaintext_metadata["field_from_a_newer_client"] = json!(["kept"]);
    let resource = data::resource_v5(&plaintext_metadata, &ADA, "user_key", "gpgkey-ada");

    let metadata = decrypt_metadata(&client, &resource).await;

    assert_eq!(serde_json::to_value(&metadata).unwrap(), plaintext_metadata);
}

#[tokio::test]
async fn rejects_metadata_that_is_not_resource_metadata() {
    let client = login_ada(&FakePassbolt::new()).await;
    let mut plaintext_metadata = data::metadata("GitHub");
    plaintext_metadata["object_type"] = "PASSBOLT_SECRET_DATA".into();
    let resource = data::resource_v5(&plaintext_metadata, &ADA, "user_key", "gpgkey-ada");

    let error = metadata_error(&client, &resource).await;

    assert!(error.contains("unexpected object_type"), "{error}");
}

#[tokio::test]
async fn batch_reports_metadata_that_cannot_be_decrypted() {
    let client = login_ada(&FakePassbolt::new()).await;
    let resource = data::resource_v5(
        &data::metadata("GitHub"),
        &BETTY,
        "user_key",
        "gpgkey-betty",
    );

    let error = client
        .decrypt_metadata_batch(&[resource])
        .await
        .unwrap_err();

    assert!(matches!(error, PassboltError::Crypto(_)), "{error:?}");
}
