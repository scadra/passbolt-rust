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

use passbolt_sdk::types::{Resource, ResourceMetadata};
use serde_json::json;

use crate::common::*;

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
#[ignore = "RES-6: v5 `uris` is an array of strings, not of objects"]
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
#[ignore = "RES-7: the metadata private key share is JSON, not an armored key"]
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
#[ignore = "RES-7: the metadata private key share is JSON, not an armored key"]
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
#[ignore = "RES-11: the metadata key is picked without looking at metadata_key_id"]
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
