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

use passbolt_sdk::{ApiError, CryptoError, PassboltError};
use serde_json::{json, Value};

use crate::common::*;

const METADATA_KEYS_PATH: &str = "/metadata/keys.json";

/// Metadata key shared with betty only.
fn metadata_keys_for_betty() -> Value {
    let mut metadata_keys = data::metadata_keys(&[("mk1", &METADATA)]);
    metadata_keys[0]["metadata_private_keys"][0]["user_id"] = BETTY_ID.into();
    metadata_keys
}

#[tokio::test]
async fn a_refused_metadata_key_request_is_an_api_error_with_the_server_message() {
    let fake = FakePassbolt::new();
    fake.on_error_saying("GET", METADATA_KEYS_PATH, 403, "Access denied.");
    let client = login_ada(&fake).await;

    let error = client.metadata_keys().await.unwrap_err();

    let PassboltError::Api(ApiError {
        status, message, ..
    }) = error
    else {
        panic!("{error:?}")
    };
    assert_eq!(status, 403);
    assert_eq!(message, "Access denied.");
}

#[tokio::test]
async fn the_metadata_key_request_asks_for_the_shares_of_keys_not_deleted() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    client.metadata_keys().await.unwrap();

    let request = &fake.requests_to("GET", METADATA_KEYS_PATH)[0];
    assert_eq!(
        request
            .query_value("contain[metadata_private_keys]")
            .as_deref(),
        Some("1")
    );
    assert_eq!(request.query_value("filter[deleted]").as_deref(), Some("0"));
}

#[tokio::test]
async fn a_key_without_a_share_for_the_user_is_skipped() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    let metadata_keys = client.metadata_keys().await.unwrap();

    assert!(metadata_keys.is_empty());
}

#[tokio::test]
async fn shared_metadata_without_a_key_share_is_an_error() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;
    let resource = data::resource_v5(&data::metadata("GitHub"), &METADATA, "shared_key", "mk1");

    let error = client
        .decrypt_resource_metadata(&resource)
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("mk1 is not shared with you"),
        "{error}"
    );
}

#[tokio::test]
async fn metadata_keys_are_looked_up_once() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    client.metadata_keys().await.unwrap();
    client.metadata_keys().await.unwrap();

    assert_eq!(fake.requests_to("GET", METADATA_KEYS_PATH).len(), 1);
}

#[tokio::test]
async fn an_undecryptable_key_share_is_a_crypto_error() {
    let fake = FakePassbolt::new();
    let mut metadata_keys = data::metadata_keys(&[("mk1", &METADATA)]);
    metadata_keys[0]["metadata_private_keys"][0]["data"] = BETTY.encrypt("for betty").into();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys);
    let client = login_ada(&fake).await;

    let error = client.metadata_keys().await.unwrap_err();

    assert!(matches!(error, PassboltError::Crypto(_)), "{error:?}");
}

#[tokio::test]
async fn rejects_a_share_holding_another_key() {
    let share = ADA.encrypt(&data::metadata_private_key(&SERVER));
    let keys = json!([data::metadata_key("mk1", &METADATA, &share)]);
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, keys);
    let client = login_ada(&fake).await;

    let error = client.metadata_keys().await.unwrap_err();

    assert!(
        matches!(&error, PassboltError::Crypto(CryptoError::KeyParse(message)) if message.contains("fingerprint mismatch")),
        "{error:?}"
    );
}

#[tokio::test]
async fn rejects_a_share_that_is_not_a_metadata_private_key() {
    let mut private_key_data: Value =
        serde_json::from_str(&data::metadata_private_key(&METADATA)).unwrap();
    private_key_data["object_type"] = "PASSBOLT_SECRET_DATA".into();
    let share = ADA.encrypt(&private_key_data.to_string());
    let keys = json!([data::metadata_key("mk1", &METADATA, &share)]);
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, keys);
    let client = login_ada(&fake).await;

    let error = client.metadata_keys().await.unwrap_err();

    assert!(
        matches!(&error, PassboltError::Crypto(CryptoError::KeyParse(message)) if message.contains("object_type")),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_expired_key_still_decrypts_the_metadata_written_with_it() {
    let fake = FakePassbolt::new();
    let mut keys = data::metadata_keys(&[("mk1", &METADATA)]);
    keys[0]["expired"] = "2025-07-01T00:00:00+00:00".into();
    fake.on("GET", METADATA_KEYS_PATH, keys);
    let client = login_ada(&fake).await;
    let resource = data::resource_v5(&data::metadata("GitHub"), &METADATA, "shared_key", "mk1");

    let metadata = client
        .decrypt_resource_metadata(&resource)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.name.as_deref(), Some("GitHub"));
}

#[tokio::test]
async fn a_deleted_key_returned_anyway_is_ignored() {
    let fake = FakePassbolt::new();
    let mut keys = data::metadata_keys(&[("mk1", &METADATA)]);
    keys[0]["deleted"] = "2025-07-01T00:00:00+00:00".into();
    fake.on("GET", METADATA_KEYS_PATH, keys);
    let client = login_ada(&fake).await;

    assert!(client.metadata_keys().await.unwrap().is_empty());
}
