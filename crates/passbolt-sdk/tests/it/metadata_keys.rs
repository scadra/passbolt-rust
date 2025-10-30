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

use passbolt_sdk::{ApiError, PassboltError};
use serde_json::Value;

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

    let error = client.ensure_metadata_key().await.unwrap_err();

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
async fn the_metadata_key_request_includes_the_private_key_shares() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    client.ensure_metadata_key().await.unwrap();

    assert_eq!(
        fake.requests_to("GET", METADATA_KEYS_PATH)[0]
            .query_value("contain[metadata_private_keys]")
            .as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn no_share_for_the_user_means_no_metadata_key() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    let metadata_key = client.ensure_metadata_key().await.unwrap();

    assert!(metadata_key.is_none());
}

#[tokio::test]
async fn shared_metadata_without_a_key_share_is_not_decrypted() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;
    let resource = data::resource_v5(&data::metadata("GitHub"), &METADATA, "shared_key", "mk1");

    let metadata = client.decrypt_resource_metadata(&resource).await.unwrap();

    assert!(metadata.is_none());
}

#[tokio::test]
async fn a_missing_metadata_key_is_looked_up_once() {
    let fake = FakePassbolt::new();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys_for_betty());
    let client = login_ada(&fake).await;

    client.ensure_metadata_key().await.unwrap();
    client.ensure_metadata_key().await.unwrap();

    assert_eq!(fake.requests_to("GET", METADATA_KEYS_PATH).len(), 1);
}

#[tokio::test]
async fn an_undecryptable_key_share_is_a_crypto_error() {
    let fake = FakePassbolt::new();
    let mut metadata_keys = data::metadata_keys(&[("mk1", &METADATA)]);
    metadata_keys[0]["metadata_private_keys"][0]["data"] = BETTY.encrypt("for betty").into();
    fake.on("GET", METADATA_KEYS_PATH, metadata_keys);
    let client = login_ada(&fake).await;

    let error = client.ensure_metadata_key().await.unwrap_err();

    assert!(matches!(error, PassboltError::Crypto(_)), "{error:?}");
}
