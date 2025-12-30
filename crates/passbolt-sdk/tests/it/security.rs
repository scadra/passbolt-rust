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

use passbolt_sdk::types::Resource;
use passbolt_sdk::{AuthError, PassboltError, PassboltSdk};
use rstest::rstest;
use serde_json::Value;

use crate::common::*;

const PATH_TRAVERSAL: &str = "../users/8b6c3a10-0000-4000-8000-00000000a0da";

/// Call the id-taking `operation` of `client` with `id`.
async fn call_with_id(client: &Client, operation: &str, id: &str) -> Result<(), PassboltError> {
    match operation {
        "get_resource" => client.get_resource(id).await.map(drop),
        "delete_resource" => client.delete_resource(id).await,
        "get_resource_permissions" => client.get_resource_permissions(id).await.map(drop),
        "get_folder" => client.get_folder(id).await.map(drop),
        "delete_folder" => client.delete_folder(id).await,
        "move_folder" => client.move_folder(id, None).await,
        "get_user" => client.get_user(id).await.map(drop),
        "delete_user" => client.delete_user(id).await,
        "delete_user_dry_run" => client.delete_user_dry_run(id).await.map(drop),
        "get_group" => client.get_group(id).await.map(drop),
        "delete_group" => client.delete_group(id).await,
        "add_favorite" => client.add_favorite(id).await.map(drop),
        "remove_favorite" => client.remove_favorite(id).await,
        "add_tag_to_resource" => client.add_tag_to_resource(id, "tag").await.map(drop),
        "delete_tag" => client.delete_tag(id).await,
        "get_comments" => client.get_comments(id).await.map(drop),
        "create_comment" => client.create_comment(id, "hi", None).await.map(drop),
        "delete_comment" => client.delete_comment(id).await,
        "encrypt_secret_for_users" => client
            .encrypt_secret_for_users("{}", &[id.to_string()])
            .await
            .map(drop),
        other => panic!("unknown operation {other}"),
    }
}

#[rstest]
#[case("get_resource")]
#[case("delete_resource")]
#[case("get_resource_permissions")]
#[case("get_folder")]
#[case("delete_folder")]
#[case("move_folder")]
#[case("get_user")]
#[case("delete_user")]
#[case("delete_user_dry_run")]
#[case("get_group")]
#[case("delete_group")]
#[case("add_favorite")]
#[case("remove_favorite")]
#[case("add_tag_to_resource")]
#[case("delete_tag")]
#[case("get_comments")]
#[case("create_comment")]
#[case("delete_comment")]
#[case("encrypt_secret_for_users")]
#[tokio::test]
async fn ids_in_url_paths_must_be_uuids(#[case] operation: &str) {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;
    let requests_after_login = fake.request_count();

    let error = call_with_id(&client, operation, PATH_TRAVERSAL)
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert_eq!(fake.request_count(), requests_after_login);
}

#[rstest]
#[case::empty("")]
#[case::query("7a5b2c30-0000-4000-8000-0000000000e1?contain[secret]=1")]
#[case::trailing_path("7a5b2c30-0000-4000-8000-0000000000e1/..")]
#[case::simple_form("7a5b2c3000004000800000000000000e1")]
#[case::braced_form("{7a5b2c30-0000-4000-8000-0000000000e1}")]
#[case::urn_form("urn:uuid:7a5b2c30-0000-4000-8000-0000000000e1")]
#[tokio::test]
async fn only_hyphenated_uuids_are_accepted(#[case] id: &str) {
    let client = login_ada(&FakePassbolt::new()).await;

    let error = client.get_resource(id).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
}

#[tokio::test]
async fn get_user_accepts_me() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;

    let user = client.get_user("me").await.unwrap();

    assert_eq!(user.id, ADA_ID);
}

#[tokio::test]
async fn a_resource_id_from_the_server_is_checked_before_fetching_its_secret() {
    let fake = FakePassbolt::new();
    let client = login_ada(&fake).await;
    let mut resource_json = data::resource_v4("password-string", "secret");
    resource_json["id"] = PATH_TRAVERSAL.into();
    resource_json["secrets"] = Value::Array(Vec::new());
    let resource: Resource = serde_json::from_value(resource_json).unwrap();
    let requests_after_login = fake.request_count();

    let error = client.decrypt_resource_secret(&resource).await.unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert_eq!(fake.request_count(), requests_after_login);
}

#[tokio::test]
async fn login_refuses_a_plain_http_server() {
    let fake = FakePassbolt::new();
    let mut config = ada_config();
    config.server_url = "http://passbolt.test".into();

    let error = PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .err()
        .unwrap();

    assert!(matches!(error, PassboltError::Config(_)), "{error:?}");
    assert_eq!(fake.request_count(), 0);
}

#[rstest]
#[case("http://localhost:8080")]
#[case("http://127.0.0.1")]
#[case("http://[::1]:8080")]
#[tokio::test]
async fn login_allows_plain_http_on_the_loopback(#[case] server_url: &str) {
    let fake = FakePassbolt::new();
    let mut config = ada_config();
    config.server_url = server_url.into();

    let error = PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .err()
        .unwrap();

    // The fake only serves BASE_URL: reaching it is enough.
    assert!(!matches!(error, PassboltError::Config(_)), "{error:?}");
    assert!(fake.request_count() > 0);
}

#[tokio::test]
async fn login_refuses_a_host_that_only_starts_like_localhost() {
    let fake = FakePassbolt::new();
    let mut config = ada_config();
    config.server_url = "http://localhost.attacker.test".into();

    let error = PassboltSdk::login(fake.clone(), &config, None, 3)
        .await
        .err()
        .unwrap();

    assert!(matches!(error, PassboltError::Config(_)), "{error:?}");
}

#[tokio::test]
async fn login_rejects_a_current_user_without_public_key() {
    let fake = FakePassbolt::new();
    let mut ada = data::user("ada");
    ada["gpgkey"] = Value::Null;
    fake.on("GET", "/users/me.json", ada);

    let error = PassboltSdk::login(fake.clone(), &ada_config(), None, 3)
        .await
        .err()
        .unwrap();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::KeyCrossCheckFailed)),
        "{error:?}"
    );
}
