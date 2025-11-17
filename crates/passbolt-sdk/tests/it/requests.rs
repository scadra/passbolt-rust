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

use passbolt_sdk::types::PasswordExpirySettings;
use passbolt_sdk::{ApiError, FolderQuery, GroupQuery, PassboltError, ResourceQuery, UserQuery};
use serde_json::{json, Value};

use crate::common::fake::RecordedRequest;
use crate::common::*;

const FAVORITE_ID: &str = "4f5a6b7c-0000-4000-8000-0000000000fa";
const COMMENT_ID: &str = "2d3e4f5a-0000-4000-8000-0000000000d1";
const TAG_ID: &str = "3e4f5a6b-0000-4000-8000-0000000000c1";
const SETTINGS_ID: &str = "6a7b8c9d-0000-4000-8000-0000000000e5";

async fn logged_in_with(method: &'static str, path: &str, body: Value) -> (FakePassbolt, Client) {
    let fake = FakePassbolt::new();
    fake.on(method, path, body);
    let client = login_ada(&fake).await;
    (fake, client)
}

fn single_request(fake: &FakePassbolt, method: &str, path: &str) -> RecordedRequest {
    let requests = fake.requests_to(method, path);
    assert_eq!(requests.len(), 1, "{method} {path} calls");
    requests[0].clone()
}

#[tokio::test]
async fn delete_resources_sends_the_ids_with_the_csrf_token() {
    let (fake, client) = logged_in_with("DELETE", "/resources.json", Value::Null).await;

    client
        .delete_resources(&["r1".into(), "r2".into()])
        .await
        .unwrap();

    let request = single_request(&fake, "DELETE", "/resources.json");
    assert_eq!(request.json_body(), &json!({ "ids": ["r1", "r2"] }));
    assert_eq!(request.header("X-CSRF-Token"), Some(CSRF_TOKEN));
}

#[tokio::test]
async fn delete_resources_reports_the_server_message() {
    let fake = FakePassbolt::new();
    fake.on_error_saying("DELETE", "/resources.json", 400, "Invalid ids.");
    let client = login_ada(&fake).await;

    let error = client.delete_resources(&["r1".into()]).await.unwrap_err();

    let PassboltError::Api(ApiError {
        status, message, ..
    }) = error
    else {
        panic!("{error:?}")
    };
    assert_eq!(status, 400);
    assert!(message.contains("Invalid ids."), "{message}");
}

#[tokio::test]
async fn move_resource_sends_the_new_parent() {
    let path = format!("/move/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, Value::Null).await;

    client
        .move_resource(RESOURCE_ID, Some(FOLDER_ID))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &path),
        json!({ "folder_parent_id": FOLDER_ID })
    );
}

#[tokio::test]
async fn move_folder_to_the_root_sends_a_null_parent() {
    let path = format!("/move/folder/{FOLDER_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, Value::Null).await;

    client.move_folder(FOLDER_ID, None).await.unwrap();

    assert_eq!(
        fake.body_of("PUT", &path),
        json!({ "folder_parent_id": null })
    );
}

#[tokio::test]
async fn update_resource_tags_sends_one_slug_per_tag() {
    let path = format!("/resources/{RESOURCE_ID}/tags.json");
    let (fake, client) =
        logged_in_with("PUT", &path, json!([data::tag("prod"), data::tag("ops")])).await;

    let tags = client
        .update_resource_tags(RESOURCE_ID, &["prod".into(), "ops".into()])
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("PUT", &path),
        json!([{ "slug": "prod" }, { "slug": "ops" }])
    );
    assert_eq!(tags.len(), 2);
}

#[tokio::test]
async fn add_tag_to_resource_posts_the_slug() {
    let path = format!("/tags/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::tag("prod")).await;

    let tag = client
        .add_tag_to_resource(RESOURCE_ID, "prod")
        .await
        .unwrap();

    assert_eq!(fake.body_of("POST", &path), json!({ "slug": "prod" }));
    assert_eq!(tag.slug, "prod");
}

#[tokio::test]
async fn update_tag_puts_the_new_slug() {
    let path = format!("/tags/{TAG_ID}.json");
    let (fake, client) = logged_in_with("PUT", &path, data::tag("staging")).await;

    client.update_tag(TAG_ID, "staging").await.unwrap();

    assert_eq!(fake.body_of("PUT", &path), json!({ "slug": "staging" }));
}

#[tokio::test]
async fn delete_tag_targets_the_tag() {
    let path = format!("/tags/{TAG_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.delete_tag(TAG_ID).await.unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn get_tags_reads_the_tag_list() {
    let (_fake, client) = logged_in_with("GET", "/tags.json", json!([data::tag("prod")])).await;

    let tags = client.get_tags().await.unwrap();

    assert_eq!(tags[0].slug, "prod");
}

#[tokio::test]
async fn create_comment_sends_the_parent_when_given() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::comment()).await;

    client
        .create_comment(RESOURCE_ID, "Agreed", Some(COMMENT_ID))
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "content": "Agreed", "parent_id": COMMENT_ID })
    );
}

#[tokio::test]
async fn create_comment_without_parent_sends_only_the_content() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::comment()).await;

    let comment = client
        .create_comment(RESOURCE_ID, "Rotated last week", None)
        .await
        .unwrap();

    assert_eq!(
        fake.body_of("POST", &path),
        json!({ "content": "Rotated last week" })
    );
    assert_eq!(comment.id, COMMENT_ID);
}

#[tokio::test]
async fn get_comments_asks_for_the_creator() {
    let path = format!("/comments/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("GET", &path, json!([data::comment()])).await;

    let comments = client.get_comments(RESOURCE_ID).await.unwrap();

    assert_eq!(comments.len(), 1);
    assert_eq!(
        single_request(&fake, "GET", &path)
            .query_value("contain[creator]")
            .as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn delete_comment_targets_the_comment() {
    let path = format!("/comments/{COMMENT_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.delete_comment(COMMENT_ID).await.unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn add_favorite_posts_an_empty_object() {
    let path = format!("/favorites/resource/{RESOURCE_ID}.json");
    let (fake, client) = logged_in_with("POST", &path, data::favorite()).await;

    let favorite = client.add_favorite(RESOURCE_ID).await.unwrap();

    let request = single_request(&fake, "POST", &path);
    assert_eq!(request.json_body(), &json!({}));
    assert_eq!(request.header("X-CSRF-Token"), Some(CSRF_TOKEN));
    assert_eq!(favorite.id.as_deref(), Some(FAVORITE_ID));
}

#[tokio::test]
async fn remove_favorite_targets_the_favorite_not_the_resource() {
    let path = format!("/favorites/{FAVORITE_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client.remove_favorite(FAVORITE_ID).await.unwrap();

    assert_eq!(
        single_request(&fake, "DELETE", &path).header("X-CSRF-Token"),
        Some(CSRF_TOKEN)
    );
}

#[tokio::test]
async fn save_password_expiry_settings_posts_the_settings() {
    let path = "/password-expiry/settings.json";
    let (fake, client) = logged_in_with("POST", path, data::password_expiry_settings()).await;
    let settings = PasswordExpirySettings {
        id: None,
        default_expiry_period_days: None,
        policy_override: Some(false),
        automatic_expiry: Some(true),
        automatic_update: Some(true),
    };

    let saved = client
        .save_password_expiry_settings(&settings)
        .await
        .unwrap();

    let body = fake.body_of("POST", path);
    assert_eq!(body["automatic_expiry"], true);
    assert_eq!(body["automatic_update"], true);
    assert_eq!(body["policy_override"], false);
    assert_eq!(saved.id.as_deref(), Some(SETTINGS_ID));
}

#[tokio::test]
#[ignore = "SDK-EXP-1: the default expiry period is sent as default_expiry_period_days, the API field is default_expiry_period"]
async fn password_expiry_settings_use_the_api_field_for_the_default_period() {
    let (_fake, client) = logged_in_with(
        "GET",
        "/password-expiry/settings.json",
        data::password_expiry_settings(),
    )
    .await;

    let settings = client.get_password_expiry_settings().await.unwrap();

    assert_eq!(settings.default_expiry_period_days, Some(90));
}

#[tokio::test]
async fn delete_password_expiry_settings_targets_the_settings() {
    let path = format!("/password-expiry/settings/{SETTINGS_ID}.json");
    let (fake, client) = logged_in_with("DELETE", &path, Value::Null).await;

    client
        .delete_password_expiry_settings(SETTINGS_ID)
        .await
        .unwrap();

    assert_eq!(fake.requests_to("DELETE", &path).len(), 1);
}

#[tokio::test]
async fn search_aros_encodes_the_search_term() {
    let path = "/share/search-aros.json";
    let (fake, client) = logged_in_with("GET", path, data::aros()).await;

    let aros = client.search_aros("betty & co/ops").await.unwrap();

    let request = single_request(&fake, "GET", path);
    assert_eq!(request.query, "filter%5Bsearch%5D=betty%20%26%20co%2Fops");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("betty & co/ops")
    );
    assert_eq!(aros.len(), 2);
}

#[tokio::test]
async fn get_users_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/users.json", json!([])).await;

    client
        .get_users(UserQuery {
            search: Some("ada".into()),
            group_id: Some(GROUP_ID.into()),
            resource_id: Some(RESOURCE_ID.into()),
            admin_only: true,
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/users.json");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("ada")
    );
    assert_eq!(
        request.query_value("filter[is-in-group]").as_deref(),
        Some(GROUP_ID)
    );
    assert_eq!(
        request.query_value("filter[has-access]").as_deref(),
        Some(RESOURCE_ID)
    );
    assert_eq!(
        request.query_value("filter[is-admin]").as_deref(),
        Some("1")
    );
}

#[tokio::test]
async fn get_users_without_filters_only_asks_for_the_contained_data() {
    let (fake, client) = logged_in_with("GET", "/users.json", json!([])).await;

    client.get_users(UserQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/users.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
    for contained in ["contain[role]", "contain[gpgkey]", "contain[groups_users]"] {
        assert_eq!(
            request.query_value(contained).as_deref(),
            Some("1"),
            "{contained}"
        );
    }
}

#[tokio::test]
async fn get_folders_sends_every_filter() {
    let (fake, client) =
        logged_in_with("GET", "/folders.json", json!([data::folder(json!([]))])).await;

    let folders = client
        .get_folders(FolderQuery {
            search: Some("ops".into()),
            group_id: Some(GROUP_ID.into()),
            parent_folder_id: Some(FOLDER_ID.into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/folders.json");
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("ops")
    );
    assert_eq!(
        request
            .query_value("filter[is-shared-with-group]")
            .as_deref(),
        Some(GROUP_ID)
    );
    assert_eq!(
        request.query_value("filter[has-parent]").as_deref(),
        Some(FOLDER_ID)
    );
    assert_eq!(folders[0].id, FOLDER_ID);
}

#[tokio::test]
async fn get_folders_without_filters_sends_none() {
    let (fake, client) = logged_in_with("GET", "/folders.json", json!([])).await;

    client.get_folders(FolderQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/folders.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
}

#[tokio::test]
async fn get_groups_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/groups.json", json!([data::group()])).await;

    let groups = client
        .get_groups(GroupQuery {
            user_id: Some(BETTY_ID.into()),
            manager_id: Some(ADA_ID.into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/groups.json");
    assert_eq!(
        request.query_value("filter[has-users]").as_deref(),
        Some(BETTY_ID)
    );
    assert_eq!(
        request.query_value("filter[has-managers]").as_deref(),
        Some(ADA_ID)
    );
    assert_eq!(groups[0].id, GROUP_ID);
}

#[tokio::test]
async fn get_groups_without_filters_sends_none() {
    let (fake, client) = logged_in_with("GET", "/groups.json", json!([])).await;

    client.get_groups(GroupQuery::default()).await.unwrap();

    let request = single_request(&fake, "GET", "/groups.json");
    assert!(!request.query.contains("filter"), "{}", request.query);
}

#[tokio::test]
async fn get_resources_sends_every_filter() {
    let (fake, client) = logged_in_with("GET", "/resources.json", json!([])).await;

    client
        .get_resources(ResourceQuery {
            favorites_only: true,
            owned_by_me: true,
            group_ids: vec![GROUP_ID.into()],
            folder_ids: vec![FOLDER_ID.into()],
            search: Some("git".into()),
            ..Default::default()
        })
        .await
        .unwrap();

    let request = single_request(&fake, "GET", "/resources.json");
    assert_eq!(
        request
            .query_value("filter[is-shared-with-group]")
            .as_deref(),
        Some(GROUP_ID)
    );
    assert_eq!(request.query_values("filter[has-parent][]"), [FOLDER_ID]);
    assert_eq!(
        request.query_value("filter[is-favorite]").as_deref(),
        Some("1")
    );
    assert_eq!(
        request.query_value("filter[is-owned-by-me]").as_deref(),
        Some("1")
    );
    assert_eq!(
        request.query_value("filter[search]").as_deref(),
        Some("git")
    );
}

#[tokio::test]
async fn get_resources_filters_on_one_group_only() {
    let (fake, client) = logged_in_with("GET", "/resources.json", json!([])).await;

    let error = client
        .get_resources(ResourceQuery {
            group_ids: vec![GROUP_ID.into(), GROUP_ID.into()],
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::InvalidArgument(_)),
        "{error:?}"
    );
    assert!(fake.requests_to("GET", "/resources.json").is_empty());
}
