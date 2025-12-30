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

use std::collections::BTreeSet;

use passbolt_sdk::{ApiError, PaginationParams, PassboltError, ResourceQuery};
use serde_json::json;

use crate::common::*;

const RESOURCES_PATH: &str = "/resources.json";

async fn list_with(client: &Client, pagination: PaginationParams) -> Vec<String> {
    client
        .get_resources(ResourceQuery {
            pagination,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_iter()
        .map(|resource| resource.id)
        .collect()
}

fn requested_pages(fake: &FakePassbolt) -> Vec<String> {
    fake.requests_to("GET", RESOURCES_PATH)
        .iter()
        .filter_map(|request| request.query_value("page"))
        .collect()
}

#[tokio::test]
async fn follows_the_pages_up_to_the_announced_count() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        4,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3", "r4"]),
        ],
    );
    let client = login_ada(&fake).await;

    let ids = list_with(&client, PaginationParams::default()).await;

    assert_eq!(ids, ["r1", "r2", "r3", "r4"]);
    assert_eq!(requested_pages(&fake), ["1", "2"]);
}

#[tokio::test]
async fn stops_at_an_incomplete_page() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        10,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3"]),
        ],
    );
    let client = login_ada(&fake).await;

    let ids = list_with(&client, PaginationParams::default()).await;

    assert_eq!(ids, ["r1", "r2", "r3"]);
    assert_eq!(requested_pages(&fake), ["1", "2"]);
}

#[tokio::test]
async fn returns_each_item_once() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        5,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3", "r4"]),
            data::listed_resources(&["r5"]),
        ],
    );
    let client = login_ada(&fake).await;

    let ids = list_with(&client, PaginationParams::default()).await;

    assert_eq!(ids.len(), 5);
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), 5);
    assert_eq!(requested_pages(&fake), ["1", "2", "3"]);
}

#[tokio::test]
async fn a_refused_page_is_an_api_error() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        4,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3", "r4"]),
        ],
    );
    fake.fail_page(RESOURCES_PATH, 2, 403);
    let client = login_ada(&fake).await;

    let error = client
        .get_resources(ResourceQuery::default())
        .await
        .unwrap_err();

    let PassboltError::Api(ApiError {
        status, message, ..
    }) = error
    else {
        panic!("{error:?}")
    };
    assert_eq!(status, 403);
    assert_eq!(message, "fake: page refused");
}

#[tokio::test]
async fn a_list_without_pagination_header_is_a_single_page() {
    let fake = FakePassbolt::new();
    fake.on("GET", RESOURCES_PATH, data::listed_resources(&["r1", "r2"]));
    let client = login_ada(&fake).await;

    let ids = list_with(&client, PaginationParams::default()).await;

    assert_eq!(ids, ["r1", "r2"]);
    assert_eq!(requested_pages(&fake), ["1"]);
}

#[tokio::test]
async fn auto_pagination_does_not_ask_for_api_v2_without_limit() {
    let fake = FakePassbolt::new();
    fake.on("GET", RESOURCES_PATH, json!([]));
    let client = login_ada(&fake).await;

    list_with(&client, PaginationParams::default()).await;

    let request = &fake.requests_to("GET", RESOURCES_PATH)[0];
    assert_eq!(request.query_value("api-version"), None);
    assert_eq!(request.query_value("limit"), None);
}

#[tokio::test]
async fn a_limit_asks_for_api_v2_on_every_page() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        3,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3"]),
        ],
    );
    let client = login_ada(&fake).await;

    let ids = list_with(
        &client,
        PaginationParams {
            page: None,
            limit: Some(2),
        },
    )
    .await;

    assert_eq!(ids, ["r1", "r2", "r3"]);
    for request in fake.requests_to("GET", RESOURCES_PATH) {
        assert_eq!(request.query_value("api-version").as_deref(), Some("v2"));
        assert_eq!(request.query_value("limit").as_deref(), Some("2"));
    }
}

#[tokio::test]
async fn a_page_number_fetches_only_that_page() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        6,
        2,
        vec![
            data::listed_resources(&["r1", "r2"]),
            data::listed_resources(&["r3", "r4"]),
            data::listed_resources(&["r5", "r6"]),
        ],
    );
    let client = login_ada(&fake).await;

    let ids = list_with(
        &client,
        PaginationParams {
            page: Some(2),
            limit: Some(2),
        },
    )
    .await;

    assert_eq!(ids, ["r3", "r4"]);
    let requests = fake.requests_to("GET", RESOURCES_PATH);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].query_value("api-version").as_deref(),
        Some("v2")
    );
    assert_eq!(requests[0].query_value("limit").as_deref(), Some("2"));
    assert_eq!(requests[0].query_value("page").as_deref(), Some("2"));
}

#[tokio::test]
async fn a_refused_single_page_is_an_api_error() {
    let fake = FakePassbolt::new();
    fake.on_pages(
        RESOURCES_PATH,
        2,
        2,
        vec![data::listed_resources(&["r1", "r2"])],
    );
    fake.fail_page(RESOURCES_PATH, 1, 400);
    let client = login_ada(&fake).await;

    let error = client
        .get_resources(ResourceQuery {
            pagination: PaginationParams {
                page: Some(1),
                limit: None,
            },
            ..Default::default()
        })
        .await
        .unwrap_err();

    assert!(
        matches!(error, PassboltError::Api(ApiError { status: 400, .. })),
        "{error:?}"
    );
}

#[tokio::test]
async fn resources_by_ids_filter_on_each_id() {
    let fake = FakePassbolt::new();
    fake.on("GET", RESOURCES_PATH, data::listed_resources(&["r1", "r2"]));
    let client = login_ada(&fake).await;

    let resources = client
        .get_resources_by_ids(&["r1".into(), "r2".into()])
        .await
        .unwrap();

    assert_eq!(resources.len(), 2);
    assert_eq!(
        fake.requests_to("GET", RESOURCES_PATH)[0].query_values("filter[has-id][]"),
        ["r1", "r2"]
    );
}
