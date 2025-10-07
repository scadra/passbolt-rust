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

use passbolt_sdk::resource::list::list_resources;
use serde_json::json;

use crate::common::*;

#[tokio::test]
async fn search_filters_resources_by_name_even_if_the_server_ignores_it() {
    let fake = FakePassbolt::new();
    let mut github = data::resource_v4("password-string", "p");
    github["name"] = "GitHub".into();
    let mut gitlab = data::resource_v4("password-string", "p");
    gitlab["name"] = "GitLab".into();
    fake.on("GET", "/resources.json", json!([github, gitlab]));
    let client = login_ada(&fake).await;

    let resources = list_resources(
        &client,
        false,
        false,
        vec![],
        vec![],
        Some("hub".into()),
        &[],
    )
    .await
    .unwrap();

    let names: Vec<&str> = resources
        .iter()
        .map(|resource| resource.name.as_str())
        .collect();
    assert_eq!(names, ["GitHub"]);
}

#[tokio::test]
async fn folder_permissions_come_with_the_folder() {
    let fake = FakePassbolt::new();
    let permissions = json!([data::permission("p-ada", "User", ADA_ID, 15)]);
    fake.on(
        "GET",
        &format!("/folders/{FOLDER_ID}.json"),
        data::folder(permissions),
    );
    let client = login_ada(&fake).await;

    let permissions = client.get_folder_permissions(FOLDER_ID).await.unwrap();

    assert_eq!(permissions[0].permission_type, Some(15));
    assert!(
        fake.requests_to("GET", &format!("/folders/{FOLDER_ID}.json"))[0]
            .query
            .contains("permissions")
    );
}
