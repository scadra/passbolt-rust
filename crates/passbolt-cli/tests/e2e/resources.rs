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

use serde_json::Value;

use crate::common::{create_resource, ids, passbolt, run, run_json, run_text, unique_name};

fn get(id: &str) -> Value {
    run_json(&["get", "resource", "--id", id])
}

#[test]
fn created_resource_reads_back_decrypted() {
    let name = unique_name("resource");
    let resource = create_resource(
        &name,
        "first-password",
        &["--username", "e2e", "--uri", "https://e2e.test"],
    );

    let fetched = get(&resource.id);

    assert_eq!(fetched["name"], name.as_str());
    assert_eq!(fetched["username"], "e2e");
    assert_eq!(fetched["uri"], "https://e2e.test");
    assert_eq!(fetched["password"], "first-password");
}

#[test]
fn created_description_reads_back() {
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--description", "first description"],
    );

    let shown = run_text(&["get", "resource", "--id", &resource.id]);

    assert!(shown.contains("first description"), "{shown}");
}

#[test]
fn updated_password_reads_back() {
    let resource = create_resource(&unique_name("resource"), "first-password", &[]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--password",
        "second-password",
    ]);

    assert_eq!(get(&resource.id)["password"], "second-password");
}

#[test]
fn updated_uri_reads_back() {
    let resource = create_resource(
        &unique_name("resource"),
        "p",
        &["--uri", "https://before.test"],
    );

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--uri",
        "https://after.test",
    ]);

    assert_eq!(get(&resource.id)["uri"], "https://after.test");
}

#[test]
#[ignore = "RES-5: updating only the description is silently ignored"]
fn updated_description_reads_back() {
    let resource = create_resource(&unique_name("resource"), "p", &["--description", "before"]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--description",
        "after",
    ]);

    let shown = run_text(&["get", "resource", "--id", &resource.id]);
    assert!(shown.contains("after"), "{shown}");
}

#[test]
fn expiry_is_set_then_cleared() {
    let resource = create_resource(&unique_name("resource"), "p", &["--expiry", "7d"]);
    assert!(get(&resource.id)["expired"].is_string(), "expiry not set");

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--expiry",
        "none",
    ]);

    assert!(get(&resource.id)["expired"].is_null(), "expiry not cleared");
}

#[test]
fn creator_owns_the_resource() {
    let resource = create_resource(&unique_name("resource"), "p", &[]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);

    assert_eq!(permissions.as_array().unwrap().len(), 1);
    assert_eq!(permissions[0]["type"], 15);
}

#[test]
fn created_resource_is_listed_by_filter_search_and_own() {
    let name = unique_name("resource");
    let resource = create_resource(&name, "p", &[]);
    let by_name = format!("name={name}");

    for args in [
        ["list", "resource", "--filter", by_name.as_str()].as_slice(),
        &["list", "resource", "--search", &name],
        &["list", "resource", "--own", "--search", &name],
    ] {
        assert_eq!(ids(&run_json(args)), [resource.id.as_str()], "{args:?}");
    }
}

#[test]
fn list_shows_the_requested_columns() {
    let name = unique_name("resource");
    let _resource = create_resource(&name, "column-password", &["--username", "column-user"]);

    let table = run_text(&[
        "list", "resource", "--search", &name, "-c", "Name", "-c", "Password",
    ]);

    assert!(
        table.contains(&name) && table.contains("column-password"),
        "{table}"
    );
    assert!(
        !table.contains("column-user"),
        "username column not requested: {table}"
    );
}

#[test]
fn deleted_resource_is_gone() {
    let resource = create_resource(&unique_name("resource"), "p", &[]);

    run(&["delete", "resource", "--id", &resource.id]);

    passbolt()
        .args(["get", "resource", "--id", &resource.id])
        .assert()
        .failure();
}
