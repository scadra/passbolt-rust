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

use crate::common::{passbolt, run, run_json, unique_name, Cleanup};

fn create(name: &str, password: &str) -> Cleanup {
    let created = run_json(&[
        "create",
        "resource",
        "--name",
        name,
        "--username",
        "e2e",
        "--uri",
        "https://e2e.test",
        "--password",
        password,
        "--description",
        "created by the e2e suite",
    ]);
    Cleanup::new("resource", &created)
}

#[test]
fn created_resource_reads_back_decrypted() {
    let name = unique_name("resource");
    let resource = create(&name, "first-password");

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);

    assert_eq!(fetched["name"], name.as_str());
    assert_eq!(fetched["username"], "e2e");
    assert_eq!(fetched["password"], "first-password");
}

#[test]
fn updated_password_reads_back() {
    let resource = create(&unique_name("resource"), "first-password");

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--password",
        "second-password",
    ]);

    assert_eq!(
        run_json(&["get", "resource", "--id", &resource.id])["password"],
        "second-password"
    );
}

#[test]
fn creator_owns_the_resource() {
    let resource = create(&unique_name("resource"), "p");

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);

    let permissions = permissions.as_array().unwrap();
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0]["type"], 15);
}

#[test]
fn created_resource_is_listed() {
    let name = unique_name("resource");
    let resource = create(&name, "p");

    let listed = run_json(&["list", "resource", "--filter", &format!("name={name}")]);

    assert_eq!(listed[0]["id"], resource.id.as_str());
}

#[test]
fn deleted_resource_is_gone() {
    let resource = create(&unique_name("resource"), "p");

    run(&["delete", "resource", "--id", &resource.id]);

    passbolt()
        .args(["get", "resource", "--id", &resource.id])
        .assert()
        .failure();
}
