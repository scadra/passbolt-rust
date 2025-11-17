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

use crate::common::{
    admin_id, create_folder, create_group, create_resource, current_user_id, ids, passbolt, run,
    run_as, run_json, run_json_as, share_with_user_id, unique_name, Account, Cleanup, ADMIN,
    UNKNOWN_ID,
};

/// Permission type granted to `user_id`, if any.
fn permission_of(permissions: &Value, user_id: &str) -> Option<i64> {
    permissions
        .as_array()
        .unwrap()
        .iter()
        .find(|permission| permission["aro_foreign_key"] == user_id)
        .and_then(|permission| permission["type"].as_i64())
}

#[test]
fn shared_resource_grants_the_permission() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("shared"), "p", &[]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "7",
        "--user",
        &recipient,
    ]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert_eq!(permission_of(&permissions, &recipient), Some(7));
}

#[test]
fn revoked_resource_permission_is_gone() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("shared"), "p", &[]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--user",
        &recipient,
    ]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "-1",
        "--user",
        &recipient,
    ]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert_eq!(permission_of(&permissions, &recipient), None);
}

#[test]
fn resharing_changes_the_permission_type() {
    let recipient = share_with_user_id();
    let resource = create_resource(&unique_name("shared"), "p", &[]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--user",
        &recipient,
    ]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "15",
        "--user",
        &recipient,
    ]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert_eq!(permission_of(&permissions, &recipient), Some(15));
}

#[test]
fn shared_folder_grants_the_permission() {
    let recipient = share_with_user_id();
    let folder = create_folder(&unique_name("shared"), &[]);

    run(&[
        "share", "folder", "--id", &folder.id, "--type", "1", "--user", &recipient,
    ]);

    let permissions = run_json(&["get", "folder-permissions", "--id", &folder.id]);
    assert_eq!(permission_of(&permissions, &recipient), Some(1));
}

#[test]
fn folder_shared_with_a_group_grants_the_permission() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);
    let folder = create_folder(&unique_name("shared"), &[]);

    run(&[
        "share", "folder", "--id", &folder.id, "--type", "1", "--group", &group.id,
    ]);

    let permissions = run_json(&["get", "folder-permissions", "--id", &folder.id]);
    assert_eq!(permission_of(&permissions, &group.id), Some(1));
}

#[test]
fn resource_shared_with_a_group_grants_the_permission() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);
    let resource = create_resource(&unique_name("shared"), "p", &[]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--group",
        &group.id,
    ]);

    let permissions = run_json(&["get", "resource-permissions", "--id", &resource.id]);
    assert_eq!(permission_of(&permissions, &group.id), Some(1));
}

#[test]
fn resource_shared_with_a_group_is_listed_by_group() {
    let group = create_group(&unique_name("group"), &admin_id(), &[]);
    let resource = create_resource(&unique_name("shared"), "p", &[]);
    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--group",
        &group.id,
    ]);

    let listed = run_json(&["list", "resource", "--group", &group.id]);

    assert_eq!(ids(&listed), [resource.id.as_str()]);
}

#[test]
fn recipient_decrypts_the_shared_password() {
    let resource = create_resource(&unique_name("shared"), "shared-password", &[]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--type",
        "1",
        "--user",
        &admin_id(),
    ]);

    let as_recipient = run_json_as(ADMIN, &["get", "resource", "--id", &resource.id]);
    assert_eq!(as_recipient["password"], "shared-password");
}

#[test]
fn read_only_recipient_cannot_modify_or_delete() {
    let created = run_json_as(
        ADMIN,
        &[
            "create",
            "resource",
            "--type",
            "password-and-description",
            "--name",
            &unique_name("read-only"),
            "--password",
            "original",
        ],
    );
    let resource = Cleanup::by(ADMIN, "resource", &created);
    let reader = current_user_id(Account::User);
    run_as(
        ADMIN,
        &[
            "share",
            "resource",
            "--id",
            &resource.id,
            "--type",
            "1",
            "--user",
            &reader,
        ],
    );

    passbolt()
        .args([
            "update",
            "resource",
            "--id",
            &resource.id,
            "--password",
            "changed",
        ])
        .assert()
        .failure();
    passbolt()
        .args(["delete", "resource", "--id", &resource.id])
        .assert()
        .failure();

    assert_eq!(
        run_json_as(ADMIN, &["get", "resource", "--id", &resource.id])["password"],
        "original"
    );
}

#[test]
fn sharing_with_an_unknown_user_fails() {
    let resource = create_resource(&unique_name("shared"), "p", &[]);

    passbolt()
        .args([
            "share",
            "resource",
            "--id",
            &resource.id,
            "--type",
            "1",
            "--user",
            UNKNOWN_ID,
        ])
        .assert()
        .failure();
}
