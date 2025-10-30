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

//! Failures must surface as a non-zero exit and a message, never as empty output.

use predicates::str::contains;

use crate::common::{
    assert_not_found, passbolt, run_json_as, unique_name, Account, Cleanup, ADMIN, UNKNOWN_ID,
};

#[test]
fn unknown_resource_is_reported() {
    assert_not_found(Account::User, &["get", "resource", "--id", UNKNOWN_ID]);
}

#[test]
fn unknown_folder_is_reported() {
    assert_not_found(Account::User, &["get", "folder", "--id", UNKNOWN_ID]);
}

#[test]
fn another_users_private_resource_is_not_readable() {
    let created = run_json_as(
        ADMIN,
        &[
            "create",
            "resource",
            "--name",
            &unique_name("private"),
            "--password",
            "p",
        ],
    );
    let resource = Cleanup::by(ADMIN, "resource", &created);

    passbolt()
        .args(["get", "resource", "--id", &resource.id])
        .assert()
        .failure();
}

#[test]
fn exec_reports_an_unknown_resource() {
    passbolt()
        .env("E2E_SECRET", format!("passbolt://{UNKNOWN_ID}"))
        .args(["exec", "--", "/bin/true"])
        .assert()
        .failure()
        .stderr(contains(UNKNOWN_ID));
}

#[test]
fn exec_returns_the_command_exit_code() {
    passbolt()
        .args(["exec", "--", "/bin/sh", "-c", "exit 3"])
        .assert()
        .code(3);
}
