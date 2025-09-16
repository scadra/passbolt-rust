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

use assert_cmd::Command;
use predicates::str::contains;

fn passbolt() -> Command {
    Command::cargo_bin("passbolt").expect("binary not found")
}

#[test]
fn test_help_flag() {
    passbolt()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Usage"));
}

#[test]
fn test_version_flag() {
    passbolt()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("0.1"));
}

#[test]
fn test_subcommand_help() {
    passbolt()
        .args(["create", "resource", "--help"])
        .assert()
        .success()
        .stdout(contains("Usage"));
}

#[test]
fn test_list_resource_fails_without_server() {
    // Point to an unreachable address so no real server is contacted.
    passbolt()
        .env("PASSBOLT_SERVER_ADDRESS", "http://127.0.0.1:1")
        .env("PASSBOLT_USER_PASSWORD", "dummy")
        .env("PASSBOLT_USER_PRIVATE_KEY", "not-a-key")
        .args(["list", "resource"])
        .assert()
        .failure();
}

#[test]
fn test_unknown_subcommand_fails() {
    passbolt().arg("nonexistent-command").assert().failure();
}
