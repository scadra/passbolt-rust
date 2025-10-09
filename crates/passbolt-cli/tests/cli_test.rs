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
    assert_cmd::cargo::cargo_bin_cmd!("passbolt")
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

#[test]
fn test_configure_writes_to_the_config_override_only() {
    let home = tempfile::tempdir().unwrap();
    let config = home.path().join("custom.toml");

    passbolt()
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("PASSBOLT_CONFIG", &config)
        .args(["configure", "--server-address", "https://example.test"])
        .assert()
        .success();

    assert!(std::fs::read_to_string(&config)
        .unwrap()
        .contains("https://example.test"));
    assert!(
        !home.path().join(".config").exists(),
        "default config location was written"
    );
}

#[test]
fn test_share_accepts_a_negative_type_to_revoke() {
    let output = passbolt()
        .env(
            "PASSBOLT_CONFIG",
            std::env::temp_dir().join("passbolt-cli-test-none.toml"),
        )
        .args([
            "share", "resource", "--id", "x", "--type", "-1", "--user", "y",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("unexpected argument"), "{stderr}");
}
