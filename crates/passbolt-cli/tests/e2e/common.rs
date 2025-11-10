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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use serde_json::Value;

/// `PASSBOLT_E2E_<name>` mapped to the `PASSBOLT_<name>` variable the CLI reads.
const REQUIRED: [&str; 3] = ["SERVER_ADDRESS", "USER_PRIVATE_KEY_FILE", "USER_PASSWORD"];
const OPTIONAL: [&str; 2] = ["RESOLVE", "TLS_SKIP_VERIFY"];

/// The CLI configured for the e2e server, isolated from any user config file.
/// Who runs the command: the regular test user or `PASSBOLT_E2E_ADMIN_*`.
#[derive(Clone, Copy)]
pub enum Account {
    User,
    Admin,
}

pub const ADMIN: Account = Account::Admin;

/// A valid UUID that matches nothing on the server.
pub const UNKNOWN_ID: &str = "00000000-0000-4000-8000-000000000000";

pub fn passbolt() -> Command {
    passbolt_as(Account::User)
}

pub fn passbolt_as(account: Account) -> Command {
    let mut command = assert_cmd::cargo::cargo_bin_cmd!("passbolt");
    command.env_clear().env(
        "PASSBOLT_CONFIG",
        std::env::temp_dir().join("passbolt-e2e-none.toml"),
    );
    for name in REQUIRED {
        let value = std::env::var(format!("PASSBOLT_E2E_{name}"))
            .unwrap_or_else(|_| panic!("PASSBOLT_E2E_{name} is not set, see .env.e2e.example"));
        command.env(format!("PASSBOLT_{name}"), value);
    }
    for name in OPTIONAL {
        if let Ok(value) = std::env::var(format!("PASSBOLT_E2E_{name}")) {
            command.env(format!("PASSBOLT_{name}"), value);
        }
    }
    if matches!(account, Account::Admin) {
        for name in ["USER_PRIVATE_KEY_FILE", "USER_PASSWORD"] {
            let value = std::env::var(format!("PASSBOLT_E2E_ADMIN_{name}")).unwrap_or_else(|_| {
                panic!("PASSBOLT_E2E_ADMIN_{name} is not set, see .env.e2e.example")
            });
            command.env(format!("PASSBOLT_{name}"), value);
        }
    }
    command.env("PASSBOLT_MFA_MODE", "none");
    command
}

/// Run `args` with `--json` and parse the output; fails the test on error.
pub fn run_json(args: &[&str]) -> Value {
    run_json_as(Account::User, args)
}

pub fn run_json_as(account: Account, args: &[&str]) -> Value {
    let output = passbolt_as(account)
        .args(args)
        .arg("--json")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&output).unwrap_or_else(|error| {
        panic!(
            "passbolt {args:?}: invalid JSON ({error}): {}",
            String::from_utf8_lossy(&output)
        )
    })
}

pub fn run(args: &[&str]) {
    run_as(Account::User, args);
}

pub fn run_as(account: Account, args: &[&str]) {
    passbolt_as(account).args(args).assert().success();
}

/// Table / text output of `args`.
pub fn run_text(args: &[&str]) -> String {
    run_text_as(Account::User, args)
}

pub fn run_text_as(account: Account, args: &[&str]) -> String {
    let output = passbolt_as(account)
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).unwrap()
}

/// Resource named `name` with `password`, plus any `extra_args`.
/// A v4 resource, unless `extra_args` sets `--type`: these tests cover the v4 flows.
pub fn create_resource(name: &str, password: &str, extra_args: &[&str]) -> Cleanup {
    let mut args = vec!["create", "resource", "--name", name, "--password", password];
    if !extra_args.contains(&"--type") {
        let v4_type = if extra_args.contains(&"--totp-key") {
            "password-description-totp"
        } else {
            "password-and-description"
        };
        args.extend(["--type", v4_type]);
    }
    args.extend_from_slice(extra_args);
    Cleanup::new("resource", &run_json(&args))
}

pub fn create_folder(name: &str, extra_args: &[&str]) -> Cleanup {
    let mut args = vec!["create", "folder", "--name", name];
    args.extend_from_slice(extra_args);
    Cleanup::new("folder", &run_json(&args))
}

/// Id of the `PASSBOLT_E2E_SHARE_WITH` user, the recipient of sharing tests.
pub fn share_with_user_id() -> String {
    let username = std::env::var("PASSBOLT_E2E_SHARE_WITH")
        .expect("PASSBOLT_E2E_SHARE_WITH is not set, see .env.e2e.example");
    user_id(&username)
}

pub fn user_id(username: &str) -> String {
    let users = run_json(&["list", "user", "--filter", &format!("username={username}")]);
    users[0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no user {username}"))
        .to_string()
}

/// Ids in a JSON list output.
pub fn ids(listed: &Value) -> Vec<&str> {
    listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect()
}

/// Name unique to this run, so tests never collide with existing data.
pub fn unique_name(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("e2e-{prefix}-{nanos}-{}-{sequence}", std::process::id())
}

/// `args` must fail because the entity does not exist (not because of the network).
pub fn assert_not_found(account: Account, args: &[&str]) {
    passbolt_as(account)
        .args(args)
        .assert()
        .failure()
        .stderr(predicates::str::contains("404"));
}

/// Deletes the entity when dropped, so a failing test leaves no data behind.
pub struct Cleanup {
    pub entity: &'static str,
    pub id: String,
    account: Account,
}

impl Cleanup {
    pub fn new(entity: &'static str, created: &Value) -> Self {
        Self::by(Account::User, entity, created)
    }

    pub fn by(account: Account, entity: &'static str, created: &Value) -> Self {
        Self {
            entity,
            id: created["id"].as_str().unwrap().to_string(),
            account,
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = passbolt_as(self.account)
            .args(["delete", self.entity, "--id", &self.id])
            .output();
    }
}

/// Id of the admin account.
pub fn admin_id() -> String {
    current_user_id(ADMIN)
}

pub fn current_user_id(account: Account) -> String {
    run_json_as(account, &["get", "user", "--id", "me"])["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Group created by the admin. Only a group manager can add members, so pass the admin
/// as `manager_id` when the test changes the membership later.
pub fn create_group(name: &str, manager_id: &str, member_ids: &[&str]) -> Cleanup {
    let mut args = vec!["create", "group", "--name", name, "--manager", manager_id];
    for member_id in member_ids {
        args.extend(["--user", member_id]);
    }
    Cleanup::by(ADMIN, "group", &run_json_as(ADMIN, &args))
}
