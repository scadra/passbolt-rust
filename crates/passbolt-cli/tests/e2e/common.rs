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

use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use serde_json::Value;

/// `PASSBOLT_E2E_<name>` mapped to the `PASSBOLT_<name>` variable the CLI reads.
const REQUIRED: [&str; 3] = ["SERVER_ADDRESS", "USER_PRIVATE_KEY_FILE", "USER_PASSWORD"];
const OPTIONAL: [&str; 2] = ["RESOLVE", "TLS_SKIP_VERIFY"];

/// The CLI configured for the e2e server, isolated from any user config file.
pub fn passbolt() -> Command {
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
    command.env("PASSBOLT_MFA_MODE", "none");
    command
}

/// Run `args` with `--json` and parse the output; fails the test on error.
pub fn run_json(args: &[&str]) -> Value {
    let output = passbolt()
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
    passbolt().args(args).assert().success();
}

/// Name unique to this run, so tests never collide with existing data.
pub fn unique_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("e2e-{prefix}-{nanos}")
}

/// Deletes the entity when dropped, so a failing test leaves no data behind.
pub struct Cleanup {
    pub entity: &'static str,
    pub id: String,
}

impl Cleanup {
    pub fn new(entity: &'static str, created: &Value) -> Self {
        Self {
            entity,
            id: created["id"].as_str().unwrap().to_string(),
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = passbolt()
            .args(["delete", self.entity, "--id", &self.id])
            .output();
    }
}
