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

use predicates::str::contains;

use crate::common::{passbolt, run_json};

#[test]
fn logs_in_and_lists_users() {
    let users = run_json(&["list", "user"]);

    assert_ne!(users.as_array().unwrap().len(), 0);
}

#[test]
fn rejects_a_wrong_passphrase() {
    passbolt()
        .env("PASSBOLT_USER_PASSWORD", "not-the-passphrase")
        .args(["list", "user"])
        .assert()
        .failure()
        .stderr(contains("Login failed"));
}
