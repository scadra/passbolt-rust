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

use serde_json::Value;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::common::{create_resource, passbolt, run, run_json, unique_name, Cleanup};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

/// The code must be the one the shared secret yields now (or in an adjacent window).
fn assert_totp_code(code: &Value, algorithm: Algorithm, digits: usize, period: u64) {
    let secret = Secret::Encoded(TOTP_KEY.to_string()).to_bytes().unwrap();
    let generator = TOTP::new_unchecked(algorithm, digits, 0, period, secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected: Vec<String> = [now - period, now, now + period]
        .into_iter()
        .map(|time| generator.generate(time))
        .collect();
    let code = code["code"].as_str().unwrap();
    assert!(
        expected.iter().any(|candidate| candidate == code),
        "{code} not in {expected:?}"
    );
}

#[test]
fn password_with_totp_generates_a_code() {
    let resource = create_resource(&unique_name("totp"), "p", &["--totp-key", TOTP_KEY]);

    assert_totp_code(
        &run_json(&["get", "totp", "--id", &resource.id]),
        Algorithm::SHA1,
        6,
        30,
    );
}

#[test]
fn totp_settings_are_kept() {
    let resource = create_resource(
        &unique_name("totp"),
        "p",
        &[
            "--totp-key",
            TOTP_KEY,
            "--totp-digits",
            "8",
            "--totp-algo",
            "SHA256",
            "--totp-period",
            "60",
        ],
    );

    let code = run_json(&["get", "totp", "--id", &resource.id]);

    assert_totp_code(&code, Algorithm::SHA256, 8, 60);
}

#[test]
fn removed_totp_no_longer_generates_a_code() {
    let resource = create_resource(&unique_name("totp"), "p", &["--totp-key", TOTP_KEY]);

    run(&["update", "resource", "--id", &resource.id, "--remove-totp"]);

    passbolt()
        .args(["get", "totp", "--id", &resource.id])
        .assert()
        .failure();
    assert_eq!(
        run_json(&["get", "resource", "--id", &resource.id])["password"],
        "p"
    );
}

#[test]
fn totp_only_resource_generates_a_code() {
    let created = run_json(&[
        "create",
        "resource",
        "--name",
        &unique_name("totp-only"),
        "--totp-key",
        TOTP_KEY,
    ]);
    let resource = Cleanup::new("resource", &created);

    assert_totp_code(
        &run_json(&["get", "totp", "--id", &resource.id]),
        Algorithm::SHA1,
        6,
        30,
    );
}

#[test]
fn changing_the_digits_keeps_the_totp_key() {
    let resource = create_resource(&unique_name("totp"), "p", &["--totp-key", TOTP_KEY]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--totp-digits",
        "8",
    ]);

    assert_totp_code(
        &run_json(&["get", "totp", "--id", &resource.id]),
        Algorithm::SHA1,
        8,
        30,
    );
}
