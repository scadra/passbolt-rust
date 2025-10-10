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

use crate::common::{create_resource, passbolt, run, run_json, unique_name};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

fn assert_totp_code(code: &serde_json::Value, digits: usize) {
    let code = code["code"].as_str().unwrap();
    assert!(
        code.len() == digits && code.chars().all(|c| c.is_ascii_digit()),
        "{code}"
    );
}

#[test]
fn password_with_totp_generates_a_code() {
    let resource = create_resource(&unique_name("totp"), "p", &["--totp-key", TOTP_KEY]);

    assert_totp_code(&run_json(&["get", "totp", "--id", &resource.id]), 6);
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

    assert_totp_code(&code, 8);
    assert!(code["ttl"].as_u64().unwrap() <= 60);
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
