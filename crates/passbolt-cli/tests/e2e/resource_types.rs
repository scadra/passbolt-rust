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

use crate::common::{
    create_resource, ids, run, run_json, share_with_user_id, unique_name, Cleanup,
};

const TOTP_KEY: &str = "JBSWY3DPEHPK3PXP";

/// Create a resource of type `slug` with `args`, then read it back.
fn create_and_get(slug: &str, args: &[&str]) -> (Cleanup, serde_json::Value) {
    let name = unique_name(slug);
    let mut create_args = vec!["create", "resource", "--type", slug, "--name", &name];
    create_args.extend_from_slice(args);
    let resource = Cleanup::new("resource", &run_json(&create_args));

    let fetched = run_json(&["get", "resource", "--id", &resource.id]);

    assert_eq!(fetched["name"], name.as_str(), "{slug}");
    (resource, fetched)
}

#[test]
fn every_creatable_type_reads_back() {
    let cases: [(&str, &[&str], bool); 10] = [
        (
            "password-string",
            &["--password", "p", "--uri", "https://e2e.test"],
            false,
        ),
        (
            "password-and-description",
            &["--password", "p", "--description", "d"],
            false,
        ),
        (
            "password-description-totp",
            &["--password", "p", "--totp-key", TOTP_KEY],
            false,
        ),
        ("totp", &["--totp-key", TOTP_KEY], false),
        (
            "v5-default",
            &[
                "--password",
                "p",
                "--uri",
                "https://a.test",
                "--uri",
                "https://b.test",
            ],
            true,
        ),
        (
            "v5-default-with-totp",
            &["--password", "p", "--totp-key", TOTP_KEY],
            true,
        ),
        ("v5-totp-standalone", &["--totp-key", TOTP_KEY], true),
        ("v5-note", &["--note", "a secret note"], true),
        ("v5-pin-code", &["--pin-code", "123456"], true),
        (
            "v5-default",
            &["--password", "p", "--username", "e2e", "--description", "d"],
            true,
        ),
    ];

    for (slug, args, v5) in cases {
        let (_resource, fetched) = create_and_get(slug, args);

        assert_eq!(fetched["metadata"].is_string(), v5, "{slug}: {fetched}");
    }
}

#[test]
fn v5_default_keeps_the_password_username_and_first_uri() {
    let (_resource, fetched) = create_and_get(
        "v5-default",
        &[
            "--password",
            "s3cr3t",
            "--username",
            "e2e",
            "--uri",
            "https://a.test",
            "--uri",
            "https://b.test",
        ],
    );

    assert_eq!(fetched["password"], "s3cr3t");
    assert_eq!(fetched["username"], "e2e");
    assert_eq!(fetched["uri"], "https://a.test");
}

#[test]
fn v5_password_string_cannot_be_created() {
    let output = crate::common::passbolt()
        .args([
            "create",
            "resource",
            "--type",
            "v5-password-string",
            "--name",
            "x",
            "--password",
            "p",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("read-only"));
}

#[test]
#[ignore = "V5-13: updating a v5 resource sends v4 fields instead of re-encrypting the metadata"]
fn v5_updated_password_reads_back() {
    let resource = create_resource(&unique_name("v5"), "first", &["--type", "v5-default"]);

    run(&[
        "update",
        "resource",
        "--id",
        &resource.id,
        "--password",
        "second",
    ]);

    assert_eq!(
        run_json(&["get", "resource", "--id", &resource.id])["password"],
        "second"
    );
}

#[test]
#[ignore = "V5-19: personal v5 metadata must be re-encrypted with the shared key before sharing"]
fn v5_personal_resource_can_be_shared() {
    let resource = create_resource(&unique_name("v5"), "p", &["--type", "v5-default"]);

    run(&[
        "share",
        "resource",
        "--id",
        &resource.id,
        "--user",
        &share_with_user_id(),
        "--type",
        "1",
    ]);
}

#[test]
#[ignore = "V5-23: --search matches the v4 name, empty for v5 resources"]
fn v5_resource_is_found_by_name() {
    let name = unique_name("v5");
    let resource = create_resource(&name, "p", &["--type", "v5-default"]);

    let found = run_json(&["list", "resource", "--search", &name]);

    assert_eq!(ids(&found), [resource.id.as_str()]);
}
