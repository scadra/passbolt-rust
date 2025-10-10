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

//! `exec`, `export keepass` and `verify`.

use keepass::db::NodeRef;
use keepass::{Database, DatabaseKey};
use predicates::str::contains;

use crate::common::{create_folder, create_resource, passbolt, run, unique_name, Cleanup};

#[test]
fn exec_injects_the_password_into_the_environment() {
    let resource = create_resource(&unique_name("exec"), "exec-password", &[]);

    passbolt()
        .env("E2E_SECRET", format!("passbolt://{}", resource.id))
        .args(["exec", "--", "/bin/sh", "-c", "printf %s \"$E2E_SECRET\""])
        .assert()
        .success()
        .stdout("exec-password");
}

#[test]
fn keepass_export_contains_the_folder_resources() {
    let folder = create_folder(&unique_name("export"), &[]);
    let name = unique_name("exported");
    let _resource = create_resource(
        &name,
        "exported-password",
        &["--folder-parent-id", &folder.id],
    );
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("export.kdbx");

    run(&[
        "export",
        "keepass",
        "--output",
        file.to_str().unwrap(),
        "--password",
        "kdbx-password",
        "--folder-id",
        &folder.id,
    ]);

    let database = Database::open(
        &mut std::fs::File::open(&file).unwrap(),
        DatabaseKey::new().with_password("kdbx-password"),
    )
    .unwrap();
    let exported = database.root.iter().any(|node| {
        matches!(node, NodeRef::Entry(entry)
            if entry.get_title() == Some(name.as_str()) && entry.get_password() == Some("exported-password"))
    });
    assert!(exported, "{name} missing from the export");
}

#[test]
fn writes_still_work_after_verify() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .arg("verify")
        .assert()
        .success()
        .stdout(contains("Fingerprint"));

    // The pre-login verify request is the one receiving the CSRF cookie.
    let output = passbolt()
        .env("PASSBOLT_CONFIG", &config)
        .args([
            "create",
            "folder",
            "--name",
            &unique_name("verified"),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let _folder = Cleanup::new("folder", &serde_json::from_slice(&output).unwrap());
}
