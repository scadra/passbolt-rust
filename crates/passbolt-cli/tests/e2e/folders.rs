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

use crate::common::{run, run_json, unique_name, Cleanup};

#[test]
fn resource_moved_into_a_folder_is_listed_there() {
    let folder = Cleanup::new(
        "folder",
        &run_json(&["create", "folder", "--name", &unique_name("folder")]),
    );
    let resource = Cleanup::new(
        "resource",
        &run_json(&[
            "create",
            "resource",
            "--name",
            &unique_name("resource"),
            "--password",
            "p",
        ]),
    );

    run(&[
        "move",
        "resource",
        "--id",
        &resource.id,
        "--folder-parent-id",
        &folder.id,
    ]);

    let listed = run_json(&["list", "resource", "--folder", &folder.id]);
    let ids: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    assert_eq!(ids, [resource.id.as_str()]);
}

#[test]
fn renamed_folder_reads_back() {
    let folder = Cleanup::new(
        "folder",
        &run_json(&["create", "folder", "--name", &unique_name("folder")]),
    );
    let new_name = unique_name("renamed");

    run(&["update", "folder", "--id", &folder.id, "--name", &new_name]);

    assert_eq!(
        run_json(&["get", "folder", "--id", &folder.id])["name"],
        new_name.as_str()
    );
}
