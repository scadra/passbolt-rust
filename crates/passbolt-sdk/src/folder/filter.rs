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

use std::collections::HashMap;

use crate::filter::{filter_entities, Filter};
use crate::types::Folder;

#[must_use]
pub fn folder_fields(folder: &Folder) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    fields.insert("id".into(), folder.id.clone());
    fields.insert("name".into(), folder.name.clone());
    fields.insert(
        "folder_parent_id".into(),
        folder.folder_parent_id.clone().unwrap_or_default(),
    );
    fields
}

pub fn filter_folders(folders: Vec<Folder>, filters: &[Filter]) -> Vec<Folder> {
    filter_entities(folders, filters, folder_fields)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn folder(value: serde_json::Value) -> Folder {
        serde_json::from_value(value).unwrap()
    }

    #[rstest]
    #[case::id("id", "f2")]
    #[case::name("name", "Ops")]
    #[case::folder_parent_id("folder_parent_id", "f1")]
    fn test_folder_fields(#[case] field: &str, #[case] expected: &str) {
        let ops = folder(json!({ "id": "f2", "name": "Ops", "folder_parent_id": "f1" }));

        assert_eq!(folder_fields(&ops)[field], expected);
    }

    #[test]
    fn test_folder_fields_root_has_an_empty_parent() {
        let root = folder(json!({ "id": "f1", "name": "Root" }));

        assert_eq!(folder_fields(&root)["folder_parent_id"], "");
    }

    #[test]
    fn test_filter_folders_by_parent() {
        let root = folder(json!({ "id": "f1", "name": "Root" }));
        let child = folder(json!({ "id": "f2", "name": "Ops", "folder_parent_id": "f1" }));
        let filter = Filter::parse("folder_parent_id=f1").unwrap();

        let folders = filter_folders(vec![root, child], &[filter]);

        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].id, "f2");
    }
}
