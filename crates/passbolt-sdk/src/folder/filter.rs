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
