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
use crate::types::Resource;

#[must_use]
pub fn resource_fields(resource: &Resource) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    fields.insert("id".into(), resource.id.clone());
    fields.insert("name".into(), resource.name.clone());
    fields.insert(
        "username".into(),
        resource.username.clone().unwrap_or_default(),
    );
    fields.insert("uri".into(), resource.uri.clone().unwrap_or_default());
    fields.insert(
        "description".into(),
        resource.description.clone().unwrap_or_default(),
    );
    fields.insert(
        "folder_parent_id".into(),
        resource.folder_parent_id.clone().unwrap_or_default(),
    );
    fields.insert(
        "resource_type_id".into(),
        resource.resource_type_id.clone().unwrap_or_default(),
    );
    fields
}

pub fn filter_resources(resources: Vec<Resource>, filters: &[Filter]) -> Vec<Resource> {
    filter_entities(resources, filters, resource_fields)
}
