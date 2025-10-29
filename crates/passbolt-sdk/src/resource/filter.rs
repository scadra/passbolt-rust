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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn resource(value: serde_json::Value) -> Resource {
        serde_json::from_value(value).unwrap()
    }

    fn github() -> Resource {
        resource(json!({
            "id": "r1",
            "name": "GitHub",
            "username": "ada",
            "uri": "https://github.com",
            "description": "prod",
            "folder_parent_id": "f1",
            "resource_type_id": "t1"
        }))
    }

    #[rstest]
    #[case::id("id", "r1")]
    #[case::name("name", "GitHub")]
    #[case::username("username", "ada")]
    #[case::uri("uri", "https://github.com")]
    #[case::description("description", "prod")]
    #[case::folder_parent_id("folder_parent_id", "f1")]
    #[case::resource_type_id("resource_type_id", "t1")]
    fn test_resource_fields(#[case] field: &str, #[case] expected: &str) {
        assert_eq!(resource_fields(&github())[field], expected);
    }

    #[rstest]
    #[case::username("username")]
    #[case::uri("uri")]
    #[case::description("description")]
    #[case::folder_parent_id("folder_parent_id")]
    #[case::resource_type_id("resource_type_id")]
    fn test_resource_fields_missing_value_is_empty(#[case] field: &str) {
        let fields = resource_fields(&resource(json!({ "id": "r2", "name": "Bare" })));

        assert_eq!(fields[field], "");
    }

    #[test]
    fn test_filter_resources_by_field() {
        let bare = resource(json!({ "id": "r2", "name": "Bare" }));
        let filter = Filter::parse("username=ada").unwrap();

        let resources = filter_resources(vec![github(), bare], &[filter]);

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].id, "r1");
    }
}
