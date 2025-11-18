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

use crate::filter::{filter_entities, Filter};
use crate::resource::view::ResourceView;

/// The resources whose decrypted fields match every filter.
pub fn filter_resources(resources: Vec<ResourceView>, filters: &[Filter]) -> Vec<ResourceView> {
    filter_entities(resources, filters, ResourceView::fields)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;
    use crate::types::Resource;

    fn view(value: serde_json::Value) -> ResourceView {
        let resource: Resource = serde_json::from_value(value).unwrap();
        ResourceView::new(resource, None, &[]).unwrap()
    }

    fn github() -> ResourceView {
        view(json!({
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
        assert_eq!(github().fields()[field], expected);
    }

    #[rstest]
    #[case::username("username")]
    #[case::uri("uri")]
    #[case::description("description")]
    #[case::folder_parent_id("folder_parent_id")]
    #[case::resource_type_id("resource_type_id")]
    #[case::password("password")]
    fn test_resource_fields_missing_value_is_empty(#[case] field: &str) {
        let fields = view(json!({ "id": "r2", "name": "Bare" })).fields();

        assert_eq!(fields[field], "");
    }

    #[test]
    fn test_filter_resources_by_field() {
        let bare = view(json!({ "id": "r2", "name": "Bare" }));
        let filter = Filter::parse("username=ada").unwrap();

        let resources = filter_resources(vec![github(), bare], &[filter]);

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].id, "r1");
    }
}
