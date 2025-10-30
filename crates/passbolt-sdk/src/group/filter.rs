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
use crate::types::Group;

#[must_use]
pub fn group_fields(group: &Group) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    fields.insert("id".into(), group.id.clone());
    fields.insert("name".into(), group.name.clone());
    fields
}

pub fn filter_groups(groups: Vec<Group>, filters: &[Filter]) -> Vec<Group> {
    filter_entities(groups, filters, group_fields)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn group(id: &str, name: &str) -> Group {
        serde_json::from_value(json!({ "id": id, "name": name })).unwrap()
    }

    #[rstest]
    #[case::id("id", "g1")]
    #[case::name("name", "Ops")]
    fn test_group_fields(#[case] field: &str, #[case] expected: &str) {
        assert_eq!(group_fields(&group("g1", "Ops"))[field], expected);
    }

    #[test]
    fn test_filter_groups_by_name() {
        let filter = Filter::parse("name^=op").unwrap();

        let groups = filter_groups(vec![group("g1", "Ops"), group("g2", "Dev")], &[filter]);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, "g1");
    }
}
