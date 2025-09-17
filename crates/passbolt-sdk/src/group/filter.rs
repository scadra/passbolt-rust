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
pub fn group_fields(g: &Group) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("id".into(), g.id.clone());
    m.insert("name".into(), g.name.clone());
    m
}

pub fn filter_groups(groups: Vec<Group>, filters: &[Filter]) -> Vec<Group> {
    filter_entities(groups, filters, group_fields)
}
