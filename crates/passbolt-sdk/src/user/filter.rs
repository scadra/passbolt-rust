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
use crate::types::User;

#[must_use]
pub fn user_fields(user: &User) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    fields.insert("id".into(), user.id.clone());
    fields.insert("username".into(), user.username.clone().unwrap_or_default());
    fields.insert("first_name".into(), user.first_name().to_string());
    fields.insert("last_name".into(), user.last_name().to_string());
    fields.insert("role".into(), user.role_name().to_string());
    fields
}

pub fn filter_users(users: Vec<User>, filters: &[Filter]) -> Vec<User> {
    filter_entities(users, filters, user_fields)
}
