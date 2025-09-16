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

use crate::api::types::User;
use crate::util::filter::{filter_entities, Filter};

pub fn user_fields(u: &User) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("id".into(), u.id.clone());
    m.insert("username".into(), u.username.clone().unwrap_or_default());
    m.insert("first_name".into(), u.first_name().to_string());
    m.insert("last_name".into(), u.last_name().to_string());
    m.insert("role".into(), u.role_name().to_string());
    m
}

pub fn filter_users(users: Vec<User>, filters: &[Filter]) -> Vec<User> {
    filter_entities(users, filters, user_fields)
}
