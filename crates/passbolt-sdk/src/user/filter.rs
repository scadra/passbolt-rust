// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn user(value: serde_json::Value) -> User {
        serde_json::from_value(value).unwrap()
    }

    fn ada() -> User {
        user(json!({
            "id": "u1",
            "username": "ada@passbolt.test",
            "profile": { "first_name": "Ada", "last_name": "Lovelace" },
            "role": { "name": "admin" }
        }))
    }

    #[rstest]
    #[case::id("id", "u1")]
    #[case::username("username", "ada@passbolt.test")]
    #[case::first_name("first_name", "Ada")]
    #[case::last_name("last_name", "Lovelace")]
    #[case::role("role", "admin")]
    fn test_user_fields(#[case] field: &str, #[case] expected: &str) {
        assert_eq!(user_fields(&ada())[field], expected);
    }

    #[rstest]
    #[case::username("username")]
    #[case::first_name("first_name")]
    #[case::last_name("last_name")]
    #[case::role("role")]
    fn test_user_fields_missing_value_is_empty(#[case] field: &str) {
        assert_eq!(user_fields(&user(json!({ "id": "u2" })))[field], "");
    }

    #[test]
    fn test_filter_users_by_role() {
        let filter = Filter::parse("role=admin").unwrap();

        let users = filter_users(vec![ada(), user(json!({ "id": "u2" }))], &[filter]);

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, "u1");
    }
}
