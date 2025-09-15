use std::collections::HashMap;

use crate::filter::{filter_entities, Filter};
use crate::types::User;

#[must_use]
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
