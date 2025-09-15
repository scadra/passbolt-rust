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
