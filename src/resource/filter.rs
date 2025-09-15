use std::collections::HashMap;

use crate::api::types::Resource;
use crate::util::filter::{filter_entities, Filter};

pub fn resource_fields(r: &Resource) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("id".into(), r.id.clone());
    m.insert("name".into(), r.name.clone());
    m.insert("username".into(), r.username.clone().unwrap_or_default());
    m.insert("uri".into(), r.uri.clone().unwrap_or_default());
    m.insert(
        "description".into(),
        r.description.clone().unwrap_or_default(),
    );
    m.insert(
        "folder_parent_id".into(),
        r.folder_parent_id.clone().unwrap_or_default(),
    );
    m.insert(
        "resource_type_id".into(),
        r.resource_type_id.clone().unwrap_or_default(),
    );
    m
}

pub fn filter_resources(resources: Vec<Resource>, filters: &[Filter]) -> Vec<Resource> {
    filter_entities(resources, filters, resource_fields)
}
