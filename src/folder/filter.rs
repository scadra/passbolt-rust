use std::collections::HashMap;

use crate::api::types::Folder;
use crate::util::filter::{filter_entities, Filter};

pub fn folder_fields(f: &Folder) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("id".into(), f.id.clone());
    m.insert("name".into(), f.name.clone());
    m.insert(
        "folder_parent_id".into(),
        f.folder_parent_id.clone().unwrap_or_default(),
    );
    m
}

pub fn filter_folders(folders: Vec<Folder>, filters: &[Filter]) -> Vec<Folder> {
    filter_entities(folders, filters, folder_fields)
}
