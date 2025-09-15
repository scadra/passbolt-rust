use anyhow::Result;

use crate::client::{FolderQuery, PassboltSdk};
use crate::filter::Filter;
use crate::folder::filter::filter_folders;
use crate::http::HttpClient;
use crate::types::Folder;

pub async fn list_folders<H: HttpClient>(
    client: &PassboltSdk<H>,
    search: Option<String>,
    group_ids: Vec<String>,
    parent_folder_ids: Vec<String>,
    filters: &[Filter],
) -> Result<Vec<Folder>> {
    let query = FolderQuery {
        search,
        group_id: group_ids.first().cloned(),
        parent_folder_id: parent_folder_ids.first().cloned(),
        ..Default::default()
    };
    let mut folders = client.get_folders(query).await?;

    // Client-side filter for additional parent folder IDs (API only supports one at a time)
    if parent_folder_ids.len() > 1 {
        folders.retain(|f| {
            f.folder_parent_id
                .as_deref()
                .is_some_and(|pid| parent_folder_ids.iter().any(|id| id == pid))
        });
    }

    Ok(filter_folders(folders, filters))
}
