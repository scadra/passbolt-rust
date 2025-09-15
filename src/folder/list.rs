use crate::api::client::{FolderQuery, PassboltClient};
use crate::api::types::Folder;
use crate::folder::filter::filter_folders;
use crate::util::filter::Filter;
use anyhow::Result;

pub async fn list_folders(
    client: &PassboltClient,
    search: Option<String>,
    group_ids: Vec<String>,
    parent_folder_ids: Vec<String>,
    filters: &[Filter],
) -> Result<Vec<Folder>> {
    let query = FolderQuery {
        search,
        group_id: group_ids.first().cloned(),
        parent_folder_id: parent_folder_ids.first().cloned(),
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
