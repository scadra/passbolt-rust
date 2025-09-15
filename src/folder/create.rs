use crate::api::client::PassboltClient;
use crate::api::types::{CreateFolderPayload, Folder};
use anyhow::Result;

pub async fn create_folder(
    client: &PassboltClient,
    name: &str,
    folder_parent_id: Option<&str>,
) -> Result<Folder> {
    let payload = CreateFolderPayload {
        name: name.to_string(),
        folder_parent_id: folder_parent_id.map(String::from),
    };
    client.create_folder(&payload).await
}
