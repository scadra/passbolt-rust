use crate::client::PassboltSdk;
use crate::error::PassboltError;
use crate::http::HttpClient;
use crate::types::{CreateFolderPayload, Folder};

pub async fn create_folder<H: HttpClient>(
    client: &PassboltSdk<H>,
    name: &str,
    folder_parent_id: Option<&str>,
) -> Result<Folder, PassboltError> {
    let payload = CreateFolderPayload {
        name: name.to_string(),
        folder_parent_id: folder_parent_id.map(String::from),
    };
    client.create_folder(&payload).await
}
