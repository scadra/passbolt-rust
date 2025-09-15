use crate::api::client::PassboltClient;
use crate::config::Config;
use anyhow::Result;

/// Build a client from the loaded config, performing login.
pub async fn get_client(cfg: &Config) -> Result<PassboltClient> {
    PassboltClient::login(cfg).await
}
