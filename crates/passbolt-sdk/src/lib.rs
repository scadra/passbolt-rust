//! Passbolt SDK — Rust library for the Passbolt API.
//!
//! This crate provides a type-safe, async Passbolt API client that is generic
//! over the HTTP backend via the [`HttpClient`] trait. For native (desktop/server)
//! usage, enable the `native` feature to get [`NativeHttpClient`] backed by reqwest.
//!
//! # Example
//!
//! ```rust,no_run
//! use passbolt_sdk::{PassboltSdk, SdkConfig, NativeHttpClient, NativeHttpConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let http_cfg = NativeHttpConfig {
//!     tls_skip_verify: false,
//!     client_cert_pem: None,
//!     client_key_pem: None,
//!     proxy_url: None,
//! };
//! let http = NativeHttpClient::new(&http_cfg)?;
//! // let client = PassboltSdk::login(http, &sdk_config, None, 3).await?;
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod comment;
pub mod config;
pub mod crypto;
pub mod error;
pub mod filter;
pub mod folder;
pub mod group;
pub mod http;
pub mod mfa;
pub mod platform;
pub mod pwned;
pub mod resource;
pub mod storage;
pub mod tag;
pub mod types;
pub mod user;

// ── Public re-exports ──────────────────────────────────────────────────────────

pub use client::{FolderQuery, GroupQuery, PassboltSdk, ResourceQuery, UserQuery};
pub use config::SdkConfig;
pub use error::{ApiError, AuthError, CryptoError, PassboltError, TransportError};
pub use folder::tree::{build_folder_tree, collect_subtree_ids, flatten_tree};
pub use http::{HttpClient, HttpResponse};
pub use mfa::MfaProvider;
pub use storage::{MemoryStorage, Storage};
pub use types::{PaginationInfo, PaginationParams};

#[cfg(feature = "native")]
pub use platform::native::{NativeHttpClient, NativeHttpConfig};
