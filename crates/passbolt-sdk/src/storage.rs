use crate::error::PassboltError;

/// Async storage backend abstraction for caching SDK data.
///
/// Implementations can target different platforms:
/// - Native: filesystem or `SQLite`
/// - WASM: `browser.storage.local`
/// - Testing: in-memory `HashMap`
///
/// All keys are namespaced strings (e.g. `"resources"`, `"folders"`, `"metadata_keys"`).
#[allow(async_fn_in_trait)]
pub trait Storage: Send + Sync {
    /// Retrieve a cached value by key. Returns `None` if the key doesn't exist.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PassboltError>;

    /// Store a value under the given key, overwriting any previous value.
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), PassboltError>;

    /// Remove a cached value by key. No-op if the key doesn't exist.
    async fn remove(&self, key: &str) -> Result<(), PassboltError>;

    /// Remove all cached values.
    async fn clear(&self) -> Result<(), PassboltError>;
}

/// In-memory storage backend for testing.
///
/// Uses `std::sync::RwLock` so it compiles on all targets (native + WASM).
#[derive(Debug, Default)]
pub struct MemoryStorage {
    data: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, PassboltError> {
        let guard = self
            .data
            .read()
            .map_err(|e| PassboltError::Other(format!("Storage lock poisoned: {e}")))?;
        Ok(guard.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), PassboltError> {
        self.data
            .write()
            .map_err(|e| PassboltError::Other(format!("Storage lock poisoned: {e}")))?
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<(), PassboltError> {
        self.data
            .write()
            .map_err(|e| PassboltError::Other(format!("Storage lock poisoned: {e}")))?
            .remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<(), PassboltError> {
        self.data
            .write()
            .map_err(|e| PassboltError::Other(format!("Storage lock poisoned: {e}")))?
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_storage_roundtrip() {
        let store = MemoryStorage::new();
        assert!(store.get("key").await.unwrap().is_none());

        store.set("key", b"value").await.unwrap();
        assert_eq!(store.get("key").await.unwrap(), Some(b"value".to_vec()));

        store.remove("key").await.unwrap();
        assert!(store.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_clear() {
        let store = MemoryStorage::new();
        store.set("a", b"1").await.unwrap();
        store.set("b", b"2").await.unwrap();

        store.clear().await.unwrap();
        assert!(store.get("a").await.unwrap().is_none());
        assert!(store.get("b").await.unwrap().is_none());
    }
}
