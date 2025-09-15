# Bindings Strategy

## Overview

The Rust SDK exposes its functionality through multiple binding layers, each tailored to a specific target platform. The core logic is identical across all bindings; only the Transport and Storage implementations differ.

## WASM Binding (Browser Extension, Web Apps)

### Technology

- **`wasm-bindgen`** + **`wasm-pack`** for Rust→WASM compilation
- **`wasm-bindgen-futures`** for async/await interop with JS Promises
- **`serde-wasm-bindgen`** for data serialization between Rust and JS

### Architecture

```
┌──────────────────────────────────┐
│  Browser Extension (JS/TS)       │
│  ┌────────────────────────────┐  │
│  │  SDK WASM Module            │  │
│  │  (passbolt_sdk_wasm.wasm)   │  │
│  │  ┌──────────────────────┐  │  │
│  │  │  Core (Rust)          │  │  │
│  │  │  Auth, Crypto, CRUD   │  │  │
│  │  └──────────┬───────────┘  │  │
│  │             │              │  │
│  │  ┌──────────┴───────────┐  │  │
│  │  │  Transport: fetch()   │  │  │
│  │  │  Storage: browser.*   │  │  │
│  │  └──────────────────────┘  │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

### Transport Implementation

The WASM transport bridges to the browser's `fetch()` API:

```rust
// Rust side (WASM)
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = "fetch")]
    async fn js_fetch(url: &str, options: &JsValue) -> JsValue;
}

pub struct WasmTransport {
    base_url: String,
    csrf_token: Option<String>,
}

#[async_trait(?Send)]  // ?Send for WASM (single-threaded)
impl Transport for WasmTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        // Bridge to JS fetch()
    }
}
```

Note: WASM is single-threaded, so `Send` is not required. The `?Send` bound handles this.

### Storage Implementation

Bridges to `browser.storage.local` (WebExtension API):

```rust
pub struct BrowserStorageTransport { /* ... */ }

#[async_trait(?Send)]
impl Storage for BrowserStorageTransport {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        // Bridge to browser.storage.local.get()
    }
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        // Bridge to browser.storage.local.set()
    }
    // ...
}
```

### Integration with Browser Extension

Two integration strategies:

1. **Import map / ES module**: Load the WASM module as an ES module via `import`
2. **Bundler (webpack)**: Use `wasm-pack` with webpack plugin for bundling

The migration path:
1. SDK WASM is loaded alongside existing JS code
2. Individual features are migrated from JS to SDK calls
3. Eventually, all business logic runs through the SDK

### Binary Size Considerations

Target WASM binary size: < 2 MB (gzipped < 500 KB)

Strategies:
- Use `wasm-opt` for size optimization
- Enable LTO (Link Time Optimization)
- Use `rpgp` over `sequoia` (smaller footprint)
- Feature flags to exclude unused modules

## FFI Binding (Mobile: iOS/Android)

### Technology

- **`uniffi`** (Mozilla) for automatic Swift and Kotlin binding generation
- UniFFI uses a UDL (Interface Definition Language) or proc-macros to define the API surface
- Generates: Swift package, Kotlin package, Python bindings

### Architecture

```
┌────────────────────┐  ┌─────────────────────┐
│  iOS App (Swift)    │  │  Android App (Kotlin)│
│  ┌──────────────┐  │  │  ┌──────────────┐   │
│  │ Swift Bindings│  │  │  │Kotlin Bindings│   │
│  │ (generated)   │  │  │  │ (generated)   │   │
│  └──────┬───────┘  │  │  └──────┬───────┘   │
│         │          │  │         │            │
│  ┌──────┴───────┐  │  │  ┌──────┴───────┐   │
│  │ libpassbolt   │  │  │  │ libpassbolt   │   │
│  │ (.dylib/.a)   │  │  │  │ (.so)         │   │
│  │              │  │  │  │              │   │
│  │ Transport:   │  │  │  │ Transport:   │   │
│  │  URLSession   │  │  │  │  OkHttp       │   │
│  │ Storage:     │  │  │  │ Storage:     │   │
│  │  Keychain+SQL │  │  │  │  Keystore+SQL │   │
│  └──────────────┘  │  │  └──────────────┘   │
└────────────────────┘  └─────────────────────┘
```

### Transport Implementation

Mobile apps inject their platform HTTP client:

```rust
// UniFFI interface
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait MobileTransport: Send + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}
```

Swift/Kotlin implement this trait using URLSession/OkHttp respectively.

### Storage Implementation

```rust
// UniFFI foreign trait uses owned String keys (UniFFI limitation).
// The FFI layer converts to &str at the boundary before calling into core.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait MobileStorage: Send + Sync {
    async fn get(&self, key: String) -> Result<Option<Vec<u8>>, StorageError>;
    async fn set(&self, key: String, value: Vec<u8>) -> Result<(), StorageError>;
    async fn remove(&self, key: String) -> Result<(), StorageError>;
    async fn clear(&self) -> Result<(), StorageError>;
}

// Bridge adapter that implements the core Storage trait (&str keys)
// by delegating to MobileStorage (String keys)
struct MobileStorageAdapter {
    inner: Arc<dyn MobileStorage>,
}

#[async_trait]
impl Storage for MobileStorageAdapter {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(key.to_owned()).await
    }
    // ... same pattern for set, remove, clear
}
```

Mobile implements this using:
- **iOS**: Keychain for secrets, UserDefaults or SQLite for non-secret data
- **Android**: Keystore for secrets, EncryptedSharedPreferences or SQLite for non-secret data

### Build Process

```bash
# Build for iOS (aarch64)
cargo build --target aarch64-apple-ios --release -p passbolt-ffi
uniffi-bindgen generate --language swift --out-dir swift-bindings

# Build for Android (multiple architectures)
cargo ndk --target aarch64-linux-android --target armv7-linux-androideabi \
    build --release -p passbolt-ffi
uniffi-bindgen generate --language kotlin --out-dir kotlin-bindings
```

## CLI Binding

### Technology

- Native Rust binary using **`clap`** for argument parsing
- **`reqwest`** for HTTP
- **`rusqlite`** for local storage
- **`rpassword`** for secure passphrase input
- **`indicatif`** for progress bars

### Architecture

```
┌────────────────────────────────┐
│  passbolt-cli                   │
│  ┌──────────────────────────┐  │
│  │  CLI Layer (clap)         │  │
│  │  Commands & subcommands   │  │
│  └──────────┬───────────────┘  │
│             │                  │
│  ┌──────────┴───────────────┐  │
│  │  Core (Rust)              │  │
│  │  Transport: reqwest       │  │
│  │  Storage: rusqlite        │  │
│  └──────────────────────────┘  │
└────────────────────────────────┘
```

### CLI Commands (example)

```bash
# Auth
passbolt login --server https://passbolt.example.com
passbolt logout
passbolt status

# Resources
passbolt resources list [--folder <id>] [--search <term>]
passbolt resources get <id> [--secret]
passbolt resources create --name "Title" --uri "https://..." --password
passbolt resources update <id> --name "New Title"
passbolt resources delete <id>

# Folders
passbolt folders list
passbolt folders create --name "My Folder" [--parent <id>]

# Sharing
passbolt share <resource_id> --user <email> --permission owner

# Export
passbolt export --format kdbx --output passwords.kdbx
```

### Configuration

CLI config stored in `~/.config/passbolt-cli/`:
- `config.toml`: Server URL, user fingerprint
- `session.db`: SQLite database for cached data and session

## n8n Binding (Node.js)

### Technology

Two options:

#### Option A: WASM in Node.js
- Same WASM module as browser extension
- Loaded via Node.js WASM support
- Transport: Node.js `fetch` or `node-fetch`
- Storage: In-memory or file-based

#### Option B: Native Node.js Module via `napi-rs`
- **`napi-rs`** for native Node.js addon
- Better performance than WASM
- Transport: `reqwest` (native)
- Storage: SQLite or in-memory

### Recommendation: `napi-rs`

For n8n server-side usage, a native module provides better performance and simpler async handling.

```rust
// napi-rs interface
#[napi]
pub struct PassboltSdk {
    inner: Arc<SdkCore<ReqwestTransport, MemoryStorage>>,
}

#[napi]
impl PassboltSdk {
    #[napi(constructor)]
    pub fn new(server_url: String) -> Self { /* ... */ }

    #[napi]
    pub async fn login(&self, fingerprint: String, private_key: String, passphrase: String) -> Result<()> { /* ... */ }

    #[napi]
    pub async fn get_resources(&self) -> Result<Vec<Resource>> { /* ... */ }
}
```

## Transport & Storage Per Binding Summary

| Binding | Transport | Storage | Async Runtime |
|---------|-----------|---------|---------------|
| WASM (browser) | JS `fetch()` bridge | `browser.storage.local` bridge | `wasm-bindgen-futures` |
| FFI (iOS) | URLSession (Swift callback) | Keychain + SQLite | `tokio` |
| FFI (Android) | OkHttp (Kotlin callback) | Keystore + SQLite | `tokio` |
| CLI | `reqwest` | `rusqlite` | `tokio` |
| n8n (napi-rs) | `reqwest` | In-memory / file | `tokio` |

## Shared Concerns

### Error Mapping

Each binding maps `SdkError` to the platform's error model:
- **WASM**: JS Error objects with custom `name` and `message`
- **UniFFI**: Swift `Error` / Kotlin `Exception`
- **CLI**: Exit codes + stderr messages
- **napi-rs**: Node.js Error objects

### Serialization

- **WASM**: `serde-wasm-bindgen` for JS ↔ Rust
- **UniFFI**: Automatic via UDL/proc-macro
- **CLI**: `serde_json` for output formatting
- **napi-rs**: `napi-derive` for JS ↔ Rust

## Distribution Strategy

| Binding | Package Format | Registry | Versioning |
|---------|---------------|----------|------------|
| WASM | npm package (`@passbolt/sdk-wasm`) | npm (private or public) | Follows SDK semver |
| FFI iOS | XCFramework + Swift Package | Swift Package Registry / GitHub releases | Follows SDK semver |
| FFI Android | AAR + Maven artifact | Maven Central or GitHub Packages | Follows SDK semver |
| CLI | Binary releases | GitHub Releases, Homebrew tap, crates.io | Follows SDK semver |
| napi-rs | npm package (`@passbolt/sdk-native`) | npm | Follows SDK semver |
| Core crate | Rust library | crates.io (if public) | Follows SDK semver |
