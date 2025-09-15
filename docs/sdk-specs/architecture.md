# Architecture

## Layered Architecture

The SDK follows a layered architecture with strict dependency rules: each layer may only depend on layers below it.

```
┌─────────────────────────────────────────────────────────┐
│                      Bindings                            │
│  ┌──────────┐  ┌───────────┐  ┌─────┐  ┌────────────┐  │
│  │   WASM   │  │ FFI/UniFFI│  │ CLI │  │  napi-rs   │  │
│  │(wasm-bg) │  │(Swift/Kt) │  │(clap)│  │  (Node)    │  │
│  └────┬─────┘  └─────┬─────┘  └──┬──┘  └─────┬──────┘  │
├───────┼──────────────┼───────────┼────────────┼─────────┤
│       └──────────────┴───────┬───┴────────────┘         │
│                              ▼                           │
│  ┌───────────────────────────────────────────────────┐  │
│  │                    Core Layer                      │  │
│  │  ┌──────┐ ┌────────┐ ┌───────────┐ ┌──────────┐  │  │
│  │  │ Auth │ │ Crypto │ │ Resources │ │ Sharing  │  │  │
│  │  ├──────┤ ├────────┤ ├───────────┤ ├──────────┤  │  │
│  │  │Folder│ │ Users  │ │  Groups   │ │ Metadata │  │  │
│  │  ├──────┤ ├────────┤ ├───────────┤ ├──────────┤  │  │
│  │  │Secret│ │  Tags  │ │ Comments  │ │  RBAC    │  │  │
│  │  └──┬───┘ └───┬────┘ └─────┬─────┘ └────┬────┘  │  │
│  └─────┼─────────┼────────────┼─────────────┼───────┘  │
│        └─────────┴──────┬─────┴─────────────┘          │
│                         ▼                                │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Abstraction Traits                     │  │
│  │  ┌─────────────────┐  ┌──────────────────────┐    │  │
│  │  │    Transport     │  │      Storage          │    │  │
│  │  │  (HTTP client)   │  │  (persistence layer)  │    │  │
│  │  └─────────────────┘  └──────────────────────┘    │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Rust Workspace Structure

```
passbolt-sdk/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── passbolt-core/            # Core business logic (pure Rust)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── auth/             # Auth module
│   │   │   ├── crypto/           # Crypto module (OpenPGP)
│   │   │   ├── resources/        # Resources CRUD
│   │   │   ├── secrets/          # Secret encrypt/decrypt
│   │   │   ├── folders/          # Folders hierarchy
│   │   │   ├── sharing/          # Sharing & permissions
│   │   │   ├── users/            # Users & profiles
│   │   │   ├── groups/           # Groups & members
│   │   │   ├── metadata/         # Metadata encryption
│   │   │   ├── tags/             # Tags
│   │   │   ├── comments/         # Comments
│   │   │   ├── rbac/             # Role-based access control
│   │   │   ├── transport.rs      # Transport trait
│   │   │   ├── storage.rs        # Storage trait
│   │   │   └── error.rs          # Error types
│   │   └── Cargo.toml
│   ├── passbolt-crypto/          # Low-level crypto primitives
│   │   ├── src/
│   │   │   ├── openpgp.rs        # OpenPGP wrapper
│   │   │   ├── keyring.rs        # Key management
│   │   │   └── session_keys.rs   # Session key handling
│   │   └── Cargo.toml
│   ├── passbolt-wasm/            # WASM bindings
│   │   └── Cargo.toml
│   ├── passbolt-ffi/             # FFI bindings (UniFFI)
│   │   └── Cargo.toml
│   ├── passbolt-cli/             # CLI binary
│   │   └── Cargo.toml
│   └── passbolt-napi/            # Node.js native module
│       └── Cargo.toml
└── tests/                        # Integration tests
```

## Transport Trait

The transport layer abstracts HTTP communication, allowing each binding to inject its own HTTP client.

```rust
/// HTTP method enum
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

/// HTTP request representation
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// HTTP response representation
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Transport trait - implemented by each binding
#[async_trait(?Send)]
pub trait Transport: MaybeSend + Sync {
    /// Execute an HTTP request and return the response
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}
```

**Implementations by binding:**
- **WASM**: Bridges to `fetch()` via `wasm-bindgen`
- **Native (CLI/Desktop)**: Uses `reqwest`
- **Mobile FFI**: Bridges to platform HTTP (URLSession on iOS, OkHttp on Android)

The current JS codebase uses `ApiClient` (from `passbolt-styleguide`) which wraps `fetch()`. The Rust `Transport` trait replaces this abstraction.

### Cookie & Session Management

The GPG auth login flow produces a `Set-Cookie` header that must be sent with subsequent requests. Cookie management is the responsibility of the `Transport` implementation, not the core SDK:

- **Native (`reqwest`)**: Use `reqwest::Client` with its built-in cookie jar (`cookie_store(true)`). The jar automatically captures `Set-Cookie` and sends cookies on subsequent requests.
- **WASM (`fetch`)**: Use `credentials: 'include'` on fetch requests. The browser manages cookies automatically. The SDK does not need to store or forward cookies.
- **Mobile FFI**: Platform HTTP clients (URLSession, OkHttp) handle cookies natively via their session/cookie jar APIs.

The core SDK never reads, stores, or manipulates cookies directly. The `Transport` trait's `send()` method is expected to handle cookie persistence transparently.

### Timeout & Retry Strategy

Timeout and retry are **not** part of the core `Transport::send()` signature. They are the responsibility of each `Transport` implementation, because optimal behavior varies by platform:

- **Native (`reqwest`)**: Configure timeout via `reqwest::ClientBuilder::timeout(Duration::from_secs(30))`. Retry with exponential backoff using `reqwest-retry` or manual logic.
- **WASM (`fetch`)**: Use `AbortController` with `setTimeout` for timeout. Browser fetch does not support retry natively; implement in the WASM binding layer.
- **Mobile FFI**: Platform HTTP clients (URLSession, OkHttp) have built-in timeout and retry configuration.

The SDK provides a `RequestOptions` struct that callers can pass through to influence transport behavior, but implementations may ignore unsupported options:

```rust
/// Optional request configuration hints for Transport implementations.
/// Implementations should respect these when possible, but may fall back
/// to their defaults if a specific option is not supported.
pub struct RequestOptions {
    /// Request timeout. Default: 30 seconds.
    pub timeout: Option<Duration>,
    /// Retry policy. Default: None (no retry).
    pub retry_policy: RetryPolicy,
}

pub enum RetryPolicy {
    /// No retry on failure
    None,
    /// Exponential backoff with configurable max retries and base delay
    ExponentialBackoff { max_retries: u32, base_delay: Duration },
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(30)),
            retry_policy: RetryPolicy::None,
        }
    }
}
```

Core SDK methods that need custom timeout/retry (e.g., keep-alive, bulk operations) pass `RequestOptions` to the transport. The transport implementation is free to merge these with its own defaults.

**Design rationale**: Embedding timeout/retry in the trait signature would force all implementations to handle `Duration` and retry logic uniformly, which is impractical across WASM (no `std::time::Instant`), native, and mobile targets. Delegating to implementations keeps the trait minimal and platform-appropriate.

## Storage Trait

The storage layer abstracts persistence, allowing each binding to use its platform-appropriate storage.

**Canonical key type**: `&str` (borrowed). FFI bindings that require owned `String` keys convert at the binding boundary, not in the core trait.

```rust
/// Storage trait - implemented by each binding
/// Keys are borrowed &str in the canonical API. FFI bindings convert at the boundary.
#[async_trait(?Send)]
pub trait Storage: MaybeSend + Sync {
    /// Get a value by key
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;

    /// Set a value by key
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Remove a value by key
    async fn remove(&self, key: &str) -> Result<(), StorageError>;

    /// Remove all values
    async fn clear(&self) -> Result<(), StorageError>;
}
```

**Implementations by binding:**
- **WASM/Browser**: Bridges to `browser.storage.local` or IndexedDB
- **Native (CLI/Desktop)**: SQLite via `rusqlite`
- **Mobile**: SQLite + Keychain/Keystore for secrets
- **In-memory**: For testing and stateless operations

The current JS codebase uses `browser.storage.local` (30+ files in `service/local_storage/`) and a keyring-specific `sdk/storage.js`. The Rust `Storage` trait unifies these.

## Crypto Dependencies

### OpenPGP Library Choice

| Criteria | `sequoia-openpgp` | `rpgp` |
|----------|-------------------|--------|
| WASM support | Partial (heavy deps) | Good (pure Rust) |
| RFC compliance | Excellent (full RFC 4880) | Good |
| Community | Large (Sequoia project) | Smaller |
| API ergonomics | Complex but powerful | Simpler |
| Binary size | Larger | Smaller |

**Recommendation**: Start with `rpgp` for better WASM compatibility and smaller binary size. It covers all operations used by Passbolt (encrypt, decrypt, sign, verify, key generation). Fall back to `sequoia-openpgp` if `rpgp` lacks needed features.

The current JS codebase uses `openpgp.js` (v5+) for all PGP operations.

### Other Crypto Dependencies

- **Password hashing**: `argon2` or `bcrypt` crates (for passphrase-derived operations)
- **Random**: `getrandom` with WASM feature flag
- **Base64**: `base64` crate
- **UUID**: `uuid` crate with v4 feature

## Error Strategy

Each module defines its own error enum using `thiserror`:

### Foundation Error Types

These error types are used by `#[from]` in every module's error enum. They must be defined in the core crate.

```rust
use thiserror::Error;

/// Errors from the HTTP transport layer
#[derive(Error, Debug)]
pub enum TransportError {
    /// HTTP error with status code and response body
    #[error("HTTP {status}: {body}")]
    HttpError { status: u16, body: String },
    /// Network-level error (DNS, connection refused, etc.)
    #[error("Network error: {0}")]
    NetworkError(String),
    /// Request timed out
    #[error("Request timed out")]
    Timeout,
    /// Response could not be parsed (invalid JSON, unexpected format)
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    /// 401 Unauthorized - session expired or not authenticated
    #[error("Unauthorized")]
    Unauthorized,
    /// 403 Forbidden - authenticated but insufficient permissions
    #[error("Forbidden")]
    Forbidden,
    /// 404 Not Found
    #[error("Not found")]
    NotFound,
}

/// Errors from the storage layer
#[derive(Error, Debug)]
pub enum StorageError {
    /// Failed to read from storage
    #[error("Read failed: {0}")]
    ReadFailed(String),
    /// Failed to write to storage
    #[error("Write failed: {0}")]
    WriteFailed(String),
    /// Key not found in storage
    #[error("Key not found: {key}")]
    NotFound { key: String },
    /// Failed to serialize/deserialize data
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
}
```

### Module Error Types

```rust
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Server verification failed: {0}")]
    ServerVerificationFailed(String),
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Session expired")]
    SessionExpired,
    #[error("MFA required: {provider}")]
    MfaRequired { provider: String },
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key not found: {fingerprint}")]
    KeyNotFound { fingerprint: String },
    // ...
}
```

A top-level `SdkError` enum aggregates all module errors for the public API:

```rust
#[derive(Error, Debug)]
pub enum SdkError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Resource(#[from] ResourceError),
    // ... one variant per module
}
```

## Pagination Strategy

All list endpoints that may return large collections use a common pagination pattern:

```rust
/// Common pagination parameters for list operations
pub struct PaginationParams {
    /// Page number (1-based). None means fetch all.
    pub page: Option<u32>,
    /// Number of items per page. Default depends on endpoint (typically 500 for resources, 100 for others).
    pub limit: Option<u32>,
}

/// Paginated response wrapper
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub pagination: PaginationInfo,
}

pub struct PaginationInfo {
    pub count: u32,
    pub page: u32,
    pub limit: u32,
}
```

**Pagination behavior:**
- Server default limit varies by endpoint; the SDK always requests explicit limits for predictability
- Local storage caches store the full dataset (fetched via repeated paginated requests if needed)
- `find_all` / `find` methods accept `PaginationParams`; when `None`, they auto-paginate to fetch all pages
- The API returns pagination info in the response body `header` field

**Endpoints supporting pagination:**
- `GET /resources.json`
- `GET /users.json`
- `GET /groups.json`
- `GET /folders.json`
- `GET /tags.json`
- `GET /comments/resource/<id>.json`
- `GET /gpgkeys.json`

## Passphrase Management

The user's passphrase is needed for many operations (decryption, signing, sharing). The SDK provides a structured approach to passphrase lifecycle.

```rust
/// Passphrase storage duration policy
pub enum PassphrasePolicy {
    /// Keep in memory until explicit logout
    UntilLogout,
    /// Keep for a specified duration, then zeroize
    Duration(std::time::Duration),
    /// Never store - caller must provide for each operation
    NeverStore,
}

/// Internal passphrase cache (not exposed to bindings)
struct PassphraseCache {
    passphrase: Option<Secret<String>>,  // Wrapped in `secrecy::Secret`
    policy: PassphrasePolicy,
    stored_at: Option<Instant>,
}
```

**Security guarantees:**
- Passphrases are wrapped in `secrecy::Secret<String>` which implements `Zeroize` on drop
- When `Duration` policy is used, a background check zeroizes expired passphrases
- The passphrase is never logged, serialized, or transmitted outside the SDK
- WASM binding: passphrase is copied into WASM linear memory and zeroized there; the JS string cannot be zeroized (JS limitation documented for consumers)
- FFI binding: passphrase is copied from the foreign string immediately and the SDK does not retain references to the foreign memory

**Usage pattern:**
- `sdk.auth().login(params)` caches the passphrase per the configured policy
- Operations that need the passphrase check the cache first; if expired/absent, return `PassphraseRequired` error
- `sdk.auth().logout()` immediately zeroizes the cached passphrase

## Async Model

The SDK uses async/await throughout. The async model differs by binding target:

### Native (CLI, Desktop, Mobile FFI)
- Runtime: `tokio` (multi-threaded)
- All traits require `Send + Sync` bounds
- Futures are `Send`

### WASM (Browser Extension)
- Runtime: `wasm-bindgen-futures` (single-threaded)
- Traits use `?Send` bound (WASM is single-threaded, `Send` not available)
- No `tokio` dependency in WASM builds

### Composition Strategy

```rust
// The core library uses conditional compilation for Send bounds:

#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

// Transport and Storage traits use MaybeSend:
#[async_trait(?Send)]
pub trait Transport: MaybeSend + Sync {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[async_trait(?Send)]
pub trait Storage: MaybeSend + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), StorageError>;
    async fn remove(&self, key: &str) -> Result<(), StorageError>;
    async fn clear(&self) -> Result<(), StorageError>;
}
```

**Key design decisions:**
- `?Send` on `async_trait` lets the same trait definition work on both WASM and native
- `MaybeSend` conditional trait keeps the core crate platform-agnostic
- Binding crates add the concrete runtime: `tokio` for native, `wasm-bindgen-futures` for WASM
- Concurrency primitives: use `futures::lock::Mutex` (not `tokio::sync::Mutex`) in core for WASM compatibility

## Concurrency & Caching

### Local Storage Concurrency

The current JS extension uses `navigator.locks` for concurrent cache access. The Rust SDK replaces this with:

```rust
/// Cache manager with locking per storage key
pub struct CacheManager<S: Storage> {
    storage: Arc<S>,
    locks: DashMap<String, Arc<futures::lock::Mutex<()>>>,
}
```

- Each storage key has its own async mutex
- Read-modify-write operations on caches are atomic within a single SDK instance
- Cross-process locking (e.g., multiple browser tabs) relies on the Storage implementation (browser.storage.local handles this natively)

**WASM compatibility note:** `DashMap` requires `Send` bounds and is not compatible with WASM's single-threaded model. Use conditional compilation:
```rust
#[cfg(not(target_arch = "wasm32"))]
type LockMap = DashMap<String, Arc<futures::lock::Mutex<()>>>;

#[cfg(target_arch = "wasm32")]
type LockMap = RefCell<HashMap<String, Rc<futures::lock::Mutex<()>>>>;
```

## Configuration

The SDK is configured via a builder pattern:

```rust
/// Server configuration for connecting to a Passbolt instance
pub struct ServerConfig {
    /// The base URL of the Passbolt server (e.g., "https://passbolt.example.com")
    pub domain: String,
    /// The fingerprint of the server's GPG public key (used for server verification)
    pub server_public_key_fingerprint: String,
}

let sdk = PassboltSdk::builder()
    .server_url("https://passbolt.example.com")
    .transport(my_transport)
    .storage(my_storage)
    .build()?;
```

This replaces the current JS config system (`config/config.json` + `SiteSettings`).

## Storage Keys

All local storage keys used by the SDK are defined as constants for consistency:

```rust
pub mod storage_keys {
    pub const RESOURCES: &str = "passbolt-resources";
    pub const FOLDERS: &str = "passbolt-folders";
    pub const USERS: &str = "passbolt-users";
    pub const GROUPS: &str = "passbolt-groups";
    pub const PUBLIC_GPGKEYS: &str = "passbolt-public-gpgkeys";
    pub const PRIVATE_GPGKEYS: &str = "passbolt-private-gpgkeys";
    pub const AUTH_STATUS: &str = "passbolt-auth-status";
    pub const RESOURCE_TYPES: &str = "passbolt-resource-types";
    pub const TAGS: &str = "passbolt-tags";
    pub const METADATA_KEYS: &str = "passbolt-metadata-keys";
}
```

## API Error Response Format

When the Passbolt server returns an error (4xx/5xx), it uses a standard JSON envelope:

```rust
/// Standard Passbolt API error response
pub struct ApiErrorResponse {
    pub header: ApiResponseHeader,
    pub body: serde_json::Value,
}

pub struct ApiResponseHeader {
    /// Request tracking ID
    pub id: String,
    /// "error" or "success"
    pub status: String,
    /// Human-readable error message
    pub message: String,
    /// HTTP status code
    pub code: u16,
}
```

Example error response:
```json
{
  "header": {
    "id": "a1b2c3d4-...",
    "status": "error",
    "message": "Could not validate resource data.",
    "code": 400
  },
  "body": {
    "name": { "_empty": "The name should not be empty." }
  }
}
```

The `body` field contains field-level validation errors when applicable. The SDK should parse this to provide structured error information to callers.

## CSRF Token Usage

The SDK must send a `X-CSRF-Token` header on all mutative requests (POST, PUT, DELETE) to prevent cross-site request forgery:

- The CSRF token is obtained after login via `get_csrf_token()` (calls `GET /users/me.json` or is returned as part of session setup)
- The token is stored in the `Session` struct and attached to every mutative HTTP request
- Read-only requests (GET) do not require the CSRF token
- On session expiry (401 response), the CSRF token is invalidated along with the session
