# Passbolt Universal SDK — Roadmap

## Context

Le CLI Rust `passbolt-rs` (45 fichiers, ~4,500 LOC) contient toute la logique Passbolt (auth GPG, crypto PGP, CRUD, metadata v5) couplée au binaire. L'objectif : extraire un **SDK Rust universel** réutilisable depuis Rust CLI, Node.js (n8n), browser extension (WASM), Python, Java, .NET.

La browser extension Passbolt (JavaScript, 50+ services, openpgpjs) utilise la même surface API avec les mêmes patterns d'auth et crypto — confirmant que le SDK peut servir de source unique.

---

## 1. Analyse de l'existant

### 1.1 Architecture actuelle du CLI

```
src/
  main.rs              # 943 LOC — tokio::main, clap dispatch, output formatting
  cli/                 # clap derive definitions (configure, verify, exec, export, gendoc)
  api/
    client.rs          # 707 LOC — PassboltClient struct + HTTP helpers + tous les endpoints
    auth.rs            # 335 LOC — GPG challenge-response, MFA TOTP, server verify
    crypto.rs          # 180 LOC — PGP encrypt/decrypt via pgp 0.14 (pure Rust)
    types.rs           # 583 LOC — Resource, Folder, User, Group, Permission, payloads
    http.rs            # 49 LOC  — build_client() reqwest builder
  resource/            # 464 LOC — create(77), get(62), list(34), update(133), share(56), filter(29), expiry(73)
  folder/              # 102 LOC — create(15), list(31), share(37), filter(19)
  user/                # 91 LOC  — create(25), list(23), update(25), filter(18)
  group/               # 120 LOC — mod(34), create(19), list(19), update(33), filter(15)
  util/                # 449 LOC — filter(243), output(198), session(8)
  keepass/             # 581 LOC — export.rs
  config.rs            # 250 LOC — Config struct, TOML, env vars
```

### 1.2 Couplages identifies

**PassboltClient** est couple directement a `reqwest::Client` :
- `client.rs:19` — `pub client: Client` (reqwest)
- `auth.rs:3` — `use reqwest::{Client, Response}`
- `http.rs` — `ClientBuilder::new().use_rustls_tls().cookie_store(true)`

**MFA est couple au terminal** :
- `auth.rs:163` — `rpassword::prompt_password("TOTP code: ")` directement dans `handle_mfa_login`

**main.rs accede aux champs prives du client** :
- `main.rs:484` — `Arc::new(client.private_key.key.clone())` pour le decrypt parallele
- `main.rs:485` — `Arc::new(client.passphrase.clone())`

**Config melange CLI et connexion** :
- `config.rs` contient workers, timeout, debug (CLI) ET server_address, passphrase (SDK)

### 1.3 Ce qui est deja SDK-ready (zero couplage CLI)

| Module | LOC | Verdict |
|--------|-----|---------|
| `api/types.rs` | 583 | 100% portable — structs serde pures |
| `api/crypto.rs` | 180 | 100% portable — pgp crate pure Rust, WASM-compatible |
| `resource/*` (sauf main.rs dispatch) | 464 | 100% portable — business logic sans IO |
| `folder/*` | 102 | 100% portable |
| `user/*` | 91 | 100% portable |
| `group/*` | 120 | 100% portable |
| `util/filter.rs` | 243 | 100% portable — generics purs |
| `resource/expiry.rs` | 73 | 100% portable — date parsing |
| **Total extractable tel quel** | **~1,856** | **~41% du code total** |

### 1.4 Ce qui necessite refactoring

| Module | Probleme | Solution |
|--------|----------|----------|
| `api/client.rs` | Couple a `reqwest::Client` | Trait `HttpClient` generique |
| `api/auth.rs` | `rpassword` inline | Trait `MfaProvider` |
| `api/http.rs` | reqwest-only | Impl native du trait `HttpClient` |
| `config.rs` | Mixe CLI + connexion | Split en `SdkConfig` + `CliConfig` |
| `main.rs:469-532` | Acces direct private_key/passphrase | Methode `decrypt_secrets_batch()` sur le client |
| `keepass/export.rs` | `indicatif` progress bars | Trait `ProgressReporter` ou callback |

### 1.5 Endpoints API couverts

**Deja implementes (Tier 1) :**
- Auth : `/auth/login.json`, `/auth/logout.json`, `/auth/verify.json`, `/mfa/verify/totp.json`
- Resources : CRUD + `/secrets/resource/{id}.json` + `/permissions/resource/{id}.json` + `/share/resource/{id}.json` + `/move/resource/{id}.json`
- Folders : CRUD + permissions + share + move
- Users : CRUD + `/users/me.json`
- Groups : CRUD
- Metadata v5 : `/metadata/keys.json`
- Lookup : `/roles.json`, `/resource-types.json`

**Manquants dans le CLI, presents dans la browser extension (Tier 2) :**
- Comments CRUD (`/comments/resource/{id}.json`)
- Tags CRUD (`/tags.json`, `/tags/resource/{id}.json`)
- Favorites (`/favorites/resource/{id}.json`)
- Password Policies (`/password-policies/settings.json`)
- Action Logs (`/actionlog.json`)
- Healthcheck (`/healthcheck.json`)

**Tier 3 (admin/avance) :**
- Account Recovery, SSO, SCIM, Org Settings, MFA Setup, GPG Keys Admin

### 1.6 Analyse WASM

**Compatible tel quel :** pgp 0.14 (pure Rust), serde, serde_json, zeroize, secrecy, chrono, uuid, base64, hex, percent-encoding, totp-rs

**Incompatible WASM :** reqwest (rustls), tokio (full), rpassword, comfy-table, colored, indicatif, directories, config, keepass

**Taille WASM estimee :** ~500-700 KB (pgp RSA = ~400-600 KB), compresse ~250 KB Brotli

**Point critique :** `getrandom = { features = ["js"] }` requis pour `pgp`/`rand` en WASM

### 1.7 Browser extension — surface API partagee

La browser extension JavaScript (50+ services) couvre les memes endpoints avec en plus :
- 45+ fichiers crypto (`service/crypto/`) — openpgpjs (remplacable par pgp WASM)
- Auth GPG challenge-response identique (memes headers X-GPGAuth-*)
- Session cookie-based (le browser gere nativement avec `credentials: 'include'`)
- CSRF token extrait de header/cookie/body (meme triple fallback que `auth.rs:216-241`)

### 1.8 Analyse detaillee des modules business logic

#### Resource modules (464 LOC total)

**resource/create.rs** (77 LOC) — Orchestre la creation avec TOTP :
- Determine le slug resource type (password-description-totp, totp, password-and-description)
- Appelle `get_resource_type_id_by_slug()`, `get_me()`, `encrypt_secret_for_users()`, `create_resource()`
- Zero couplage CLI

**resource/update.rs** (133 LOC) — Le plus complexe :
- Merge intelligent des champs TOTP (preserve les champs non specifies)
- Re-encryption pour tous les users ayant acces : `get_resource_permissions()` -> `encrypt_secret_for_users()`
- Gere `remove_totp` flag
- Zero couplage CLI

**resource/share.rs** (56 LOC) — Share/revoke :
- `permission_type == -1` = signal de revoke
- Revoke : fetch existing perms -> filter par user/group IDs -> mark `delete: true`
- Share : decrypt current secret -> encrypt for new users -> API call
- Zero couplage CLI

**resource/get.rs** (62 LOC) — Fetch + decrypt + TOTP code generation :
- `get_totp_code()` parse les params TOTP et genere un code via `totp_rs`
- Zero couplage CLI

**resource/list.rs** (34 LOC) — List avec search client-side :
- Search case-insensitive sur `name` + generic filters
- Zero couplage CLI

**resource/filter.rs** (29 LOC) — Map fields pour le filter generique
**resource/expiry.rs** (73 LOC) — Parse RFC3339, durations (7d/48h/30m), "none"

#### Folder modules (102 LOC)
- `create.rs` (15 LOC) — wrapper trivial
- `list.rs` (31 LOC) — multi-parent filtering client-side
- `share.rs` (37 LOC) — meme pattern que resource/share sans re-encryption
- `filter.rs` (19 LOC) — map fields

#### User modules (91 LOC)
- `create.rs` (25 LOC) — role name -> ID lookup via `get_role_id_by_name()`
- `list.rs` (23 LOC) — search + filters
- `update.rs` (25 LOC) — partial update profile/role
- `filter.rs` (18 LOC) — map fields

#### Group modules (120 LOC)
- `mod.rs` (34 LOC) — `build_group_members()` helper (dedup managers/members)
- `create.rs` (19 LOC), `list.rs` (19 LOC), `update.rs` (33 LOC), `filter.rs` (15 LOC)

#### Generic filter system (util/filter.rs — 243 LOC)
- `Filter` struct : parse expressions (`name=foo`, `name~=foo`, `name^=foo`, `name$=foo`, `name!=foo`)
- `FilterOp` enum : Eq, NotEq, Contains, StartsWith, EndsWith
- `filter_entities<T, F>()` : generique, AND semantics, case-insensitive
- 15 tests unitaires

#### KeePass export (keepass/export.rs — 581 LOC)
- Parallel decrypt via `JoinSet::spawn_blocking` + `Semaphore`
- BFS folder hierarchy, subtree export
- v5 metadata support (user_key vs shared_key dispatch)
- `KeePassEntry` avec `ZeroizeOnDrop`
- **Seul module avec couplage CLI** (`indicatif` progress bars, `println!`)

---

## 2. Architecture SDK cible

### 2.1 Workspace layout

```
passbolt/
  Cargo.toml                     # [workspace]
  crates/
    passbolt-sdk/                # Lib core, platform-agnostic
      Cargo.toml
      src/
        lib.rs                   # Re-exports publics
        error.rs                 # PassboltError (thiserror, #[non_exhaustive])
        types.rs                 # <- api/types.rs
        crypto.rs                # <- api/crypto.rs
        auth.rs                  # <- api/auth.rs (refactored: MfaProvider trait)
        client.rs                # PassboltSdk<H: HttpClient>
        filter.rs                # <- util/filter.rs
        http.rs                  # HttpClient trait + HttpResponse
        platform/
          mod.rs
          native.rs              # reqwest impl (#[cfg(feature = "native")])
        resource/                # <- resource/*.rs (business logic)
        folder/                  # <- folder/*.rs
        user/                    # <- user/*.rs
        group/                   # <- group/*.rs
    passbolt-cli/                # Bin, thin wrapper
    passbolt-napi/               # napi-rs (Node.js/n8n)
    passbolt-wasm/               # wasm-bindgen (browser extension)
    passbolt-ffi/                # UniFFI (Python, Java, .NET)
```

### 2.2 Abstractions cles

**HttpClient trait** — decouple du transport :
```rust
#[async_trait(?Send)]  // ?Send pour WASM single-thread
pub trait HttpClient {
    async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, PassboltError>;
    async fn post(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse, PassboltError>;
    async fn put(&self, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<HttpResponse, PassboltError>;
    async fn delete(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse, PassboltError>;
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
```

- Native : reqwest + cookie_store + rustls (existant `http.rs` adapte)
- WASM : web-sys fetch + `credentials: 'include'` (cookies browser natifs)
- Le cookie jar est gere par l'impl, pas par le SDK core

**MfaProvider trait** — decouple du terminal :
```rust
#[async_trait(?Send)]
pub trait MfaProvider {
    async fn get_totp_code(&self) -> Result<String, PassboltError>;
}
```

- CLI : `TerminalMfaProvider` (rpassword prompt)
- n8n : `AutoTotpProvider` (genere depuis secret base32)
- Browser : `PopupMfaProvider` (UI JavaScript callback)

**SdkConfig** — params de connexion uniquement :
```rust
pub struct SdkConfig {
    pub server_url: String,
    pub private_key_armored: String,
    pub passphrase: SecretString,
    pub mfa_mode: MfaMode,
    pub tls_skip_verify: bool,
    pub tls_client_cert_pem: Option<Vec<u8>>,
    pub tls_client_key_pem: Option<Vec<u8>>,
    pub proxy_url: Option<String>,
    pub server_verify_fingerprint: Option<String>,
    pub server_verify_token: Option<String>,
}
```

### 2.3 Error handling

```rust
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum PassboltError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("Login failed: {0}")]
    LoginFailed(String),
    #[error("MFA required")]
    MfaRequired,
    #[error("MFA failed after {attempts} attempts: {message}")]
    MfaFailed { attempts: u32, message: String },
    #[error("Server identity mismatch: {0}")]
    ServerIdentityMismatch(String),
    #[error("PGP key parse error: {0}")]
    PgpKeyParse(String),
    #[error("PGP decrypt failed: {0}")]
    PgpDecrypt(String),
    #[error("PGP encrypt failed: {0}")]
    PgpEncrypt(String),
    #[error("Key cross-check failed")]
    KeyCrossCheckFailed,
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("{0}")]
    Other(String),
}
```

- SDK : `Result<T, PassboltError>` partout (zero anyhow)
- CLI : wrap en `anyhow::Result` a la frontiere
- napi-rs : map vers JS Error avec code string (`AUTH_FAILED`, `MFA_REQUIRED`, etc.)

### 2.4 Feature flags

```toml
[features]
default = ["native"]
native = ["dep:reqwest", "dep:tokio"]
wasm = ["dep:web-sys", "dep:wasm-bindgen", "dep:wasm-bindgen-futures", "dep:gloo-net", "dep:getrandom"]
totp = ["dep:totp-rs"]
comments = []
tags = []
favorites = []
full = ["totp", "comments", "tags", "favorites"]
```

### 2.5 API publique du SDK

```rust
impl<H: HttpClient> PassboltSdk<H> {
    // Lifecycle
    pub async fn login(http: H, config: SdkConfig, mfa: Option<&dyn MfaProvider>) -> Result<Self, PassboltError>;
    pub async fn logout(&self) -> Result<(), PassboltError>;
    pub async fn verify_server(http: &H, base_url: &str, key: &PrivateKey, pass: &str) -> Result<ServerIdentity, PassboltError>;

    // Resources (maps to resource/*.rs business logic)
    pub async fn list_resources(&self, query: ResourceQuery) -> Result<Vec<Resource>, PassboltError>;
    pub async fn get_resource(&self, id: &str) -> Result<Resource, PassboltError>;
    pub async fn create_resource(&self, params: CreateResourceParams) -> Result<Resource, PassboltError>;
    pub async fn update_resource(&self, id: &str, params: UpdateResourceParams) -> Result<Resource, PassboltError>;
    pub async fn delete_resource(&self, id: &str) -> Result<(), PassboltError>;
    pub async fn share_resource(&self, id: &str, params: ShareParams) -> Result<(), PassboltError>;
    pub async fn move_resource(&self, id: &str, folder_id: Option<&str>) -> Result<(), PassboltError>;
    pub async fn get_totp_code(&self, id: &str) -> Result<(String, u64), PassboltError>;

    // Secrets
    pub fn decrypt_secret(&self, resource: &Resource) -> Result<SecretData, PassboltError>;  // sync, CPU-only
    pub async fn decrypt_metadata(&self, resource: &Resource) -> Result<Option<ResourceMetadata>, PassboltError>;

    // Folders
    pub async fn list_folders(&self, query: FolderQuery) -> Result<Vec<Folder>, PassboltError>;
    pub async fn get_folder(&self, id: &str) -> Result<Folder, PassboltError>;
    pub async fn create_folder(&self, name: &str, parent_id: Option<&str>) -> Result<Folder, PassboltError>;
    pub async fn update_folder(&self, id: &str, name: &str) -> Result<Folder, PassboltError>;
    pub async fn delete_folder(&self, id: &str) -> Result<(), PassboltError>;
    pub async fn share_folder(&self, id: &str, params: ShareParams) -> Result<(), PassboltError>;
    pub async fn move_folder(&self, id: &str, parent_id: Option<&str>) -> Result<(), PassboltError>;

    // Users
    pub async fn list_users(&self, query: UserQuery) -> Result<Vec<User>, PassboltError>;
    pub async fn get_user(&self, id: &str) -> Result<User, PassboltError>;
    pub async fn get_me(&self) -> Result<User, PassboltError>;
    pub async fn create_user(&self, params: CreateUserParams) -> Result<User, PassboltError>;
    pub async fn update_user(&self, id: &str, params: UpdateUserParams) -> Result<User, PassboltError>;
    pub async fn delete_user(&self, id: &str) -> Result<(), PassboltError>;

    // Groups
    pub async fn list_groups(&self, query: GroupQuery) -> Result<Vec<Group>, PassboltError>;
    pub async fn get_group(&self, id: &str) -> Result<Group, PassboltError>;
    pub async fn create_group(&self, params: CreateGroupParams) -> Result<Group, PassboltError>;
    pub async fn update_group(&self, id: &str, params: UpdateGroupParams) -> Result<Group, PassboltError>;
    pub async fn delete_group(&self, id: &str) -> Result<(), PassboltError>;

    // Lookup helpers
    pub async fn get_role_id_by_name(&self, name: &str) -> Result<String, PassboltError>;
    pub async fn get_resource_type_by_slug(&self, slug: &str) -> Result<Option<String>, PassboltError>;
}
```

**Note** : `decrypt_secret` est synchrone car PGP decrypt est CPU-bound sans IO. Les consumers gerent la parallelisation (CLI: `JoinSet::spawn_blocking`, WASM: sequentiel).

---

## 3. Bindings multi-langages

| Cible | Crate | Technologie | Justification |
|-------|-------|-------------|---------------|
| **Rust CLI** | `passbolt-cli` | `use passbolt_sdk` direct | Wrapper clap mince |
| **Node.js / n8n** | `passbolt-napi` | napi-rs | Cookie jar persistent en memoire, tokio runtime interne, async -> Promise |
| **Browser extension** | `passbolt-wasm` | wasm-bindgen + serde-wasm-bindgen | Cookies geres par le browser, crypto stateless aussi expose |
| **Python** | `passbolt-ffi` | PyO3 / maturin | Module `import passbolt` |
| **Java / .NET** | `passbolt-ffi` | UniFFI (Mozilla) | Genere JNI + C-ABI automatiquement |

### Pourquoi napi-rs pour Node.js (pas WASM)

L'auth GPG challenge-response (`auth.rs:48-150`) necessite un cookie jar persistent entre 3 requetes HTTP sequentielles. En WASM Node.js, `reqwest` ne supporte pas `cookie_store`. napi-rs garde le runtime tokio + reqwest en memoire native.

### WASM pour le browser

Le browser gere les cookies nativement (`credentials: 'include'` sur fetch). Le module WASM expose aussi des fonctions crypto stateless pour remplacer openpgpjs progressivement :

```rust
// Fonctions crypto stateless (pas besoin de session)
#[wasm_bindgen(js_name = "decryptMessage")]
pub fn decrypt_message_static(armored: &str, private_key: &str, passphrase: &str) -> Result<Vec<u8>, JsError>;

#[wasm_bindgen(js_name = "encryptMessage")]
pub fn encrypt_message_static(plaintext: &[u8], public_keys: Vec<JsValue>) -> Result<String, JsError>;
```

### n8n node structure

```
n8n-nodes-passbolt/
  credentials/
    PassboltApi.credentials.ts   # serverUrl, privateKey, passphrase, mfaMode, totpSecret
  nodes/
    Passbolt/
      Passbolt.node.ts           # Resource/Folder/User/Group x Get/GetMany/Create/Update/Delete/Share
```

- Session : login une fois par `execute()`, logout dans `finally { session.logout() }`
- Pas de mode MFA interactif (n8n headless)
- Credential test : login + immediate logout

---

## 4. Plan d'execution

### Phase 0 : Refactoring preparatoire (dans le crate actuel)

**Objectif** : decoupler sans changer de comportement.

| Tache | Fichiers | Detail |
|-------|----------|--------|
| Creer `SdkConfig` | `config.rs` | Struct avec server_url, private_key_armored, passphrase, TLS, proxy, MFA. `Config::to_sdk_config() -> Result<SdkConfig>` pour convertir. |
| Extraire `MfaProvider` trait | `api/auth.rs` | Trait dans `auth.rs`, `TerminalMfaProvider` dans nouveau `util/mfa.rs`. `handle_mfa_login` prend `&dyn MfaProvider` au lieu d'appeler `rpassword` directement (`auth.rs:163`). |
| Ajouter `decrypt_secrets_batch()` | `api/client.rs` | Methode qui encapsule la logique de `main.rs:469-532` (JoinSet + Semaphore + Arc). Elimine l'acces direct a `client.private_key.key` et `client.passphrase` depuis main.rs. |
| Ajouter `decrypt_metadata_batch()` | `api/client.rs` | Meme pattern pour `main.rs:535-552`. |
| Deplacer `build_group_members` | `group/mod.rs` -> `api/types.rs` | Helper pur, pas de dep sur le client. |

**Validation** : `cargo test && cargo clippy -- -D warnings && cargo fmt --check`

### Phase 1 : Creation workspace + SDK crate

**Objectif** : extraire la lib, CLI reste identique en comportement.

1. Convertir `Cargo.toml` en workspace (`crates/sdk/` + `crates/cli/`)
2. Copier dans le SDK (aucune modification logique) :
   - `api/types.rs` -> `sdk/src/types.rs` (583 LOC, verbatim)
   - `api/crypto.rs` -> `sdk/src/crypto.rs` (180 LOC, `anyhow` -> `PassboltError`)
   - `util/filter.rs` -> `sdk/src/filter.rs` (243 LOC, verbatim)
   - `resource/expiry.rs` -> `sdk/src/resource/expiry.rs` (73 LOC)
3. Creer `sdk/src/http.rs` avec le trait `HttpClient`
4. Creer `sdk/src/platform/native.rs` — adapter `api/http.rs` (49 LOC)
5. Refactorer `api/client.rs` -> `sdk/src/client.rs` (707 LOC) :
   - `PassboltClient` -> `PassboltSdk<H: HttpClient>`
   - Remplacer `self.client.get/post/put/delete` par `self.http.get/post/put/delete`
   - `anyhow::Result` -> `Result<T, PassboltError>`
6. Deplacer business logic :
   - `resource/*.rs` (464 LOC) -> `sdk/src/resource/`
   - `folder/*.rs` (102 LOC) -> `sdk/src/folder/`
   - `user/*.rs` (91 LOC) -> `sdk/src/user/`
   - `group/*.rs` (120 LOC) -> `sdk/src/group/`
7. CLI : remplacer `use crate::api::*` par `use passbolt_sdk::*`
8. Ajouter `#[non_exhaustive]` sur tous les types et enums publics

**Validation** : `cargo test --workspace && cargo clippy --workspace -- -D warnings`

### Phase 2 : Bindings WASM (browser extension)

1. Creer `crates/passbolt-wasm/` (cdylib)
2. Implementer `BrowserHttpBackend` :
   - `web-sys` fetch avec `RequestCredentials::Include`
   - Headers extraction pour CSRF token
   - Pas de cookie jar explicite (browser natif)
3. Exporter via `#[wasm_bindgen]` :
   - `PassboltSession` (login/logout/CRUD)
   - Fonctions crypto stateless (`decrypt_message`, `encrypt_message`) pour remplacement progressif d'openpgpjs
4. Deps: `getrandom = { features = ["js"] }`, `serde-wasm-bindgen = "0.6"`
5. Build: `wasm-pack build --target web --release`
6. Profil release: `opt-level = "s"`, LTO, `wasm-opt -Oz`

**Migration incrementale de l'extension :**
1. Remplacer openpgpjs par crypto WASM stateless (impact minimal, meme API)
2. Remplacer auth JS par `PassboltSession.login()`
3. Remplacer services CRUD un par un (ResourceService, FolderService...)

### Phase 3 : Bindings napi-rs (Node.js / n8n)

1. Creer `crates/passbolt-napi/`
2. `PassboltSession` wrappant `Arc<Mutex<Option<PassboltSdk<NativeHttpClient>>>>` avec tokio runtime
3. Exposer CRUD + decrypt comme methodes async -> `Promise<T>` en JS
4. Mapping erreurs : `PassboltError` -> JS Error avec code (`[AUTH_FAILED]`, `[MFA_REQUIRED]`, etc.)
5. CI cross-compilation : linux-x64, linux-arm64, darwin-x64, darwin-arm64
6. Publier `@passbolt/napi` sur npm

### Phase 4 : Bindings universels (UniFFI)

1. Creer `crates/passbolt-ffi/`
2. Definir interface `.udl` (UniFFI Definition Language)
3. Generer automatiquement :
   - Python : `pip install passbolt-sdk` (PyO3/maturin)
   - Kotlin/Java : `.jar` avec JNI
   - Swift : framework natif
   - C# : P/Invoke via C-ABI
4. CI : build matrix par plateforme/langage

### Phase 5 : Tier 2 endpoints + stabilisation

1. Ajouter Comments, Tags, Favorites, Password Policies, Action Logs (feature-gated)
2. `#[non_exhaustive]` partout, builders pour query structs
3. Revue API publique, `#![deny(missing_docs)]`
4. Validation cross-platform : CLI + n8n + browser + Python
5. Publier `passbolt-sdk` 1.0.0 sur crates.io

---

## 5. Risques et mitigations

| Risque | Impact | Mitigation |
|--------|--------|------------|
| pgp crate WASM : `rand::thread_rng()` | Build fail | `getrandom = { features = ["js"] }` |
| WASM bundle size (pgp RSA) | 500-700 KB | `opt-level = "s"`, LTO, wasm-opt, Brotli compression |
| Cookie handling WASM vs native | Auth break | Trait abstrait le transport; browser gere nativement |
| `tokio::sync::OnceCell` pas WASM | Metadata cache | Type alias `#[cfg(feature = "wasm")]` -> `std::cell::OnceCell` |
| napi-rs tokio conflict avec event loop n8n | Runtime crash | napi-rs spawne son propre tokio runtime (pattern SWC/Prisma) |
| `SecretString` en WASM linear memory | Fuite potentielle | `zeroize` fonctionne en WASM; passphrase acceptee en `&[u8]` (Uint8Array) pour zero-copy JS |
| Breaking changes API SDK | Consumers cassent | `#[non_exhaustive]`, builders, semver strict |

---

## 6. Verification

| Niveau | Outil | Couverture |
|--------|-------|-----------|
| Unit tests SDK | `cargo test` | types, crypto, filter, auth mock, expiry |
| Integration SDK | `mockito` | Tous les endpoints moques |
| CLI regression | `assert_cmd` existants | Comportement identique post-migration |
| WASM | `wasm-pack test --headless --chrome` | Login, CRUD, crypto |
| napi-rs | Jest | Module natif, session lifecycle |
| Python | pytest | Bindings PyO3 |
| E2E | Docker Passbolt CE | Flow complet auth -> CRUD -> logout |
| Qualite | `cargo clippy --workspace -- -D warnings` + `cargo fmt` | Zero warnings |
