# Roadmap

## Implementation Phases

### Phase 1: Foundation

**Goal**: Set up the Rust workspace, define core traits, and implement the crypto module.

#### Deliverables

1. **Rust workspace** with crate structure:
   - `passbolt-core` (library)
   - `passbolt-crypto` (library)
   - `passbolt-wasm` (cdylib)
   - `passbolt-ffi` (cdylib)
   - `passbolt-cli` (binary)
2. **Core traits**: `Transport`, `Storage`, error types
3. **Crypto module** (full implementation):
   - Key generation (RSA + ECC)
   - Encrypt/decrypt (asymmetric, symmetric, session key)
   - Sign/verify
   - Private key encrypt/decrypt
   - Keyring (in-memory for now)
   - Key info extraction
4. **Test suite**: Unit tests for all crypto operations using known test vectors from openpgp.js

#### Acceptance Criteria

- [ ] All crypto operations produce output compatible with openpgp.js
- [ ] Messages encrypted by JS can be decrypted by Rust and vice-versa
- [ ] Key generation produces valid keys accepted by the Passbolt server
- [ ] Compiles to WASM target (`wasm32-unknown-unknown`)
- [ ] CI pipeline with `cargo test` and `wasm-pack test`

---

### Phase 2: Authentication

**Goal**: Implement the GPG challenge-response login flow.

#### Deliverables

1. **Auth module**:
   - GPG challenge-response login (2-stage)
   - Server key verification
   - Auth status check
   - Logout + session cleanup
   - Passphrase validation
2. **Transport implementations**:
   - `reqwest`-based transport for testing/CLI
   - In-memory transport mock for unit tests
3. **Storage implementations**:
   - In-memory storage for testing
4. **Integration test**: Full login flow against a real Passbolt server (docker-based CI)

#### Acceptance Criteria

- [ ] Can successfully authenticate against a Passbolt server
- [ ] Session cookies are properly managed
- [ ] Server key verification works
- [ ] Logout properly cleans up session state
- [ ] Error messages match expected behavior

---

### Phase 3: Resources & Secrets

**Goal**: Implement resource CRUD and secret encryption/decryption.

#### Deliverables

1. **Resources module**:
   - Create resource (v4 + v5 types)
   - Find/list resources with filters
   - Update resource
   - Delete resource (single + bulk)
   - Move resource to folder
   - Favorites
2. **Secrets module**:
   - Find and decrypt secret
   - Bulk decrypt secrets
   - Encrypt secret for recipients
   - Password breach check (HIBP API)
3. **Resource types**: Parse and validate resource type schemas
4. **Local storage**: Resource caching with Storage trait

#### Acceptance Criteria

- [ ] Can create a resource and retrieve its decrypted secret
- [ ] Supports all resource types (password, TOTP, mixed)
- [ ] Bulk operations work correctly
- [ ] HIBP password check works with k-anonymity
- [ ] Local cache stays in sync with server

---

### Phase 4: Folders & Sharing

**Goal**: Implement folder hierarchy and sharing with re-encryption.

#### Deliverables

1. **Folders module**:
   - CRUD operations
   - Move with permission recalculation
   - Tree building from flat list
2. **Sharing module**:
   - Share resources (with secret re-encryption)
   - Share folders (cascading)
   - Permission changes tracking
   - ARO search
3. **Permission model**: Full permission entity support

#### Acceptance Criteria

- [ ] Can create nested folder structures
- [ ] Moving a folder correctly handles permission changes
- [ ] Sharing a resource encrypts secrets for all new recipients
- [ ] Sharing a folder cascades to all contents
- [ ] Permission changes are correctly computed

---

### Phase 5: Users & Groups

**Goal**: Implement user and group management.

#### Deliverables

1. **Users module**:
   - CRUD operations
   - Profile and avatar management
   - Role management
   - RBAC
2. **Groups module**:
   - CRUD operations
   - Member management with secret re-encryption
   - Delete dry-run

#### Acceptance Criteria

- [ ] Can list, create, update, and delete users
- [ ] Group member changes correctly trigger re-encryption
- [ ] RBAC permissions are correctly fetched and enforced
- [ ] Delete dry-run shows accurate impact

---

### Phase 6: Metadata, Tags & Comments

**Goal**: Implement metadata encryption and auxiliary features.

#### Deliverables

1. **Metadata module**:
   - Metadata key management
   - Encrypt/decrypt metadata
   - Key rotation
   - v4→v5 migration support
2. **Tags module**: Full CRUD
3. **Comments module**: Full CRUD

#### Acceptance Criteria

- [ ] Metadata encrypted by SDK is compatible with existing server/clients
- [ ] Key rotation handles interruption and resume
- [ ] v4→v5 migration correctly encrypts all metadata
- [ ] Tags and comments work end-to-end

---

### Phase 7: WASM Binding + Browser Extension Integration

**Goal**: Create the WASM binding and integrate with the browser extension.

#### Deliverables

1. **WASM binding crate** (`passbolt-wasm`):
   - `wasm-bindgen` exports for all SDK methods
   - JS/TS type definitions
   - WASM Transport (fetch bridge)
   - WASM Storage (browser.storage.local bridge)
2. **Browser extension integration**:
   - Load WASM module in background service worker
   - Replace one feature end-to-end (e.g., password creation) as proof of concept
   - Performance benchmarks vs JS implementation
3. **npm package**: Publishable `@passbolt/sdk-wasm`

#### Acceptance Criteria

- [ ] WASM binary < 2 MB (gzipped < 500 KB)
- [ ] All SDK methods accessible from JS
- [ ] At least one full user flow works through WASM in the extension
- [ ] No regressions in existing extension functionality
- [ ] Performance equal or better than JS for crypto operations

---

### Phase 8: FFI Mobile + CLI

**Goal**: Create mobile FFI bindings and the CLI tool.

#### Deliverables

1. **FFI binding crate** (`passbolt-ffi`):
   - UniFFI interface definition
   - Generated Swift bindings + XCFramework
   - Generated Kotlin bindings + AAR
2. **CLI crate** (`passbolt-cli`):
   - All commands (login, resources, folders, share, export)
   - Configuration management
   - Shell completion
3. **Mobile integration guide**: How to use the SDK from iOS/Android apps

#### Acceptance Criteria

- [ ] Swift bindings compile and work in an iOS project
- [ ] Kotlin bindings compile and work in an Android project
- [ ] CLI can perform full workflows (login → list → create → share → logout)
- [ ] CLI supports JSON output for scripting
- [ ] Mobile: all crypto operations work on-device

---

### Phase 9: Full Migration

**Goal**: Migrate the browser extension to use the SDK for all business logic.

#### Deliverables

1. **Complete migration** of all 39 event handlers to SDK calls
2. **Remove JS business logic**: Service files, model files, crypto files
3. **Performance optimization**: Minimize JS↔WASM boundary crossings
4. **Extension size reduction**: Remove openpgp.js and related JS dependencies

#### Acceptance Criteria

- [ ] All extension functionality works through the SDK
- [ ] No direct API calls from JS (all go through SDK)
- [ ] Extension bundle size reduced (no openpgp.js)
- [ ] All existing tests pass or are migrated
- [ ] No user-facing regressions

## Phase Dependencies

```
Phase 1 (Foundation + Crypto)
    │
    ├── Phase 2 (Auth)
    │       │
    │       ├── Phase 3 (Resources + Secrets)
    │       │       │
    │       │       ├── Phase 4 (Folders + Sharing)
    │       │       │       │
    │       │       │       └── Phase 5 (Users + Groups)
    │       │       │               │
    │       │       │               └── Phase 6 (Metadata + Tags + Comments)
    │       │       │                       │
    │       │       └───────────────────────┤
    │       │                               │
    │       └── Phase 7 (WASM Binding) ─────┤
    │                                       │
    └── Phase 8 (FFI + CLI) ────────────────┤
                                            │
                                     Phase 9 (Full Migration)
```

Phase 7 (WASM) can start as early as Phase 2 completion, with incremental integration as more modules become available. Phase 8 (FFI + CLI) can be developed in parallel with Phases 4-6.

## Rollback Strategy

Each phase has a clear rollback path to minimize risk during integration:

### Phase 7 (WASM Binding) - Highest Risk

The browser extension integration is the riskiest phase since it replaces production code.

**Strategy: Feature-flag migration**
1. The WASM SDK is loaded alongside existing JS code (not replacing it)
2. A feature flag per module controls whether the SDK or JS path is used: `sdk.auth.enabled`, `sdk.resources.enabled`, etc.
3. Flags default to `false` (JS path) and are toggled per feature
4. If a regression is detected, the flag is reverted to `false` - instant rollback, no code changes needed
5. Dual-mode can run both paths simultaneously in development for comparison testing

**Extension manifest versioning:** The extension version is bumped for each SDK-enabled feature. Rollback = publish previous version.

### Phase 9 (Full Migration)

Once all features are SDK-powered and validated:
1. JS business logic files are removed in a single release
2. If critical issues arise, the previous release (with JS code) can be re-published
3. A minimum 2-week canary period on internal/beta channels before general release

### General Rollback Principles

- SDK crate versions are pinned in `Cargo.lock` - rollback = revert lock file
- Integration tests run against both JS and SDK paths during migration
- No server-side changes are required for SDK adoption (pure client-side)

## Server Compatibility Matrix

The SDK targets compatibility with the following Passbolt server versions:

| Server Version | Support Level | Notes |
|---------------|---------------|-------|
| 4.x (latest) | Full | Primary target, all features |
| 4.0+ | Full | Minimum for v5 metadata support |
| 3.x | Partial | No v5 metadata, no TOTP resources, basic CRUD + auth |
| < 3.0 | Not supported | |

**API version detection:** The SDK reads the server version from `GET /healthcheck.json` on first connection and adjusts feature availability accordingly. Features unsupported by the server version return `UnsupportedByServer` errors.

## Test Strategy

### Framework

- **Unit tests**: `cargo test` with built-in Rust test framework
- **Integration tests**: Against a dockerized Passbolt server (CE edition)
- **WASM tests**: `wasm-pack test --headless --chrome/firefox`
- **Cross-platform**: CI matrix for `x86_64-linux`, `aarch64-apple-darwin`, `wasm32-unknown-unknown`

### Coverage Goals

| Layer | Target | Tool |
|-------|--------|------|
| Crypto module | 95%+ | `cargo-llvm-cov` |
| Core business logic | 85%+ | `cargo-llvm-cov` |
| Bindings | 70%+ (integration) | Platform-specific |

### Test Categories

1. **Crypto compatibility tests**: Verify Rust encrypt ↔ JS decrypt and vice versa using test vectors from `openpgp.js`
2. **API contract tests**: Mock HTTP responses matching real server payloads (captured from a running instance)
3. **Integration tests**: Full flows (login → create resource → share → decrypt → logout) against a live server
4. **Regression tests**: Each bug fix includes a test that reproduces the bug
5. **Performance benchmarks**: `criterion` benchmarks for crypto operations, compared against `openpgp.js` baselines

### CI Pipeline

```
cargo fmt --check
cargo clippy -- -D warnings
cargo test --all-features
wasm-pack test --headless --chrome
cargo bench (nightly, non-blocking)
```

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| `rpgp` missing needed OpenPGP features | Evaluate early in Phase 1; fall back to `sequoia-openpgp` for native targets |
| WASM binary too large | Profile with `twiggy`; use feature flags; consider lazy loading |
| JS↔WASM boundary performance | Minimize crossings; batch operations; use `SharedArrayBuffer` if needed |
| Mobile build complexity | Start UniFFI integration early in Phase 1 to validate build pipeline |
| Compatibility with existing server | Comprehensive integration tests against dockerized server from Phase 2 |
| SDK regression breaks extension | Feature-flag migration with instant rollback (see Rollback Strategy) |
| Async model incompatibility | Validate `MaybeSend` pattern in Phase 1 with WASM target compilation |
