# Passbolt Rust SDK - Specifications

## Overview

The Passbolt Rust SDK is a native Rust reimplementation of the core business logic currently embedded in the Passbolt browser extension (JavaScript). The goal is to provide a single, high-performance, memory-safe codebase that can be consumed across all Passbolt clients.

## Objectives

- **Single source of truth**: One Rust codebase for all crypto, auth, and CRUD logic
- **Cross-platform**: Compile to WASM, native binaries, and C-compatible FFI
- **Performance**: Native speed for crypto operations (OpenPGP, key derivation)
- **Safety**: Memory-safe handling of secrets, keys, and passphrases
- **Testability**: Pure Rust core with injectable transport and storage layers

## Target Consumers

| Consumer | Binding | Transport | Storage |
|----------|---------|-----------|---------|
| Browser extension | WASM (`wasm-bindgen`) | `fetch` via JS bridge | `browser.storage.local` / IndexedDB |
| n8n nodes | WASM or `napi-rs` | `fetch` / Node HTTP | In-memory / file |
| Mobile (iOS/Android) | FFI via UniFFI | Platform HTTP (URLSession / OkHttp) | SQLite / Keychain |
| Desktop (Electron) | WASM or FFI | `reqwest` | SQLite / OS keychain |
| CLI | Native binary | `reqwest` | SQLite / file |

## Spec Documents

### Architecture
- [Architecture](./architecture.md) - Layered architecture, dependency choices, error strategy
- [Bindings](./bindings.md) - WASM, FFI, CLI, and n8n binding strategies
- [Roadmap](./roadmap.md) - Phased implementation plan

### Module Specs
- [Auth](./modules/auth.md) - GPG challenge-response login, SSO, MFA, session management
- [Crypto](./modules/crypto.md) - OpenPGP operations, keyring, key generation
- [Resources](./modules/resources.md) - Password/credential CRUD operations
- [Secrets](./modules/secrets.md) - Secret encryption/decryption, types, breach check
- [Folders](./modules/folders.md) - Folder hierarchy and permission inheritance
- [Sharing](./modules/sharing.md) - Resource/folder sharing and re-encryption
- [Users](./modules/users.md) - User management, profiles, roles, RBAC
- [Groups](./modules/groups.md) - Group management and member re-encryption
- [Metadata](./modules/metadata.md) - Encrypted metadata, key rotation, v4→v5 migration
- [Tags & Comments](./modules/tags-comments.md) - Tagging and commenting on resources

### Reference
- [API Reference](./api-reference.md) - Complete mapping of JS events to Rust SDK methods
- [Parity with go-passbolt](../PARITY-GO.md) - Gaps and candidate tickets vs go-passbolt / go-passbolt-cli

## Versioning & Licence

- **Versioning**: The SDK follows [Semantic Versioning 2.0](https://semver.org/). All crates in the workspace share the same version number.
  - **Major**: Breaking changes to the public API (trait signatures, type changes, removed methods)
  - **Minor**: New features, new modules, new methods (backwards-compatible)
  - **Patch**: Bug fixes, performance improvements, dependency updates
- **Breaking changes policy**: Breaking changes are collected and released together in major versions. During the 0.x phase, minor versions may contain breaking changes.
- **Licence**: AGPL-3.0 (same as the Passbolt browser extension)
- **Minimum Supported Rust Version (MSRV)**: Documented in the workspace `Cargo.toml`. Bumping the MSRV is a minor version change.

## Current Codebase Reference

The browser extension source code lives under `src/all/background_page/` with:
- **39 event files** in `event/` defining the current public API
- **34+ entity types** in `model/entity/` with JSON Schema validation
- **47 crypto service files** in `service/crypto/`
- **30+ local storage files** in `service/local_storage/`
- Abstract REST API pattern in `service/api/abstract/abstractService.js`
