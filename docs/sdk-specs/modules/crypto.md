# Crypto Module

## Overview

The Crypto module provides all OpenPGP operations: key generation, encryption/decryption, signing/verification, keyring management, and session key handling. It wraps a Rust OpenPGP library (recommended: `rpgp`) and replaces the current `openpgp.js` dependency.

**Current JS references:**
- `service/crypto/encryptMessageService.js` - Encrypt messages (asymmetric + symmetric)
- `service/crypto/decryptMessageService.js` - Decrypt messages (with session key, symmetric, asymmetric)
- `service/crypto/signMessageService.js` - Sign messages
- `service/crypto/verifyMessageSign.js` - Verify signatures
- `service/crypto/generateGpgKeyPairService.js` - Generate key pairs
- `service/crypto/decryptPrivateKeyService.js` - Decrypt private key with passphrase
- `service/crypto/encryptPrivateKeyService.js` - Re-encrypt private key
- `service/crypto/getGpgKeyInfoService.js` - Extract key metadata
- `service/crypto/getSessionKeyService.js` - Extract session keys from messages
- `service/crypto/checkPassphraseService.js` - Validate passphrase
- `service/crypto/revokeGpgKeyService.js` - Revoke keys
- `service/crypto/signGpgKeyService.js` - Sign keys
- `service/crypto/verifyGpgKeyService.js` - Verify key signatures
- `service/crypto/compareGpgKeyService.js` - Compare keys
- `service/crypto/findSignatureService.js` - Find signatures in messages
- `model/keyring.js` - Keyring (public + private key storage)
- `event/keyringEvents.js` - Keyring event handlers

## Key Generation

**Current JS reference:** `generateGpgKeyPairService.js`

Generates an OpenPGP key pair with:
- **Algorithm**: RSA (2048, 3072, 4096) or ECC (curve25519)
- **User ID**: `name <email>` format
- **Passphrase**: Protects the private key

```rust
pub struct KeyGenerationParams {
    pub name: String,
    pub email: String,
    pub passphrase: String,
    pub key_type: KeyType,
    pub key_size: Option<u32>,  // For RSA: 2048, 3072, 4096
}

pub enum KeyType {
    Rsa,
    Ecc,  // curve25519
}

pub struct GeneratedKeyPair {
    pub public_armored: String,
    pub private_armored: String,
    pub fingerprint: String,
}
```

## Encryption

**Current JS reference:** `encryptMessageService.js`

### Asymmetric Encryption (PGP)

Encrypts a plaintext message with one or more public keys, optionally signing with a private key.

- Used for: secrets, metadata, auth tokens
- Input: plaintext string, recipient public key(s), optional signing private key
- Output: armored PGP message

### Symmetric Encryption

Encrypts a message with a password (used for SSO kit, metadata symmetric encryption).

- Input: plaintext string, password(s), optional signing key
- Output: armored PGP message

## Decryption

**Current JS reference:** `decryptMessageService.js`

Three decryption modes:

1. **Asymmetric**: Decrypt with private key, optionally verify signature
2. **Symmetric**: Decrypt with password, optionally verify signature
3. **Session key**: Decrypt with a pre-extracted session key (for performance when decrypting the same message for multiple recipients)

All modes support signature verification with `verificationKeys`.

## Signing & Verification

**Current JS references:** `signMessageService.js`, `verifyMessageSign.js`

- **Sign**: Create a detached or inline signature using a private key
- **Verify**: Verify a signature against a public key

Used in auth flow (GPG challenge-response) and metadata integrity checks.

## Private Key Operations

### Decrypt Private Key

**Current JS reference:** `decryptPrivateKeyService.js`

Unlocks an encrypted private key using a passphrase. Required before any signing or decryption operation.

### Encrypt Private Key

**Current JS reference:** `encryptPrivateKeyService.js`

Re-encrypts a private key with a new passphrase (used during passphrase change).

### Revoke Key

**Current JS reference:** `revokeGpgKeyService.js`

Generates a revocation certificate for a key.

## Session Key Handling

**Current JS reference:** `getSessionKeyService.js`

Extracts the session key from an encrypted PGP message. This allows:
1. Decrypt the session key once with the user's private key
2. Use the session key to decrypt multiple messages encrypted with the same key
3. Performance optimization for bulk decryption (e.g., metadata)

```rust
/// Symmetric encryption algorithm used for session keys.
/// Maps to `rpgp::crypto::sym::SymmetricKeyAlgorithm`.
pub enum SymmetricAlgorithm {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
}

pub struct SessionKey {
    pub algorithm: SymmetricAlgorithm,
    pub data: Vec<u8>,
}
```

### Session Key Reuse Semantics

Session keys are extracted from PGP messages to optimize bulk decryption scenarios:

- **Metadata decryption**: All users sharing the same metadata key receive the same session key. Extract once, decrypt all metadata items without re-doing the asymmetric operation.
- **Secret decryption**: Each secret is encrypted independently with a unique session key per recipient. Session keys are **not reusable** across different secrets.
- **Sharing re-encryption**: When re-encrypting for new recipients, the SDK decrypts the plaintext and re-encrypts with each recipient's public key. Session keys are not transferred between users.

Session keys should be zeroized after use (implement `Zeroize` on `SessionKey.data`).

**Interop note**: The JS codebase (`getSessionKeyService.js`) represents session keys as a string `"algorithm:hexData"` (e.g., `"9:abcdef012345..."`). The Rust SDK uses the struct representation above, which is more type-safe. When interoperating with the JS format (e.g., passing session keys via WASM bindings), convert using:
- JS → Rust: Split on `:`, parse algorithm ID to `SymmetricAlgorithm`, hex-decode data
- Rust → JS: Format as `"{algorithm_id}:{hex_data}"`

Algorithm IDs follow the OpenPGP standard: 2=TripleDes, 7=Aes128, 8=Aes192, 9=Aes256.

```rust
// Example: bulk metadata decryption with session key reuse
let session_key = crypto.get_session_key(&encrypted_metadata[0], &private_key)?;
for item in &encrypted_metadata {
    let plaintext = crypto.decrypt_with_session_key(item, &session_key, None)?;
    // process plaintext...
}
```

## Keyring Management

**Current JS reference:** `model/keyring.js`

The keyring stores public keys for all known users and the current user's private key.

### Storage Layout

- `passbolt-public-gpgkeys`: Map of `user_id -> { armored_key, user_id, fingerprint }`
- `passbolt-private-gpgkeys`: Map with single entry `MY_KEY_ID -> { armored_key }`

### Operations

- `find_public(user_id)` → Get a user's public key
- `find_private()` → Get the current user's private key
- `import_public(armored_key, user_id)` → Import a public key
- `import_private(armored_key)` → Import the user's private key
- `import_server_public(armored_key, server_id)` → Import server's public key
- `sync()` → Sync public keyring with server (`GET /gpgkeys.json`)
- `flush()` → Clear the keyring

### Keyring Sync Details

**Endpoint**: `GET /gpgkeys.json?api-version=v2[&modified_after=<timestamp>]`

**Response format**:
```json
{
  "header": {
    "servertime": "2024-06-01T12:00:00Z",
    "status": "success",
    "message": "..."
  },
  "body": [
    {
      "user_id": "<uuid>",
      "armored_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
    }
  ]
}
```

**Incremental sync**: The `modified_after` query parameter enables incremental syncs. The SDK stores `header.servertime` from the last successful sync and passes it on subsequent calls. This avoids re-fetching all keys on every sync.

**Sync algorithm**:
1. Read `latestSync` timestamp from storage
2. Fetch `GET /gpgkeys.json?modified_after={latestSync}` (or without parameter on first sync)
3. For each key in response body, call `import_public(armored_key, user_id)`
4. Store `header.servertime` as `latestSync`

**Error handling**: If a key in the response is malformed (invalid armored format, unsupported algorithm), skip it and continue syncing the rest. Log a warning but do not fail the entire sync.

### Key Info

**Current JS reference:** `getGpgKeyInfoService.js`

Extracts metadata from an armored key:
- Fingerprint, key ID
- Algorithm, key length, curve
- Creation date, expiration date
- User IDs (name, email)
- Can encrypt, can sign flags
- Revocation status

## Library Choice: `rpgp` vs `sequoia-openpgp`

### Recommendation: `rpgp`

| Feature | `rpgp` | `sequoia-openpgp` |
|---------|--------|-------------------|
| Pure Rust | Yes | Depends on Nettle/CNG |
| WASM target | Excellent | Difficult (C deps) |
| Binary size | ~1.5 MB | ~4+ MB |
| RFC 4880 | Full | Full + RFC 4880bis |
| ECC (curve25519) | Yes | Yes |
| RSA | Yes | Yes |
| Session keys | Yes | Yes |
| API complexity | Simple | Complex |

`rpgp` is recommended because:
1. Pure Rust with no C dependencies → easy WASM compilation
2. Smaller binary size → important for browser extension WASM
3. Covers all operations used by Passbolt (encrypt, decrypt, sign, verify, keygen, session keys)
4. Active maintenance and reasonable community

If `rpgp` proves insufficient (e.g., missing a specific OpenPGP feature), `sequoia-openpgp` can be used as fallback for native-only bindings.

## Proposed Rust API

```rust
/// Main crypto service
pub struct CryptoService {
    keyring: Keyring,
}

impl CryptoService {
    // --- Key Generation ---

    /// Generate a new OpenPGP key pair
    pub fn generate_key(&self, params: KeyGenerationParams) -> Result<GeneratedKeyPair, CryptoError>;

    // --- Encryption ---

    /// Encrypt a message for a recipient (asymmetric)
    pub fn encrypt(
        &self,
        plaintext: &str,
        recipient_key: &PublicKey,
        signing_key: Option<&DecryptedPrivateKey>,
    ) -> Result<String, CryptoError>;

    /// Encrypt a message symmetrically with a password
    pub fn encrypt_symmetric(
        &self,
        plaintext: &str,
        passwords: &[&str],
        signing_key: Option<&DecryptedPrivateKey>,
    ) -> Result<String, CryptoError>;

    // --- Decryption ---

    /// Decrypt an armored PGP message
    pub fn decrypt(
        &self,
        armored_message: &str,
        private_key: &DecryptedPrivateKey,
        verification_keys: Option<&[PublicKey]>,
    ) -> Result<String, CryptoError>;

    /// Decrypt with a session key
    pub fn decrypt_with_session_key(
        &self,
        armored_message: &str,
        session_key: &SessionKey,
        verification_keys: Option<&[PublicKey]>,
    ) -> Result<String, CryptoError>;

    /// Decrypt a symmetric message
    pub fn decrypt_symmetric(
        &self,
        armored_message: &str,
        password: &str,
        verification_keys: Option<&[PublicKey]>,
    ) -> Result<String, CryptoError>;

    // --- Session Keys ---

    /// Extract session key from an encrypted message
    pub fn get_session_key(
        &self,
        armored_message: &str,
        private_key: &DecryptedPrivateKey,
    ) -> Result<SessionKey, CryptoError>;

    // --- Signing ---

    /// Sign a message
    pub fn sign(
        &self,
        message: &str,
        private_key: &DecryptedPrivateKey,
    ) -> Result<String, CryptoError>;

    /// Verify a signed message
    pub fn verify(
        &self,
        signed_message: &str,
        verification_keys: &[PublicKey],
    ) -> Result<String, CryptoError>;

    // --- Private Key Operations ---

    /// Decrypt (unlock) a private key with passphrase
    pub fn decrypt_private_key(
        &self,
        armored_key: &str,
        passphrase: &str,
    ) -> Result<DecryptedPrivateKey, CryptoError>;

    /// Re-encrypt a private key with a new passphrase
    pub fn encrypt_private_key(
        &self,
        private_key: &DecryptedPrivateKey,
        new_passphrase: &str,
    ) -> Result<String, CryptoError>;

    /// Validate a passphrase against a private key
    pub fn check_passphrase(
        &self,
        armored_key: &str,
        passphrase: &str,
    ) -> Result<(), CryptoError>;

    // --- Key Info ---

    /// Extract metadata from an armored key
    pub fn get_key_info(&self, armored_key: &str) -> Result<GpgKeyInfo, CryptoError>;
}

/// Keyring for managing public and private keys
pub struct Keyring {
    storage: Arc<dyn Storage>,
}

impl Keyring {
    pub fn find_public(&self, user_id: &Uuid) -> Result<Option<PublicKey>, CryptoError>;
    pub fn find_private(&self) -> Result<Option<ArmoredPrivateKey>, CryptoError>;
    pub async fn import_public(&self, armored_key: &str, user_id: &Uuid) -> Result<(), CryptoError>;
    pub async fn import_private(&self, armored_key: &str) -> Result<(), CryptoError>;
    pub async fn sync<T: Transport>(&self, transport: &T) -> Result<(), CryptoError>;
    pub async fn flush(&self) -> Result<(), CryptoError>;
    pub fn get_all_public(&self) -> Result<Vec<(Uuid, PublicKey)>, CryptoError>;
}

// --- Data Types ---

pub struct GpgKeyInfo {
    pub fingerprint: String,
    pub key_id: String,
    pub algorithm: String,
    pub length: u32,
    pub curve: Option<String>,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub user_ids: Vec<KeyUserId>,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub revoked: bool,
}

pub struct KeyUserId {
    pub name: String,
    pub email: String,
}

/// Generic armored PGP key (public or private). Used as a lightweight
/// string wrapper when the key type is not yet determined or when the
/// API returns a key that could be either type.
pub struct ArmoredKey(pub String);

/// Parsed public key (from rpgp). Wraps the library's SignedPublicKey type.
/// Used for encryption, signature verification, and keyring lookups.
pub struct PublicKey { /* inner: rpgp::SignedPublicKey */ }

/// Armored private key that has not yet been decrypted.
/// This is the storage format - the key material is still passphrase-protected.
pub struct ArmoredPrivateKey {
    pub armored: String,
}

/// A private key that has been decrypted (unlocked) with a passphrase.
/// Zeroizes on drop for security.
pub struct DecryptedPrivateKey { /* inner: rpgp::SignedSecretKey */ }

impl Drop for DecryptedPrivateKey {
    fn drop(&mut self) {
        // Zeroize sensitive material
    }
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key not found for user: {user_id}")]
    KeyNotFound { user_id: String },
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error(transparent)]
    Storage(#[from] StorageError),
}
```

## Key Expiration & Revocation

### Expiration

- Keys generated by the SDK can optionally include an expiration date, but Passbolt currently generates keys **without expiration** (matching `openpgp.js` behavior)
- The `GpgKeyInfo.expires` field reports the expiration date if present
- The SDK does **not** reject expired keys during encryption (the server validates key status)
- Future consideration: the SDK may warn when using expired keys, but this is not blocking for implementation

### Revocation

- `CryptoService::revoke_key()` generates a revocation certificate (not currently exposed in the public API but available internally)
- Revoked keys are detectable via `GpgKeyInfo.revoked`
- The SDK does **not** encrypt to revoked keys
- Key revocation is primarily a server-side operation (admin revokes a user's key); the SDK supports generating revocation certificates for the CLI and account recovery flows

## Security Considerations

1. **Zeroization**: All secret material (private keys, passphrases, session keys) must be zeroized on drop using the `zeroize` crate
2. **No logging of secrets**: Never log private keys, passphrases, or decrypted content
3. **Constant-time comparison**: Use `subtle` crate for comparing tokens/signatures
4. **Memory protection**: Consider `secrecy` crate for wrapping sensitive values
