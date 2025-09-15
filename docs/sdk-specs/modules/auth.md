# Auth Module

## Overview

The Auth module handles all authentication flows: GPG challenge-response login, session management, SSO, MFA, and server key verification. It is the entry point for any authenticated SDK operation.

**Current JS references:**
- `controller/auth/authLoginController.js` - Main login flow
- `service/auth/authVerifyLoginChallengeService.js` - GPG challenge-response
- `service/auth/authVerifyServerChallengeService.js` - Server key verification
- `controller/auth/authLogoutController.js` - Logout
- `controller/auth/authCheckStatusController.js` - Auth status check
- `service/crypto/checkPassphraseService.js` - Passphrase validation
- `service/session_storage/passphraseStorageService.js` - Passphrase storage
- `service/local_storage/authStatusLocalStorage.js` - Auth status cache
- `event/authEvents.js` - Auth event handlers

## GPG Challenge-Response Login

The login flow is a two-stage GPG authentication protocol:

### Flow

```
Client                                Server
  │                                     │
  │  Stage 1: POST /auth/login          │
  │  { gpg_auth: { keyid: fingerprint }}│
  │ ──────────────────────────────────► │
  │                                     │ Server encrypts a token with
  │                                     │ the user's public key
  │  Response headers:                  │
  │  x-gpgauth-user-auth-token: <enc>  │
  │ ◄────────────────────────────────── │
  │                                     │
  │  Client decrypts token with         │
  │  private key + passphrase           │
  │                                     │
  │  Stage 2: POST /auth/login          │
  │  { gpg_auth: {                      │
  │      keyid: fingerprint,            │
  │      user_token_result: <token>     │
  │  }}                                 │
  │ ──────────────────────────────────► │
  │                                     │ Server validates token,
  │  Response: Set-Cookie + headers     │ sets session cookie
  │ ◄────────────────────────────────── │
```

### Steps (from `authVerifyLoginChallengeService.js`)

1. **Stage 1**: Send user's key fingerprint to `POST /auth/login.json`
2. **Validate headers**: Check `x-gpgauth-authenticated`, `x-gpgauth-progress`, `x-gpgauth-user-auth-token` via `GpgAuthHeader`
3. **Decrypt token**: Use `DecryptUserAuthTokenService` to decrypt the `x-gpgauth-user-auth-token` with user's private key + passphrase
4. **Validate token format**: Token must match UUID v4 format `gpgauthv1.3.0|36|<uuid>|gpgauthv1.3.0`
5. **Stage 2**: Send decrypted token back to `POST /auth/login.json`
6. **Validate completion**: Check response headers for `x-gpgauth-authenticated: true`

### Pre-login (from `authLoginController.js`)

Before the GPG challenge:
1. Check passphrase validity against the private key
2. Update SSO kit if needed (non-blocking)

### Post-login

After successful authentication:
1. Store passphrase in session storage (duration based on `rememberMe`)
2. Start keep-alive service if `rememberMe` is enabled
3. Execute `PostLoginService` (refresh local caches)
4. Store user's remember-me preference

### Keep-Alive Services

The SDK uses two complementary background services to maintain session state:

#### 1. Session Keep-Alive (Passphrase-Based)

**Current JS reference:** `service/session_storage/keepSessionAliveService.js`

- **Endpoint**: `GET /users/me.json`
- **Interval**: Every 15 minutes
- **Condition**: Only active when passphrase is stored in memory
- **Purpose**: Extends the server session by making periodic authenticated requests
- **Stops**: On `logout()`, when passphrase expires, or when SDK is dropped

#### 2. Auth Session Check (Authentication-Based)

**Current JS reference:** `service/auth/startLoopAuthSessionCheckService.js`

- **Endpoint**: `GET /auth/is-authenticated.json`
- **Interval**: Every 60 seconds
- **Condition**: Always running after login
- **Purpose**: Validates the session is still active. If `isAuthenticated` returns `false`, triggers automatic logout (zeroizes passphrase, clears caches, emits logout event)
- **Stops**: On `logout()` or when SDK is dropped

#### KeepAliveConfig

```rust
pub struct KeepAliveConfig {
    /// Interval for session keep-alive requests. Default: 15 minutes.
    pub keep_alive_interval: Duration,
    /// Interval for authentication status checks. Default: 60 seconds.
    pub auth_check_interval: Duration,
    /// Enable session keep-alive (requires passphrase in memory). Default: true when remember_me.
    pub keep_alive_enabled: bool,
    /// Enable auth status checks. Default: true.
    pub auth_check_enabled: bool,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(900),  // 15 minutes
            auth_check_interval: Duration::from_secs(60),   // 60 seconds
            keep_alive_enabled: true,
            auth_check_enabled: true,
        }
    }
}
```

#### Implementation Notes

- **Native (tokio)**: Both services use `tokio::spawn` with `tokio::time::interval`
- **WASM**: Use `setInterval` via JS bridge or `browser.alarms` API
- **Coordination**: The two services are independent. Keep-alive extends the session; auth-check validates it. If auth-check detects session loss, it triggers logout regardless of keep-alive state

## Server Key Verification

Verifies the server's identity by encrypting a token and checking that the server can decrypt it.

**Current JS reference:** `service/auth/authVerifyServerChallengeService.js`

### Flow

1. Generate a random token: `gpgauthv1.3.0|36|<uuid>|gpgauthv1.3.0`
2. Encrypt the token with the server's public key
3. Send to `POST /auth/verify.json` with `{ gpg_auth: { keyid, server_verify_token: encrypted_token }}`
4. Server decrypts and returns the token in `x-gpgauth-verify-response` header
5. Compare returned token with original

## Check Auth Status

**Current JS reference:** `controller/auth/authCheckStatusController.js`

- Calls `GET /auth/is-authenticated.json`
- Returns `{ isAuthenticated: bool, isMfaRequired: bool }`
- Caches result in `AuthStatusLocalStorage`

## Logout

**Current JS reference:** `controller/auth/authLogoutController.js`, `service/auth/postLogoutService.js`

1. Call `POST /auth/logout.json`
2. Flush all local storage caches
3. Clear passphrase from session storage
4. Stop keep-alive service
5. Clear in-memory caches

## Passphrase Validation

**Current JS reference:** `service/crypto/checkPassphraseService.js`

- Attempts to decrypt the user's private key with the given passphrase
- Uses `DecryptPrivateKeyService.decrypt(armoredKey, passphrase)`
- Throws if passphrase is incorrect

## SSO Authentication

**Current JS references:** `controller/sso/ssoAuthenticationController.js`, `service/api/sso/ssoLoginService.js`, `service/api/sso/ssoKitServerPartService.js`, `service/account/updateSsoCredentialsService.js`

### SSO Endpoints

#### Get SSO Login URL

```
POST /sso/<provider>/login.json
Body: { "user_id": "<uuid>" }
Response: { "url": "<OAuth provider login URL>" }
```

Supported providers: `azure`, `google`, `oauth2`.

The server returns a redirect URL for the OAuth provider. The client opens this URL in a popup/browser tab for the user to authenticate.

#### Exchange SSO Token for Server Kit

```
GET /sso/keys/<sso_kit_id>/<user_id>/<sso_token>.json
Response: { "data": "<base64-encoded JWK>" }
```

After the user authenticates with the OAuth provider, a UUID token is returned. This token is exchanged for the server-side SSO kit (an AES-GCM key in JWK format).

#### Setup SSO Kit (During Account Setup)

```
POST /sso/keys.json
Body: {
  "id": "<uuid>",
  "user_id": "<uuid>",
  "provider": "azure|google|oauth2",
  "key": "<base64-encoded JWK>"
}
Response: Created SsoKitServerPart entity
```

#### Delete SSO Kit

```
DELETE /sso/keys/<sso_kit_id>.json
Response: 200 OK
```

#### Get Current SSO Settings

```
GET /sso/settings/current.json
Response: { "provider": "azure|google|oauth2|null", ... }
```

### SSO Login Flow (Detailed)

```
Client                                Server / OAuth Provider
  │                                     │
  │  1. POST /sso/{provider}/login      │
  │     { user_id }                     │
  │ ──────────────────────────────────► │
  │  Response: { url: "<oauth_url>" }   │
  │ ◄────────────────────────────────── │
  │                                     │
  │  2. Open popup to OAuth provider    │
  │ ───────────────────────────────────►│ OAuth Provider
  │  User authenticates                 │
  │  Provider returns UUID sso_token    │
  │ ◄───────────────────────────────────│
  │                                     │
  │  3. GET /sso/keys/{kitId}/{userId}/ │
  │       {ssoToken}                    │
  │ ──────────────────────────────────► │
  │  Response: { data: "<base64 JWK>" } │
  │ ◄────────────────────────────────── │
  │                                     │
  │  4. Import server key (AES-GCM)     │
  │  5. Decrypt passphrase from local   │
  │     SSO kit using server key        │
  │  6. Close OAuth popup               │
  │  7. Standard GPG challenge-response │
  │     login using recovered passphrase│
  │  8. Store passphrase + start keep-  │
  │     alive + post-login tasks        │
```

### SSO Kit Encryption

The SSO kit uses a split-key design. The user's passphrase is encrypted client-side and can only be recovered by combining:
- **Client-side kit** (stored in IndexedDB/local storage)
- **Server-side kit** (stored on the Passbolt server)

#### Client-Side SSO Kit Structure

```json
{
  "id": "<uuid>",
  "provider": "azure|google|oauth2",
  "secret": "<encrypted passphrase>",
  "nek": "<nonce encryption key>",
  "iv1": "<initialization vector 1>",
  "iv2": "<initialization vector 2>"
}
```

#### Server-Side SSO Kit Structure

```json
{
  "id": "<uuid>",
  "user_id": "<uuid>",
  "provider": "azure|google|oauth2",
  "key": "<base64-encoded JWK (AES-GCM key)>"
}
```

#### Decryption Process

```
1. Import server JWK as AES-GCM key via WebCrypto
2. Decrypt passphrase using:
   - client_kit.secret (encrypted passphrase)
   - client_kit.nek (nonce encryption key)
   - server_key (AES-GCM key from server)
   - client_kit.iv1, client_kit.iv2 (initialization vectors)
3. Result: user's master passphrase in plaintext
```

#### Lifecycle

- **Generated**: During initial login or account setup when SSO is enabled
- **Updated**: When SSO provider token changes (via `UpdateSsoCredentialsService`)
- **Deleted**: On logout or when SSO is disabled

### SSO Kit Update During Login

**Current JS reference:** `service/account/updateSsoCredentialsService.js`

After each login, `UpdateSsoCredentialsService.updateSsoKitIfNeeded(passphrase)` is called:

| SSO Plugin | Local Kit Exists | Provider Configured | Action |
|-----------|-----------------|-------------------|--------|
| Disabled  | Yes             | Any               | Flush kit |
| Disabled  | No              | Any               | No action |
| Enabled   | No              | Yes               | Generate new kit |
| Enabled   | Yes             | Same              | No action |
| Enabled   | Yes             | None              | Flush kit |

`forceUpdateSsoKit(passphrase)` flushes the existing kit and regenerates unconditionally (used during password recovery).

## MFA Challenge

**Current JS references:** `service/api/multiFactorAuthentication/multiFactorAuthenticationService.js`, `controller/mfaSetup/`

### MFA Detection

After GPG auth login, the server may require MFA. Detection happens via `GET /auth/is-authenticated.json`:
- **Full authentication**: Returns 200 OK
- **MFA required**: The response URL matches `/mfa/verify/error.json`, indicating MFA verification is pending

The `CheckAuthStatusService` catches this and sets `{ isAuthenticated: true, isMfaRequired: true }`.

### MFA Verification Endpoints

#### Verify TOTP Code

```
POST /mfa/setup/totp.json
Body: {
  "totp": "<6-character-code>",
  "otpProvisioningUri": "otpauth://totp/..."
}
Response: 200 OK {}
```

The `totp` field must match pattern `^[a-z0-9]{6}$` (6 alphanumeric characters).

#### Get TOTP Setup Info (QR Code)

```
GET /mfa/setup/totp.json
Response: {
  "otpProvisioningUri": "otpauth://totp/server:user@example.com?issuer=server&secret=BASE32SECRET&algorithm=SHA1&digits=6&period=30"
}
```

#### Verify Yubikey OTP

```
POST /mfa/setup/yubikey.json
Body: { "hotp": "<yubikey-otp-string>" }
Response: 200 OK { "provider": "yubikey", "verified": true }
```

#### Get Available MFA Providers

```
GET /mfa/setup/select.json
Response: {
  "providers": {
    "totp": { "enabled": true, "verified": true },
    "yubikey": { "enabled": false, "verified": false },
    "duo": { "enabled": true, "verified": true }
  }
}
```

#### Check MFA Provider Status

```
GET /mfa/setup/<provider>.json
Response: MfaVerifyProviderEntity with verification status
```

#### Remove MFA Provider

```
DELETE /mfa/setup/<provider>.json
Response: 200 OK
```

#### Disable All MFA for a User (Admin)

```
DELETE /mfa/setup/<user_id>.json
Response: 200 OK
```

#### Get MFA Policy

```
GET /mfa/policy/get.json
Response: MfaPolicyEntity (mandatory/optional MFA config, allowed providers)
```

### Supported Providers

| Provider | Setup Endpoint | Verify Payload | Notes |
|----------|---------------|----------------|-------|
| TOTP     | `POST /mfa/setup/totp.json` | `{ totp, otpProvisioningUri }` | 6-digit code from authenticator app |
| Yubikey  | `POST /mfa/setup/yubikey.json` | `{ hotp }` | OTP generated by YubiKey hardware |
| Duo      | Provider-specific | N/A | Handled via Duo redirect flow |

## Proposed Rust API

```rust
/// Authentication module
pub struct AuthClient<T: Transport, S: Storage> {
    transport: Arc<T>,
    storage: Arc<S>,
    config: ServerConfig,
}

impl<T: Transport, S: Storage> AuthClient<T, S> {
    /// Login with GPG challenge-response
    /// Returns session info on success
    pub async fn login(&self, params: LoginParams) -> Result<Session, AuthError>;

    /// Logout and cleanup session
    pub async fn logout(&self) -> Result<(), AuthError>;

    /// Check current authentication status
    pub async fn check_status(&self) -> Result<AuthStatus, AuthError>;

    /// Verify the server's GPG key
    pub async fn verify_server_key(&self) -> Result<(), AuthError>;

    /// Verify a passphrase against the stored private key
    pub async fn verify_passphrase(&self, passphrase: &str) -> Result<(), AuthError>;

    /// Get the server's public key
    pub async fn get_server_key(&self) -> Result<ArmoredKey, AuthError>;

    /// Replace the server's public key (admin)
    pub async fn replace_server_key(&self, new_key: &ArmoredKey) -> Result<(), AuthError>;

    /// Get CSRF token
    pub async fn get_csrf_token(&self) -> Result<String, AuthError>;
}

/// SSO authentication
pub struct SsoClient<T: Transport, S: Storage> { /* ... */ }

impl<T: Transport, S: Storage> SsoClient<T, S> {
    /// Get current SSO settings
    pub async fn get_settings(&self) -> Result<SsoSettings, AuthError>;

    /// Login via SSO provider
    pub async fn login(&self, provider_token: &str) -> Result<Session, AuthError>;

    /// Generate SSO kit (encrypt passphrase for SSO recovery)
    pub async fn generate_kit(&self, passphrase: &str) -> Result<(), AuthError>;
}

/// MFA verification
pub struct MfaClient<T: Transport, S: Storage> { /* ... */ }

impl<T: Transport, S: Storage> MfaClient<T, S> {
    /// Verify TOTP code
    pub async fn verify_totp(&self, code: &str) -> Result<(), AuthError>;

    /// Verify Yubikey OTP
    pub async fn verify_yubikey(&self, otp: &str) -> Result<(), AuthError>;

    /// Check if MFA is required
    pub async fn is_required(&self) -> Result<bool, AuthError>;
}

// --- Data types ---

pub struct LoginParams {
    pub user_fingerprint: String,
    pub user_private_armored_key: String,
    pub passphrase: String,
    pub remember_me: bool,
}

pub struct AuthStatus {
    pub is_authenticated: bool,
    pub is_mfa_required: bool,
}

pub struct Session {
    pub user_id: Uuid,
    pub csrf_token: String,
}
```

## Error Types

```rust
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error("Server verification failed: {0}")]
    ServerVerificationFailed(String),
    #[error("Invalid GPG auth token format")]
    InvalidTokenFormat,
    #[error("Session expired")]
    SessionExpired,
    #[error("User already logged in")]
    AlreadyLoggedIn,
    #[error("MFA required: {provider}")]
    MfaRequired { provider: String },
    #[error("SSO error: {0}")]
    SsoError(String),
    #[error("Passphrase required but not cached")]
    PassphraseRequired,
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}
```

## Dependencies

- **Crypto module**: For GPG decrypt/encrypt, passphrase validation
- **Transport trait**: For HTTP calls to `/auth/*`, `/sso/*`, `/mfa/*` endpoints
- **Storage trait**: For session/auth status caching, SSO kit storage
