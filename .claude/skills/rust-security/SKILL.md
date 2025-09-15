---
name: rust-security
description: Enforce secure memory handling for structs containing passwords, keys, or tokens (zeroize, secrecy, no logging of secrets)
triggers: password, secret, token, key, credential, GPG, private key, mot de passe
layer: 1
domain: security
---

For any struct containing sensitive data (passwords, private keys, tokens):

1. Derive `Zeroize` + `ZeroizeOnDrop`:
   ```rust
   #[derive(Zeroize, ZeroizeOnDrop)]
   struct Credentials {
       password: String,
       private_key: Vec<u8>,
   }
   ```

2. Wrap string secrets in `SecretString` from the `secrecy` crate:
   ```rust
   use secrecy::{SecretString, ExposeSecret};
   let password: SecretString = SecretString::from(raw_password);
   // Only expose when absolutely needed:
   let exposed = password.expose_secret();
   ```

3. Never log secrets — use `#[tracing::instrument(skip(password))]`
4. Clear GPG buffers: call `.zeroize()` on Vec<u8> after GPG operations
5. Use `keyring` to store session tokens in OS keychain, not in plaintext config files
