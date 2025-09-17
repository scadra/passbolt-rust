// Passbolt ~ Open source password manager for teams
// Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) 2025 Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use pgp::{types::PublicKeyTrait, Deserializable, Message, SignedPublicKey, SignedSecretKey};
use std::io::Cursor;
use zeroize::Zeroize;

use super::error::PassboltError;

/// Parsed private key used for decryption / fingerprint.
pub struct PrivateKey {
    pub key: SignedSecretKey,
    pub fingerprint: String,
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

/// Parse and validate a PGP private key from ASCII-armored text.
pub fn parse_private_key(armored: &str) -> Result<PrivateKey, PassboltError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedSecretKey::from_armor_single(cursor)
        .map_err(|e| PassboltError::PgpKeyParse(format!("private key: {e}")))?;
    key.verify()
        .map_err(|e| PassboltError::PgpKeyParse(format!("private key verification: {e}")))?;

    let fp = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
    Ok(PrivateKey {
        key,
        fingerprint: fp,
    })
}

/// Parse a PGP public key from ASCII-armored text.
pub fn parse_public_key(armored: &str) -> Result<SignedPublicKey, PassboltError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedPublicKey::from_armor_single(cursor)
        .map_err(|e| PassboltError::PgpKeyParse(format!("public key: {e}")))?;
    key.verify()
        .map_err(|e| PassboltError::PgpKeyParse(format!("public key verification: {e}")))?;
    Ok(key)
}

pub fn decrypt_message(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<u8>, PassboltError> {
    let cursor = Cursor::new(armored_message.as_bytes());
    let (msg, _) = Message::from_armor_single(cursor)
        .map_err(|e| PassboltError::PgpDecrypt(format!("parse message: {e}")))?;

    let (decrypted, _) = msg
        .decrypt(|| passphrase.to_string(), &[private_key])
        .map_err(|e| PassboltError::PgpDecrypt(format!("{e}")))?;

    let content = decrypted
        .get_literal()
        .ok_or_else(|| PassboltError::PgpDecrypt("no literal content".into()))?;

    Ok(content.data().to_vec())
}

pub fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, PassboltError> {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    let msg = Message::new_literal_bytes("", plaintext);
    let mut rng = rand::thread_rng();

    let encrypted = msg
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, recipients)
        .map_err(|e| PassboltError::PgpEncrypt(format!("{e}")))?;

    let armored = encrypted
        .to_armored_string(Default::default())
        .map_err(|e| PassboltError::PgpEncrypt(format!("armor: {e}")))?;

    Ok(armored)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a fresh RSA-2048 keypair with an empty passphrase for tests.
    fn generate_test_keypair() -> (SignedSecretKey, SignedPublicKey) {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder};
        use pgp::types::SecretKeyTrait;

        let mut rng = rand::thread_rng();

        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .can_encrypt(true)
            .primary_user_id("Test User <test@test.local>".into())
            .build()
            .expect("key params");

        let secret_key = params.generate(&mut rng).expect("key generate");
        let signed_secret = secret_key
            .sign(&mut rng, || "".to_string())
            .expect("sign secret key");
        // public_key() returns an unsigned PublicKey; sign it to get SignedPublicKey
        let public_key = signed_secret.public_key();
        let signed_public = public_key
            .sign(&mut rng, &signed_secret, || "".to_string())
            .expect("sign public key");

        (signed_secret, signed_public)
    }

    #[test]
    fn test_parse_private_key_invalid() {
        assert!(parse_private_key("not a pgp key at all").is_err());
    }

    #[test]
    fn test_parse_private_key_valid() {
        let (secret_key, _pub) = generate_test_keypair();
        let armored = secret_key
            .to_armored_string(Default::default())
            .expect("armor");
        let parsed = parse_private_key(&armored);
        assert!(parsed.is_ok());
        // Fingerprint is a non-empty hex string
        let pk = parsed.unwrap();
        assert!(!pk.fingerprint.is_empty());
        assert!(pk.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret_key, pub_key) = generate_test_keypair();
        let plaintext = b"super secret passphrase";

        let armored = encrypt_message(plaintext, &[&pub_key]).expect("encrypt");
        let decrypted = decrypt_message(&armored, &secret_key, "").expect("decrypt");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_for_multiple_keys() {
        let (sk1, pk1) = generate_test_keypair();
        let (sk2, pk2) = generate_test_keypair();
        let plaintext = b"hello both";

        let armored = encrypt_message(plaintext, &[&pk1, &pk2]).expect("encrypt");

        let d1 = decrypt_message(&armored, &sk1, "").expect("decrypt key1");
        let d2 = decrypt_message(&armored, &sk2, "").expect("decrypt key2");
        assert_eq!(d1, plaintext);
        assert_eq!(d2, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (_sk1, pk1) = generate_test_keypair();
        let (sk2, _pk2) = generate_test_keypair();
        let plaintext = b"secret";

        let armored = encrypt_message(plaintext, &[&pk1]).expect("encrypt");
        // sk2 was not a recipient — decryption must fail
        assert!(decrypt_message(&armored, &sk2, "").is_err());
    }

    #[test]
    fn test_parse_public_key_invalid() {
        assert!(parse_public_key("garbage data").is_err());
    }

    #[test]
    fn test_parse_public_key_valid() {
        let (_sk, pub_key) = generate_test_keypair();
        let armored = pub_key
            .to_armored_string(Default::default())
            .expect("armor");
        assert!(parse_public_key(&armored).is_ok());
    }
}
