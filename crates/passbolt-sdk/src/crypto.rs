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

use pgp::{
    types::PublicKeyTrait, ArmorOptions, Deserializable, Message, SignedPublicKey, SignedSecretKey,
};
use std::io::Cursor;
use zeroize::Zeroize;

use crate::error::CryptoError;

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
pub fn parse_private_key(armored: &str) -> Result<PrivateKey, CryptoError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedSecretKey::from_armor_single(cursor)
        .map_err(|error| CryptoError::KeyParse(format!("private key: {error}")))?;
    key.verify()
        .map_err(|error| CryptoError::KeyParse(format!("private key verification: {error}")))?;

    let fingerprint = hex::encode(key.fingerprint().as_bytes()).to_uppercase();
    Ok(PrivateKey { key, fingerprint })
}

/// Parse a PGP public key from ASCII-armored text.
pub fn parse_public_key(armored: &str) -> Result<SignedPublicKey, CryptoError> {
    let cursor = Cursor::new(armored.as_bytes());
    let (key, _) = SignedPublicKey::from_armor_single(cursor)
        .map_err(|error| CryptoError::KeyParse(format!("public key: {error}")))?;
    key.verify()
        .map_err(|error| CryptoError::KeyParse(format!("public key verification: {error}")))?;
    Ok(key)
}

pub fn decrypt_message(
    armored_message: &str,
    private_key: &SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let cursor = Cursor::new(armored_message.as_bytes());
    let (message, _) = Message::from_armor_single(cursor)
        .map_err(|error| CryptoError::Decrypt(format!("parse message: {error}")))?;

    let (decrypted, _) = message
        .decrypt(|| passphrase.to_string(), &[private_key])
        .map_err(|error| CryptoError::Decrypt(format!("{error}")))?;

    // GnuPG (the Passbolt server) compresses by default.
    decrypted
        .get_content()
        .map_err(|error| CryptoError::Decrypt(format!("decompress: {error}")))?
        .ok_or_else(|| CryptoError::Decrypt("no literal content".into()))
}

pub fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    let message = Message::new_literal_bytes("", plaintext);
    let mut rng = rand::thread_rng();

    let encrypted = message
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES256, recipients)
        .map_err(|error| CryptoError::Encrypt(format!("{error}")))?;

    let armored = encrypted
        .to_armored_string(ArmorOptions::default())
        .map_err(|error| CryptoError::Encrypt(format!("armor: {error}")))?;

    Ok(armored)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_PRIVATE: &str = include_str!("../tests/fixtures/keys/server_private.asc");
    const SERVER_PUBLIC: &str = include_str!("../tests/fixtures/keys/server_public.asc");
    const METADATA_PRIVATE: &str = include_str!("../tests/fixtures/keys/metadata_private.asc");
    const METADATA_PUBLIC: &str = include_str!("../tests/fixtures/keys/metadata_public.asc");

    /// Fixture keypair without passphrase.
    fn keypair(private: &str, public: &str) -> (SignedSecretKey, SignedPublicKey) {
        (
            parse_private_key(private).unwrap().key.clone(),
            parse_public_key(public).unwrap(),
        )
    }

    #[test]
    fn test_parse_private_key_invalid() {
        assert!(parse_private_key("not a pgp key at all").is_err());
    }

    #[test]
    fn test_parse_private_key_fingerprint() {
        let fingerprint = parse_private_key(SERVER_PRIVATE)
            .unwrap()
            .fingerprint
            .clone();

        assert_eq!(fingerprint.len(), 40);
        assert!(fingerprint
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_lowercase()));
    }

    #[test]
    fn test_parse_public_key_invalid() {
        assert!(parse_public_key("garbage data").is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);

        let armored = encrypt_message(b"secret", &[&public]).unwrap();

        assert_eq!(decrypt_message(&armored, &secret, "").unwrap(), b"secret");
    }

    #[test]
    fn test_encrypt_for_multiple_keys() {
        let (server_secret, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"both", &[&server_public, &metadata_public]).unwrap();

        assert_eq!(
            decrypt_message(&armored, &server_secret, "").unwrap(),
            b"both"
        );
        assert_eq!(
            decrypt_message(&armored, &metadata_secret, "").unwrap(),
            b"both"
        );
    }

    #[test]
    fn test_decrypt_compressed_message() {
        use pgp::crypto::sym::SymmetricKeyAlgorithm;
        use pgp::types::CompressionAlgorithm;
        let (secret, public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let armored = Message::new_literal_bytes("", b"gpgauthv1.3.0")
            .compress(CompressionAlgorithm::ZLIB)
            .unwrap()
            .encrypt_to_keys_seipdv1(
                rand::thread_rng(),
                SymmetricKeyAlgorithm::AES256,
                &[&public],
            )
            .unwrap()
            .to_armored_string(ArmorOptions::default())
            .unwrap();

        assert_eq!(
            decrypt_message(&armored, &secret, "").unwrap(),
            b"gpgauthv1.3.0"
        );
    }

    #[test]
    fn test_decrypt_with_another_key_fails() {
        let (_, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, _) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"secret", &[&server_public]).unwrap();

        assert!(decrypt_message(&armored, &metadata_secret, "").is_err());
    }
}
