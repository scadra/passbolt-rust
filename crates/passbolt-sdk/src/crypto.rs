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
    ser::Serialize, types::PublicKeyTrait, ArmorOptions, Deserializable, Message, SignedPublicKey,
    SignedSecretKey,
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

/// Encrypt `plaintext` for `recipients`, as a binary literal.
pub fn encrypt_message(
    plaintext: &[u8],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    encrypt(&Message::new_literal_bytes("", plaintext), recipients)
}

/// A key able to sign: a private key and its passphrase.
pub struct Signer<'a> {
    pub key: &'a SignedSecretKey,
    pub passphrase: &'a str,
}

/// Sign `plaintext` with every signer, then encrypt it for `recipients`, as a UTF-8 text literal.
///
/// Passbolt clients sign secrets with the user key, shared metadata with the metadata key too.
pub fn sign_and_encrypt(
    plaintext: &str,
    signers: &[Signer<'_>],
    recipients: &[&SignedPublicKey],
) -> Result<String, CryptoError> {
    use pgp::crypto::hash::HashAlgorithm;

    let mut message = Message::new_literal("", plaintext);
    for signer in signers {
        message = message
            .sign(
                rand::thread_rng(),
                signer.key,
                || signer.passphrase.to_string(),
                HashAlgorithm::SHA2_256,
            )
            .map_err(|error| CryptoError::Encrypt(format!("sign: {error}")))?;
    }
    encrypt(&message, recipients)
}

fn encrypt(message: &Message, recipients: &[&SignedPublicKey]) -> Result<String, CryptoError> {
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::packet::{PublicKeyEncryptedSessionKey, SymEncryptedProtectedData};
    use pgp::{Edata, Esk};

    const ALGORITHM: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm::AES256;
    let failure = |error: pgp::errors::Error| CryptoError::Encrypt(error.to_string());
    let mut rng = rand::thread_rng();
    let session_key = ALGORITHM.new_session_key(&mut rng);

    // Recipients mix primary keys and subkeys: one session key packet each.
    let esk = recipients
        .iter()
        .map(|recipient| {
            let packet = match encryption_subkey(recipient) {
                Some(subkey) => PublicKeyEncryptedSessionKey::from_session_key_v3(
                    &mut rng,
                    &session_key,
                    ALGORITHM,
                    &subkey.key,
                ),
                None if recipient.primary_key.is_encryption_key() => {
                    PublicKeyEncryptedSessionKey::from_session_key_v3(
                        &mut rng,
                        &session_key,
                        ALGORITHM,
                        &recipient.primary_key,
                    )
                }
                None => {
                    return Err(CryptoError::Encrypt(format!(
                        "key {} has no encryption key",
                        hex::encode_upper(recipient.fingerprint().as_bytes())
                    )))
                }
            };
            packet
                .map(Esk::PublicKeyEncryptedSessionKey)
                .map_err(failure)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let data = message.to_bytes().map_err(failure)?;
    let edata = Edata::SymEncryptedProtectedData(
        SymEncryptedProtectedData::encrypt_seipdv1(&mut rng, ALGORITHM, &session_key, &data)
            .map_err(failure)?,
    );
    Message::Encrypted { esk, edata }
        .to_armored_string(ArmorOptions::default())
        .map_err(|error| CryptoError::Encrypt(format!("armor: {error}")))
}

/// The subkey flagged for encryption, as `OpenPGP` requires over the primary key.
fn encryption_subkey(key: &SignedPublicKey) -> Option<&pgp::SignedPublicSubKey> {
    key.public_subkeys.iter().find(|subkey| {
        subkey.key.is_encryption_key()
            && subkey.signatures.iter().any(|signature| {
                let flags = signature.key_flags();
                flags.encrypt_comms() || flags.encrypt_storage()
            })
    })
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

    /// Verify every signature layer of `armored` against `signers`, outermost first.
    fn verified_text(
        armored: &str,
        secret: &SignedSecretKey,
        signers: &[&SignedPublicKey],
    ) -> String {
        let (message, _) = Message::from_armor_single(Cursor::new(armored.as_bytes())).unwrap();
        let (mut message, _) = message.decrypt(String::new, &[secret]).unwrap();
        for signer in signers {
            message.verify(*signer).unwrap();
            let Message::Signed { message: inner, .. } = message else {
                panic!(
                    "not signed by {}",
                    hex::encode_upper(signer.fingerprint().as_bytes())
                )
            };
            message = *inner.unwrap();
        }
        let Message::Literal(literal) = message else {
            panic!("more signatures than expected")
        };
        assert!(!literal.is_binary(), "not a text literal");
        literal.to_string().unwrap()
    }

    #[test]
    fn test_sign_and_encrypt_signs_with_every_signer() {
        let (server_secret, server_public) = keypair(SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) = keypair(METADATA_PRIVATE, METADATA_PUBLIC);
        let signers = [
            Signer {
                key: &server_secret,
                passphrase: "",
            },
            Signer {
                key: &metadata_secret,
                passphrase: "",
            },
        ];

        let armored = sign_and_encrypt("signed é", &signers, &[&metadata_public]).unwrap();

        assert_eq!(
            verified_text(
                &armored,
                &metadata_secret,
                &[&metadata_public, &server_public]
            ),
            "signed é"
        );
    }
}
