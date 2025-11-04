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

//! v5 resource metadata: the shared metadata keys and the decryption of `metadata`.

use std::collections::HashMap;

use pgp::SignedSecretKey;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::crypto;
use crate::error::{CryptoError, PassboltError};
use crate::types::{MetadataKey, Resource, ResourceMetadata};

const PRIVATE_KEY_OBJECT_TYPE: &str = "PASSBOLT_METADATA_PRIVATE_KEY";
const RESOURCE_METADATA_OBJECT_TYPE: &str = "PASSBOLT_RESOURCE_METADATA";

/// Decrypted `metadata_private_keys[].data`.
#[derive(Deserialize)]
struct MetadataPrivateKeyData {
    object_type: String,
    fingerprint: String,
    armored_key: String,
    passphrase: SecretString,
}

struct MetadataPrivateKey {
    key: SignedSecretKey,
    passphrase: SecretString,
}

/// Shared metadata private keys the user holds a share of, by metadata key id.
#[derive(Default)]
pub struct MetadataKeys(HashMap<String, MetadataPrivateKey>);

/// Lists the key ids only: the keys are secret.
impl std::fmt::Debug for MetadataKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.0.keys()).finish()
    }
}

impl MetadataKeys {
    /// Decrypt the user's share of every metadata key not deleted.
    ///
    /// A key without a share for the user is skipped: in zero-knowledge mode it has not been shared yet.
    pub fn decrypt(
        keys: &[MetadataKey],
        user_id: &str,
        user_key: &SignedSecretKey,
        user_passphrase: &str,
    ) -> Result<Self, PassboltError> {
        let mut decrypted_keys = HashMap::new();
        for metadata_key in keys.iter().filter(|key| key.deleted.is_none()) {
            let Some(share) = metadata_key
                .metadata_private_keys
                .iter()
                .find(|share| share.user_id.as_deref() == Some(user_id))
            else {
                continue;
            };
            let plaintext = crypto::decrypt_message(&share.data, user_key, user_passphrase)
                .map_err(|error| {
                    CryptoError::Decrypt(format!("metadata key {} share: {error}", metadata_key.id))
                })?;
            let private_key = parse_private_key_data(metadata_key, &plaintext)?;
            decrypted_keys.insert(metadata_key.id.clone(), private_key);
        }
        Ok(Self(decrypted_keys))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The share must hold the private part of the metadata key it is attached to.
fn parse_private_key_data(
    metadata_key: &MetadataKey,
    plaintext: &[u8],
) -> Result<MetadataPrivateKey, PassboltError> {
    let invalid = |reason: String| {
        CryptoError::KeyParse(format!("metadata key {} share: {reason}", metadata_key.id))
    };
    let data: MetadataPrivateKeyData = serde_json::from_slice(plaintext)
        .map_err(|error| invalid(format!("not a metadata private key: {error}")))?;
    if data.object_type != PRIVATE_KEY_OBJECT_TYPE {
        return Err(invalid(format!("unexpected object_type {}", data.object_type)).into());
    }
    let private_key = crypto::parse_private_key(&data.armored_key)?;
    let fingerprints_match = private_key
        .fingerprint
        .eq_ignore_ascii_case(&data.fingerprint)
        && metadata_key
            .fingerprint
            .as_deref()
            .is_none_or(|fingerprint| fingerprint.eq_ignore_ascii_case(&data.fingerprint));
    if !fingerprints_match {
        return Err(invalid("fingerprint mismatch".into()).into());
    }
    Ok(MetadataPrivateKey {
        key: private_key.key.clone(),
        passphrase: data.passphrase,
    })
}

/// Decrypt the `metadata` of a v5 resource; `None` for a v4 resource.
///
/// `user_key` metadata is encrypted for the user, `shared_key` metadata for `metadata_key_id`.
pub fn decrypt_resource_metadata(
    resource: &Resource,
    user_key: &SignedSecretKey,
    user_passphrase: &str,
    shared_keys: &MetadataKeys,
) -> Result<Option<ResourceMetadata>, PassboltError> {
    let Some(armored) = resource.armored_metadata() else {
        return Ok(None);
    };
    let failure = |reason: String| {
        CryptoError::Decrypt(format!("resource {} metadata: {reason}", resource.id))
    };

    let plaintext = if resource.metadata_key_type.as_deref() == Some("user_key") {
        crypto::decrypt_message(armored, user_key, user_passphrase)
    } else {
        let key_id = resource.metadata_key_id.as_deref().unwrap_or_default();
        let metadata_key = shared_keys
            .0
            .get(key_id)
            .ok_or_else(|| failure(format!("the metadata key {key_id} is not shared with you")))?;
        crypto::decrypt_message(
            armored,
            &metadata_key.key,
            metadata_key.passphrase.expose_secret(),
        )
    }
    .map_err(|error| failure(error.to_string()))?;

    let metadata: ResourceMetadata = serde_json::from_slice(&plaintext)
        .map_err(|error| failure(format!("invalid JSON: {error}")))?;
    if metadata.object_type.as_deref() != Some(RESOURCE_METADATA_OBJECT_TYPE) {
        return Err(failure(format!("unexpected object_type {:?}", metadata.object_type)).into());
    }
    Ok(Some(metadata))
}
