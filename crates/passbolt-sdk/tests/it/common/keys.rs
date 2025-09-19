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

//! Test-only PGP keys from `tests/fixtures/keys`.

use passbolt_sdk::crypto;
use serde_json::Value;

pub struct TestKey {
    pub name: &'static str,
    pub private: &'static str,
    pub public: &'static str,
    pub passphrase: &'static str,
}

macro_rules! key {
    ($name:literal, $passphrase:literal) => {
        TestKey {
            name: $name,
            private: include_str!(concat!("../../fixtures/keys/", $name, "_private.asc")),
            public: include_str!(concat!("../../fixtures/keys/", $name, "_public.asc")),
            passphrase: $passphrase,
        }
    };
}

pub const ADA: TestKey = key!("ada", "ada-passphrase");
pub const BETTY: TestKey = key!("betty", "betty-passphrase");
pub const CAROL: TestKey = key!("carol", "carol-passphrase");
pub const ERIN: TestKey = key!("erin", "erin-passphrase");
pub const SERVER: TestKey = key!("server", "");
pub const METADATA: TestKey = key!("metadata", "");

pub fn by_name(name: &str) -> &'static TestKey {
    [&ADA, &BETTY, &CAROL, &ERIN, &SERVER, &METADATA]
        .into_iter()
        .find(|key| key.name == name)
        .unwrap_or_else(|| panic!("no fixture key named {name}"))
}

impl TestKey {
    pub fn fingerprint(&self) -> String {
        crypto::parse_private_key(self.private)
            .unwrap()
            .fingerprint
            .clone()
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let public_key = crypto::parse_public_key(self.public).unwrap();
        crypto::encrypt_message(plaintext.as_bytes(), &[&public_key]).unwrap()
    }

    pub fn decrypt(&self, armored_message: &str) -> String {
        let private_key = crypto::parse_private_key(self.private).unwrap();
        String::from_utf8(
            crypto::decrypt_message(armored_message, &private_key.key, self.passphrase).unwrap(),
        )
        .unwrap()
    }

    pub fn decrypt_json(&self, armored_message: &str) -> Value {
        serde_json::from_str(&self.decrypt(armored_message)).unwrap()
    }
}
