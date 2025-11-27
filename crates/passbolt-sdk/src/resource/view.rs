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

//! Resources as people read them, whatever their version: v5 metadata decrypted, the secret on demand.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::PassboltError;
use crate::types::{Resource, ResourceMetadata, ResourceType};

/// A resource with its v5 metadata decrypted, and its secret when it was asked for.
#[derive(Debug, Clone, Serialize)]
pub struct ResourceView {
    pub id: String,
    pub name: String,
    pub username: String,
    /// The first of `uris`.
    pub uri: String,
    pub uris: Vec<String>,
    /// The v5 metadata description, else the v4 one, from the secret for most v4 types.
    pub description: String,
    pub folder_parent_id: Option<String>,
    /// The type slug; `None` for a type the server does not list.
    pub resource_type: Option<String>,
    pub resource_type_id: Option<String>,
    pub personal: Option<bool>,
    /// `user_key` (personal) or `shared_key` for v5 resources.
    pub metadata_key_type: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub expired: Option<DateTime<Utc>>,
    /// The decrypted v5 metadata, or the v4 fields.
    pub metadata: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// The decrypted secret; a `password-string` secret as `{"password": …}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<Map<String, Value>>,
    /// Why the metadata or the secret could not be decrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip)]
    pub resource: Resource,
}

impl ResourceView {
    /// The view of `resource`, with its decrypted `metadata` for a v5 resource.
    pub fn new(
        resource: Resource,
        metadata: Option<ResourceMetadata>,
        resource_types: &[ResourceType],
    ) -> Result<Self, PassboltError> {
        let resource_type = resource_types
            .iter()
            .find(|resource_type| resource.resource_type_id.as_deref() == Some(&resource_type.id))
            .map(|resource_type| resource_type.slug.clone());
        let mut fields = match metadata {
            Some(metadata) => match serde_json::to_value(metadata)? {
                Value::Object(fields) => fields,
                _ => Map::new(),
            },
            None => v4_fields(&resource),
        };
        fields.remove("object_type");
        fields.remove("resource_type_id");
        let text = |key: &str| {
            fields
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let uris: Vec<String> = match fields.get("uris") {
            Some(Value::Array(uris)) => uris
                .iter()
                .filter_map(|uri| uri.as_str().map(String::from))
                .collect(),
            _ => fields
                .get("uri")
                .and_then(Value::as_str)
                .map(String::from)
                .into_iter()
                .collect(),
        };
        Ok(Self {
            id: resource.id.clone(),
            name: text("name"),
            username: text("username"),
            uri: uris.first().cloned().unwrap_or_default(),
            uris,
            description: text("description"),
            folder_parent_id: resource.folder_parent_id.clone(),
            resource_type,
            resource_type_id: resource.resource_type_id.clone(),
            personal: resource.personal,
            metadata_key_type: resource.metadata_key_type.clone(),
            created: resource.created,
            modified: resource.modified,
            expired: resource.expired,
            metadata: fields,
            password: None,
            secret: None,
            error: None,
            resource,
        })
    }

    /// Add the decrypted secret: `password-string` types hold the password itself.
    pub fn with_secret(mut self, plaintext: &str) -> Result<Self, PassboltError> {
        let is_string = matches!(
            self.resource_type.as_deref(),
            Some("password-string" | "v5-password-string")
        );
        // Not a JSON object: a password-string, or a type this SDK does not know.
        let secret = match serde_json::from_str(plaintext) {
            Ok(Value::Object(secret)) if !is_string => secret,
            _ => Map::from_iter([("password".to_string(), Value::from(plaintext))]),
        };
        self.password = secret
            .get("password")
            .and_then(Value::as_str)
            .map(String::from);
        if self.description.is_empty() && !self.is_v5() {
            if let Some(description) = secret.get("description").and_then(Value::as_str) {
                self.description = description.to_string();
            }
        }
        self.secret = Some(secret);
        Ok(self)
    }

    /// Record why the resource could not be decrypted.
    #[must_use]
    pub fn with_error(mut self, error: &PassboltError) -> Self {
        self.error = Some(error.to_string());
        self
    }

    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.resource.is_v5()
    }

    /// The secret note of v5 types: their secret description.
    #[must_use]
    pub fn note(&self) -> Option<&str> {
        if !self.is_v5() {
            return None;
        }
        self.secret.as_ref()?.get("description")?.as_str()
    }

    /// The fields `--filter` matches, by name.
    #[must_use]
    pub fn fields(&self) -> HashMap<String, String> {
        let date =
            |date: Option<DateTime<Utc>>| date.map(|date| date.to_rfc3339()).unwrap_or_default();
        HashMap::from([
            ("id".into(), self.id.clone()),
            ("name".into(), self.name.clone()),
            ("username".into(), self.username.clone()),
            ("uri".into(), self.uri.clone()),
            ("uris".into(), self.uris.join(" ")),
            ("description".into(), self.description.clone()),
            (
                "folder_parent_id".into(),
                self.folder_parent_id.clone().unwrap_or_default(),
            ),
            (
                "resource_type".into(),
                self.resource_type.clone().unwrap_or_default(),
            ),
            (
                "resource_type_id".into(),
                self.resource_type_id.clone().unwrap_or_default(),
            ),
            ("password".into(), self.password.clone().unwrap_or_default()),
            ("created".into(), date(self.created)),
            ("modified".into(), date(self.modified)),
            ("expired".into(), date(self.expired)),
        ])
    }
}

pub(crate) fn v4_fields(resource: &Resource) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("name".into(), resource.name.clone().into());
    for (key, value) in [
        ("username", &resource.username),
        ("uri", &resource.uri),
        ("description", &resource.description),
    ] {
        if let Some(value) = value {
            fields.insert(key.into(), value.clone().into());
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn view(slug: Option<&str>, metadata: Option<Value>) -> ResourceView {
        let mut resource = json!({"id": "r1", "name": "GitHub"});
        if let Some(slug) = slug {
            resource["resource_type_id"] = format!("{slug}-id").into();
        }
        if metadata.is_some() {
            resource["metadata"] = "-----BEGIN PGP MESSAGE-----".into();
        }
        let types: Vec<ResourceType> = ["password-string", "v5-default"]
            .into_iter()
            .map(|slug| ResourceType {
                id: format!("{slug}-id"),
                slug: slug.into(),
                name: None,
                definition: None,
            })
            .collect();
        let metadata = metadata.map(|metadata| serde_json::from_value(metadata).unwrap());
        ResourceView::new(serde_json::from_value(resource).unwrap(), metadata, &types).unwrap()
    }

    #[test]
    fn test_a_password_string_secret_is_the_password_even_as_json() {
        let view = view(Some("password-string"), None)
            .with_secret("{}")
            .unwrap();

        assert_eq!(view.password.as_deref(), Some("{}"));
    }

    #[test]
    fn test_a_secret_of_an_unknown_type_is_read_as_json() {
        let view = view(None, None).with_secret(r#"{"password":"p"}"#).unwrap();

        assert_eq!(view.password.as_deref(), Some("p"));
    }

    #[test]
    fn test_a_v4_description_in_the_secret_is_not_a_note() {
        let view = view(Some("password-string"), None)
            .with_secret("p")
            .unwrap();

        assert_eq!(view.note(), None);
    }

    #[test]
    fn test_the_v5_secret_description_is_the_note() {
        let metadata = json!({"object_type": "PASSBOLT_RESOURCE_METADATA", "name": "GitHub"});
        let view = view(Some("v5-default"), Some(metadata))
            .with_secret(r#"{"password":"p","description":"a note"}"#)
            .unwrap();

        assert_eq!(view.note(), Some("a note"));
        assert_eq!(view.description, "");
    }

    #[test]
    fn test_with_error_keeps_the_reason() {
        let view = view(None, None).with_error(&PassboltError::Other("no key".into()));

        assert_eq!(view.error.as_deref(), Some("no key"));
    }
}
