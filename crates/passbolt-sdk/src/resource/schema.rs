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

//! The JSON Schema subset of the resource type definitions served by `/resource-types.json`.
//!
//! The server never sees decrypted metadata or secrets: validating them is the client's job.

use std::sync::OnceLock;

use serde_json::{Map, Value};

/// The definitions of `SlugDefinition.php` in passbolt-pro-api, by slug.
///
/// Bundled like the browser extension does: servers keep the definitions of the
/// release that created each type, some incomplete (`password-string` without `uri`).
const DEFINITIONS: [(&str, &str); 11] = [
    (
        "password-string",
        include_str!("schemas/password-string.json"),
    ),
    (
        "password-and-description",
        include_str!("schemas/password-and-description.json"),
    ),
    (
        "password-description-totp",
        include_str!("schemas/password-description-totp.json"),
    ),
    ("totp", include_str!("schemas/totp.json")),
    ("v5-default", include_str!("schemas/v5-default.json")),
    (
        "v5-password-string",
        include_str!("schemas/v5-password-string.json"),
    ),
    (
        "v5-default-with-totp",
        include_str!("schemas/v5-default-with-totp.json"),
    ),
    (
        "v5-totp-standalone",
        include_str!("schemas/v5-totp-standalone.json"),
    ),
    (
        "v5-custom-fields",
        include_str!("schemas/v5-custom-fields.json"),
    ),
    ("v5-note", include_str!("schemas/v5-note.json")),
    ("v5-pin-code", include_str!("schemas/v5-pin-code.json")),
];

/// The `{resource, secret}` schemas of `slug`; `None` for a type this SDK does not know.
pub fn definition(slug: &str) -> Option<&'static Value> {
    static PARSED: OnceLock<Vec<(&str, Value)>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            DEFINITIONS
                .iter()
                .filter_map(|(slug, json)| Some((*slug, serde_json::from_str(json).ok()?)))
                .collect()
        })
        .iter()
        .find(|(known_slug, _)| *known_slug == slug)
        .map(|(_, definition)| definition)
}

/// Check `value` against `schema`; the error names the first offending field.
///
/// Objects are strict: a property the schema does not declare is an error.
pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    check(schema, value, "")
}

fn check(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let field = if path.is_empty() { "value" } else { path };
    if let Some(alternatives) = schema.get("anyOf").and_then(Value::as_array) {
        return if alternatives
            .iter()
            .any(|alternative| check(alternative, value, path).is_ok())
        {
            Ok(())
        } else {
            Err(format!("{field} does not match any allowed form"))
        };
    }
    if let Some(expected) = schema.get("type").and_then(Value::as_str) {
        if !has_type(value, expected) {
            return Err(format!("{field} must be of type {expected}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Err(format!(
                "{field} must be one of {}",
                Value::from(allowed.clone())
            ));
        }
    }
    match value {
        Value::String(text) => check_string(schema, text, field),
        Value::Number(_) => check_number(schema, value, field),
        Value::Array(items) => check_array(schema, items, path, field),
        Value::Object(properties) => check_object(schema, properties, path),
        _ => Ok(()),
    }
}

fn has_type(value: &Value, expected: &str) -> bool {
    match expected {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn check_string(schema: &Value, text: &str, field: &str) -> Result<(), String> {
    let length = text.chars().count();
    if let Some(max) = count_limit(schema, "maxLength") {
        if length > max {
            return Err(format!("{field} is longer than {max} characters"));
        }
    }
    if let Some(min) = count_limit(schema, "minLength") {
        if length < min {
            return Err(format!("{field} is shorter than {min} characters"));
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        let regex = regex_lite::Regex::new(pattern)
            .map_err(|error| format!("{field}: invalid schema pattern {pattern}: {error}"))?;
        if !regex.is_match(text) {
            return Err(format!("{field} does not match {pattern}"));
        }
    }
    if schema.get("format").and_then(Value::as_str) == Some("uuid")
        && uuid::Uuid::try_parse(text).is_err()
    {
        return Err(format!("{field} must be a UUID"));
    }
    Ok(())
}

fn check_number(schema: &Value, value: &Value, field: &str) -> Result<(), String> {
    let number = value.as_f64().unwrap_or_default();
    if let Some(min) = limit(schema, "minimum") {
        if number < min {
            return Err(format!("{field} must be at least {min}"));
        }
    }
    if let Some(max) = limit(schema, "maximum") {
        if number > max {
            return Err(format!("{field} must be at most {max}"));
        }
    }
    if let Some(max) = limit(schema, "exclusiveMaximum") {
        if number >= max {
            return Err(format!("{field} must be less than {max}"));
        }
    }
    Ok(())
}

fn check_array(schema: &Value, items: &[Value], path: &str, field: &str) -> Result<(), String> {
    if let Some(max) = count_limit(schema, "maxItems") {
        if items.len() > max {
            return Err(format!("{field} has more than {max} items"));
        }
    }
    if let Some(item_schema) = schema.get("items") {
        for (index, item) in items.iter().enumerate() {
            check(item_schema, item, &format!("{path}[{index}]"))?;
        }
    }
    Ok(())
}

fn check_object(schema: &Value, object: &Map<String, Value>, path: &str) -> Result<(), String> {
    let declared = schema.get("properties").and_then(Value::as_object);
    let name_of = |key: &str| {
        if path.is_empty() {
            key.to_string()
        } else {
            format!("{path}.{key}")
        }
    };
    for required in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(required) {
            return Err(format!("{} is required", name_of(required)));
        }
    }
    let Some(declared) = declared else {
        return Ok(());
    };
    for (key, value) in object {
        let property_schema = declared
            .get(key)
            .ok_or_else(|| format!("{} is not allowed by this resource type", name_of(key)))?;
        check(property_schema, value, &name_of(key))?;
    }
    Ok(())
}

fn limit(schema: &Value, keyword: &str) -> Option<f64> {
    schema.get(keyword).and_then(Value::as_f64)
}

fn count_limit(schema: &Value, keyword: &str) -> Option<usize> {
    schema
        .get(keyword)
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_every_bundled_definition_parses() {
        for (slug, _) in DEFINITIONS {
            let definition = definition(slug).unwrap_or_else(|| panic!("{slug} does not parse"));
            assert!(
                definition["resource"].is_object() && !definition["secret"].is_null(),
                "{slug}"
            );
        }
    }

    fn uris_schema() -> Value {
        json!({
            "type": "array",
            "maxItems": 2,
            "items": {"anyOf": [{"type": "string", "maxLength": 5}, {"type": "null"}]}
        })
    }

    #[rstest::rstest]
    #[case::string_too_long(json!({"type": "string", "maxLength": 3}), json!("abcd"), "longer than 3")]
    #[case::characters_not_bytes(json!({"type": "string", "maxLength": 3}), json!("ééé"), "")]
    #[case::wrong_type(json!({"type": "string"}), json!(1), "of type string")]
    #[case::integer(json!({"type": "integer"}), json!(1.5), "of type integer")]
    #[case::enumeration(json!({"enum": ["a"]}), json!("b"), "one of")]
    #[case::pattern(json!({"type": "string", "pattern": "^\\d+$"}), json!("12a"), "does not match")]
    #[case::uuid(json!({"type": "string", "format": "uuid"}), json!("nope"), "UUID")]
    #[case::minimum(json!({"type": "number", "minimum": 6}), json!(5), "at least 6")]
    #[case::exclusive_maximum(json!({"type": "number", "exclusiveMaximum": 9}), json!(9), "less than 9")]
    #[case::any_of_null(uris_schema(), json!([null, "ab"]), "")]
    #[case::any_of_item(uris_schema(), json!(["abcdef"]), "[0] does not match")]
    #[case::max_items(uris_schema(), json!(["a", "b", "c"]), "more than 2 items")]
    fn test_validate(#[case] schema: Value, #[case] value: Value, #[case] expected_error: &str) {
        let result = validate(&schema, &value);

        match result {
            Ok(()) => assert!(
                expected_error.is_empty(),
                "accepted, expected {expected_error}"
            ),
            Err(error) => assert!(
                !expected_error.is_empty() && error.contains(expected_error),
                "{error}"
            ),
        }
    }

    #[test]
    fn test_validate_names_a_missing_required_field() {
        let schema = json!({"type": "object", "required": ["totp"], "properties": {"totp": {}}});

        assert_eq!(
            validate(&schema, &json!({})).unwrap_err(),
            "totp is required"
        );
    }

    #[test]
    fn test_validate_rejects_an_undeclared_field() {
        let schema = json!({"type": "object", "properties": {"name": {"type": "string"}}});

        assert_eq!(
            validate(&schema, &json!({"name": "a", "username": "b"})).unwrap_err(),
            "username is not allowed by this resource type"
        );
    }

    #[test]
    fn test_validate_names_nested_fields() {
        let schema = json!({"type": "object", "properties": {
            "totp": {"type": "object", "properties": {"digits": {"type": "number", "minimum": 6}}}
        }});

        assert_eq!(
            validate(&schema, &json!({"totp": {"digits": 4}})).unwrap_err(),
            "totp.digits must be at least 6"
        );
    }
}
