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

use colored::Colorize;
use comfy_table::{Cell, Color, ContentArrangement, Table};
use serde::Serialize;

/// Print data as a formatted table.
/// `columns` — column headers, `rows` — each row as Vec<String>.
///
/// Cell values are stripped of ASCII control characters to prevent terminal injection.
pub fn print_table(columns: &[&str], rows: Vec<Vec<String>>) {
    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(
            columns
                .iter()
                .map(|column| Cell::new(column).fg(Color::Cyan)),
        );

    for row in rows {
        let safe_row: Vec<String> = row
            .into_iter()
            .map(|cell| strip_control_chars(&cell))
            .collect();
        table.add_row(safe_row);
    }
    println!("{table}");
}

/// Remove ASCII control characters (0x00–0x1F and 0x7F) from a string.
/// Prevents terminal escape injection from resource names/values.
fn strip_control_chars(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .collect()
}

/// Print any serializable value as pretty JSON.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

/// Convert a display column name to a JSON field name (`snake_case`).
///
/// Handles the common Passbolt column name conventions used in table output.
fn column_to_field(column: &str) -> String {
    // Map known display names → JSON field names
    match column.to_lowercase().as_str() {
        "id" => "id".into(),
        "name" => "name".into(),
        "username" => "username".into(),
        "uri" | "url" => "uri".into(),
        "description" => "description".into(),
        "folderparentid" | "folder_parent_id" | "parent id" | "parent" => "folder_parent_id".into(),
        "created" => "created".into(),
        "modified" => "modified".into(),
        "created_by" | "createdby" => "created_by".into(),
        "modified_by" | "modifiedby" => "modified_by".into(),
        "personal" => "personal".into(),
        "expired" | "expiry" => "expired".into(),
        "resource_type_id" | "resourcetypeid" | "type" => "resource_type_id".into(),
        "members" => "groups_users".into(),
        "role" => "role".into(),
        "active" => "active".into(),
        "deleted" => "deleted".into(),
        // Fallback: convert CamelCase/PascalCase to snake_case
        other => camel_to_snake(other),
    }
}

fn camel_to_snake(text: &str) -> String {
    let mut snake = String::with_capacity(text.len() + 4);
    for (i, character) in text.char_indices() {
        if character.is_uppercase() && i > 0 {
            snake.push('_');
        }
        for lowercase in character.to_lowercase() {
            snake.push(lowercase);
        }
    }
    snake
}

/// Print a list of serializable values as pretty JSON, filtered to the given columns.
///
/// If `columns` is empty the full objects are printed (no filtering).
pub fn print_json_with_columns<T: Serialize>(
    values: &[T],
    columns: &[String],
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(&select_columns(values, columns)?)?;
    println!("{json}");
    Ok(())
}

/// Serialize `values`, keeping only the fields named by `columns` (all of them if empty).
fn select_columns<T: Serialize>(
    values: &[T],
    columns: &[String],
) -> anyhow::Result<serde_json::Value> {
    let serialized = serde_json::to_value(values)?;
    if columns.is_empty() {
        return Ok(serialized);
    }

    let fields: Vec<String> = columns
        .iter()
        .map(|column| column_to_field(column))
        .collect();

    let serde_json::Value::Array(items) = serialized else {
        return Ok(serialized);
    };
    let filtered = items
        .into_iter()
        .map(|item| {
            let serde_json::Value::Object(map) = item else {
                return serde_json::Value::Object(serde_json::Map::new());
            };
            let filtered_map: serde_json::Map<String, serde_json::Value> = fields
                .iter()
                .filter_map(|field| {
                    map.get(field)
                        .map(|field_value| (field.clone(), field_value.clone()))
                })
                .collect();
            serde_json::Value::Object(filtered_map)
        })
        .collect();
    Ok(serde_json::Value::Array(filtered))
}

/// Print key-value pairs, stripped of control characters like table cells.
pub fn print_kv(pairs: &[(&str, &str)]) {
    for (key, value) in pairs {
        println!("{}", format_kv(key, value));
    }
}

fn format_kv(key: &str, value: &str) -> String {
    format!(
        "{}: {}",
        strip_control_chars(key).bold(),
        strip_control_chars(value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    // ─── strip_control_chars ──────────────────────────────────────────────────

    #[test]
    fn test_strip_control_chars_removes_escape() {
        // \x1b (ESC, 0x1B) is a control char and is removed;
        // the printable chars that follow it ("[31m") are kept as-is.
        assert_eq!(strip_control_chars("\x1b[31mred\x1b[0m"), "[31mred[0m");
    }

    #[test]
    fn test_strip_control_chars_removes_null_and_tab() {
        assert_eq!(strip_control_chars("a\x00b\tc"), "abc");
    }

    #[test]
    fn test_strip_control_chars_passthrough_normal() {
        assert_eq!(strip_control_chars("hello world"), "hello world");
    }

    // ─── camel_to_snake ───────────────────────────────────────────────────────

    #[test]
    fn test_camel_to_snake_converts() {
        assert_eq!(camel_to_snake("FolderParentId"), "folder_parent_id");
        assert_eq!(camel_to_snake("createdBy"), "created_by");
        assert_eq!(camel_to_snake("id"), "id");
    }

    // ─── column_to_field ─────────────────────────────────────────────────────

    #[test]
    fn test_column_to_field_known_names() {
        assert_eq!(column_to_field("id"), "id");
        assert_eq!(column_to_field("URI"), "uri");
        assert_eq!(column_to_field("FolderParentID"), "folder_parent_id");
        assert_eq!(column_to_field("Members"), "groups_users");
    }

    // ─── print_json_with_columns ─────────────────────────────────────────────

    #[derive(Serialize)]
    struct Item {
        id: String,
        name: String,
        secret: String,
    }

    fn make_items() -> Vec<Item> {
        vec![Item {
            id: "abc".into(),
            name: "Test".into(),
            secret: "s3cr3t".into(),
        }]
    }

    #[test]
    fn test_select_columns_without_columns_keeps_every_field() {
        let selected = select_columns(&make_items(), &[]).unwrap();

        assert_eq!(
            selected,
            serde_json::json!([{"id": "abc", "name": "Test", "secret": "s3cr3t"}])
        );
    }

    #[test]
    fn test_select_columns_keeps_only_the_given_columns() {
        let columns = vec!["id".to_string(), "Name".to_string()];

        let selected = select_columns(&make_items(), &columns).unwrap();

        assert_eq!(selected, serde_json::json!([{"id": "abc", "name": "Test"}]));
    }

    #[test]
    fn test_select_columns_skips_an_unknown_column() {
        let columns = vec!["id".to_string(), "nonexistent_column".to_string()];

        let selected = select_columns(&make_items(), &columns).unwrap();

        assert_eq!(selected, serde_json::json!([{"id": "abc"}]));
    }

    #[test]
    fn test_select_columns_maps_members_to_groups_users() {
        let groups = vec![serde_json::json!({
            "id": "group",
            "groups_users": [{"user_id": "ada"}],
            "secret": "s3cr3t"
        })];
        let columns = vec!["Members".to_string()];

        let selected = select_columns(&groups, &columns).unwrap();

        assert_eq!(
            selected,
            serde_json::json!([{"groups_users": [{"user_id": "ada"}]}])
        );
    }

    // ─── print_kv ────────────────────────────────────────────────────────────

    #[test]
    fn test_format_kv_strips_control_characters_from_the_value() {
        let line = format_kv("Name", "\x1b[31mred\x07");

        assert!(line.ends_with(": [31mred"), "{line:?}");
        assert!(!line.contains("\x1b[31m"), "{line:?}");
    }

    #[test]
    fn test_format_kv_strips_control_characters_from_the_key() {
        let line = format_kv("Na\x1b]0;title\x07me", "value");

        assert!(!line.contains("\x1b]0;"), "{line:?}");
        assert!(line.contains("Na]0;titleme"), "{line:?}");
    }
}
