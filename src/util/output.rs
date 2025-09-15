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
        .set_header(columns.iter().map(|c| Cell::new(c).fg(Color::Cyan)));

    for row in rows {
        let safe_row: Vec<String> = row.into_iter().map(|v| strip_control_chars(&v)).collect();
        table.add_row(safe_row);
    }
    println!("{table}");
}

/// Remove ASCII control characters (0x00–0x1F and 0x7F) from a string.
/// Prevents terminal escape injection from resource names/values.
fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Print any serializable value as pretty JSON.
pub fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}

/// Convert a display column name to a JSON field name (snake_case).
///
/// Handles the common Passbolt column name conventions used in table output.
fn column_to_field(col: &str) -> String {
    // Map known display names → JSON field names
    match col.to_lowercase().as_str() {
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

fn camel_to_snake(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, ch) in s.char_indices() {
        if ch.is_uppercase() && i > 0 {
            out.push('_');
        }
        for c in ch.to_lowercase() {
            out.push(c);
        }
    }
    out
}

/// Print a list of serializable values as pretty JSON, filtered to the given columns.
///
/// If `columns` is empty the full objects are printed (no filtering).
pub fn print_json_with_columns<T: Serialize>(
    values: &[T],
    columns: &[String],
) -> anyhow::Result<()> {
    if columns.is_empty() {
        let json = serde_json::to_string_pretty(values)?;
        println!("{json}");
        return Ok(());
    }

    let fields: Vec<String> = columns.iter().map(|c| column_to_field(c)).collect();

    let filtered: Vec<serde_json::Value> = values
        .iter()
        .map(|v| {
            let obj = serde_json::to_value(v).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(map) = obj {
                let filtered_map: serde_json::Map<String, serde_json::Value> = fields
                    .iter()
                    .filter_map(|f| map.get(f).map(|val| (f.clone(), val.clone())))
                    .collect();
                serde_json::Value::Object(filtered_map)
            } else {
                serde_json::Value::Object(serde_json::Map::new())
            }
        })
        .collect();

    let json = serde_json::to_string_pretty(&filtered)?;
    println!("{json}");
    Ok(())
}

/// Print key-value pairs.
pub fn print_kv(pairs: &[(&str, &str)]) {
    for (k, v) in pairs {
        println!("{}: {}", k.bold(), v);
    }
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
    fn test_columns_empty_returns_ok() {
        let items = make_items();
        assert!(print_json_with_columns(&items, &[]).is_ok());
    }

    #[test]
    fn test_columns_subset_returns_ok() {
        let items = make_items();
        let cols = vec!["id".to_string(), "name".to_string()];
        assert!(print_json_with_columns(&items, &cols).is_ok());
    }

    #[test]
    fn test_columns_unknown_returns_ok() {
        let items = make_items();
        let cols = vec!["nonexistent_column".to_string()];
        assert!(print_json_with_columns(&items, &cols).is_ok());
    }
}
