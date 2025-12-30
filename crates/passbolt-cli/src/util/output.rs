// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
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

/// Report a write: `Deleted resource <id>`, or `{"id": …, "result": "deleted"}` with `--json`.
pub fn print_done(json: bool, result: &str, entity: &str, id: &str) -> anyhow::Result<()> {
    if json {
        return print_json(&serde_json::json!({ "id": id, "result": result }));
    }
    let mut verb = result.to_string();
    if let Some(first) = verb.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    println!("{verb} {entity} {id}");
    Ok(())
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
