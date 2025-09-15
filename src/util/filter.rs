/// Simple field-based filter for structured data.
///
/// Syntax: `field=value`, `field~=value` (contains), `field^=value` (starts),
/// `field$=value` (ends with). Case-insensitive comparisons.
#[derive(Debug, Clone)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: String,
}

#[derive(Debug, Clone)]
pub enum FilterOp {
    Eq,
    Contains,
    StartsWith,
    EndsWith,
    NotEq,
}

impl Filter {
    pub fn parse(expr: &str) -> anyhow::Result<Self> {
        // Check operators in descending specificity
        if let Some(pos) = expr.find("~=") {
            return Ok(Self {
                field: expr[..pos].trim().to_lowercase(),
                op: FilterOp::Contains,
                value: expr[pos + 2..].trim().to_string(),
            });
        }
        if let Some(pos) = expr.find("^=") {
            return Ok(Self {
                field: expr[..pos].trim().to_lowercase(),
                op: FilterOp::StartsWith,
                value: expr[pos + 2..].trim().to_string(),
            });
        }
        if let Some(pos) = expr.find("$=") {
            return Ok(Self {
                field: expr[..pos].trim().to_lowercase(),
                op: FilterOp::EndsWith,
                value: expr[pos + 2..].trim().to_string(),
            });
        }
        if let Some(pos) = expr.find("!=") {
            return Ok(Self {
                field: expr[..pos].trim().to_lowercase(),
                op: FilterOp::NotEq,
                value: expr[pos + 2..].trim().to_string(),
            });
        }
        if let Some(pos) = expr.find('=') {
            return Ok(Self {
                field: expr[..pos].trim().to_lowercase(),
                op: FilterOp::Eq,
                value: expr[pos + 1..].trim().to_string(),
            });
        }
        anyhow::bail!("Invalid filter expression: {expr}  (expected: field=value)")
    }

    /// Test a field value string against this filter.
    pub fn matches_str(&self, candidate: &str) -> bool {
        let val = self.value.to_lowercase();
        let cand = candidate.to_lowercase();
        match self.op {
            FilterOp::Eq => cand == val,
            FilterOp::NotEq => cand != val,
            FilterOp::Contains => cand.contains(&val),
            FilterOp::StartsWith => cand.starts_with(&val),
            FilterOp::EndsWith => cand.ends_with(&val),
        }
    }
}

/// Apply multiple filters against a map of field→value strings.
/// All filters must match (AND semantics).
pub fn apply_filters(
    filters: &[Filter],
    fields: &std::collections::HashMap<String, String>,
) -> bool {
    filters.iter().all(|f| {
        fields
            .get(&f.field)
            .map(|v| f.matches_str(v))
            .unwrap_or(false)
    })
}

/// Generic filter: extract a field map per entity via `fields`, then apply `filters`.
///
/// Returns the input unchanged if `filters` is empty.
pub fn filter_entities<T, F>(entities: Vec<T>, filters: &[Filter], fields: F) -> Vec<T>
where
    F: Fn(&T) -> std::collections::HashMap<String, String>,
{
    if filters.is_empty() {
        return entities;
    }
    entities
        .into_iter()
        .filter(|e| apply_filters(filters, &fields(e)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ─── Filter::parse ────────────────────────────────────────────────────────

    #[test]
    fn test_parse_eq() {
        let f = Filter::parse("name=foo").unwrap();
        assert_eq!(f.field, "name");
        assert!(matches!(f.op, FilterOp::Eq));
        assert_eq!(f.value, "foo");
    }

    #[test]
    fn test_parse_contains() {
        let f = Filter::parse("name~=foo").unwrap();
        assert_eq!(f.field, "name");
        assert!(matches!(f.op, FilterOp::Contains));
        assert_eq!(f.value, "foo");
    }

    #[test]
    fn test_parse_startswith() {
        let f = Filter::parse("name^=foo").unwrap();
        assert_eq!(f.field, "name");
        assert!(matches!(f.op, FilterOp::StartsWith));
        assert_eq!(f.value, "foo");
    }

    #[test]
    fn test_parse_endswith() {
        let f = Filter::parse("name$=foo").unwrap();
        assert_eq!(f.field, "name");
        assert!(matches!(f.op, FilterOp::EndsWith));
        assert_eq!(f.value, "foo");
    }

    #[test]
    fn test_parse_noteq() {
        let f = Filter::parse("name!=foo").unwrap();
        assert_eq!(f.field, "name");
        assert!(matches!(f.op, FilterOp::NotEq));
        assert_eq!(f.value, "foo");
    }

    #[test]
    fn test_parse_invalid() {
        assert!(Filter::parse("noop").is_err());
    }

    #[test]
    fn test_parse_field_trimmed_lowercase() {
        let f = Filter::parse("  Name  =bar").unwrap();
        assert_eq!(f.field, "name");
        assert_eq!(f.value, "bar");
    }

    // ─── Filter::matches_str ──────────────────────────────────────────────────

    #[test]
    fn test_matches_eq_case_insensitive() {
        let f = Filter::parse("name=FOO").unwrap();
        assert!(f.matches_str("foo"));
        assert!(f.matches_str("FOO"));
        assert!(!f.matches_str("bar"));
    }

    #[test]
    fn test_matches_contains() {
        let f = Filter::parse("name~=oo").unwrap();
        assert!(f.matches_str("foobar"));
        assert!(!f.matches_str("bar"));
    }

    #[test]
    fn test_matches_startswith() {
        let f = Filter::parse("name^=foo").unwrap();
        assert!(f.matches_str("foobar"));
        assert!(!f.matches_str("barfoo"));
    }

    #[test]
    fn test_matches_endswith() {
        let f = Filter::parse("name$=bar").unwrap();
        assert!(f.matches_str("foobar"));
        assert!(!f.matches_str("barfoo"));
    }

    #[test]
    fn test_matches_not_eq() {
        let f = Filter::parse("name!=foo").unwrap();
        assert!(f.matches_str("bar"));
        assert!(!f.matches_str("foo"));
    }

    // ─── filter_entities ─────────────────────────────────────────────────────

    fn make_fields(name: &str) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("name".into(), name.into());
        m
    }

    #[test]
    fn test_filter_entities_empty_filters_returns_all() {
        let items = vec!["alpha", "beta", "gamma"];
        let result = filter_entities(items.clone(), &[], |s| make_fields(s));
        assert_eq!(result, items);
    }

    #[test]
    fn test_filter_entities_no_match() {
        let items = vec!["alpha", "beta"];
        let f = Filter::parse("name=zzz").unwrap();
        let result = filter_entities(items, &[f], |s| make_fields(s));
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_entities_partial_match() {
        let items = vec!["alpha", "beta", "alphabet"];
        let f = Filter::parse("name^=alpha").unwrap();
        let result = filter_entities(items, &[f], |s| make_fields(s));
        assert_eq!(result, vec!["alpha", "alphabet"]);
    }

    #[test]
    fn test_filter_entities_multiple_filters_and_semantics() {
        let items = vec!["foobar", "foo", "bar", "foobaz"];
        let f1 = Filter::parse("name^=foo").unwrap();
        let f2 = Filter::parse("name$=bar").unwrap();
        let result = filter_entities(items, &[f1, f2], |s| make_fields(s));
        // Only "foobar" starts with "foo" AND ends with "bar"
        assert_eq!(result, vec!["foobar"]);
    }
}
