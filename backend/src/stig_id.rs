//! The one rule for STIG ids, used wherever one is created or read.
//!
//! A valid id is 1..=128 bytes of ASCII alphanumerics and `-`. Reads accept
//! either case so catalogs created before the lower-case rule keep working;
//! newly created ids (upload, library import, sync) must also be lower case.

/// Longest accepted STIG id, in bytes.
pub const MAX_BYTES: usize = 128;

/// Read rule: non-empty, at most [`MAX_BYTES`], ASCII alphanumerics and `-`.
pub fn is_valid(id: &str) -> bool {
    !id.is_empty() && id.len() <= MAX_BYTES && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Create rule: [`is_valid`] and no upper-case letters.
pub fn is_valid_new(id: &str) -> bool {
    is_valid(id) && !id.bytes().any(|b| b.is_ascii_uppercase())
}

/// How many offending ids the startup warning lists before "and N more".
const WARN_LIST_CAP: usize = 50;

/// Build the startup warning text from `(source, id)` rows, or `None` when
/// every id conforms. Lists at most [`WARN_LIST_CAP`] ids, each truncated.
pub fn warning_message(rows: &[(String, String)]) -> Option<String> {
    let bad: Vec<String> = rows
        .iter()
        .filter(|(_, id)| !is_valid(id))
        .map(|(src, id)| format!("{src}:{:?}", id.chars().take(64).collect::<String>()))
        .collect();
    if bad.is_empty() {
        return None;
    }
    let mut list = bad.iter().take(WARN_LIST_CAP).cloned().collect::<Vec<_>>().join(", ");
    if bad.len() > WARN_LIST_CAP {
        list.push_str(&format!(" and {} more", bad.len() - WARN_LIST_CAP));
    }
    Some(format!(
        "{} STIG id(s) do not match the id rule (ASCII alphanumerics and '-', 1-{MAX_BYTES} bytes) \
         and cannot be read until re-uploaded: {list}",
        bad.len()
    ))
}

/// Log a startup warning listing catalog and checklist ids that fail the
/// read rule. Nothing is migrated or renamed.
pub async fn warn_non_conforming(pool: &sqlx::PgPool) {
    let rows: Result<Vec<(String, String)>, _> = sqlx::query_as(
        "SELECT 'catalog', id FROM stigs_catalog
         UNION
         SELECT DISTINCT 'checklist', stig_id FROM checklists
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => {
            if let Some(msg) = warning_message(&rows) {
                tracing::warn!("{msg}");
            }
        }
        Err(e) => tracing::warn!("could not check STIG ids against the id rule: {e:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_rule_table() {
        assert!(!is_valid(""));
        assert!(is_valid(&"a".repeat(128)));
        assert!(!is_valid(&"a".repeat(129)));
        for bad in ["a/b", "a.b", "a b", "é", "../x", "a_b"] {
            assert!(!is_valid(bad), "{bad}");
        }
        assert!(is_valid("Windows-10"));
        assert!(is_valid("edge"));
    }

    #[test]
    fn create_rule_rejects_upper_case() {
        assert!(is_valid_new("windows-10"));
        assert!(!is_valid_new("Windows-10"));
        assert!(!is_valid_new(""));
    }

    #[test]
    fn warning_message_is_none_when_all_conform() {
        assert_eq!(warning_message(&[("catalog".into(), "ok".into())]), None);
    }

    #[test]
    fn warning_message_lists_and_caps() {
        let mut rows = vec![("checklist".to_string(), "\u{e9}".to_string()), ("catalog".into(), "fine".into())];
        let m = warning_message(&rows).expect("message");
        assert!(m.starts_with("1 STIG id(s)") && m.contains("checklist:") && !m.contains("fine"), "{m}");
        rows.extend((0..59).map(|i| ("catalog".to_string(), format!("bad.{i}"))));
        let m = warning_message(&rows).expect("message");
        assert!(m.starts_with("60 STIG id(s)") && m.ends_with("and 10 more"), "{m}");
    }
}
