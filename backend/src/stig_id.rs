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

/// Ids in `ids` that fail the read rule.
pub fn non_conforming<'a>(ids: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    ids.into_iter().filter(|i| !is_valid(i)).collect()
}

/// Log a startup warning listing catalog and checklist ids that fail the
/// read rule. Nothing is migrated or renamed.
pub async fn warn_non_conforming(pool: &sqlx::PgPool) {
    let rows: Result<Vec<(String, String)>, _> = sqlx::query_as(
        "SELECT 'catalog', id FROM stigs_catalog
         UNION
         SELECT 'checklist', stig_id FROM checklists
         ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => {
            let bad_ids = non_conforming(rows.iter().map(|(_, id)| id.as_str()));
            let bad: Vec<String> = rows
                .iter()
                .filter(|(_, id)| bad_ids.contains(&id.as_str()))
                .map(|(src, id)| format!("{src}:{:?}", id.chars().take(64).collect::<String>()))
                .collect();
            if !bad.is_empty() {
                tracing::warn!(
                    "{} STIG id(s) do not match the id rule (ASCII alphanumerics and '-', 1-{} bytes) \
                     and cannot be read until re-uploaded: {}",
                    bad.len(),
                    MAX_BYTES,
                    bad.join(", ")
                );
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
    fn non_conforming_lists_bad_ids() {
        assert_eq!(non_conforming(["ok", "é", "", "Ok-1"]), ["é", ""]);
    }
}
