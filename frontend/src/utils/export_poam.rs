use super::cci_map::cci_info;
use super::parse_xccdf::js_trim;
use crate::model::{AssetInfo, Stig};

const POAM_HEADERS: [&str; 16] = [
    "Control Vulnerability ID",
    "Office / Org",
    "Security Control Number (800-53)",
    "Weakness Name",
    "Weakness Description",
    "Weakness Detector Source",
    "Weakness Source Identifier",
    "Asset Identifier",
    "Point of Contact",
    "Resources Required",
    "Scheduled Completion Date",
    "Milestone with Completion Dates",
    "Milestone Changes",
    "Source Identifying Control Vulnerability",
    "Status",
    "Comments",
];

type PoamRow = [String; 16];

/// Maps a rule's CCI IDs to their SP 800-53 control references: the distinct
/// mapped controls in first-seen order, comma-joined (unmapped CCIs are skipped).
fn resolve_control(cci_ids: &[String]) -> String {
    let mut unique: Vec<&str> = Vec::new();
    for control in cci_ids
        .iter()
        .filter_map(|id| cci_info(id))
        .map(|info| info.control)
    {
        if !control.is_empty() && !unique.contains(&control) {
            unique.push(control);
        }
    }
    unique.join(", ")
}

/// Quote a CSV field only when it contains a comma, quote or newline.
fn csv_field(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

fn build_rows(stig: &Stig, asset: &AssetInfo, include_non_reviewed: bool) -> Vec<PoamRow> {
    stig.rules
        .iter()
        .filter(|r| {
            if r.status == "not_a_finding" || r.status == "not_applicable" {
                return false;
            }
            include_non_reviewed || r.status == "open"
        })
        .map(|r| {
            let version = if stig.version.is_empty() {
                String::new()
            } else {
                format!("v{}", stig.version)
            };
            let source = format!("{} {} {}", stig.title, version, stig.release_info);
            [
                r.stig_id.clone(),
                asset.hostname.clone(),
                resolve_control(&r.cci_ids),
                r.title.clone(),
                r.description.clone(),
                format!("DISA STIG: {}", stig.title),
                r.id.clone(),
                asset.hostname.clone(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                js_trim(&source).to_string(),
                if r.status == "open" {
                    "Ongoing"
                } else {
                    "Submitted"
                }
                .to_string(),
                r.comments.clone(),
            ]
        })
        .collect()
}

fn csv_line<S: AsRef<str>>(fields: &[S]) -> String {
    fields
        .iter()
        .map(|f| csv_field(f.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

/// A JSON string literal, escaped the way `JSON.stringify` does.
fn json_string(s: &str) -> String {
    serde_json::Value::from(s).to_string()
}

/// Generates a POAM CSV string. `include_non_reviewed` adds Not Reviewed
/// findings to the Open ones.
pub fn export_poam_csv(stig: &Stig, asset: &AssetInfo, include_non_reviewed: bool) -> String {
    let rows = build_rows(stig, asset, include_non_reviewed);
    let header = csv_line(&POAM_HEADERS);
    let body = rows
        .iter()
        .map(|row| csv_line(row))
        .collect::<Vec<_>>()
        .join("\n");
    format!("{header}\n{body}")
}

/// Generates the POAM as a JSON array of objects keyed by the POAM column
/// headers (in column order), pretty-printed with two-space indentation —
/// i.e. the text of `JSON.stringify(exportPOAMJSON(...), null, 2)`.
pub fn export_poam_json(stig: &Stig, asset: &AssetInfo, include_non_reviewed: bool) -> String {
    let rows = build_rows(stig, asset, include_non_reviewed);
    if rows.is_empty() {
        return "[]".to_string();
    }
    let objects: Vec<String> = rows
        .iter()
        .map(|row| {
            let members: Vec<String> = POAM_HEADERS
                .iter()
                .zip(row)
                .map(|(header, value)| {
                    format!("    {}: {}", json_string(header), json_string(value))
                })
                .collect();
            format!("  {{\n{}\n  }}", members.join(",\n"))
        })
        .collect();
    format!("[\n{}\n]", objects.join(",\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::sample_stig::generate_sample_stig;
    use crate::model::Rule;

    const HEADER: &str = "Control Vulnerability ID,Office / Org,Security Control Number (800-53),\
        Weakness Name,Weakness Description,Weakness Detector Source,Weakness Source Identifier,\
        Asset Identifier,Point of Contact,Resources Required,Scheduled Completion Date,\
        Milestone with Completion Dates,Milestone Changes,Source Identifying Control Vulnerability,\
        Status,Comments";

    fn asset(hostname: &str) -> AssetInfo {
        AssetInfo {
            hostname: hostname.into(),
            ..AssetInfo::default()
        }
    }

    fn rule(stig_id: &str, status: &str) -> Rule {
        Rule {
            id: format!("SV-{stig_id}"),
            stig_id: stig_id.into(),
            title: format!("Title {stig_id}"),
            description: "Desc".into(),
            status: status.into(),
            ..Rule::default()
        }
    }

    #[test]
    fn csv_field_quotes_only_when_needed() {
        assert_eq!(csv_field("plain text"), "plain text");
        assert_eq!(csv_field(""), "");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("line 1\nline 2"), "\"line 1\nline 2\"");
        // Carriage returns, semicolons, tabs and leading spaces do not trigger quoting.
        assert_eq!(csv_field("a\rb;c\td"), "a\rb;c\td");
        assert_eq!(csv_field(" padded "), " padded ");
    }

    #[test]
    fn resolve_control_dedupes_in_first_seen_order_and_skips_unmapped() {
        let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(resolve_control(&[]), "");
        assert_eq!(resolve_control(&ids(&["CCI-999999"])), "");
        // CCI-000015 and CCI-000010 both map to AC-2(c).
        assert_eq!(
            resolve_control(&ids(&[
                "CCI-000015",
                "CCI-000010",
                "CCI-999999",
                "CCI-000040"
            ])),
            "AC-2(c), AC-3"
        );
    }

    #[test]
    fn csv_has_header_only_when_nothing_matches() {
        let stig = Stig {
            rules: vec![rule("V-1", "not_a_finding")],
            ..Stig::default()
        };
        assert_eq!(
            export_poam_csv(&stig, &asset("h"), true),
            format!("{HEADER}\n")
        );
        assert_eq!(export_poam_json(&stig, &asset("h"), true), "[]");
    }

    #[test]
    fn filters_by_status() {
        let stig = Stig {
            rules: vec![
                rule("V-1", "open"),
                rule("V-2", "not_reviewed"),
                rule("V-3", "not_a_finding"),
                rule("V-4", "not_applicable"),
            ],
            ..Stig::default()
        };
        let ids = |include| {
            build_rows(&stig, &asset(""), include)
                .iter()
                .map(|r| r[0].clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(false), vec!["V-1"]);
        assert_eq!(ids(true), vec!["V-1", "V-2"]);
        assert_eq!(build_rows(&stig, &asset(""), true)[0][14], "Ongoing");
        assert_eq!(build_rows(&stig, &asset(""), true)[1][14], "Submitted");
    }

    #[test]
    fn csv_rows_are_quoted_and_ordered_exactly() {
        let mut open = rule("V-1", "open");
        open.title = "Enforce, \"strictly\"".into();
        open.description = "Line 1\nLine 2".into();
        open.cci_ids = vec!["CCI-000040".into()];
        open.comments = "ok".into();
        let stig = Stig {
            title: "My STIG".into(),
            version: "3".into(),
            release_info: "Release: 1".into(),
            rules: vec![open, rule("V-2", "not_reviewed")],
            ..Stig::default()
        };
        let csv = export_poam_csv(&stig, &asset("web,01"), true);
        let expected = format!(
            "{HEADER}\n\
             V-1,\"web,01\",AC-3,\"Enforce, \"\"strictly\"\"\",\"Line 1\nLine 2\",DISA STIG: My STIG,SV-V-1,\"web,01\",,,,,,My STIG v3 Release: 1,Ongoing,ok\n\
             V-2,\"web,01\",,Title V-2,Desc,DISA STIG: My STIG,SV-V-2,\"web,01\",,,,,,My STIG v3 Release: 1,Submitted,"
        );
        assert_eq!(csv, expected);
    }

    #[test]
    fn source_column_keeps_inner_gaps_but_trims_the_ends() {
        let stig = Stig {
            title: "T".into(),
            rules: vec![rule("V-1", "open")],
            ..Stig::default()
        };
        assert_eq!(build_rows(&stig, &asset(""), false)[0][13], "T");
        let stig = Stig {
            release_info: "R1".into(),
            ..stig
        };
        assert_eq!(build_rows(&stig, &asset(""), false)[0][13], "T  R1");
    }

    #[test]
    fn json_is_pretty_printed_in_header_order() {
        let mut open = rule("V-1", "open");
        open.comments = "say \"hi\"\n\ttab \\ é \u{1}".into();
        let stig = Stig {
            title: "S".into(),
            rules: vec![open],
            ..Stig::default()
        };
        let expected = r#"[
  {
    "Control Vulnerability ID": "V-1",
    "Office / Org": "host",
    "Security Control Number (800-53)": "",
    "Weakness Name": "Title V-1",
    "Weakness Description": "Desc",
    "Weakness Detector Source": "DISA STIG: S",
    "Weakness Source Identifier": "SV-V-1",
    "Asset Identifier": "host",
    "Point of Contact": "",
    "Resources Required": "",
    "Scheduled Completion Date": "",
    "Milestone with Completion Dates": "",
    "Milestone Changes": "",
    "Source Identifying Control Vulnerability": "S",
    "Status": "Ongoing",
    "Comments": "say \"hi\"\n\ttab \\ é \u0001"
  }
]"#;
        assert_eq!(export_poam_json(&stig, &asset("host"), false), expected);
    }

    #[test]
    fn sample_stig_exports_its_single_open_finding() {
        let stig = generate_sample_stig();
        let csv = export_poam_csv(&stig, &asset("web01"), false);
        let lines: Vec<&str> = csv.split('\n').collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("V-1006,web01,AC-2(c),"));
        assert!(lines[1].ends_with(
            ",Sample STIG - Web Application Security (Demo) v3 Release: 1 Benchmark Date: 19 Feb 2026,Ongoing,Planned fix in next sprint."
        ));
        let json: serde_json::Value =
            serde_json::from_str(&export_poam_json(&stig, &asset("web01"), true)).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 10); // 1 open + 9 not reviewed
    }
}
