use crate::model::{Rule, Stig};

#[allow(clippy::too_many_arguments)]
fn rule(
    id: &str,
    stig_id: &str,
    group_id: &str,
    title: &str,
    severity: &str,
    description: &str,
    fix_text: &str,
    check_text: &str,
    cci_ids: &[&str],
    status: &str,
    finding_details: &str,
    comments: &str,
) -> Rule {
    Rule {
        id: id.into(),
        stig_id: stig_id.into(),
        group_id: group_id.into(),
        title: title.into(),
        severity: severity.into(),
        description: description.into(),
        fix_text: fix_text.into(),
        check_text: check_text.into(),
        cci_ids: cci_ids.iter().map(|c| c.to_string()).collect(),
        status: status.into(),
        finding_details: finding_details.into(),
        comments: comments.into(),
        extra: Default::default(),
    }
}

/// Built-in demo STIG for the "Load sample" button.
pub fn generate_sample_stig() -> Stig {
    Stig {
        title: "Sample STIG - Web Application Security (Demo)".into(),
        description: "Demonstration STIG for testing the Web STIG Tools".into(),
        version: "3".into(),
        release_info: "Release: 1 Benchmark Date: 19 Feb 2026".into(),
        rules: vec![
            rule(
                "SV-1001r1_rule",
                "V-1001",
                "SRG-APP-000001",
                "The application must enforce approved authorizations for logical access to information and system resources.",
                "CAT I",
                "Authentication to the application must be performed using DoD PKI certificates. Applications must validate user identity via CAC/PIV before granting access to any system resources.",
                "Configure the application to require CAC/PIV authentication for all user access. Ensure the application validates the certificate chain against a trusted DoD CA.",
                "Verify the application requires CAC/PIV for authentication.\n\nIf the application allows password-based authentication or does not validate DoD certificates, this is a finding.",
                &["CCI-000213"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1002r1_rule",
                "V-1002",
                "SRG-APP-000002",
                "The application must implement cryptographic mechanisms to protect the integrity of session tokens.",
                "CAT I",
                "Session tokens must be generated using FIPS 140-2/3 validated cryptographic modules with a minimum of 128 bits of entropy.",
                "Configure the application to generate session tokens using FIPS-validated cryptographic modules. Implement secure cookie attributes (HttpOnly, Secure, SameSite).",
                "Review the application session management configuration.\n\nVerify session tokens are generated using FIPS-validated modules.\nVerify tokens contain at least 128 bits of entropy.\n\nIf not, this is a finding.",
                &["CCI-000068"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1003r1_rule",
                "V-1003",
                "SRG-APP-000003",
                "The application must use TLS 1.2 or higher for all network communications.",
                "CAT I",
                "All data transmitted between the application and clients must be encrypted using TLS 1.2 or TLS 1.3. Legacy protocols must be disabled.",
                "Configure the web server to only accept TLS 1.2 and TLS 1.3. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Configure CNSA 2.0 compliant cipher suites.",
                "Verify TLS configuration:\n\nRun: nmap --script ssl-enum-ciphers -p 443 <hostname>\n\nIf TLS 1.0 or 1.1 is enabled, this is a finding.",
                &["CCI-000197", "CCI-002420"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1004r1_rule",
                "V-1004",
                "SRG-APP-000015",
                "The application must enforce password complexity requirements.",
                "CAT II",
                "When password-based authentication is used, passwords must meet minimum complexity: 15 characters minimum, uppercase/lowercase/numeric/special characters.",
                "Configure the application password policy to require a minimum of 15 characters with complexity requirements.",
                "Review the application password policy.\n\nIf password minimum length is less than 15 characters or complexity is not enforced, this is a finding.",
                &["CCI-000192", "CCI-000193"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1005r1_rule",
                "V-1005",
                "SRG-APP-000033",
                "The application must enforce approved authorizations for controlling the flow of information.",
                "CAT II",
                "The application must implement network segmentation consistent with the DAF macrosegmentation plan.",
                "Implement network segmentation per DAF Base Area Network standards. Configure firewall rules between security zones.",
                "Review network segmentation configuration.\n\nVerify traffic between zones is filtered and logged.\n\nIf not, this is a finding.",
                &["CCI-001368"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1006r1_rule",
                "V-1006",
                "SRG-APP-000039",
                "The application must generate audit records for all account creation activities.",
                "CAT II",
                "The application must produce audit records when user accounts are created, including identity of creator, date/time, and account type.",
                "Configure the application to generate audit records for all account creation events.",
                "Create a test account and verify an audit record is generated.\n\nIf no audit record is generated, this is a finding.",
                &["CCI-000015"],
                "open",
                "Audit records are not generated for account creation events in the current deployment.",
                "Planned fix in next sprint.",
            ),
            rule(
                "SV-1007r1_rule",
                "V-1007",
                "SRG-APP-000065",
                "The application must enforce a minimum 15-minute lock after 3 consecutive invalid login attempts.",
                "CAT II",
                "The application must implement account lockout after 3 consecutive failed login attempts for a minimum of 15 minutes.",
                "Configure the application to lock accounts after 3 consecutive failed login attempts for 15 minutes.",
                "Attempt to log in with incorrect credentials 3 times.\n\nVerify the account is locked for at least 15 minutes.\n\nIf not, this is a finding.",
                &["CCI-000044"],
                "not_a_finding",
                "Verified account lockout triggers after 3 failed attempts with a 15-minute lockout period.",
                "",
            ),
            rule(
                "SV-1008r1_rule",
                "V-1008",
                "SRG-APP-000095",
                "The application must produce audit records containing sufficient information to establish what occurred.",
                "CAT II",
                "Audit records must contain event type, timestamp, source, outcome, and user identity.",
                "Configure application logging to include all required fields. Forward logs to a centralized SIEM.",
                "Review sample audit log entries.\n\nVerify each entry contains: event type, timestamp, source IP, outcome, and user identity.\n\nIf any fields are missing, this is a finding.",
                &["CCI-000130", "CCI-000131", "CCI-000132"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1009r1_rule",
                "V-1009",
                "SRG-APP-000141",
                "The application must implement NIST FIPS-validated cryptography for data at rest.",
                "CAT II",
                "Data at rest must be encrypted using FIPS 140-2/3 validated cryptographic modules. AES-256 is the minimum acceptable algorithm.",
                "Configure the application to use AES-256 via FIPS-validated cryptographic modules for all data at rest.",
                "Verify data-at-rest encryption configuration.\n\nVerify FIPS mode is enabled and AES-256 is used.\n\nIf not, this is a finding.",
                &["CCI-001199"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1010r1_rule",
                "V-1010",
                "SRG-APP-000175",
                "The application must support IPv6 per DAF IPv6 transition requirements.",
                "CAT III",
                "Applications must support dual-stack or IPv6-only operation. IPv6 security controls must be equivalent to IPv4.",
                "Enable IPv6 support. Configure dual-stack listeners. Ensure security controls apply equally to IPv6 traffic.",
                "Verify the application listens on IPv6 addresses.\n\nIf the application does not support IPv6, this is a finding.",
                &["CCI-000366"],
                "not_applicable",
                "",
                "System is IPv4-only per approved network design document.",
            ),
            rule(
                "SV-1011r1_rule",
                "V-1011",
                "SRG-APP-000190",
                "The application must terminate user sessions after 15 minutes of inactivity.",
                "CAT III",
                "The application must automatically terminate sessions after 15 minutes of user inactivity.",
                "Configure session timeout to 15 minutes. Implement server-side session expiration and client-side timeout notification.",
                "Log in and remain idle for 15 minutes.\n\nVerify the session is terminated.\n\nIf the session remains active after 15 minutes, this is a finding.",
                &["CCI-001133"],
                "not_reviewed",
                "",
                "",
            ),
            rule(
                "SV-1012r1_rule",
                "V-1012",
                "SRG-APP-000211",
                "The application must display an approved DoD notice and consent banner.",
                "CAT III",
                "The application must display the Standard Mandatory DoD Notice and Consent Banner and require acknowledgment.",
                "Configure the application to display the DoD Notice and Consent Banner at login. Require the user to click 'I Agree' before access.",
                "Access the application login page.\n\nVerify the DoD Notice and Consent Banner is displayed and acknowledgment is required.\n\nIf not, this is a finding.",
                &["CCI-001384", "CCI-001385"],
                "not_reviewed",
                "",
                "",
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_the_demo_header() {
        let s = generate_sample_stig();
        assert_eq!(s.title, "Sample STIG - Web Application Security (Demo)");
        assert_eq!(
            s.description,
            "Demonstration STIG for testing the Web STIG Tools"
        );
        assert_eq!(s.version, "3");
        assert_eq!(s.release_info, "Release: 1 Benchmark Date: 19 Feb 2026");
    }

    #[test]
    fn has_the_expected_rules() {
        let s = generate_sample_stig();
        assert_eq!(s.rules.len(), 12);
        let count = |v: &str| s.rules.iter().filter(|r| r.status == v).count();
        assert_eq!(count("not_reviewed"), 9);
        assert_eq!(count("open"), 1);
        assert_eq!(count("not_a_finding"), 1);
        assert_eq!(count("not_applicable"), 1);
        let sev = |v: &str| s.rules.iter().filter(|r| r.severity == v).count();
        assert_eq!((sev("CAT I"), sev("CAT II"), sev("CAT III")), (3, 6, 3));
        for (i, r) in s.rules.iter().enumerate() {
            assert_eq!(r.id, format!("SV-{}r1_rule", 1001 + i));
            assert_eq!(r.stig_id, format!("V-{}", 1001 + i));
        }
        let third = &s.rules[2];
        assert_eq!(third.cci_ids, vec!["CCI-000197", "CCI-002420"]);
        assert!(third
            .check_text
            .contains("\n\nRun: nmap --script ssl-enum-ciphers -p 443 <hostname>\n\n"));
        assert_eq!(s.rules[5].comments, "Planned fix in next sprint.");
    }
}
