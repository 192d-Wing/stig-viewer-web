//! Static mapping of DISA Control Correlation Identifier (CCI) IDs to
//! NIST SP 800-53 Revision 5 security control identifiers and titles.
//!
//! Sourced from the Defense Information Systems Agency (DISA) CCI list, mapped to
//! NIST SP 800-53 Rev 5 controls. CCI provides a granular standard means to
//! correlate policy, procedures, and standards with technical system security
//! requirements.
//!
//! References:
//!   - DISA CCI List: https://public.cyber.mil/stigs/cci/
//!   - NIST SP 800-53 Rev 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
//!
//! # API
//!
//! - [`cci_info`]`(cci: &str) -> Option<&'static CciInfo>` — the JS `CCI_MAP[id]`
//!   lookup. Keys are zero-padded six-digit CCI strings (e.g. `"CCI-000002"`),
//!   matched exactly (no trimming or case folding, same as the JS object lookup).
//! - [`CciInfo`] has two `&'static str` fields: `control` (e.g. `"AC-3"`,
//!   `"IA-5(1)"`) and `title` (short title of the control / enhancement).
//! - [`CCI_MAP`] is the full table as `(cci, CciInfo)` pairs, sorted by CCI id,
//!   for callers that need to iterate.

/// One CCI → NIST SP 800-53 Rev 5 mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CciInfo {
    /// NIST SP 800-53 Rev 5 control identifier (e.g. "AC-3", "IA-5(1)").
    pub control: &'static str,
    /// Short descriptive title of the control or control enhancement.
    pub title: &'static str,
}

/// Look up a CCI id (e.g. `"CCI-000213"`). `None` when the id is unmapped.
pub fn cci_info(cci: &str) -> Option<&'static CciInfo> {
    CCI_MAP
        .binary_search_by(|(id, _)| (*id).cmp(cci))
        .ok()
        .and_then(|i| CCI_MAP.get(i))
        .map(|(_, info)| info)
}

const fn e(control: &'static str, title: &'static str) -> CciInfo {
    CciInfo { control, title }
}

/// CCI id → control mapping, sorted by id (binary-searched by [`cci_info`]).
#[rustfmt::skip]
pub static CCI_MAP: [(&str, CciInfo); 205] = [
    ("CCI-000002", e("AC-1(a)(1)", "Policy and Procedures")),
    ("CCI-000003", e("AC-1(a)(2)", "Policy and Procedures")),
    ("CCI-000004", e("AC-1(b)(1)", "Policy and Procedures")),
    ("CCI-000007", e("AC-1(b)(2)", "Policy and Procedures")),
    ("CCI-000008", e("AC-2(a)", "Account Management")),
    ("CCI-000009", e("AC-2(b)", "Account Management")),
    ("CCI-000010", e("AC-2(c)", "Account Management")),
    ("CCI-000011", e("AC-2(d)", "Account Management")),
    ("CCI-000012", e("AC-2(e)", "Account Management")),
    ("CCI-000013", e("AC-2(f)", "Account Management")),
    ("CCI-000014", e("AC-2(g)", "Account Management")),
    ("CCI-000015", e("AC-2(c)", "Account Management")),
    ("CCI-000016", e("AC-2(d)", "Account Management")),
    ("CCI-000017", e("AC-2(e)", "Account Management")),
    ("CCI-000018", e("AC-2(j)", "Account Management")),
    ("CCI-000040", e("AC-3", "Access Enforcement")),
    ("CCI-000044", e("AC-7(a)", "Unsuccessful Logon Attempts")),
    ("CCI-000045", e("AC-7(b)", "Unsuccessful Logon Attempts")),
    ("CCI-000046", e("AC-7(c)", "Unsuccessful Logon Attempts")),
    ("CCI-000054", e("AC-10", "Concurrent Session Control")),
    ("CCI-000057", e("AC-11(a)", "Device Lock")),
    ("CCI-000058", e("AC-11(b)", "Device Lock")),
    ("CCI-000060", e("AC-11(1)", "Device Lock | Pattern-Hiding Displays")),
    ("CCI-000061", e("AC-12", "Session Termination")),
    ("CCI-000067", e("AC-17(2)", "Remote Access | Protection of Confidentiality/Integrity")),
    ("CCI-000068", e("IA-7", "Cryptographic Module Authentication")),
    ("CCI-000130", e("AU-3(a)", "Content of Audit Records")),
    ("CCI-000131", e("AU-3(b)", "Content of Audit Records")),
    ("CCI-000132", e("AU-3(c)", "Content of Audit Records")),
    ("CCI-000133", e("AU-3(d)", "Content of Audit Records")),
    ("CCI-000134", e("AU-3(e)", "Content of Audit Records")),
    ("CCI-000135", e("AU-3(f)", "Content of Audit Records")),
    ("CCI-000139", e("AU-5(a)", "Response to Audit Logging Process Failures")),
    ("CCI-000140", e("AU-5(b)", "Response to Audit Logging Process Failures")),
    ("CCI-000154", e("AU-7(1)", "Audit Record Review, Analysis, and Reporting | Automatic Processing")),
    ("CCI-000158", e("AU-9", "Protection of Audit Information")),
    ("CCI-000159", e("AU-9(a)", "Protection of Audit Information")),
    ("CCI-000163", e("AU-9(3)", "Protection of Audit Information | Cryptographic Protection")),
    ("CCI-000169", e("AU-12(a)", "Audit Record Generation")),
    ("CCI-000170", e("AU-12(b)", "Audit Record Generation")),
    ("CCI-000171", e("AU-12(c)", "Audit Record Generation")),
    ("CCI-000172", e("AU-12(d)", "Audit Record Generation")),
    ("CCI-000185", e("CM-1(a)(1)", "Configuration Management Policy and Procedures")),
    ("CCI-000192", e("IA-5(1)(a)", "Authenticator Management | Password-Based Authentication (Uppercase)")),
    ("CCI-000193", e("IA-5(1)(a)", "Authenticator Management | Password-Based Authentication (Lowercase)")),
    ("CCI-000194", e("IA-5(1)(a)", "Authenticator Management | Password-Based Authentication (Numeric)")),
    ("CCI-000195", e("IA-5(1)(b)", "Authenticator Management | Password-Based Authentication (Min Lifetime)")),
    ("CCI-000196", e("IA-5(1)(c)", "Authenticator Management | Password-Based Authentication (Max Lifetime)")),
    ("CCI-000197", e("IA-5(1)(d)", "Authenticator Management | Password-Based Authentication (Reuse)")),
    ("CCI-000198", e("IA-5(1)(e)", "Authenticator Management | Password-Based Authentication (Encryption)")),
    ("CCI-000199", e("IA-5(1)(f)", "Authenticator Management | Password-Based Authentication (Min Length)")),
    ("CCI-000200", e("IA-5(1)(g)", "Authenticator Management | Password-Based Authentication (Complexity)")),
    ("CCI-000205", e("IA-5(2)(a)", "Authenticator Management | PKI-Based Authentication")),
    ("CCI-000213", e("AC-3", "Access Enforcement")),
    ("CCI-000214", e("AC-3(1)", "Access Enforcement | Restricted Access to Privileged Functions")),
    ("CCI-000215", e("AC-3(2)", "Access Enforcement | Dual Authorization")),
    ("CCI-000225", e("AC-6", "Least Privilege")),
    ("CCI-000226", e("AC-6(1)", "Least Privilege | Authorize Access to Security Functions")),
    ("CCI-000230", e("AC-6(5)", "Least Privilege | Privileged Accounts")),
    ("CCI-000238", e("AC-6(9)", "Least Privilege | Log Use of Privileged Functions")),
    ("CCI-000239", e("AC-6(10)", "Least Privilege | Prohibit Non-Privileged Users")),
    ("CCI-000258", e("AC-17", "Remote Access")),
    ("CCI-000295", e("CM-3", "Configuration Change Control")),
    ("CCI-000296", e("CM-3(a)", "Configuration Change Control")),
    ("CCI-000318", e("CM-4", "Security and Privacy Impact Analysis")),
    ("CCI-000345", e("CM-5", "Access Restrictions for Change")),
    ("CCI-000366", e("CM-6(a)", "Configuration Settings")),
    ("CCI-000370", e("CM-6(b)", "Configuration Settings")),
    ("CCI-000381", e("CM-7(a)", "Least Functionality")),
    ("CCI-000382", e("CM-7(b)", "Least Functionality")),
    ("CCI-000764", e("IA-2", "Identification and Authentication (Organizational Users)")),
    ("CCI-000765", e("IA-2(1)", "Identification and Authentication | Multi-Factor Authentication to Privileged Accounts")),
    ("CCI-000766", e("IA-2(2)", "Identification and Authentication | Multi-Factor Authentication to Non-Privileged Accounts")),
    ("CCI-000767", e("IA-2(3)", "Identification and Authentication | Local Access to Privileged Accounts")),
    ("CCI-000768", e("IA-2(4)", "Identification and Authentication | Local Access to Non-Privileged Accounts")),
    ("CCI-000778", e("IA-3", "Device Identification and Authentication")),
    ("CCI-000795", e("IA-4(e)", "Identifier Management")),
    ("CCI-000803", e("IA-6", "Authentication Feedback")),
    ("CCI-000804", e("IA-7", "Cryptographic Module Authentication")),
    ("CCI-000879", e("MA-2(a)", "Controlled Maintenance")),
    ("CCI-000946", e("PE-2(a)", "Physical Access Authorizations")),
    ("CCI-001082", e("SC-2", "Separation of System and User Functionality")),
    ("CCI-001084", e("SC-3", "Security Function Isolation")),
    ("CCI-001090", e("SC-4", "Information in Shared System Resources")),
    ("CCI-001095", e("SC-5", "Denial of Service Protection")),
    ("CCI-001133", e("SC-10", "Network Disconnect")),
    ("CCI-001135", e("SC-10", "Network Disconnect")),
    ("CCI-001167", e("SC-18(1)", "Mobile Code | Identify Unacceptable Code / Take Corrective Actions")),
    ("CCI-001170", e("SI-3", "Malicious Code Protection")),
    ("CCI-001184", e("SC-23", "Session Authenticity")),
    ("CCI-001185", e("SC-23(1)", "Session Authenticity | Invalidate Session Identifiers at Logout")),
    ("CCI-001186", e("SC-23(3)", "Session Authenticity | Unique Session Identifiers with Randomization")),
    ("CCI-001187", e("SC-23(5)", "Session Authenticity | Allowed Certificate Authorities")),
    ("CCI-001188", e("AC-2(5)", "Account Management | Inactivity Logout")),
    ("CCI-001199", e("SC-28", "Protection of Information at Rest")),
    ("CCI-001200", e("SC-28(1)", "Protection of Information at Rest | Cryptographic Protection")),
    ("CCI-001312", e("SI-11(a)", "Error Handling")),
    ("CCI-001313", e("SI-11(b)", "Error Handling")),
    ("CCI-001314", e("SI-11", "Error Handling")),
    ("CCI-001368", e("AC-4", "Information Flow Enforcement")),
    ("CCI-001384", e("AC-8(a)", "System Use Notification")),
    ("CCI-001385", e("AC-8(b)", "System Use Notification")),
    ("CCI-001386", e("AC-8(c)(1)", "System Use Notification")),
    ("CCI-001387", e("AC-8(c)(2)", "System Use Notification")),
    ("CCI-001388", e("AC-8(c)(3)", "System Use Notification")),
    ("CCI-001389", e("SC-12", "Cryptographic Key Establishment and Management")),
    ("CCI-001390", e("SC-12(1)", "Cryptographic Key Establishment and Management | Availability")),
    ("CCI-001391", e("SC-12(2)", "Cryptographic Key Establishment and Management | Symmetric Keys")),
    ("CCI-001392", e("SC-12(3)", "Cryptographic Key Establishment and Management | Asymmetric Keys")),
    ("CCI-001402", e("SC-13", "Cryptographic Protection")),
    ("CCI-001403", e("AC-2(4)", "Account Management | Automated Audit Actions")),
    ("CCI-001404", e("AC-2(4)", "Account Management | Automated Audit Actions")),
    ("CCI-001405", e("AC-2(4)", "Account Management | Automated Audit Actions")),
    ("CCI-001406", e("AC-2(4)", "Account Management | Automated Audit Actions")),
    ("CCI-001414", e("AC-17(1)", "Remote Access | Monitoring and Control")),
    ("CCI-001499", e("CM-11", "User-Installed Software")),
    ("CCI-001544", e("AC-6(8)", "Least Privilege | Security Functions")),
    ("CCI-001546", e("AC-2(1)", "Account Management | Automated System Account Management")),
    ("CCI-001547", e("AC-2(2)", "Account Management | Automated Temporary and Emergency Account Management")),
    ("CCI-001619", e("IA-5(1)(h)", "Authenticator Management | Password-Based Authentication (Special Characters)")),
    ("CCI-001620", e("IA-5(1)(i)", "Authenticator Management | Password-Based Authentication (Prohibit Reuse)")),
    ("CCI-001621", e("AC-12(1)", "Session Termination | User-Initiated Logouts / Message Displays")),
    ("CCI-001625", e("SA-10", "Developer Configuration Management")),
    ("CCI-001632", e("SC-8", "Transmission Confidentiality and Integrity")),
    ("CCI-001633", e("SC-8(1)", "Transmission Confidentiality and Integrity | Cryptographic Protection")),
    ("CCI-001665", e("SC-39", "Process Isolation")),
    ("CCI-001749", e("CM-11(2)", "User-Installed Software | Software Installation with Privileged Status")),
    ("CCI-001752", e("CM-8(3)(a)", "System Component Inventory | Automated Unauthorized Component Detection")),
    ("CCI-001753", e("CM-8(3)(b)", "System Component Inventory | Automated Unauthorized Component Detection")),
    ("CCI-001754", e("CM-8(5)", "System Component Inventory | No Duplicate Accounting of Components")),
    ("CCI-001755", e("IA-3(1)", "Device Identification and Authentication | Cryptographic Bidirectional Authentication")),
    ("CCI-001762", e("CM-7(5)(b)", "Least Functionality | Authorized Software / Allow-by-Exception")),
    ("CCI-001812", e("AU-11", "Audit Record Retention")),
    ("CCI-001813", e("CM-6(1)", "Configuration Settings | Automated Management / Application / Verification")),
    ("CCI-001814", e("CM-6(1)", "Configuration Settings | Automated Management / Application / Verification")),
    ("CCI-001851", e("AU-4(1)", "Audit Log Storage Capacity | Transfer to Alternate Storage")),
    ("CCI-001852", e("AU-11", "Audit Record Retention")),
    ("CCI-001853", e("AU-12(1)", "Audit Record Generation | System-Wide and Time-Correlated Audit Trail")),
    ("CCI-001854", e("AU-12(3)", "Audit Record Generation | Changes by Authorized Individuals")),
    ("CCI-001855", e("AU-13", "Monitoring for Information Disclosure")),
    ("CCI-001862", e("SI-2(6)", "Flaw Remediation | Removal of Previous Versions of Software/Firmware")),
    ("CCI-001876", e("SI-7(1)", "Software, Firmware, and Information Integrity | Integrity Checks")),
    ("CCI-001877", e("SI-7(2)", "Software, Firmware, and Information Integrity | Automated Notifications of Integrity Violations")),
    ("CCI-001878", e("SI-7(5)", "Software, Firmware, and Information Integrity | Automated Response to Integrity Violations")),
    ("CCI-001879", e("SI-7(7)", "Software, Firmware, and Information Integrity | Integration of Detection and Response")),
    ("CCI-001880", e("SI-7(14)", "Software, Firmware, and Information Integrity | Binary or Machine Executable Code")),
    ("CCI-001891", e("AU-8(1)", "Time Stamps | Synchronization with Authoritative Time Source")),
    ("CCI-001892", e("AU-8(1)(b)", "Time Stamps | Synchronization with Authoritative Time Source")),
    ("CCI-001893", e("AU-8(2)", "Time Stamps | Secondary Authoritative Time Source")),
    ("CCI-001894", e("AU-8(a)", "Time Stamps")),
    ("CCI-001895", e("AU-8(b)", "Time Stamps")),
    ("CCI-002001", e("IA-2(11)", "Identification and Authentication | Remote Access - Separate Device")),
    ("CCI-002002", e("IA-2(12)", "Identification and Authentication | Acceptance of PIV Credentials")),
    ("CCI-002004", e("IA-2(8)", "Identification and Authentication | Access to Accounts - Replay Resistant")),
    ("CCI-002007", e("IA-2(6)", "Identification and Authentication | Access to Accounts - Separate Device")),
    ("CCI-002009", e("IA-2(3)", "Identification and Authentication | Local Access to Privileged Accounts")),
    ("CCI-002010", e("IA-8(2)", "Identification and Authentication (Non-Organizational Users) | Acceptance of External Authenticators")),
    ("CCI-002016", e("IA-11", "Re-Authentication")),
    ("CCI-002038", e("IA-5(13)", "Authenticator Management | Expiration of Cached Authenticators")),
    ("CCI-002039", e("IA-5(14)", "Authenticator Management | Managing Content of PKI Trust Stores")),
    ("CCI-002040", e("IA-5(15)", "Authenticator Management | GSA-Approved Products and Services")),
    ("CCI-002041", e("IA-5(16)", "Authenticator Management | In-Person or Trusted Third-Party Registration")),
    ("CCI-002061", e("AC-2(12)", "Account Management | Account Monitoring for Atypical Usage")),
    ("CCI-002062", e("AC-2(13)", "Account Management | Disable Accounts for High-Risk Individuals")),
    ("CCI-002063", e("AC-2(7)", "Account Management | Privileged User Accounts")),
    ("CCI-002100", e("AC-17(4)", "Remote Access | Privileged Commands/Access")),
    ("CCI-002105", e("AC-20", "Use of External Systems")),
    ("CCI-002132", e("AC-2(11)", "Account Management | Usage Conditions")),
    ("CCI-002133", e("AC-2(10)", "Account Management | Shared and Group Account Credential Change")),
    ("CCI-002142", e("AC-3(4)", "Access Enforcement | Discretionary Access Control")),
    ("CCI-002149", e("AC-3(8)", "Access Enforcement | Revocation of Access Authorizations")),
    ("CCI-002165", e("AC-3(9)", "Access Enforcement | Controlled Release")),
    ("CCI-002176", e("AC-3(13)", "Access Enforcement | Attribute-Based Access Control")),
    ("CCI-002184", e("AC-6(7)", "Least Privilege | Review of User Privileges")),
    ("CCI-002192", e("AC-6(2)", "Least Privilege | Non-Privileged Access for Non-Security Functions")),
    ("CCI-002205", e("AC-14", "Permitted Actions Without Identification or Authentication")),
    ("CCI-002234", e("AC-6(9)", "Least Privilege | Log Use of Privileged Functions")),
    ("CCI-002235", e("AC-6(10)", "Least Privilege | Prohibit Non-Privileged Users from Executing Privileged Functions")),
    ("CCI-002361", e("AC-12", "Session Termination")),
    ("CCI-002385", e("SI-10", "Information Input Validation")),
    ("CCI-002418", e("SC-8", "Transmission Confidentiality and Integrity")),
    ("CCI-002419", e("SC-8(1)", "Transmission Confidentiality and Integrity | Cryptographic Protection")),
    ("CCI-002420", e("SC-8(1)", "Transmission Confidentiality and Integrity | Cryptographic Protection")),
    ("CCI-002421", e("SC-8(2)", "Transmission Confidentiality and Integrity | Pre/Post Transmission Handling")),
    ("CCI-002422", e("SC-8(3)", "Transmission Confidentiality and Integrity | Cryptographic Protection for Message Externals")),
    ("CCI-002423", e("SC-8(4)", "Transmission Confidentiality and Integrity | Conceal or Randomize Communications")),
    ("CCI-002427", e("SC-9", "Transmission Confidentiality")),
    ("CCI-002430", e("SC-13", "Cryptographic Protection")),
    ("CCI-002450", e("SC-13(1)", "Cryptographic Protection | FIPS-Validated Cryptography")),
    ("CCI-002454", e("SC-15", "Collaborative Computing Devices and Applications")),
    ("CCI-002461", e("SC-17", "Public Key Infrastructure Certificates")),
    ("CCI-002470", e("SC-20", "Secure Name/Address Resolution Service (Authoritative Source)")),
    ("CCI-002471", e("SC-20(a)", "Secure Name/Address Resolution Service")),
    ("CCI-002472", e("SC-20(b)", "Secure Name/Address Resolution Service")),
    ("CCI-002475", e("SC-28(1)", "Protection of Information at Rest | Cryptographic Protection")),
    ("CCI-002476", e("SC-28(2)", "Protection of Information at Rest | Off-Line Storage")),
    ("CCI-002530", e("SI-2(5)", "Flaw Remediation | Automatic Software/Firmware Updates")),
    ("CCI-002534", e("SI-3(1)", "Malicious Code Protection | Signature Updates")),
    ("CCI-002605", e("SI-2(a)", "Flaw Remediation")),
    ("CCI-002607", e("SI-2(c)", "Flaw Remediation")),
    ("CCI-002617", e("SI-2(2)", "Flaw Remediation | Automated Flaw Remediation Status")),
    ("CCI-002696", e("SI-6(a)", "Security and Privacy Function Verification")),
    ("CCI-002699", e("SI-6(b)", "Security and Privacy Function Verification")),
    ("CCI-002702", e("SI-6(d)", "Security and Privacy Function Verification")),
    ("CCI-002754", e("SI-7(15)", "Software, Firmware, and Information Integrity | Code Authentication")),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(CCI_MAP.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn looks_up_known_ids() {
        let first = cci_info("CCI-000002").unwrap();
        assert_eq!(first.control, "AC-1(a)(1)");
        assert_eq!(first.title, "Policy and Procedures");
        let last = cci_info("CCI-002754").unwrap();
        assert_eq!(last.control, "SI-7(15)");
        assert_eq!(
            last.title,
            "Software, Firmware, and Information Integrity | Code Authentication"
        );
        assert_eq!(cci_info("CCI-000015").unwrap().control, "AC-2(c)");
    }

    #[test]
    fn unknown_ids_are_none() {
        assert_eq!(cci_info("CCI-999999"), None);
        assert_eq!(cci_info(""), None);
        assert_eq!(cci_info("cci-000002"), None);
        assert_eq!(cci_info(" CCI-000002"), None);
    }
}
