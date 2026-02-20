import { useState, useCallback, useMemo, useRef, useEffect } from "react";

// ─── Constants ───────────────────────────────────────────────────────────────
const SEVERITY_MAP = { high: "CAT I", medium: "CAT II", low: "CAT III" };
const SEVERITY_COLORS = {
  "CAT I": "#ff4444",
  "CAT II": "#ffaa00",
  "CAT III": "#44aaff",
};
const STATUS_OPTIONS = [
  { value: "not_reviewed", label: "Not Reviewed", color: "#6b7280" },
  { value: "not_a_finding", label: "Not a Finding", color: "#22c55e" },
  { value: "open", label: "Open", color: "#ef4444" },
  { value: "not_applicable", label: "Not Applicable", color: "#8b5cf6" },
];
const FINDING_DETAILS_FIELDS = [
  { key: "findingDetails", label: "Finding Details" },
  { key: "comments", label: "Comments" },
];

// ─── XML Parsing Helpers ─────────────────────────────────────────────────────
function getTextContent(el, tagName) {
  if (!el) return "";
  const nodes = el.getElementsByTagName(tagName);
  return nodes.length > 0 ? nodes[0].textContent?.trim() || "" : "";
}

function getAttribute(el, attr) {
  return el?.getAttribute(attr) || "";
}

function parseXCCDF(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "text/xml");

  const benchmarkEl =
    doc.getElementsByTagName("Benchmark")[0] ||
    doc.getElementsByTagNameNS("*", "Benchmark")[0];
  if (!benchmarkEl) throw new Error("No Benchmark element found in XCCDF");

  const title =
    getTextContent(benchmarkEl, "title") ||
    getTextContent(benchmarkEl, "Title") ||
    "Unknown STIG";
  const description =
    getTextContent(benchmarkEl, "description") ||
    getTextContent(benchmarkEl, "Description") ||
    "";
  const version =
    getTextContent(benchmarkEl, "version") ||
    getTextContent(benchmarkEl, "Version") ||
    "";
  const releaseInfo =
    getTextContent(benchmarkEl, "plain-text") ||
    getTextContent(benchmarkEl, "release-info") ||
    "";

  const groups =
    benchmarkEl.getElementsByTagName("Group").length > 0
      ? benchmarkEl.getElementsByTagName("Group")
      : benchmarkEl.getElementsByTagNameNS("*", "Group");

  const rules = [];
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i];
    const groupId = getAttribute(group, "id");
    const ruleEl =
      group.getElementsByTagName("Rule")[0] ||
      group.getElementsByTagNameNS("*", "Rule")[0];
    if (!ruleEl) continue;

    const ruleId = getAttribute(ruleEl, "id");
    const severity = getAttribute(ruleEl, "severity") || "medium";
    const ruleTitle =
      getTextContent(ruleEl, "title") || getTextContent(ruleEl, "Title") || "";
    const ruleDesc =
      getTextContent(ruleEl, "description") ||
      getTextContent(ruleEl, "Description") ||
      "";
    const fixText =
      getTextContent(ruleEl, "fixtext") ||
      getTextContent(ruleEl, "fix") ||
      getTextContent(ruleEl, "Fix") ||
      "";

    let checkText = "";
    const checkContentEls = ruleEl.getElementsByTagName("check-content");
    if (checkContentEls.length > 0) {
      checkText = checkContentEls[0].textContent?.trim() || "";
    }

    const identEls = ruleEl.getElementsByTagName("ident");
    const cciIds = [];
    for (let j = 0; j < identEls.length; j++) {
      const val = identEls[j].textContent?.trim();
      if (val) cciIds.push(val);
    }

    const stigId =
      groupId?.replace("V-", "V-") || `V-${(100000 + i).toString()}`;
    const cat = SEVERITY_MAP[severity] || "CAT II";

    rules.push({
      id: ruleId || `rule-${i}`,
      stigId,
      groupId,
      title: ruleTitle,
      severity: cat,
      description: cleanDescription(ruleDesc),
      fixText,
      checkText,
      cciIds,
      status: "not_reviewed",
      findingDetails: "",
      comments: "",
    });
  }

  return { title, description, version, releaseInfo, rules };
}

function cleanDescription(desc) {
  return desc
    .replace(/<VulnDiscussion>/gi, "")
    .replace(/<\/VulnDiscussion>/gi, "")
    .replace(/<FalsePositives>.*?<\/FalsePositives>/gis, "")
    .replace(/<FalseNegatives>.*?<\/FalseNegatives>/gis, "")
    .replace(/<Documentable>.*?<\/Documentable>/gis, "")
    .replace(/<Mitigations>.*?<\/Mitigations>/gis, "")
    .replace(/<SeverityOverrideGuidance>.*?<\/SeverityOverrideGuidance>/gis, "")
    .replace(
      /<PotentialImpacts>.*?<\/PotentialImpacts>/gis,
      ""
    )
    .replace(
      /<ThirdPartyTools>.*?<\/ThirdPartyTools>/gis,
      ""
    )
    .replace(
      /<MitigationControl>.*?<\/MitigationControl>/gis,
      ""
    )
    .replace(/<Responsibility>.*?<\/Responsibility>/gis, "")
    .replace(/<IAControls>.*?<\/IAControls>/gis, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function parseCKL(xmlText) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "text/xml");

  const stigInfoEl = doc.getElementsByTagName("STIG_INFO")[0];
  let title = "",
    version = "",
    releaseInfo = "";
  if (stigInfoEl) {
    const siData = stigInfoEl.getElementsByTagName("SI_DATA");
    for (let i = 0; i < siData.length; i++) {
      const name = getTextContent(siData[i], "SID_NAME");
      const val = getTextContent(siData[i], "SID_DATA");
      if (name === "title") title = val;
      if (name === "version") version = val;
      if (name === "releaseinfo") releaseInfo = val;
    }
  }

  const vulns = doc.getElementsByTagName("VULN");
  const rules = [];
  for (let i = 0; i < vulns.length; i++) {
    const vuln = vulns[i];
    const stigData = vuln.getElementsByTagName("STIG_DATA");
    const attrs = {};
    for (let j = 0; j < stigData.length; j++) {
      const name = getTextContent(stigData[j], "VULN_ATTRIBUTE");
      const val = getTextContent(stigData[j], "ATTRIBUTE_DATA");
      if (name === "CCI_REF") {
        if (!attrs.cciIds) attrs.cciIds = [];
        attrs.cciIds.push(val);
      } else {
        attrs[name] = val;
      }
    }

    const rawStatus = getTextContent(vuln, "STATUS");
    let status = "not_reviewed";
    if (rawStatus === "NotAFinding" || rawStatus === "Not_A_Finding")
      status = "not_a_finding";
    else if (rawStatus === "Open") status = "open";
    else if (rawStatus === "Not_Applicable" || rawStatus === "NotApplicable")
      status = "not_applicable";

    const severityRaw = (attrs.Severity || "medium").toLowerCase();
    const cat = SEVERITY_MAP[severityRaw] || "CAT II";

    rules.push({
      id: attrs.Rule_ID || `rule-${i}`,
      stigId: attrs.Vuln_Num || `V-${100000 + i}`,
      groupId: attrs.Group_Title || "",
      title: attrs.Rule_Title || "",
      severity: cat,
      description: cleanDescription(attrs.Vuln_Discuss || ""),
      fixText: attrs.Fix_Text || attrs.STIGRef || "",
      checkText: attrs.Check_Content || "",
      cciIds: attrs.cciIds || [],
      status,
      findingDetails: getTextContent(vuln, "FINDING_DETAILS"),
      comments: getTextContent(vuln, "COMMENTS"),
    });
  }

  return { title: title || "Imported Checklist", description: "", version, releaseInfo, rules };
}

function exportCKL(stig, hostname = "", ip = "", mac = "", fqdn = "") {
  const escXml = (s) =>
    s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;");

  const statusMap = {
    not_reviewed: "Not_Reviewed",
    not_a_finding: "NotAFinding",
    open: "Open",
    not_applicable: "Not_Applicable",
  };

  const sevMap = { "CAT I": "high", "CAT II": "medium", "CAT III": "low" };

  let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
  xml += `<!--DISA STIG Viewer :: Web STIG Viewer Export-->\n`;
  xml += `<CHECKLIST>\n`;
  xml += `  <ASSET>\n`;
  xml += `    <ROLE>None</ROLE>\n`;
  xml += `    <ASSET_TYPE>Computing</ASSET_TYPE>\n`;
  xml += `    <HOST_NAME>${escXml(hostname)}</HOST_NAME>\n`;
  xml += `    <HOST_IP>${escXml(ip)}</HOST_IP>\n`;
  xml += `    <HOST_MAC>${escXml(mac)}</HOST_MAC>\n`;
  xml += `    <HOST_FQDN>${escXml(fqdn)}</HOST_FQDN>\n`;
  xml += `    <TARGET_COMMENT></TARGET_COMMENT>\n`;
  xml += `    <TECH_AREA></TECH_AREA>\n`;
  xml += `    <TARGET_KEY></TARGET_KEY>\n`;
  xml += `    <WEB_OR_DATABASE>false</WEB_OR_DATABASE>\n`;
  xml += `    <WEB_DB_SITE></WEB_DB_SITE>\n`;
  xml += `    <WEB_DB_INSTANCE></WEB_DB_INSTANCE>\n`;
  xml += `  </ASSET>\n`;
  xml += `  <STIGS>\n`;
  xml += `    <iSTIG>\n`;
  xml += `      <STIG_INFO>\n`;
  xml += `        <SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>${escXml(stig.title)}</SID_DATA></SI_DATA>\n`;
  xml += `        <SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>${escXml(stig.version)}</SID_DATA></SI_DATA>\n`;
  xml += `        <SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>${escXml(stig.releaseInfo)}</SID_DATA></SI_DATA>\n`;
  xml += `      </STIG_INFO>\n`;

  for (const rule of stig.rules) {
    xml += `      <VULN>\n`;
    const sd = (name, val) =>
      `        <STIG_DATA><VULN_ATTRIBUTE>${escXml(name)}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>${escXml(val)}</ATTRIBUTE_DATA></STIG_DATA>\n`;
    xml += sd("Vuln_Num", rule.stigId);
    xml += sd("Severity", sevMap[rule.severity] || "medium");
    xml += sd("Group_Title", rule.groupId);
    xml += sd("Rule_ID", rule.id);
    xml += sd("Rule_Title", rule.title);
    xml += sd("Vuln_Discuss", rule.description);
    xml += sd("Check_Content", rule.checkText);
    xml += sd("Fix_Text", rule.fixText);
    for (const cci of rule.cciIds) {
      xml += sd("CCI_REF", cci);
    }
    xml += `        <STATUS>${statusMap[rule.status]}</STATUS>\n`;
    xml += `        <FINDING_DETAILS>${escXml(rule.findingDetails)}</FINDING_DETAILS>\n`;
    xml += `        <COMMENTS>${escXml(rule.comments)}</COMMENTS>\n`;
    xml += `        <SEVERITY_OVERRIDE></SEVERITY_OVERRIDE>\n`;
    xml += `        <SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>\n`;
    xml += `      </VULN>\n`;
  }

  xml += `    </iSTIG>\n`;
  xml += `  </STIGS>\n`;
  xml += `</CHECKLIST>`;
  return xml;
}

// ─── Sample STIG for Demo ────────────────────────────────────────────────────
function generateSampleSTIG() {
  return {
    title: "Sample STIG - Web Application Security (Demo)",
    description: "Demonstration STIG for testing the Web STIG Viewer",
    version: "3",
    releaseInfo: "Release: 1 Benchmark Date: 19 Feb 2026",
    rules: [
      {
        id: "SV-1001r1_rule", stigId: "V-1001", groupId: "SRG-APP-000001",
        title: "The application must enforce approved authorizations for logical access to information and system resources.",
        severity: "CAT I",
        description: "Authentication to the application must be performed using DoD PKI certificates. Applications must validate user identity via CAC/PIV before granting access to any system resources. Failure to enforce strong authentication allows unauthorized users to gain access to sensitive information.",
        fixText: "Configure the application to require CAC/PIV authentication for all user access. Ensure the application validates the certificate chain against a trusted DoD CA. Disable all password-based authentication mechanisms.",
        checkText: "Verify the application requires CAC/PIV for authentication.\n\nIf the application allows password-based authentication or does not validate DoD certificates, this is a finding.",
        cciIds: ["CCI-000213"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1002r1_rule", stigId: "V-1002", groupId: "SRG-APP-000002",
        title: "The application must implement cryptographic mechanisms to protect the integrity of session tokens.",
        severity: "CAT I",
        description: "Session tokens must be generated using FIPS 140-2/3 validated cryptographic modules. Tokens must have sufficient entropy to prevent prediction or brute-force attacks. Session management must include secure token storage, transmission, and invalidation mechanisms.",
        fixText: "Configure the application to generate session tokens using FIPS-validated cryptographic modules with a minimum of 128 bits of entropy. Implement secure cookie attributes (HttpOnly, Secure, SameSite).",
        checkText: "Review the application session management configuration.\n\nVerify session tokens are generated using FIPS-validated modules.\nVerify tokens contain at least 128 bits of entropy.\n\nIf the application does not use FIPS-validated cryptographic modules for session management, this is a finding.",
        cciIds: ["CCI-000068"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1003r1_rule", stigId: "V-1003", groupId: "SRG-APP-000003",
        title: "The application must use TLS 1.2 or higher for all network communications.",
        severity: "CAT I",
        description: "All data transmitted between the application and clients must be encrypted using TLS 1.2 or TLS 1.3. Legacy protocols (SSL, TLS 1.0, TLS 1.1) must be disabled. CNSA 2.0 compliant cipher suites should be preferred.",
        fixText: "Configure the web server and application to only accept TLS 1.2 and TLS 1.3 connections. Disable all SSLv2, SSLv3, TLS 1.0, and TLS 1.1 protocols. Configure CNSA 2.0 compliant cipher suites.",
        checkText: "Verify TLS configuration on the server.\n\nRun: nmap --script ssl-enum-ciphers -p 443 <hostname>\n\nIf TLS 1.0 or 1.1 is enabled, or if SSLv2/SSLv3 is present, this is a finding.",
        cciIds: ["CCI-000197", "CCI-002420"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1004r1_rule", stigId: "V-1004", groupId: "SRG-APP-000015",
        title: "The application must enforce password complexity requirements.",
        severity: "CAT II",
        description: "When password-based authentication is used (for service accounts or emergency access), passwords must meet minimum complexity requirements: 15 characters minimum, combination of upper/lower/numeric/special characters.",
        fixText: "Configure the application password policy to require a minimum of 15 characters with complexity requirements including uppercase, lowercase, numeric, and special characters.",
        checkText: "Review the application password policy settings.\n\nIf password minimum length is less than 15 characters or complexity is not enforced, this is a finding.",
        cciIds: ["CCI-000192", "CCI-000193"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1005r1_rule", stigId: "V-1005", groupId: "SRG-APP-000033",
        title: "The application must enforce approved authorizations for controlling the flow of information.",
        severity: "CAT II",
        description: "The application must implement network segmentation and access controls consistent with the DAF macrosegmentation plan. Traffic between security zones must be filtered and logged. East-west traffic must be controlled via microsegmentation policies.",
        fixText: "Implement network segmentation per DAF Base Area Network standards. Configure firewall rules between security zones. Enable logging for all inter-zone traffic flows. Implement microsegmentation for east-west traffic.",
        checkText: "Review network segmentation configuration.\n\nVerify traffic between zones is filtered.\nVerify logging is enabled for inter-zone traffic.\n\nIf inter-zone traffic is not filtered or logged, this is a finding.",
        cciIds: ["CCI-001368"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1006r1_rule", stigId: "V-1006", groupId: "SRG-APP-000039",
        title: "The application must generate audit records for all account creation activities.",
        severity: "CAT II",
        description: "The application must produce audit records when user accounts are created. Audit records must include the identity of the individual who created the account, the date and time, and the type of account created.",
        fixText: "Configure the application to generate audit records for all account creation events. Ensure records include the creating user identity, timestamp, and account type.",
        checkText: "Create a test account and verify an audit record is generated.\n\nReview audit logs for account creation entries.\n\nIf no audit record is generated for account creation, this is a finding.",
        cciIds: ["CCI-000015"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1007r1_rule", stigId: "V-1007", groupId: "SRG-APP-000065",
        title: "The application must enforce a minimum 15-minute lock after 3 consecutive invalid login attempts.",
        severity: "CAT II",
        description: "The application must implement account lockout after 3 consecutive failed login attempts. The lockout duration must be a minimum of 15 minutes or until an administrator unlocks the account.",
        fixText: "Configure the application to lock accounts after 3 consecutive failed login attempts for a minimum of 15 minutes.",
        checkText: "Attempt to log in with incorrect credentials 3 times.\n\nVerify the account is locked.\nVerify the lockout duration is at least 15 minutes.\n\nIf the account is not locked after 3 failed attempts, this is a finding.",
        cciIds: ["CCI-000044"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1008r1_rule", stigId: "V-1008", groupId: "SRG-APP-000095",
        title: "The application must produce audit records containing sufficient information to establish what occurred.",
        severity: "CAT II",
        description: "Audit records must contain sufficient detail to determine the type of event, when the event occurred, the source of the event, the outcome of the event, and the identity of associated subjects/objects.",
        fixText: "Configure application logging to include event type, timestamp, source, outcome, and user identity in all audit records. Forward logs to a centralized SIEM.",
        checkText: "Review sample audit log entries.\n\nVerify each entry contains: event type, timestamp, source IP, outcome (success/fail), and user identity.\n\nIf any of these fields are missing, this is a finding.",
        cciIds: ["CCI-000130", "CCI-000131", "CCI-000132"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1009r1_rule", stigId: "V-1009", groupId: "SRG-APP-000141",
        title: "The application must implement NIST FIPS-validated cryptography for data at rest.",
        severity: "CAT II",
        description: "Data at rest must be encrypted using FIPS 140-2/3 validated cryptographic modules. AES-256 is the minimum acceptable algorithm for symmetric encryption of stored data.",
        fixText: "Configure the application and underlying storage to use AES-256 encryption via FIPS-validated cryptographic modules for all data at rest.",
        checkText: "Verify data-at-rest encryption configuration.\n\nCheck that FIPS mode is enabled on the OS.\nVerify the storage encryption algorithm is AES-256.\n\nIf FIPS-validated encryption is not used for data at rest, this is a finding.",
        cciIds: ["CCI-001199"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1010r1_rule", stigId: "V-1010", groupId: "SRG-APP-000175",
        title: "The application must support IPv6 per DAF IPv6 transition requirements.",
        severity: "CAT III",
        description: "Applications must support dual-stack or IPv6-only operation consistent with DAF network modernization initiatives. IPv6 support must include proper address handling, DNS resolution, and security controls equivalent to IPv4.",
        fixText: "Enable IPv6 support in the application. Configure dual-stack listeners. Ensure all security controls apply equally to IPv6 traffic. Test application functionality over IPv6-only connections.",
        checkText: "Verify the application listens on IPv6 addresses.\n\nTest application functionality over IPv6.\nVerify security controls apply to IPv6 traffic.\n\nIf the application does not support IPv6, this is a finding.",
        cciIds: ["CCI-000366"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1011r1_rule", stigId: "V-1011", groupId: "SRG-APP-000190",
        title: "The application must terminate user sessions after 15 minutes of inactivity.",
        severity: "CAT III",
        description: "Inactive sessions represent a security risk. The application must automatically terminate sessions after 15 minutes of user inactivity to prevent unauthorized access from unattended workstations.",
        fixText: "Configure session timeout to 15 minutes of inactivity. Implement both server-side session expiration and client-side timeout notification.",
        checkText: "Log in to the application and remain idle for 15 minutes.\n\nVerify the session is terminated and the user is required to re-authenticate.\n\nIf the session remains active after 15 minutes of inactivity, this is a finding.",
        cciIds: ["CCI-001133"], status: "not_reviewed", findingDetails: "", comments: "",
      },
      {
        id: "SV-1012r1_rule", stigId: "V-1012", groupId: "SRG-APP-000211",
        title: "The application must display an approved DoD notice and consent banner.",
        severity: "CAT III",
        description: "The application must display the Standard Mandatory DoD Notice and Consent Banner before granting access. The banner must require user acknowledgment before proceeding.",
        fixText: "Configure the application to display the Standard Mandatory DoD Notice and Consent Banner at the login screen. Require the user to click 'OK' or 'I Agree' before accessing the application.",
        checkText: "Access the application login page.\n\nVerify the DoD Notice and Consent Banner is displayed.\nVerify the user must acknowledge the banner before accessing the application.\n\nIf the banner is not displayed or acknowledgment is not required, this is a finding.",
        cciIds: ["CCI-001384", "CCI-001385"], status: "not_reviewed", findingDetails: "", comments: "",
      },
    ],
  };
}

// ─── Components ──────────────────────────────────────────────────────────────

function StatusBadge({ status, small = false }) {
  const opt = STATUS_OPTIONS.find((s) => s.value === status) || STATUS_OPTIONS[0];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        padding: small ? "1px 6px" : "2px 8px",
        borderRadius: 3,
        fontSize: small ? 10 : 11,
        fontWeight: 600,
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        letterSpacing: "0.02em",
        color: opt.color,
        background: opt.color + "18",
        border: `1px solid ${opt.color}40`,
        textTransform: "uppercase",
        whiteSpace: "nowrap",
      }}
    >
      <span
        style={{
          width: small ? 5 : 6,
          height: small ? 5 : 6,
          borderRadius: "50%",
          background: opt.color,
        }}
      />
      {opt.label}
    </span>
  );
}

function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || "#888";
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 3,
        fontSize: 11,
        fontWeight: 700,
        fontFamily: "'JetBrains Mono', monospace",
        color: "#000",
        background: color,
        letterSpacing: "0.04em",
      }}
    >
      {severity}
    </span>
  );
}

function StatCard({ label, value, color, onClick, active }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: active ? color + "20" : "#1a1d23",
        border: active ? `1px solid ${color}` : "1px solid #2a2d35",
        borderRadius: 6,
        padding: "10px 14px",
        cursor: "pointer",
        textAlign: "left",
        minWidth: 100,
        transition: "all 0.15s",
      }}
    >
      <div
        style={{
          fontSize: 22,
          fontWeight: 700,
          color,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontSize: 10,
          color: "#8b919a",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          fontWeight: 600,
          marginTop: 2,
        }}
      >
        {label}
      </div>
    </button>
  );
}

function AssetModal({ show, onClose, assetInfo, setAssetInfo }) {
  if (!show) return null;
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "#1a1d23",
          border: "1px solid #2a2d35",
          borderRadius: 8,
          padding: 24,
          width: 420,
          maxWidth: "90vw",
        }}
      >
        <h3 style={{ color: "#e8dcc8", margin: "0 0 16px", fontSize: 16, fontWeight: 700 }}>
          Asset Information
        </h3>
        {["hostname", "ip", "mac", "fqdn"].map((field) => (
          <div key={field} style={{ marginBottom: 12 }}>
            <label
              style={{
                display: "block",
                fontSize: 11,
                color: "#8b919a",
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                marginBottom: 4,
                fontWeight: 600,
              }}
            >
              {field === "ip"
                ? "IP Address"
                : field === "mac"
                ? "MAC Address"
                : field === "fqdn"
                ? "FQDN"
                : "Hostname"}
            </label>
            <input
              type="text"
              value={assetInfo[field]}
              onChange={(e) => setAssetInfo({ ...assetInfo, [field]: e.target.value })}
              style={{
                width: "100%",
                background: "#0f1115",
                border: "1px solid #2a2d35",
                borderRadius: 4,
                padding: "8px 10px",
                color: "#c5c9d2",
                fontSize: 13,
                fontFamily: "'JetBrains Mono', monospace",
                boxSizing: "border-box",
              }}
            />
          </div>
        ))}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 8 }}>
          <button
            onClick={onClose}
            style={{
              padding: "8px 16px",
              background: "#c9a227",
              color: "#000",
              border: "none",
              borderRadius: 4,
              cursor: "pointer",
              fontWeight: 700,
              fontSize: 12,
            }}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Main App ────────────────────────────────────────────────────────────────
export default function STIGViewer() {
  const [stig, setStig] = useState(null);
  const [selectedRule, setSelectedRule] = useState(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [showAssetModal, setShowAssetModal] = useState(false);
  const [assetInfo, setAssetInfo] = useState({ hostname: "", ip: "", mac: "", fqdn: "" });
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef(null);
  const detailRef = useRef(null);

  const handleFileLoad = useCallback(async (file) => {
    try {
      const text = await file.text();
      let parsed;
      if (file.name.endsWith(".ckl")) {
        parsed = parseCKL(text);
      } else {
        parsed = parseXCCDF(text);
      }
      setStig(parsed);
      setSelectedRule(null);
      setSearchTerm("");
      setSeverityFilter(null);
      setStatusFilter(null);
    } catch (err) {
      alert("Error parsing file: " + err.message);
    }
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer?.files?.[0];
      if (file) handleFileLoad(file);
    },
    [handleFileLoad]
  );

  const handleExport = useCallback(() => {
    if (!stig) return;
    const xml = exportCKL(stig, assetInfo.hostname, assetInfo.ip, assetInfo.mac, assetInfo.fqdn);
    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${stig.title.replace(/[^a-zA-Z0-9]/g, "_")}.ckl`;
    a.click();
    URL.revokeObjectURL(url);
  }, [stig, assetInfo]);

  const updateRule = useCallback(
    (ruleId, updates) => {
      setStig((prev) => {
        if (!prev) return prev;
        const newRules = prev.rules.map((r) => (r.id === ruleId ? { ...r, ...updates } : r));
        return { ...prev, rules: newRules };
      });
      setSelectedRule((prev) => (prev?.id === ruleId ? { ...prev, ...updates } : prev));
    },
    []
  );

  const setAllStatus = useCallback((status) => {
    setStig((prev) => {
      if (!prev) return prev;
      return { ...prev, rules: prev.rules.map((r) => ({ ...r, status })) };
    });
    setSelectedRule((prev) => (prev ? { ...prev, status } : prev));
  }, []);

  const filteredRules = useMemo(() => {
    if (!stig) return [];
    return stig.rules.filter((r) => {
      if (severityFilter && r.severity !== severityFilter) return false;
      if (statusFilter && r.status !== statusFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return (
          r.title.toLowerCase().includes(term) ||
          r.stigId.toLowerCase().includes(term) ||
          r.id.toLowerCase().includes(term) ||
          r.description.toLowerCase().includes(term) ||
          r.checkText.toLowerCase().includes(term) ||
          r.fixText.toLowerCase().includes(term)
        );
      }
      return true;
    });
  }, [stig, searchTerm, severityFilter, statusFilter]);

  const stats = useMemo(() => {
    if (!stig) return null;
    const total = stig.rules.length;
    const bySeverity = { "CAT I": 0, "CAT II": 0, "CAT III": 0 };
    const byStatus = { not_reviewed: 0, not_a_finding: 0, open: 0, not_applicable: 0 };
    stig.rules.forEach((r) => {
      bySeverity[r.severity] = (bySeverity[r.severity] || 0) + 1;
      byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    });
    const evaluated = total - byStatus.not_reviewed;
    return { total, bySeverity, byStatus, evaluated, pct: total ? Math.round((evaluated / total) * 100) : 0 };
  }, [stig]);

  useEffect(() => {
    if (selectedRule && detailRef.current) {
      detailRef.current.scrollTop = 0;
    }
  }, [selectedRule]);

  // ─── Landing / Drop Zone ─────────────────────────────────────────────────
  if (!stig) {
    return (
      <div
        style={{
          minHeight: "100vh",
          background: "#0f1115",
          color: "#c5c9d2",
          fontFamily: "'Segoe UI', system-ui, sans-serif",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: 32,
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
      >
        <style>{`
          @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Source+Sans+3:wght@400;600;700;900&display=swap');
          * { box-sizing: border-box; margin: 0; padding: 0; }
          ::-webkit-scrollbar { width: 6px; }
          ::-webkit-scrollbar-track { background: #0f1115; }
          ::-webkit-scrollbar-thumb { background: #2a2d35; border-radius: 3px; }
          ::-webkit-scrollbar-thumb:hover { background: #3a3d45; }
          textarea:focus, input:focus, select:focus { outline: none; border-color: #c9a227 !important; }
          ::selection { background: #c9a22740; }
        `}</style>

        <div style={{ textAlign: "center", maxWidth: 560 }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 12,
              marginBottom: 24,
            }}
          >
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <rect width="40" height="40" rx="8" fill="#c9a227" />
              <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1115" />
              <path d="M28 22l4 4-4 4" stroke="#0f1115" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <div>
              <div
                style={{
                  fontSize: 28,
                  fontWeight: 900,
                  color: "#e8dcc8",
                  fontFamily: "'Source Sans 3', sans-serif",
                  letterSpacing: "-0.02em",
                  lineHeight: 1,
                }}
              >
                STIG Viewer
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: "#c9a227",
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 600,
                  letterSpacing: "0.1em",
                }}
              >
                WEB EDITION v3.0
              </div>
            </div>
          </div>

          <div
            style={{
              border: dragOver ? "2px solid #c9a227" : "2px dashed #2a2d35",
              borderRadius: 12,
              padding: "48px 32px",
              background: dragOver ? "#c9a22708" : "#1a1d2380",
              transition: "all 0.2s",
              cursor: "pointer",
              marginBottom: 20,
            }}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml,.ckl"
              style={{ display: "none" }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFileLoad(file);
              }}
            />
            <svg
              width="48"
              height="48"
              viewBox="0 0 48 48"
              fill="none"
              style={{ margin: "0 auto 16px", display: "block", opacity: 0.5 }}
            >
              <path
                d="M24 32V16m0 0l-8 8m8-8l8 8M8 36h32"
                stroke="#c5c9d2"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#e8dcc8", marginBottom: 6 }}>
              Drop STIG file or click to browse
            </div>
            <div style={{ fontSize: 12, color: "#6b7280" }}>
              Supports XCCDF (.xml) and Checklist (.ckl) formats
            </div>
          </div>

          <button
            onClick={() => setStig(generateSampleSTIG())}
            style={{
              background: "transparent",
              border: "1px solid #2a2d35",
              color: "#8b919a",
              padding: "10px 20px",
              borderRadius: 6,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
              transition: "all 0.15s",
            }}
            onMouseEnter={(e) => {
              e.target.style.borderColor = "#c9a227";
              e.target.style.color = "#c9a227";
            }}
            onMouseLeave={(e) => {
              e.target.style.borderColor = "#2a2d35";
              e.target.style.color = "#8b919a";
            }}
          >
            Load Demo STIG
          </button>
        </div>
      </div>
    );
  }

  // ─── Main Viewer ─────────────────────────────────────────────────────────
  return (
    <div
      style={{
        height: "100vh",
        background: "#0f1115",
        color: "#c5c9d2",
        fontFamily: "'Segoe UI', system-ui, sans-serif",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
      }}
    >
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Source+Sans+3:wght@400;600;700;900&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f1115; }
        ::-webkit-scrollbar-thumb { background: #2a2d35; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #3a3d45; }
        textarea:focus, input:focus, select:focus { outline: none; border-color: #c9a227 !important; }
        ::selection { background: #c9a22740; }
      `}</style>

      {/* ── Header ── */}
      <div
        style={{
          background: "#1a1d23",
          borderBottom: "1px solid #2a2d35",
          padding: "8px 16px",
          display: "flex",
          alignItems: "center",
          gap: 16,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <svg width="24" height="24" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="8" fill="#c9a227" />
            <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1115" />
            <path d="M28 22l4 4-4 4" stroke="#0f1115" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span
            style={{
              fontSize: 15,
              fontWeight: 800,
              color: "#e8dcc8",
              fontFamily: "'Source Sans 3', sans-serif",
              letterSpacing: "-0.01em",
            }}
          >
            STIG Viewer
          </span>
        </div>

        <div
          style={{
            flex: 1,
            fontSize: 12,
            color: "#8b919a",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          <span style={{ color: "#c9a227", fontWeight: 700 }}>{stig.title}</span>
          {stig.version && (
            <span style={{ marginLeft: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
              v{stig.version}
            </span>
          )}
          {stig.releaseInfo && (
            <span style={{ marginLeft: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>
              {stig.releaseInfo}
            </span>
          )}
        </div>

        <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
          <button
            onClick={() => setShowAssetModal(true)}
            style={{
              background: "#0f1115",
              border: "1px solid #2a2d35",
              color: "#8b919a",
              padding: "5px 10px",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 11,
              fontWeight: 600,
            }}
          >
            Asset Info
          </button>
          <button
            onClick={() => fileInputRef.current?.click()}
            style={{
              background: "#0f1115",
              border: "1px solid #2a2d35",
              color: "#8b919a",
              padding: "5px 10px",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 11,
              fontWeight: 600,
            }}
          >
            Open File
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xml,.ckl"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFileLoad(file);
            }}
          />
          <button
            onClick={handleExport}
            style={{
              background: "#c9a227",
              border: "none",
              color: "#0f1115",
              padding: "5px 12px",
              borderRadius: 4,
              cursor: "pointer",
              fontSize: 11,
              fontWeight: 700,
            }}
          >
            Export .ckl
          </button>
        </div>
      </div>

      {/* ── Stats Bar ── */}
      <div
        style={{
          padding: "10px 16px",
          display: "flex",
          gap: 8,
          alignItems: "center",
          borderBottom: "1px solid #1a1d23",
          overflowX: "auto",
          flexShrink: 0,
        }}
      >
        <StatCard
          label="Total"
          value={stats.total}
          color="#e8dcc8"
          onClick={() => {
            setSeverityFilter(null);
            setStatusFilter(null);
          }}
          active={!severityFilter && !statusFilter}
        />
        <div style={{ width: 1, height: 36, background: "#2a2d35" }} />
        {Object.entries(stats.bySeverity).map(([sev, count]) => (
          <StatCard
            key={sev}
            label={sev}
            value={count}
            color={SEVERITY_COLORS[sev]}
            onClick={() => {
              setSeverityFilter(severityFilter === sev ? null : sev);
              setStatusFilter(null);
            }}
            active={severityFilter === sev}
          />
        ))}
        <div style={{ width: 1, height: 36, background: "#2a2d35" }} />
        {STATUS_OPTIONS.map((s) => (
          <StatCard
            key={s.value}
            label={s.label}
            value={stats.byStatus[s.value]}
            color={s.color}
            onClick={() => {
              setStatusFilter(statusFilter === s.value ? null : s.value);
              setSeverityFilter(null);
            }}
            active={statusFilter === s.value}
          />
        ))}
        <div style={{ flex: 1 }} />
        <div style={{ textAlign: "right", minWidth: 80 }}>
          <div
            style={{
              fontSize: 11,
              color: "#8b919a",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
            }}
          >
            Evaluated
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, justifyContent: "flex-end" }}>
            <div
              style={{
                width: 60,
                height: 4,
                background: "#2a2d35",
                borderRadius: 2,
                overflow: "hidden",
              }}
            >
              <div
                style={{
                  width: `${stats.pct}%`,
                  height: "100%",
                  background: stats.pct === 100 ? "#22c55e" : "#c9a227",
                  borderRadius: 2,
                  transition: "width 0.3s",
                }}
              />
            </div>
            <span
              style={{
                fontSize: 14,
                fontWeight: 700,
                color: stats.pct === 100 ? "#22c55e" : "#c9a227",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {stats.pct}%
            </span>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* ── Rule List Panel ── */}
        <div
          style={{
            width: selectedRule ? "40%" : "100%",
            minWidth: 320,
            display: "flex",
            flexDirection: "column",
            borderRight: selectedRule ? "1px solid #2a2d35" : "none",
            transition: "width 0.2s",
          }}
        >
          {/* Search */}
          <div style={{ padding: "10px 12px", borderBottom: "1px solid #1a1d23" }}>
            <div style={{ position: "relative" }}>
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#6b7280"
                strokeWidth="2"
                style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }}
              >
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                placeholder="Search rules by ID, title, or content..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  width: "100%",
                  padding: "8px 10px 8px 32px",
                  background: "#0f1115",
                  border: "1px solid #2a2d35",
                  borderRadius: 6,
                  color: "#c5c9d2",
                  fontSize: 13,
                  fontFamily: "'Segoe UI', system-ui, sans-serif",
                }}
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm("")}
                  style={{
                    position: "absolute",
                    right: 8,
                    top: "50%",
                    transform: "translateY(-50%)",
                    background: "none",
                    border: "none",
                    color: "#6b7280",
                    cursor: "pointer",
                    fontSize: 16,
                    lineHeight: 1,
                  }}
                >
                  ×
                </button>
              )}
            </div>
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                marginTop: 6,
                fontSize: 11,
                color: "#6b7280",
              }}
            >
              <span>
                {filteredRules.length} of {stig.rules.length} rules
              </span>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => setAllStatus("not_a_finding")}
                  style={{
                    background: "none",
                    border: "none",
                    color: "#22c55e",
                    cursor: "pointer",
                    fontSize: 10,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                  }}
                >
                  All NaF
                </button>
                <button
                  onClick={() => setAllStatus("not_reviewed")}
                  style={{
                    background: "none",
                    border: "none",
                    color: "#6b7280",
                    cursor: "pointer",
                    fontSize: 10,
                    fontWeight: 600,
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                  }}
                >
                  Reset All
                </button>
              </div>
            </div>
          </div>

          {/* Rule list */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            {filteredRules.map((rule) => (
              <div
                key={rule.id}
                onClick={() => setSelectedRule(rule)}
                style={{
                  padding: "10px 14px",
                  borderBottom: "1px solid #1a1d2380",
                  cursor: "pointer",
                  background:
                    selectedRule?.id === rule.id ? "#c9a22710" : "transparent",
                  borderLeft:
                    selectedRule?.id === rule.id
                      ? "3px solid #c9a227"
                      : "3px solid transparent",
                  transition: "all 0.1s",
                }}
                onMouseEnter={(e) => {
                  if (selectedRule?.id !== rule.id)
                    e.currentTarget.style.background = "#1a1d23";
                }}
                onMouseLeave={(e) => {
                  if (selectedRule?.id !== rule.id)
                    e.currentTarget.style.background = "transparent";
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    marginBottom: 4,
                  }}
                >
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 12,
                      fontWeight: 700,
                      color: "#c9a227",
                      minWidth: 65,
                    }}
                  >
                    {rule.stigId}
                  </span>
                  <SeverityBadge severity={rule.severity} />
                  <StatusBadge status={rule.status} small />
                </div>
                <div
                  style={{
                    fontSize: 13,
                    color: "#e0e0e0",
                    lineHeight: 1.4,
                    display: "-webkit-box",
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: "vertical",
                    overflow: "hidden",
                  }}
                >
                  {rule.title}
                </div>
              </div>
            ))}
            {filteredRules.length === 0 && (
              <div
                style={{
                  padding: 32,
                  textAlign: "center",
                  color: "#6b7280",
                  fontSize: 13,
                }}
              >
                No rules match the current filters
              </div>
            )}
          </div>
        </div>

        {/* ── Detail Panel ── */}
        {selectedRule && (
          <div
            ref={detailRef}
            style={{
              flex: 1,
              overflowY: "auto",
              padding: 0,
            }}
          >
            {/* Detail header */}
            <div
              style={{
                padding: "16px 20px",
                borderBottom: "1px solid #1a1d23",
                background: "#1a1d2360",
                position: "sticky",
                top: 0,
                zIndex: 10,
                backdropFilter: "blur(12px)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: 8,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: 16,
                      fontWeight: 700,
                      color: "#c9a227",
                    }}
                  >
                    {selectedRule.stigId}
                  </span>
                  <SeverityBadge severity={selectedRule.severity} />
                </div>
                <button
                  onClick={() => setSelectedRule(null)}
                  style={{
                    background: "none",
                    border: "none",
                    color: "#6b7280",
                    cursor: "pointer",
                    fontSize: 20,
                    lineHeight: 1,
                    padding: "4px 8px",
                  }}
                >
                  ×
                </button>
              </div>
              <div
                style={{
                  fontSize: 14,
                  fontWeight: 600,
                  color: "#e8dcc8",
                  lineHeight: 1.5,
                }}
              >
                {selectedRule.title}
              </div>
              <div
                style={{
                  marginTop: 6,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 10,
                  color: "#6b7280",
                }}
              >
                Rule ID: {selectedRule.id}
                {selectedRule.cciIds.length > 0 && (
                  <span style={{ marginLeft: 12 }}>
                    CCI: {selectedRule.cciIds.join(", ")}
                  </span>
                )}
              </div>
            </div>

            {/* Status selector */}
            <div style={{ padding: "16px 20px", borderBottom: "1px solid #1a1d23" }}>
              <div
                style={{
                  fontSize: 11,
                  color: "#8b919a",
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  fontWeight: 700,
                  marginBottom: 8,
                }}
              >
                Compliance Status
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {STATUS_OPTIONS.map((s) => (
                  <button
                    key={s.value}
                    onClick={() => updateRule(selectedRule.id, { status: s.value })}
                    style={{
                      padding: "7px 14px",
                      borderRadius: 5,
                      border:
                        selectedRule.status === s.value
                          ? `2px solid ${s.color}`
                          : "2px solid #2a2d35",
                      background:
                        selectedRule.status === s.value ? s.color + "20" : "#0f1115",
                      color:
                        selectedRule.status === s.value ? s.color : "#8b919a",
                      cursor: "pointer",
                      fontSize: 12,
                      fontWeight: 600,
                      transition: "all 0.15s",
                    }}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Content sections */}
            <div style={{ padding: "0 20px 24px" }}>
              {[
                { title: "Description", content: selectedRule.description },
                { title: "Check Text", content: selectedRule.checkText },
                { title: "Fix Text", content: selectedRule.fixText },
              ].map(
                (section) =>
                  section.content && (
                    <div key={section.title} style={{ marginTop: 16 }}>
                      <div
                        style={{
                          fontSize: 11,
                          color: "#c9a227",
                          textTransform: "uppercase",
                          letterSpacing: "0.08em",
                          fontWeight: 700,
                          marginBottom: 6,
                        }}
                      >
                        {section.title}
                      </div>
                      <div
                        style={{
                          fontSize: 13,
                          lineHeight: 1.65,
                          color: "#b8bcc5",
                          background: "#1a1d2360",
                          border: "1px solid #2a2d35",
                          borderRadius: 6,
                          padding: "12px 14px",
                          whiteSpace: "pre-wrap",
                          fontFamily: section.title === "Check Text" ? "'JetBrains Mono', monospace" : "inherit",
                          ...(section.title === "Check Text" ? { fontSize: 12 } : {}),
                        }}
                      >
                        {section.content}
                      </div>
                    </div>
                  )
              )}

              {/* Finding Details / Comments */}
              {FINDING_DETAILS_FIELDS.map((field) => (
                <div key={field.key} style={{ marginTop: 16 }}>
                  <div
                    style={{
                      fontSize: 11,
                      color: "#c9a227",
                      textTransform: "uppercase",
                      letterSpacing: "0.08em",
                      fontWeight: 700,
                      marginBottom: 6,
                    }}
                  >
                    {field.label}
                  </div>
                  <textarea
                    value={selectedRule[field.key]}
                    onChange={(e) =>
                      updateRule(selectedRule.id, { [field.key]: e.target.value })
                    }
                    placeholder={`Enter ${field.label.toLowerCase()}...`}
                    rows={4}
                    style={{
                      width: "100%",
                      background: "#0f1115",
                      border: "1px solid #2a2d35",
                      borderRadius: 6,
                      padding: "10px 12px",
                      color: "#c5c9d2",
                      fontSize: 13,
                      lineHeight: 1.5,
                      resize: "vertical",
                      fontFamily: "'Segoe UI', system-ui, sans-serif",
                    }}
                  />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <AssetModal
        show={showAssetModal}
        onClose={() => setShowAssetModal(false)}
        assetInfo={assetInfo}
        setAssetInfo={setAssetInfo}
      />
    </div>
  );
}
