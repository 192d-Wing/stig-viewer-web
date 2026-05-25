import { useCallback, useContext, useEffect, useState } from "react";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Select from "@cloudscape-design/components/select";
import Input from "@cloudscape-design/components/input";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import LineChart from "@cloudscape-design/components/line-chart";
import Toggle from "@cloudscape-design/components/toggle";
import { apiGet, apiJson, apiFetch, BACKEND } from "../utils/api.js";
import { renderMarkdown } from "../utils/markdown.js";
import { AuthContext } from "./AuthGate.jsx";

export default function AssetDetail({ assetId, onBack, onOpenChecklist, onEdit }) {
  const currentUser = useContext(AuthContext);

  const [asset, setAsset] = useState(null);
  const [checklists, setChecklists] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [trend, setTrend] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [applyOpen, setApplyOpen] = useState(false);
  const [selectedStig, setSelectedStig] = useState(null);
  const [applyError, setApplyError] = useState(null);
  const [applying, setApplying] = useState(false);

  // ── Sharing (ACL) state ────────────────────────────────────────────
  // Loaded lazily — the ACL list endpoint 403s for non-managers, so we
  // probe it once and surface the section only when the response was
  // 200. `aclVisible` is the gate (owner / global admin / acl-admin).
  const [aclRows, setAclRows] = useState([]);
  const [aclVisible, setAclVisible] = useState(false);
  const [allUsers, setAllUsers] = useState([]);
  const [aclTarget, setAclTarget] = useState(null);
  const [aclPermission, setAclPermission] = useState({
    label: "Write",
    value: "write",
  });
  const [aclError, setAclError] = useState(null);
  const [aclBusy, setAclBusy] = useState(false);

  // ── Email CC state ─────────────────────────────────────────────────
  // The list endpoint 403s for anyone who can't manage the asset, so we
  // probe it and only render the section if the response was 200 — same
  // pattern as the Sharing section above. Owner / write-ACL / admin.
  const [ccRows, setCcRows] = useState([]);
  const [ccVisible, setCcVisible] = useState(false);
  const [ccInput, setCcInput] = useState("");
  const [ccError, setCcError] = useState(null);
  const [ccBusy, setCcBusy] = useState(false);
  const [emailSendStatus, setEmailSendStatus] = useState(null);
  const [emailSending, setEmailSending] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [a, cls, cat, tr] = await Promise.all([
        apiGet(`/api/assets/${assetId}`),
        apiGet(`/api/assets/${assetId}/checklists`),
        // catalog is public — but apiGet sends creds anyway, no harm
        apiGet("/api/catalog"),
        apiGet(`/api/assets/${assetId}/trend?days=30`).catch(() => null),
      ]);
      setAsset(a);
      setChecklists(cls);
      setCatalog(cat);
      setTrend(tr);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  /// Probe + load the ACL roster. The backend 403s when the caller can't
  /// manage sharing on the asset, which is exactly the signal we want for
  /// hiding the section UI. We swallow the 403 and leave `aclVisible`
  /// false so the section stays hidden.
  const refreshAcl = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/assets/${assetId}/acl`);
      if (res.status === 403) {
        setAclVisible(false);
        return;
      }
      if (!res.ok) {
        setAclVisible(false);
        return;
      }
      const rows = await res.json();
      setAclRows(rows);
      setAclVisible(true);
      // Lazy-load the user picker too — only needed inside the section.
      try {
        const users = await apiGet("/api/users");
        setAllUsers(users);
      } catch {
        // Picker just won't have options if this fails; surface via the
        // shared error path so it's visible to operators.
        setAllUsers([]);
      }
    } catch {
      // Network-level failure — keep the section hidden rather than
      // leaking auth state via an alarming alert.
      setAclVisible(false);
    }
  }, [assetId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Re-probe ACL access whenever the asset changes. Done after `refresh`
  // so the owner-id is already populated client-side and the section
  // shows up promptly for the obvious case (you own the asset).
  useEffect(() => {
    refreshAcl();
  }, [refreshAcl]);

  const grantAcl = useCallback(async () => {
    if (!aclTarget) return;
    setAclBusy(true);
    setAclError(null);
    try {
      await apiJson(`/api/assets/${assetId}/acl`, "POST", {
        userId: aclTarget.value,
        permission: aclPermission.value,
      });
      setAclTarget(null);
      setAclPermission({ label: "Write", value: "write" });
      await refreshAcl();
    } catch (err) {
      setAclError(err.message);
    } finally {
      setAclBusy(false);
    }
  }, [aclTarget, aclPermission, assetId, refreshAcl]);

  const revokeAcl = useCallback(
    async (userId) => {
      const res = await apiFetch(
        `/api/assets/${assetId}/acl/${encodeURIComponent(userId)}`,
        { method: "DELETE" },
      );
      if (!res.ok && res.status !== 204) {
        setAclError(`Revoke failed: ${res.status}`);
        return;
      }
      await refreshAcl();
    },
    [assetId, refreshAcl],
  );

  // ── Email CC: probe + load ────────────────────────────────────────
  // Mirrors `refreshAcl` — a 403 from the list endpoint is the signal
  // that the current user can't manage this asset, so we hide the
  // section silently instead of surfacing a scary error.
  const refreshCc = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/assets/${assetId}/email-cc`);
      if (!res.ok) {
        setCcVisible(false);
        return;
      }
      const rows = await res.json();
      setCcRows(rows);
      setCcVisible(true);
    } catch {
      setCcVisible(false);
    }
  }, [assetId]);

  useEffect(() => {
    refreshCc();
  }, [refreshCc]);

  const addCc = useCallback(async () => {
    const email = ccInput.trim();
    if (!email || !email.includes("@")) {
      setCcError("Enter a valid email address (must contain @).");
      return;
    }
    setCcBusy(true);
    setCcError(null);
    try {
      const rows = await apiJson(`/api/assets/${assetId}/email-cc`, "POST", {
        email,
      });
      setCcRows(rows);
      setCcInput("");
    } catch (err) {
      setCcError(err.message || "Failed to add recipient.");
    } finally {
      setCcBusy(false);
    }
  }, [assetId, ccInput]);

  const removeCc = useCallback(
    async (email) => {
      setCcError(null);
      const res = await apiFetch(
        `/api/assets/${assetId}/email-cc/${encodeURIComponent(email)}`,
        { method: "DELETE" },
      );
      if (!res.ok && res.status !== 204) {
        setCcError(`Remove failed: ${res.status}`);
        return;
      }
      await refreshCc();
    },
    [assetId, refreshCc],
  );

  // ── Scheduled email cadence ────────────────────────────────────────
  // Re-uses the same write-ACL gate the on-demand send already uses
  // (ccVisible). Persists via the asset PATCH endpoint and re-reads the
  // asset row so `emailLastSentAt` reflects whatever the scheduler last
  // stamped.
  const CADENCE_OPTIONS = [
    { label: "Off", value: "off" },
    { label: "Daily", value: "daily" },
    { label: "Weekly", value: "weekly" },
    { label: "Monthly", value: "monthly" },
  ];
  const [cadenceBusy, setCadenceBusy] = useState(false);
  const setCadence = useCallback(
    async (next) => {
      if (!asset) return;
      setCadenceBusy(true);
      try {
        const updated = await apiJson(
          `/api/assets/${asset.id}`,
          "PATCH",
          { emailCadence: next },
        );
        setAsset(updated);
      } catch (err) {
        setCcError(err.message || "Failed to update cadence.");
      } finally {
        setCadenceBusy(false);
      }
    },
    [asset],
  );

  const emailReportNow = useCallback(async () => {
    setEmailSending(true);
    setEmailSendStatus(null);
    try {
      const result = await apiJson(
        `/api/assets/${assetId}/email-report`,
        "POST",
        {},
      );
      setEmailSendStatus({
        type: "success",
        recipients: result.recipients || [],
        mode: result.mode,
        error: result.error || null,
      });
    } catch (err) {
      setEmailSendStatus({
        type: "error",
        message: err.message || "Failed to send report.",
      });
    } finally {
      setEmailSending(false);
    }
  }, [assetId]);

  const isOwner = asset && currentUser?.id === asset.ownerId;

  const appliedStigIds = new Set(checklists.map((c) => c.stigId));
  const availableStigs = catalog.filter((s) => !appliedStigIds.has(s.id));

  const apply = useCallback(async () => {
    if (!selectedStig) return;
    setApplying(true);
    setApplyError(null);
    try {
      await apiJson(`/api/assets/${assetId}/checklists`, "POST", {
        stigId: selectedStig.value,
      });
      setApplyOpen(false);
      setSelectedStig(null);
      await refresh();
    } catch (err) {
      setApplyError(err.message);
    } finally {
      setApplying(false);
    }
  }, [assetId, selectedStig, refresh]);

  const removeChecklist = useCallback(
    async (cid) => {
      const res = await apiFetch(`/api/checklists/${cid}`, { method: "DELETE" });
      if (!res.ok && res.status !== 204) {
        setError(`Delete failed: ${res.status}`);
        return;
      }
      await refresh();
    },
    [refresh],
  );

  const [approvalToggleBusy, setApprovalToggleBusy] = useState(false);
  const toggleApprovalPolicy = useCallback(
    async (next) => {
      if (!asset) return;
      setApprovalToggleBusy(true);
      try {
        const updated = await apiJson(
          `/api/assets/${asset.id}/approval-policy`,
          "PATCH",
          { requiresApproval: next },
        );
        setAsset(updated);
      } catch (err) {
        setError(err.message);
      } finally {
        setApprovalToggleBusy(false);
      }
    },
    [asset],
  );

  // OSCAL JSON download — fetched via apiFetch so we carry the
  // X-User-Id header through, then triggered as a blob download in the
  // browser. The filename comes from the server's Content-Disposition
  // when present (which is the case here — see backend/src/api/oscal.rs).
  const downloadOscal = useCallback(async () => {
    if (!asset) return;
    try {
      const res = await apiFetch(`/api/assets/${asset.id}/oscal.json`);
      if (!res.ok) {
        setError(`OSCAL download failed: ${res.status}`);
        return;
      }
      const blob = await res.blob();
      // Pull filename out of Content-Disposition if the server sent one;
      // fall back to a sensible default so we don't end up with "download".
      const cd = res.headers.get("Content-Disposition") || "";
      const m = cd.match(/filename="?([^";]+)"?/i);
      const filename = m ? m[1] : `oscal-${asset.name}.json`;

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      // Defer revoke so the click has time to start the download.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setError(err.message || "OSCAL download failed");
    }
  }, [asset]);

  const [reapplyTarget, setReapplyTarget] = useState(null);
  const [reapplying, setReapplying] = useState(false);
  const reapply = useCallback(async () => {
    if (!reapplyTarget) return;
    setReapplying(true);
    try {
      await apiJson(
        `/api/checklists/${reapplyTarget.id}/reapply`,
        "POST",
        {},
      );
      setReapplyTarget(null);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setReapplying(false);
    }
  }, [reapplyTarget, refresh]);

  if (loading) {
    return (
      <Box padding="xxl" textAlign="center">
        <StatusIndicator type="loading">Loading system</StatusIndicator>
      </Box>
    );
  }

  if (error) {
    return (
      <Box padding="m">
        <Alert type="error" header="Error">
          {error}
        </Alert>
        <Box padding={{ top: "m" }}>
          <Button onClick={onBack}>Back to systems</Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box padding="m">
      <SpaceBetween direction="vertical" size="l">
        <Button iconName="arrow-left" onClick={onBack}>
          Back to systems
        </Button>

        <Container
          header={
            <Header
              variant="h1"
              description={asset.description || undefined}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button
                    iconName="download"
                    href={`${BACKEND}/api/assets/${asset.id}/report.pdf`}
                    target="_blank"
                    download
                  >
                    Download PDF report
                  </Button>
                  <Button
                    iconName="download"
                    href={`${BACKEND}/api/assets/${asset.id}/bundle.zip`}
                    target="_blank"
                    download
                    ariaLabel="Download bundle (includes CKL files and evidence attachments)"
                  >
                    Download bundle
                  </Button>
                  <Button
                    iconName="download"
                    onClick={downloadOscal}
                    ariaLabel="Download OSCAL assessment-results JSON"
                  >
                    Download OSCAL
                  </Button>
                </SpaceBetween>
              }
            >
              {asset.name}
            </Header>
          }
        >
          <ColumnLayout columns={4} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Hostname</Box>
              <div>{asset.hostname || "—"}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">Classification</Box>
              <Badge>{asset.classification}</Badge>
            </div>
            <div>
              <Box variant="awsui-key-label">Owner</Box>
              <div>{isOwner ? "You" : asset.ownerId}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">
                Require approval to close findings
              </Box>
              <Toggle
                checked={!!asset.requiresApproval}
                disabled={!isOwner || approvalToggleBusy}
                onChange={({ detail }) =>
                  toggleApprovalPolicy(detail.checked)
                }
                data-testid="approval-policy-toggle"
              >
                {asset.requiresApproval ? "Enabled" : "Disabled"}
              </Toggle>
            </div>
          </ColumnLayout>
        </Container>

        {trend && trend.overall.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                description={`${trend.overall.length} snapshot${trend.overall.length === 1 ? "" : "s"} in the last 30 days`}
              >
                Posture over time
              </Header>
            }
          >
            <LineChart
              series={[
                {
                  title: "Open",
                  type: "line",
                  color: "#d13212",
                  data: trend.overall.map((p) => ({
                    x: new Date(p.capturedAt),
                    y: p.open,
                  })),
                },
                {
                  title: "Reviewed",
                  type: "line",
                  color: "#1d8102",
                  data: trend.overall.map((p) => ({
                    x: new Date(p.capturedAt),
                    y: p.reviewed,
                  })),
                },
              ]}
              xScaleType="time"
              xTitle="Time"
              yTitle="Rules"
              height={220}
              hideFilter
              ariaLabel={`${asset.name} posture trend`}
              empty={
                <Box textAlign="center" color="inherit">
                  No snapshots yet
                </Box>
              }
              noMatch={
                <Box textAlign="center" color="inherit">
                  No data in selected range
                </Box>
              }
            />
          </Container>
        )}

        {trend && trend.overall.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                description={`${trend.overall.length} snapshot${trend.overall.length === 1 ? "" : "s"} in the last 30 days`}
              >
                Compliance trend
              </Header>
            }
          >
            <LineChart
              series={[
                {
                  title: "Compliance",
                  type: "line",
                  color: "#1d8102",
                  data: trend.overall.map((p) => ({
                    x: new Date(p.capturedAt),
                    y: p.complianceScore ?? 0,
                  })),
                },
              ]}
              xScaleType="time"
              xTitle="Time"
              yTitle="Compliance (%)"
              yDomain={[0, 100]}
              height={220}
              hideFilter
              ariaLabel={`${asset.name} compliance trend`}
              empty={
                <Box textAlign="center" color="inherit">
                  No snapshots yet
                </Box>
              }
              noMatch={
                <Box textAlign="center" color="inherit">
                  No data in selected range
                </Box>
              }
            />
          </Container>
        )}

        <Table
          variant="container"
          items={checklists}
          columnDefinitions={[
            {
              id: "stig",
              header: "STIG",
              cell: (c) => {
                const meta = catalog.find((s) => s.id === c.stigId);
                const outdated =
                  c.appliedVersion &&
                  meta &&
                  (meta.version !== c.appliedVersion ||
                    meta.releaseInfo !== c.appliedRelease);
                return (
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button
                      variant="inline-link"
                      onClick={() => onOpenChecklist(c.id)}
                    >
                      {meta?.title || c.stigId}
                    </Button>
                    {outdated && (
                      <>
                        <Badge color="red">Out of date</Badge>
                        <Button
                          variant="inline-link"
                          disabled={!isOwner}
                          onClick={() =>
                            setReapplyTarget({
                              id: c.id,
                              title: meta?.title || c.stigId,
                              fromVersion: c.appliedVersion,
                              fromRelease: c.appliedRelease,
                              toVersion: meta?.version ?? "",
                              toRelease: meta?.releaseInfo ?? "",
                            })
                          }
                        >
                          Re-apply
                        </Button>
                      </>
                    )}
                  </SpaceBetween>
                );
              },
            },
            {
              id: "status",
              header: "Status",
              cell: (c) => <Badge>{c.status}</Badge>,
            },
            {
              id: "updated",
              header: "Last activity",
              cell: (c) => new Date(c.updatedAt).toLocaleString(),
            },
            {
              id: "actions",
              header: "",
              cell: (c) => (
                <Button
                  variant="inline-link"
                  disabled={!isOwner}
                  onClick={() => removeChecklist(c.id)}
                >
                  Remove
                </Button>
              ),
            },
          ]}
          empty={
            <Box textAlign="center" padding="l">
              <Box variant="p" color="text-body-secondary">
                No STIGs applied to this system yet.
              </Box>
            </Box>
          }
          header={
            <Header
              counter={`(${checklists.length})`}
              actions={
                <Button
                  variant="primary"
                  disabled={!isOwner || availableStigs.length === 0}
                  onClick={() => {
                    setSelectedStig(null);
                    setApplyError(null);
                    setApplyOpen(true);
                  }}
                >
                  Apply STIG
                </Button>
              }
            >
              Applied STIGs
            </Header>
          }
        />

        {aclVisible && (
          <Container
            header={
              <Header
                variant="h2"
                counter={`(${aclRows.length})`}
                description="Owner and global admins always have full access. Add a user below to grant additional read/write/admin permission on this system."
              >
                Sharing
              </Header>
            }
            data-testid="sharing-section"
          >
            <SpaceBetween direction="vertical" size="m">
              {aclError && (
                <Alert type="error" onDismiss={() => setAclError(null)} dismissible>
                  {aclError}
                </Alert>
              )}
              <Table
                variant="embedded"
                items={aclRows}
                data-testid="sharing-table"
                columnDefinitions={[
                  {
                    id: "user",
                    header: "User",
                    cell: (r) => r.displayName || r.userId,
                  },
                  {
                    id: "permission",
                    header: "Permission",
                    cell: (r) => <Badge>{r.permission}</Badge>,
                  },
                  {
                    id: "grantedAt",
                    header: "Granted",
                    cell: (r) => new Date(r.grantedAt).toLocaleString(),
                  },
                  {
                    id: "actions",
                    header: "",
                    cell: (r) => (
                      <Button
                        variant="inline-link"
                        onClick={() => revokeAcl(r.userId)}
                        data-testid={`sharing-remove-${r.userId}`}
                      >
                        Remove
                      </Button>
                    ),
                  },
                ]}
                empty={
                  <Box textAlign="center" padding="m">
                    <Box variant="p" color="text-body-secondary">
                      No additional users have been granted access.
                    </Box>
                  </Box>
                }
              />
              <ColumnLayout columns={3}>
                <FormField label="User">
                  <Select
                    selectedOption={aclTarget}
                    onChange={({ detail }) =>
                      setAclTarget(detail.selectedOption)
                    }
                    placeholder="Choose a user"
                    filteringType="auto"
                    data-testid="sharing-user-select"
                    options={allUsers
                      // Hide the owner and anyone already in the roster
                      // — re-adding them is either a no-op or rejected
                      // by the backend.
                      .filter(
                        (u) =>
                          u.id !== asset?.ownerId &&
                          !aclRows.some((r) => r.userId === u.id),
                      )
                      .map((u) => ({
                        label: u.displayName,
                        value: u.id,
                      }))}
                  />
                </FormField>
                <FormField label="Permission">
                  <Select
                    selectedOption={aclPermission}
                    onChange={({ detail }) =>
                      setAclPermission(detail.selectedOption)
                    }
                    data-testid="sharing-permission-select"
                    options={[
                      { label: "Read", value: "read" },
                      { label: "Write", value: "write" },
                      { label: "Admin", value: "admin" },
                    ]}
                  />
                </FormField>
                <FormField label="&nbsp;">
                  <Button
                    variant="primary"
                    loading={aclBusy}
                    disabled={!aclTarget}
                    onClick={grantAcl}
                    data-testid="sharing-add-button"
                  >
                    Add
                  </Button>
                </FormField>
              </ColumnLayout>
            </SpaceBetween>
          </Container>
        )}

        {ccVisible && (
          <Container
            header={
              <Header
                variant="h2"
                counter={`(${ccRows.length})`}
                description="Additional addresses that receive the per-asset compliance PDF when you click ‘Email report now’. The asset owner's email is always included if set."
                actions={
                  <Button
                    variant="primary"
                    loading={emailSending}
                    onClick={emailReportNow}
                    data-testid="email-report-now-button"
                  >
                    Email report now
                  </Button>
                }
              >
                Email recipients
              </Header>
            }
            data-testid="email-cc-section"
          >
            <SpaceBetween direction="vertical" size="m">
              {ccError && (
                <Alert
                  type="error"
                  dismissible
                  onDismiss={() => setCcError(null)}
                >
                  {ccError}
                </Alert>
              )}
              {emailSendStatus?.type === "success" && (
                <Alert
                  type={emailSendStatus.error ? "warning" : "success"}
                  dismissible
                  onDismiss={() => setEmailSendStatus(null)}
                  data-testid="email-send-result"
                  header={
                    emailSendStatus.error
                      ? `Email send reported an error (mode: ${emailSendStatus.mode})`
                      : `Email ${emailSendStatus.mode === "dryrun" ? "queued (dry-run)" : "sent"} to ${emailSendStatus.recipients.length} recipient${emailSendStatus.recipients.length === 1 ? "" : "s"}`
                  }
                >
                  {emailSendStatus.recipients.join(", ") || "(no recipients)"}
                  {emailSendStatus.error ? ` — ${emailSendStatus.error}` : ""}
                </Alert>
              )}
              {emailSendStatus?.type === "error" && (
                <Alert
                  type="error"
                  dismissible
                  onDismiss={() => setEmailSendStatus(null)}
                  data-testid="email-send-result"
                >
                  {emailSendStatus.message}
                </Alert>
              )}
              <ColumnLayout columns={2}>
                <FormField
                  label="Scheduled cadence"
                  description="Auto-mail the per-asset compliance PDF to the recipients above on this cadence. ‘Off’ disables scheduled sends; the on-demand button above still works."
                >
                  <Select
                    selectedOption={
                      CADENCE_OPTIONS.find(
                        (o) => o.value === (asset?.emailCadence || "off"),
                      ) || CADENCE_OPTIONS[0]
                    }
                    onChange={({ detail }) =>
                      setCadence(detail.selectedOption.value)
                    }
                    options={CADENCE_OPTIONS}
                    disabled={cadenceBusy}
                    data-testid="email-cadence-select"
                  />
                </FormField>
                <FormField label="Last sent">
                  <Box
                    data-testid="email-last-sent"
                    color="text-body-secondary"
                  >
                    {asset?.emailLastSentAt
                      ? new Date(asset.emailLastSentAt).toLocaleString()
                      : "Never"}
                  </Box>
                </FormField>
              </ColumnLayout>
              <Table
                variant="embedded"
                items={ccRows}
                data-testid="email-cc-table"
                columnDefinitions={[
                  {
                    id: "email",
                    header: "Email",
                    cell: (r) => r.email,
                  },
                  {
                    id: "added",
                    header: "Added",
                    cell: (r) => new Date(r.addedAt).toLocaleString(),
                  },
                  {
                    id: "actions",
                    header: "",
                    cell: (r) => (
                      <Button
                        variant="inline-link"
                        onClick={() => removeCc(r.email)}
                        data-testid={`email-cc-remove-${r.email}`}
                      >
                        Remove
                      </Button>
                    ),
                  },
                ]}
                empty={
                  <Box textAlign="center" padding="m">
                    <Box variant="p" color="text-body-secondary">
                      No additional recipients configured yet.
                    </Box>
                  </Box>
                }
              />
              <ColumnLayout columns={2}>
                <FormField label="Email address">
                  <Input
                    value={ccInput}
                    onChange={({ detail }) => setCcInput(detail.value)}
                    placeholder="ops@example.gov"
                    data-testid="email-cc-input"
                  />
                </FormField>
                <FormField label="&nbsp;">
                  <Button
                    variant="primary"
                    loading={ccBusy}
                    disabled={ccInput.trim().length === 0}
                    onClick={addCc}
                    data-testid="email-cc-add-button"
                  >
                    Add
                  </Button>
                </FormField>
              </ColumnLayout>
            </SpaceBetween>
          </Container>
        )}

        <Container
          header={
            <Header
              variant="h2"
              description="Free-form markdown notes for this system — operational steps, escalation contacts, known issues."
              actions={
                // Edit is gated on write-or-better. `ccVisible` is a
                // good proxy because the email-cc list endpoint 403s
                // for users without the write ACL — reusing the
                // signal avoids a separate ACL probe round-trip. The
                // PUT endpoint server-side gates on `admin`, so non-
                // owner write-ACL users will get a 403 if they try
                // to save — handled by the existing error path in
                // the modal.
                (isOwner || ccVisible) && onEdit ? (
                  <Button
                    onClick={() => onEdit(asset)}
                    data-testid="runbook-edit-button"
                  >
                    Edit
                  </Button>
                ) : null
              }
            >
              Runbook
            </Header>
          }
          data-testid="runbook-section"
        >
          {asset.runbook && asset.runbook.trim().length > 0 ? (
            <div
              className="runbook-rendered"
              data-testid="runbook-rendered"
              // The renderer in `utils/markdown.js` HTML-escapes
              // every text token before assembling tags, so the
              // only "raw" content here is the tag shell we
              // constructed. Bare URLs are autolinked with
              // rel="noopener noreferrer".
              dangerouslySetInnerHTML={{
                __html: renderMarkdown(asset.runbook),
              }}
            />
          ) : (
            <Box
              color="text-body-secondary"
              data-testid="runbook-placeholder"
            >
              No runbook yet — click Edit to add one.
            </Box>
          )}
        </Container>
      </SpaceBetween>

      <Modal
        visible={applyOpen}
        onDismiss={() => setApplyOpen(false)}
        header="Apply STIG to this system"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setApplyOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={applying}
                disabled={!selectedStig}
                onClick={apply}
              >
                Apply
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="STIG">
            <Select
              selectedOption={selectedStig}
              onChange={({ detail }) => setSelectedStig(detail.selectedOption)}
              options={availableStigs.map((s) => ({
                label: s.title,
                value: s.id,
                description: `${s.category} · v${s.version}`,
              }))}
              placeholder="Choose a STIG"
              filteringType="auto"
              empty="All STIGs have already been applied."
            />
          </FormField>
          {applyError && <Alert type="error">{applyError}</Alert>}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={reapplyTarget !== null}
        onDismiss={() => setReapplyTarget(null)}
        header="Re-apply STIG"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setReapplyTarget(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={reapplying}
                onClick={reapply}
              >
                Re-apply
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {reapplyTarget && (
          <SpaceBetween direction="vertical" size="m">
            <Box>
              <strong>{reapplyTarget.title}</strong>
              <Box variant="p" color="text-body-secondary">
                {`v${reapplyTarget.fromVersion} (${reapplyTarget.fromRelease}) → v${reapplyTarget.toVersion} (${reapplyTarget.toRelease})`}
              </Box>
            </Box>
            <Alert type="info">
              Existing rule statuses are preserved where rule IDs still exist
              in the new revision. Overrides for rules that no longer exist
              will be dropped.
            </Alert>
          </SpaceBetween>
        )}
      </Modal>
    </Box>
  );
}
