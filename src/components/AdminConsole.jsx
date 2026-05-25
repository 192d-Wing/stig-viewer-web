import { useCallback, useEffect, useMemo, useState } from "react";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Modal from "@cloudscape-design/components/modal";
import Box from "@cloudscape-design/components/box";
import Badge from "@cloudscape-design/components/badge";
import Select from "@cloudscape-design/components/select";
import Multiselect from "@cloudscape-design/components/multiselect";
import Input from "@cloudscape-design/components/input";
import Toggle from "@cloudscape-design/components/toggle";
import FormField from "@cloudscape-design/components/form-field";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Alert from "@cloudscape-design/components/alert";
import Container from "@cloudscape-design/components/container";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Textarea from "@cloudscape-design/components/textarea";
import DatePicker from "@cloudscape-design/components/date-picker";
import Pagination from "@cloudscape-design/components/pagination";
import FileUpload from "@cloudscape-design/components/file-upload";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import { apiGet, apiJson, apiFetch, BACKEND } from "../utils/api.js";

const ROLE_OPTIONS = [
  { label: "Author", value: "author" },
  { label: "Reviewer", value: "reviewer" },
  { label: "Admin", value: "admin" },
  { label: "Viewer", value: "viewer" },
];

const ROLE_BADGE = {
  author: "blue",
  reviewer: "green",
  admin: "red",
  viewer: "grey",
};

// Event kinds the backend currently knows how to fire. Keep in sync
// with ALLOWED_KINDS in backend/src/api/webhooks.rs — the create/update
// handlers reject anything outside that set with a 400.
const KIND_OPTIONS = [
  { label: "Assigned", value: "assigned" },
  { label: "Overdue digest", value: "overdue_digest" },
  { label: "Compliance report", value: "compliance_report" },
];

function roleLabel(value) {
  return ROLE_OPTIONS.find((o) => o.value === value)?.label ?? value;
}

/** Human-readable relative time. Falls back to absolute when older than ~30d. */
function relativeTime(iso) {
  if (!iso) return "Never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "Never";
  const diff = Date.now() - then;
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return new Date(iso).toLocaleDateString();
}

/** Show a truncated URL with hover-title for the full value. */
function truncateUrl(url, max = 50) {
  if (!url) return "";
  return url.length > max ? `${url.slice(0, max - 1)}…` : url;
}

export default function AdminConsole() {
  const [users, setUsers] = useState([]);
  const [assets, setAssets] = useState([]);
  const [webhooks, setWebhooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Role edit modal state: { user, role } | null
  const [roleModal, setRoleModal] = useState(null);
  const [roleSubmitting, setRoleSubmitting] = useState(false);
  const [roleError, setRoleError] = useState(null);

  // Owner re-assign form state
  const [ownerAsset, setOwnerAsset] = useState(null);
  const [ownerUser, setOwnerUser] = useState(null);
  const [ownerSubmitting, setOwnerSubmitting] = useState(false);
  const [ownerError, setOwnerError] = useState(null);
  const [ownerSuccess, setOwnerSuccess] = useState(null);

  // Webhook modal state. `mode` is 'create' or 'edit'.
  const [hookModal, setHookModal] = useState(null);
  const [hookSubmitting, setHookSubmitting] = useState(false);
  const [hookError, setHookError] = useState(null);

  // Deliveries panel state: { webhook, rows, loading } | null
  const [deliveriesPanel, setDeliveriesPanel] = useState(null);
  const [testFlash, setTestFlash] = useState(null);

  // Compliance reports
  const [reports, setReports] = useState([]);

  // Outbound email deliveries (compliance-report emails, dryrun + sent)
  const [emails, setEmails] = useState([]);

  // Background-job dashboard state: { latest: {name->row}, history: [row] }.
  // Auto-refreshed on a 10s interval below so admins watch ticks land
  // without manually hitting "Refresh".
  const [schedulerRuns, setSchedulerRuns] = useState({
    latest: {},
    history: [],
  });

  // Active sessions audit. Populated from /api/admin/sessions and
  // pruned when the admin clicks Revoke on a row.
  const [sessions, setSessions] = useState([]);
  const [revokeBusyId, setRevokeBusyId] = useState(null);

  // Pending finding-close approval queue. Reviewer/admin only — for
  // anyone else the GET returns just their own rows (which is fine,
  // AdminConsole is gated by an admin route anyway).
  const [approvals, setApprovals] = useState([]);
  const [rejectModal, setRejectModal] = useState(null);
  const [rejectReason, setRejectReason] = useState("");
  const [rejectBusy, setRejectBusy] = useState(false);
  const [rejectError, setRejectError] = useState(null);
  const [approveBusyId, setApproveBusyId] = useState(null);

  // Audit log search state. Filters are applied on Search-button click
  // rather than on every keystroke so we don't spam the backend while
  // an admin is still choosing dates / users.
  const [auditUser, setAuditUser] = useState(null);
  const [auditAsset, setAuditAsset] = useState(null);
  const [auditFrom, setAuditFrom] = useState("");
  const [auditTo, setAuditTo] = useState("");
  const [auditPage, setAuditPage] = useState(1);
  const AUDIT_PAGE_SIZE = 50;
  const [auditRows, setAuditRows] = useState([]);
  const [auditTotal, setAuditTotal] = useState(0);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState(null);
  // Bumped on every Search click. The fetch effect watches it so a
  // pagination change reuses the most-recently-submitted filters
  // without snapshotting them via refs.
  const [auditSearchTick, setAuditSearchTick] = useState(0);
  // Snapshot of filters at the moment Search was clicked. Pagination
  // changes re-run with these values, ignoring any unsubmitted edits
  // the admin made to the filter row.
  const [auditSubmitted, setAuditSubmitted] = useState({
    userId: "",
    assetId: "",
    from: "",
    to: "",
  });

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [u, a, w, r, e, ap, sr, sess] = await Promise.all([
        apiGet("/api/admin/users"),
        apiGet("/api/assets"),
        apiGet("/api/webhooks").catch(() => []),
        apiGet("/api/reports").catch(() => []),
        apiGet("/api/admin/email-deliveries").catch(() => []),
        apiGet("/api/approvals?status=pending").catch(() => []),
        apiGet("/api/admin/scheduler-runs").catch(() => ({
          latest: {},
          history: [],
        })),
        apiGet("/api/admin/sessions").catch(() => []),
      ]);
      setUsers(u);
      setAssets(a);
      setWebhooks(w);
      setReports(r);
      setEmails(e);
      setApprovals(ap);
      setSchedulerRuns(sr);
      setSessions(sess);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll the background-job feed every 10s so the admin sees ticks
  // land without manually refreshing. We only re-fetch the scheduler
  // endpoint here (not the whole console) to keep this cheap.
  useEffect(() => {
    const tick = async () => {
      try {
        const sr = await apiGet("/api/admin/scheduler-runs");
        setSchedulerRuns(sr);
      } catch {
        // Silently ignore — the manual Refresh surfaces real errors.
      }
    };
    const handle = setInterval(tick, 10_000);
    return () => clearInterval(handle);
  }, []);

  // Backup / restore admin tools — full DB + attachments dump and a
  // multipart upload to restore from such a dump. State here is local;
  // there's no list view, just one-shot actions.
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupError, setBackupError] = useState(null);
  const [restoreFiles, setRestoreFiles] = useState([]);
  const [restoreForce, setRestoreForce] = useState(false);
  const [restoreBusy, setRestoreBusy] = useState(false);
  const [restoreResult, setRestoreResult] = useState(null);
  const [restoreError, setRestoreError] = useState(null);

  const downloadBackup = useCallback(async () => {
    setBackupBusy(true);
    setBackupError(null);
    try {
      // apiFetch wires up X-User-Id + credentials so the admin gate
      // applies. A raw <a href> would skip the header and 403 in test
      // mode, so we go through the helper and dump to a blob URL.
      const res = await apiFetch("/api/admin/backup");
      if (!res.ok) {
        throw new Error(`backup failed: ${res.status}`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const date = new Date().toISOString().slice(0, 10);
      a.download = `stig-backup-${date}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // Give the browser a tick to actually start the download before
      // revoking the object URL.
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setBackupError(err.message);
    } finally {
      setBackupBusy(false);
    }
  }, []);

  const submitRestore = useCallback(async () => {
    if (!restoreFiles.length) {
      setRestoreError("Pick a backup .zip first.");
      return;
    }
    setRestoreBusy(true);
    setRestoreError(null);
    setRestoreResult(null);
    try {
      const fd = new FormData();
      fd.append("file", restoreFiles[0], restoreFiles[0].name);
      const qs = restoreForce ? "?force=true" : "?force=false";
      const res = await apiFetch(`/api/admin/restore${qs}`, {
        method: "POST",
        body: fd,
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body.error || `restore failed: ${res.status}`);
      }
      setRestoreResult(body);
      // Refresh the rest of the console so any newly-restored users /
      // assets / webhooks show up immediately.
      await refresh();
    } catch (err) {
      setRestoreError(err.message);
    } finally {
      setRestoreBusy(false);
    }
  }, [restoreFiles, restoreForce, refresh]);

  const revokeSession = useCallback(
    async (row) => {
      setRevokeBusyId(row.id);
      try {
        const res = await apiFetch(`/api/admin/sessions/${row.id}`, {
          method: "DELETE",
        });
        if (!res.ok && res.status !== 204) {
          throw new Error(`Revoke failed: ${res.status}`);
        }
        await refresh();
      } catch (err) {
        setError(err.message);
      } finally {
        setRevokeBusyId(null);
      }
    },
    [refresh],
  );

  // Re-fetch the audit page whenever the submitted filter set or page
  // changes. The Search button bumps `auditSearchTick` (with page reset
  // to 1) so a click always lands on page 1 even if the previous run
  // was on a later page.
  useEffect(() => {
    if (auditSearchTick === 0) return;
    let cancelled = false;
    const run = async () => {
      setAuditLoading(true);
      setAuditError(null);
      try {
        const qs = new URLSearchParams();
        if (auditSubmitted.userId) qs.set("userId", auditSubmitted.userId);
        if (auditSubmitted.assetId) qs.set("assetId", auditSubmitted.assetId);
        if (auditSubmitted.from) qs.set("from", auditSubmitted.from);
        if (auditSubmitted.to) qs.set("to", auditSubmitted.to);
        qs.set("page", String(auditPage));
        qs.set("pageSize", String(AUDIT_PAGE_SIZE));
        const res = await apiGet(`/api/audit/search?${qs.toString()}`);
        if (cancelled) return;
        setAuditRows(res.rows ?? []);
        setAuditTotal(res.totalCount ?? 0);
      } catch (err) {
        if (!cancelled) setAuditError(err.message);
      } finally {
        if (!cancelled) setAuditLoading(false);
      }
    };
    run();
    return () => {
      cancelled = true;
    };
  }, [auditSearchTick, auditPage, auditSubmitted]);

  const runAuditSearch = useCallback(() => {
    setAuditSubmitted({
      userId: auditUser?.value ?? "",
      assetId: auditAsset?.value ?? "",
      from: auditFrom,
      to: auditTo,
    });
    setAuditPage(1);
    setAuditSearchTick((t) => t + 1);
  }, [auditUser, auditAsset, auditFrom, auditTo]);

  const openRoleModal = useCallback((user) => {
    setRoleModal({ user, role: user.role });
    setRoleError(null);
  }, []);

  const submitRole = useCallback(async () => {
    if (!roleModal) return;
    setRoleSubmitting(true);
    setRoleError(null);
    try {
      await apiJson(
        `/api/admin/users/${roleModal.user.id}/role`,
        "PATCH",
        { role: roleModal.role },
      );
      setRoleModal(null);
      await refresh();
    } catch (err) {
      setRoleError(err.message);
    } finally {
      setRoleSubmitting(false);
    }
  }, [roleModal, refresh]);

  const submitOwnerChange = useCallback(async () => {
    if (!ownerAsset || !ownerUser) {
      setOwnerError("Pick an asset and a new owner.");
      return;
    }
    setOwnerSubmitting(true);
    setOwnerError(null);
    setOwnerSuccess(null);
    try {
      await apiJson(
        `/api/admin/assets/${ownerAsset.value}/owner`,
        "PATCH",
        { ownerId: ownerUser.value },
      );
      setOwnerSuccess(
        `Re-assigned ${ownerAsset.label} to ${ownerUser.label}.`,
      );
      setOwnerAsset(null);
      setOwnerUser(null);
      await refresh();
    } catch (err) {
      setOwnerError(err.message);
    } finally {
      setOwnerSubmitting(false);
    }
  }, [ownerAsset, ownerUser, refresh]);

  // ── Approval queue helpers ─────────────────────────────────────────────

  const approveRow = useCallback(
    async (row) => {
      setApproveBusyId(row.id);
      try {
        await apiJson(`/api/approvals/${row.id}/approve`, "POST", {});
        await refresh();
      } catch (err) {
        setError(err.message);
      } finally {
        setApproveBusyId(null);
      }
    },
    [refresh],
  );

  const openRejectModal = useCallback((row) => {
    setRejectModal(row);
    setRejectReason("");
    setRejectError(null);
  }, []);

  const submitReject = useCallback(async () => {
    if (!rejectModal) return;
    const reason = rejectReason.trim();
    if (!reason) {
      setRejectError("A reason is required to reject an approval.");
      return;
    }
    setRejectBusy(true);
    setRejectError(null);
    try {
      await apiJson(`/api/approvals/${rejectModal.id}/reject`, "POST", {
        reason,
      });
      setRejectModal(null);
      setRejectReason("");
      await refresh();
    } catch (err) {
      setRejectError(err.message);
    } finally {
      setRejectBusy(false);
    }
  }, [rejectModal, rejectReason, refresh]);

  // ── Webhook helpers ────────────────────────────────────────────────────

  const openCreateHook = useCallback(() => {
    setHookModal({
      mode: "create",
      id: null,
      name: "",
      url: "",
      secret: "",
      kinds: ["assigned"],
      enabled: true,
    });
    setHookError(null);
  }, []);

  const submitHook = useCallback(async () => {
    if (!hookModal) return;
    setHookSubmitting(true);
    setHookError(null);
    try {
      const body = {
        name: hookModal.name,
        url: hookModal.url,
        secret: hookModal.secret,
        kinds: hookModal.kinds,
      };
      if (hookModal.mode === "create") {
        await apiJson("/api/webhooks", "POST", body);
      } else {
        await apiJson(`/api/webhooks/${hookModal.id}`, "PATCH", {
          ...body,
          enabled: hookModal.enabled,
        });
      }
      setHookModal(null);
      await refresh();
    } catch (err) {
      setHookError(err.message);
    } finally {
      setHookSubmitting(false);
    }
  }, [hookModal, refresh]);

  const toggleHookEnabled = useCallback(
    async (hook, next) => {
      try {
        await apiJson(`/api/webhooks/${hook.id}`, "PATCH", { enabled: next });
        await refresh();
      } catch (err) {
        setError(err.message);
      }
    },
    [refresh],
  );

  const deleteHook = useCallback(
    async (hook) => {
      if (
        !window.confirm(`Delete webhook "${hook.name}"? This can't be undone.`)
      ) {
        return;
      }
      try {
        const res = await apiFetch(`/api/webhooks/${hook.id}`, {
          method: "DELETE",
        });
        if (!res.ok && res.status !== 204) {
          throw new Error(`Delete failed: ${res.status}`);
        }
        await refresh();
      } catch (err) {
        setError(err.message);
      }
    },
    [refresh],
  );

  const testHook = useCallback(async (hook) => {
    setTestFlash(null);
    try {
      const res = await apiFetch(`/api/webhooks/${hook.id}/test`, {
        method: "POST",
      });
      if (!res.ok && res.status !== 202) {
        throw new Error(`Test failed: ${res.status}`);
      }
      setTestFlash(
        `Test event dispatched to "${hook.name}". Open Deliveries to view the result.`,
      );
    } catch (err) {
      setError(err.message);
    }
  }, []);

  const openDeliveries = useCallback(async (hook) => {
    setDeliveriesPanel({ webhook: hook, rows: [], loading: true });
    try {
      const rows = await apiGet(`/api/webhooks/${hook.id}/deliveries`);
      setDeliveriesPanel({
        webhook: hook,
        rows: rows.slice(0, 10),
        loading: false,
      });
    } catch (err) {
      setDeliveriesPanel({
        webhook: hook,
        rows: [],
        loading: false,
        error: err.message,
      });
    }
  }, []);

  const columns = useMemo(
    () => [
      {
        id: "display_name",
        header: "Display name",
        cell: (u) => u.displayName,
        sortingField: "displayName",
      },
      {
        id: "email",
        header: "Email",
        cell: (u) => u.email || "—",
      },
      {
        id: "role",
        header: "Role",
        cell: (u) => (
          <Badge color={ROLE_BADGE[u.role] ?? "grey"}>
            {roleLabel(u.role)}
          </Badge>
        ),
      },
      {
        id: "last_login",
        header: "Last login",
        cell: (u) => relativeTime(u.lastLogin),
      },
      {
        id: "created",
        header: "Created",
        cell: (u) =>
          u.createdAt ? new Date(u.createdAt).toLocaleDateString() : "—",
      },
      {
        id: "actions",
        header: "",
        cell: (u) => (
          <Button variant="inline-link" onClick={() => openRoleModal(u)}>
            Change role
          </Button>
        ),
      },
    ],
    [openRoleModal],
  );

  const webhookColumns = useMemo(
    () => [
      {
        id: "name",
        header: "Name",
        cell: (w) => w.name,
      },
      {
        id: "url",
        header: "URL",
        cell: (w) => <span title={w.url}>{truncateUrl(w.url)}</span>,
      },
      {
        id: "kinds",
        header: "Events",
        cell: (w) => (
          <SpaceBetween direction="horizontal" size="xxs">
            {(w.kinds ?? []).map((k) => (
              <Badge key={k} color="blue">
                {k}
              </Badge>
            ))}
          </SpaceBetween>
        ),
      },
      {
        id: "enabled",
        header: "Enabled",
        cell: (w) => (
          <Toggle
            checked={w.enabled}
            onChange={({ detail }) => toggleHookEnabled(w, detail.checked)}
          />
        ),
      },
      {
        id: "actions",
        header: "",
        cell: (w) => (
          <SpaceBetween direction="horizontal" size="xs">
            <Button variant="inline-link" onClick={() => testHook(w)}>
              Test
            </Button>
            <Button variant="inline-link" onClick={() => openDeliveries(w)}>
              Deliveries
            </Button>
            <Button
              variant="inline-link"
              onClick={() =>
                setHookModal({
                  mode: "edit",
                  id: w.id,
                  name: w.name,
                  url: w.url,
                  secret: w.secret ?? "",
                  kinds: w.kinds ?? ["assigned"],
                  enabled: w.enabled,
                })
              }
            >
              Edit
            </Button>
            <Button variant="inline-link" onClick={() => deleteHook(w)}>
              Delete
            </Button>
          </SpaceBetween>
        ),
      },
    ],
    [toggleHookEnabled, testHook, openDeliveries, deleteHook],
  );

  const assetOptions = useMemo(
    () =>
      assets.map((a) => ({
        label: a.name,
        value: a.id,
        description: `Owner: ${a.ownerName}`,
      })),
    [assets],
  );

  const userOptions = useMemo(
    () =>
      users.map((u) => ({
        label: u.displayName,
        value: u.id,
        description: u.email || roleLabel(u.role),
      })),
    [users],
  );

  const selectedKindOptions = hookModal
    ? KIND_OPTIONS.filter((o) => (hookModal.kinds ?? []).includes(o.value))
    : [];

  // Five known scheduler names, ordered the way ops scan them. We
  // render a row per name even if no run has happened yet so the
  // dashboard is recognizable as soon as the table loads.
  const SCHEDULER_NAMES = [
    "sync",
    "snapshot",
    "overdue_digest",
    "audit_retention",
    "compliance_report",
  ];

  const latestRows = SCHEDULER_NAMES.map(
    (name) => schedulerRuns.latest?.[name] ?? { name, status: "—" },
  );

  const statusBadge = (status) => {
    if (status === "ok") return <Badge color="green">ok</Badge>;
    if (status === "error") return <Badge color="red">error</Badge>;
    if (status === "running") return <Badge color="blue">running</Badge>;
    return <Badge color="grey">{status}</Badge>;
  };

  const schedulerColumns = [
    {
      id: "name",
      header: "Scheduler",
      cell: (r) => r.name,
    },
    {
      id: "started",
      header: "Started",
      cell: (r) => (r.startedAt ? relativeTime(r.startedAt) : "—"),
    },
    {
      id: "finished",
      header: "Finished",
      cell: (r) => (r.finishedAt ? relativeTime(r.finishedAt) : "—"),
    },
    {
      id: "status",
      header: "Status",
      cell: (r) => statusBadge(r.status),
    },
    {
      id: "message",
      header: "Message",
      cell: (r) => (
        <Box variant="code" title={r.message ?? ""}>
          {(r.message ?? "").slice(0, 80)}
        </Box>
      ),
    },
  ];

  return (
    <SpaceBetween direction="vertical" size="l">
      {error && <Alert type="error">{error}</Alert>}
      {testFlash && (
        <Alert type="success" dismissible onDismiss={() => setTestFlash(null)}>
          {testFlash}
        </Alert>
      )}

      <Table
        variant="container"
        items={latestRows}
        columnDefinitions={schedulerColumns}
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No scheduler runs yet.
            </Box>
          </Box>
        }
        header={
          <Header
            counter={`(${Object.keys(schedulerRuns.latest ?? {}).length}/${SCHEDULER_NAMES.length})`}
            description="Latest tick per background scheduler. Auto-refreshes every 10 seconds."
          >
            Background jobs
          </Header>
        }
        data-testid="scheduler-latest-table"
      />

      <Table
        variant="container"
        items={schedulerRuns.history ?? []}
        columnDefinitions={schedulerColumns}
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No run history yet.
            </Box>
          </Box>
        }
        header={
          <Header
            counter={`(${(schedulerRuns.history ?? []).length})`}
            description="Most recent 10 scheduler ticks across every job, newest first."
          >
            Recent scheduler history
          </Header>
        }
        data-testid="scheduler-history-table"
      />

      <Table
        variant="container"
        items={sessions}
        loading={loading}
        loadingText="Loading active sessions"
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No active sessions.
            </Box>
          </Box>
        }
        columnDefinitions={[
          {
            id: "user",
            header: "User",
            cell: (s) => s.userName,
          },
          {
            id: "ip",
            header: "IP",
            cell: (s) => s.ip || "—",
          },
          {
            id: "user_agent",
            header: "User-Agent",
            cell: (s) => (
              <span title={s.userAgent || ""}>
                {s.userAgent ? truncateUrl(s.userAgent, 60) : "—"}
              </span>
            ),
          },
          {
            id: "created",
            header: "Created",
            cell: (s) => relativeTime(s.createdAt),
          },
          {
            id: "expires",
            header: "Expires",
            cell: (s) =>
              s.expiresAt ? new Date(s.expiresAt).toLocaleString() : "—",
          },
          {
            id: "actions",
            header: "",
            cell: (s) => (
              <Button
                variant="inline-link"
                loading={revokeBusyId === s.id}
                onClick={() => revokeSession(s)}
                data-testid={`revoke-session-${s.id}`}
              >
                Revoke
              </Button>
            ),
          },
        ]}
        header={
          <Header
            counter={`(${sessions.length})`}
            description="Currently-active sessions across every user. Revoke forces a re-login on the next request without touching the audit row."
          >
            Active sessions
          </Header>
        }
        data-testid="active-sessions-table"
      />

      <Table
        items={users}
        columnDefinitions={columns}
        loading={loading}
        loadingText="Loading users"
        empty={
          <Box textAlign="center" padding="l">
            No users yet.
          </Box>
        }
        header={
          <Header
            counter={`(${users.length})`}
            actions={
              <Button iconName="refresh" onClick={refresh} loading={loading}>
                Refresh
              </Button>
            }
          >
            Users
          </Header>
        }
      />

      <Table
        items={approvals}
        loading={loading}
        loadingText="Loading approvals"
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No pending approvals.
            </Box>
          </Box>
        }
        columnDefinitions={[
          {
            id: "asset",
            header: "Asset",
            cell: (r) => r.assetName,
          },
          {
            id: "stig",
            header: "STIG",
            cell: (r) => r.stigTitle,
          },
          {
            id: "rule",
            header: "Rule",
            cell: (r) => r.ruleId,
          },
          {
            id: "proposed",
            header: "Proposed status",
            cell: (r) => <Badge>{r.proposedStatus}</Badge>,
          },
          {
            id: "requested_by",
            header: "Requested by",
            cell: (r) => r.requestedByName,
          },
          {
            id: "requested_at",
            header: "Requested",
            cell: (r) => relativeTime(r.requestedAt),
          },
          {
            id: "actions",
            header: "",
            cell: (r) => (
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="primary"
                  loading={approveBusyId === r.id}
                  onClick={() => approveRow(r)}
                  data-testid={`approve-${r.id}`}
                >
                  Approve
                </Button>
                <Button
                  onClick={() => openRejectModal(r)}
                  data-testid={`reject-${r.id}`}
                >
                  Reject
                </Button>
              </SpaceBetween>
            ),
          },
        ]}
        header={
          <Header
            counter={`(${approvals.length})`}
            description="Closing transitions on assets with the approval policy enabled. Approve to apply the proposed status; reject with a reason to keep the rule open."
          >
            Pending finding-close approvals
          </Header>
        }
        data-testid="approvals-table"
      />

      <Container
        header={
          <Header
            description="Move an asset to a different owner. Useful when a teammate leaves or hands off a system."
          >
            Re-assign asset owner
          </Header>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="Asset">
            <Select
              placeholder="Choose an asset"
              selectedOption={ownerAsset}
              onChange={({ detail }) => setOwnerAsset(detail.selectedOption)}
              options={assetOptions}
              empty="No assets available"
              filteringType="auto"
            />
          </FormField>
          <FormField label="New owner">
            <Select
              placeholder="Choose a user"
              selectedOption={ownerUser}
              onChange={({ detail }) => setOwnerUser(detail.selectedOption)}
              options={userOptions}
              empty="No users available"
              filteringType="auto"
            />
          </FormField>
          {ownerError && <Alert type="error">{ownerError}</Alert>}
          {ownerSuccess && <Alert type="success">{ownerSuccess}</Alert>}
          <Box>
            <Button
              variant="primary"
              loading={ownerSubmitting}
              disabled={!ownerAsset || !ownerUser}
              onClick={submitOwnerChange}
            >
              Re-assign owner
            </Button>
          </Box>
        </SpaceBetween>
      </Container>

      <Container
        header={
          <Header
            description="Cross-cutting search over rule_audit. Filter by user, asset, and date range; results are paginated server-side."
          >
            Audit log
          </Header>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
              gap: "var(--space-scaled-m, 12px)",
            }}
          >
            <FormField label="User">
              <Select
                placeholder="Any user"
                selectedOption={auditUser}
                onChange={({ detail }) =>
                  setAuditUser(detail.selectedOption ?? null)
                }
                options={[
                  { label: "Any user", value: "" },
                  ...userOptions,
                ]}
                empty="No users available"
                filteringType="auto"
                data-testid="audit-user-select"
              />
            </FormField>
            <FormField label="Asset">
              <Select
                placeholder="Any asset"
                selectedOption={auditAsset}
                onChange={({ detail }) =>
                  setAuditAsset(detail.selectedOption ?? null)
                }
                options={[
                  { label: "Any asset", value: "" },
                  ...assetOptions,
                ]}
                empty="No assets available"
                filteringType="auto"
                data-testid="audit-asset-select"
              />
            </FormField>
            <FormField label="From">
              <DatePicker
                value={auditFrom}
                onChange={({ detail }) => setAuditFrom(detail.value || "")}
                placeholder="YYYY/MM/DD"
                data-testid="audit-from-picker"
              />
            </FormField>
            <FormField label="To">
              <DatePicker
                value={auditTo}
                onChange={({ detail }) => setAuditTo(detail.value || "")}
                placeholder="YYYY/MM/DD"
                data-testid="audit-to-picker"
              />
            </FormField>
          </div>
          <Box>
            <Button
              variant="primary"
              loading={auditLoading}
              onClick={runAuditSearch}
              data-testid="audit-search-button"
            >
              Search
            </Button>
          </Box>
          {auditError && <Alert type="error">{auditError}</Alert>}
          <Table
            variant="embedded"
            items={auditRows}
            loading={auditLoading}
            loadingText="Searching audit log"
            empty={
              <Box textAlign="center" padding="l">
                <Box variant="p" color="text-body-secondary">
                  {auditSearchTick === 0
                    ? "Click Search to query the audit log."
                    : "No audit rows match the current filters."}
                </Box>
              </Box>
            }
            columnDefinitions={[
              {
                id: "when",
                header: "When",
                cell: (r) =>
                  r.occurredAt
                    ? new Date(r.occurredAt).toLocaleString()
                    : "—",
              },
              {
                id: "by",
                header: "By",
                cell: (r) => r.byName,
              },
              {
                id: "asset",
                header: "Asset",
                cell: (r) => r.assetName ?? "—",
              },
              {
                id: "stig",
                header: "STIG",
                cell: (r) => r.stigTitle ?? "—",
              },
              {
                id: "rule",
                header: "Rule",
                cell: (r) => r.ruleId,
              },
              {
                id: "field",
                header: "Field",
                cell: (r) => r.field,
              },
              {
                id: "from",
                header: "From",
                cell: (r) => (
                  <span title={r.fromValue ?? ""}>
                    {truncateUrl(r.fromValue ?? "", 60)}
                  </span>
                ),
              },
              {
                id: "to",
                header: "To",
                cell: (r) => (
                  <span title={r.toValue ?? ""}>
                    {truncateUrl(r.toValue ?? "", 60)}
                  </span>
                ),
              },
            ]}
            pagination={
              <Pagination
                currentPageIndex={auditPage}
                pagesCount={Math.max(
                  1,
                  Math.ceil(auditTotal / AUDIT_PAGE_SIZE),
                )}
                onChange={({ detail }) => {
                  setAuditPage(detail.currentPageIndex);
                  // Force a re-fetch on page change. Submitted filters
                  // are reused; the tick bump is what wakes the effect.
                  setAuditSearchTick((t) => (t === 0 ? 1 : t + 1));
                }}
              />
            }
            header={
              <Header
                counter={`(${auditTotal})`}
                description="Newest first. Truncated values show the full text on hover."
              >
                Results
              </Header>
            }
            data-testid="audit-search-table"
          />
        </SpaceBetween>
      </Container>

      <Table
        items={webhooks}
        columnDefinitions={webhookColumns}
        loading={loading}
        loadingText="Loading webhooks"
        empty={
          <Box textAlign="center" padding="l">
            No webhooks configured.
          </Box>
        }
        header={
          <Header
            counter={`(${webhooks.length})`}
            description="Outbound HTTP notifications fired when a finding is assigned. Compatible with Slack incoming webhooks."
            actions={
              <Button variant="primary" onClick={openCreateHook}>
                Add webhook
              </Button>
            }
          >
            Webhooks
          </Header>
        }
      />

      <Table
        variant="container"
        items={reports}
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No compliance reports yet. The scheduler runs weekly.
            </Box>
          </Box>
        }
        columnDefinitions={[
          {
            id: "generated",
            header: "Generated",
            cell: (r) => new Date(r.generatedAt).toLocaleString(),
          },
          {
            id: "compliance",
            header: "Compliance",
            cell: (r) => `${r.summary?.complianceScore ?? 0}%`,
          },
          {
            id: "assets",
            header: "Assets",
            cell: (r) => r.summary?.assets ?? 0,
          },
          {
            id: "open",
            header: "Open findings",
            cell: (r) => r.summary?.openFindings ?? 0,
          },
          {
            id: "top",
            header: "Top-risk system",
            cell: (r) => r.summary?.topAssetName ?? "—",
          },
          {
            id: "download",
            header: "",
            cell: (r) => (
              <Button
                variant="inline-link"
                href={`${BACKEND}/api/reports/${r.id}/report.pdf`}
                iconName="download"
                target="_blank"
              >
                PDF
              </Button>
            ),
          },
        ]}
        header={
          <Header
            counter={`(${reports.length})`}
            description="Fleet-wide compliance snapshots. Generated on the configured cadence and emitted to compliance_report webhooks."
          >
            Compliance reports
          </Header>
        }
      />

      <Table
        variant="container"
        items={emails}
        empty={
          <Box textAlign="center" padding="l">
            <Box variant="p" color="text-body-secondary">
              No email deliveries yet. SMTP is unconfigured by default —
              set SMTP_HOST + COMPLIANCE_REPORT_RECIPIENTS to send for real.
            </Box>
          </Box>
        }
        columnDefinitions={[
          {
            id: "when",
            header: "When",
            cell: (e) => relativeTime(e.attemptedAt),
          },
          {
            id: "kind",
            header: "Kind",
            cell: (e) => e.kind,
          },
          {
            id: "to",
            header: "To",
            cell: (e) => (
              <span title={e.toAddresses}>
                {e.toAddresses ? truncateUrl(e.toAddresses, 40) : "—"}
              </span>
            ),
          },
          {
            id: "subject",
            header: "Subject",
            cell: (e) => (
              <span title={e.subject}>{truncateUrl(e.subject, 60)}</span>
            ),
          },
          {
            id: "mode",
            header: "Mode",
            cell: (e) => {
              if (e.error) return <Badge color="red">error</Badge>;
              if (e.mode === "sent") return <Badge color="green">sent</Badge>;
              return <Badge color="grey">{e.mode}</Badge>;
            },
          },
          {
            id: "error",
            header: "Error",
            cell: (e) =>
              e.error ? (
                <Box variant="code" title={e.error}>
                  {e.error.slice(0, 80)}
                </Box>
              ) : (
                "—"
              ),
          },
        ]}
        header={
          <Header
            counter={`(${emails.length})`}
            description="Outbound email audit log. Dryrun rows are recorded when SMTP isn't configured so ops can verify the path fires."
          >
            Email deliveries
          </Header>
        }
      />

      <Container
        header={
          <Header
            variant="h2"
            description="Dump every user-generated table + attachment blob to a single ZIP, or restore from a previously-taken backup. The STIG catalog itself is sourced externally and is not included."
          >
            Backup &amp; restore
          </Header>
        }
        data-testid="backup-restore-section"
      >
        <ColumnLayout columns={2}>
          <SpaceBetween direction="vertical" size="m">
            <Box variant="h3">Backup</Box>
            <Box variant="p" color="text-body-secondary">
              Streams a ZIP containing one JSONL per table plus the raw
              attachment blobs. Safe to take at any time.
            </Box>
            {backupError && <Alert type="error">{backupError}</Alert>}
            <Box>
              <Button
                variant="primary"
                iconName="download"
                loading={backupBusy}
                onClick={downloadBackup}
                data-testid="backup-download-btn"
              >
                Download backup
              </Button>
            </Box>
          </SpaceBetween>

          <SpaceBetween direction="vertical" size="m">
            <Box variant="h3">Restore</Box>
            <Box variant="p" color="text-body-secondary">
              Upload a backup .zip. Without <strong>Force overwrite</strong>
              {" "}the target must be empty (no assets, no checklists). With
              force, every backed-up table is truncated first —
              destructive.
            </Box>
            <FormField label="Backup file">
              <FileUpload
                value={restoreFiles}
                onChange={({ detail }) => {
                  setRestoreFiles(detail.value);
                  setRestoreResult(null);
                  setRestoreError(null);
                }}
                accept=".zip"
                showFileSize
                i18nStrings={{
                  uploadButtonText: () => "Choose backup .zip",
                  dropzoneText: () => "Drop backup .zip here",
                  removeFileAriaLabel: (i) => `Remove file ${i + 1}`,
                  limitShowFewer: "Show fewer files",
                  limitShowMore: "Show more files",
                  errorIconAriaLabel: "Error",
                }}
                data-testid="restore-file-input"
              />
            </FormField>
            <div data-testid="restore-force-toggle">
              <Toggle
                checked={restoreForce}
                onChange={({ detail }) => setRestoreForce(detail.checked)}
              >
                Force overwrite (truncates existing data)
              </Toggle>
            </div>
            <Box>
              <Button
                variant="primary"
                loading={restoreBusy}
                disabled={!restoreFiles.length}
                onClick={submitRestore}
                data-testid="restore-submit-btn"
              >
                Restore
              </Button>
            </Box>
            {restoreError && (
              <Alert type="error" data-testid="restore-error">
                {restoreError}
              </Alert>
            )}
            {restoreResult && (
              <Alert type="success" data-testid="restore-success">
                Restored {Object.values(restoreResult.restored ?? {}).reduce(
                  (a, b) => a + b,
                  0,
                )}{" "}
                rows across {Object.keys(restoreResult.restored ?? {}).length}{" "}
                tables and {restoreResult.attachmentsWritten ?? 0}{" "}
                attachment blob(s)
                {restoreResult.forced ? " (force overwrite)" : ""}.
              </Alert>
            )}
          </SpaceBetween>
        </ColumnLayout>
      </Container>

      <Modal
        visible={roleModal !== null}
        onDismiss={() => setRoleModal(null)}
        header={`Change role: ${roleModal?.user?.displayName ?? ""}`}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setRoleModal(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={roleSubmitting}
                onClick={submitRole}
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="Role">
            <Select
              selectedOption={
                ROLE_OPTIONS.find((o) => o.value === roleModal?.role) ??
                ROLE_OPTIONS[0]
              }
              onChange={({ detail }) =>
                setRoleModal((m) =>
                  m ? { ...m, role: detail.selectedOption.value } : m,
                )
              }
              options={ROLE_OPTIONS}
            />
          </FormField>
          {roleError && <Alert type="error">{roleError}</Alert>}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={hookModal !== null}
        onDismiss={() => setHookModal(null)}
        header={hookModal?.mode === "edit" ? "Edit webhook" : "Add webhook"}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setHookModal(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={hookSubmitting}
                onClick={submitHook}
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="Name">
            <Input
              value={hookModal?.name ?? ""}
              onChange={({ detail }) =>
                setHookModal((m) => (m ? { ...m, name: detail.value } : m))
              }
              placeholder="Slack #security"
            />
          </FormField>
          <FormField
            label="URL"
            description="Slack incoming webhook URL or any HTTPS endpoint."
          >
            <Input
              value={hookModal?.url ?? ""}
              onChange={({ detail }) =>
                setHookModal((m) => (m ? { ...m, url: detail.value } : m))
              }
              placeholder="https://hooks.slack.com/services/…"
            />
          </FormField>
          <FormField
            label="Secret"
            description="Optional. Sent as the X-Webhook-Secret header on each delivery."
          >
            <Input
              value={hookModal?.secret ?? ""}
              type="password"
              onChange={({ detail }) =>
                setHookModal((m) => (m ? { ...m, secret: detail.value } : m))
              }
            />
          </FormField>
          <FormField label="Events">
            <Multiselect
              selectedOptions={selectedKindOptions}
              onChange={({ detail }) =>
                setHookModal((m) =>
                  m
                    ? {
                        ...m,
                        kinds: detail.selectedOptions.map((o) => o.value),
                      }
                    : m,
                )
              }
              options={KIND_OPTIONS}
              placeholder="Select event kinds"
            />
          </FormField>
          {hookError && <Alert type="error">{hookError}</Alert>}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={deliveriesPanel !== null}
        onDismiss={() => setDeliveriesPanel(null)}
        header={`Recent deliveries: ${deliveriesPanel?.webhook?.name ?? ""}`}
        size="large"
        footer={
          <Box float="right">
            <Button variant="link" onClick={() => setDeliveriesPanel(null)}>
              Close
            </Button>
          </Box>
        }
      >
        {deliveriesPanel?.loading ? (
          <Box textAlign="center" padding="l">
            Loading…
          </Box>
        ) : deliveriesPanel?.error ? (
          <Alert type="error">{deliveriesPanel.error}</Alert>
        ) : !deliveriesPanel?.rows?.length ? (
          <Box textAlign="center" padding="l">
            No deliveries yet.
          </Box>
        ) : (
          <Table
            variant="embedded"
            items={deliveriesPanel.rows}
            columnDefinitions={[
              {
                id: "attempted_at",
                header: "When",
                cell: (d) => relativeTime(d.attemptedAt),
              },
              {
                id: "kind",
                header: "Kind",
                cell: (d) => d.kind,
              },
              {
                id: "status",
                header: "Status",
                cell: (d) =>
                  d.error ? (
                    <StatusIndicator type="error">Failed</StatusIndicator>
                  ) : d.httpStatus && d.httpStatus >= 200 && d.httpStatus < 300 ? (
                    <StatusIndicator type="success">
                      {d.httpStatus}
                    </StatusIndicator>
                  ) : (
                    <StatusIndicator type="warning">
                      {d.httpStatus ?? "—"}
                    </StatusIndicator>
                  ),
              },
              {
                id: "detail",
                header: "Detail",
                cell: (d) => (
                  <Box variant="code">
                    {(d.error ?? d.response ?? "").slice(0, 200)}
                  </Box>
                ),
              },
            ]}
          />
        )}
      </Modal>

      <Modal
        visible={rejectModal !== null}
        onDismiss={() => setRejectModal(null)}
        header="Reject approval request"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setRejectModal(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={rejectBusy}
                onClick={submitReject}
                data-testid="reject-submit"
              >
                Reject
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          {rejectModal && (
            <Box>
              {rejectModal.assetName} · {rejectModal.stigTitle} ·{" "}
              {rejectModal.ruleId}
            </Box>
          )}
          <FormField
            label="Reason"
            description="The requester will see this reason in their notifications."
          >
            <Textarea
              value={rejectReason}
              onChange={({ detail }) => setRejectReason(detail.value)}
              rows={4}
              data-testid="reject-reason"
            />
          </FormField>
          {rejectError && <Alert type="error">{rejectError}</Alert>}
        </SpaceBetween>
      </Modal>
    </SpaceBetween>
  );
}
