import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Box from "@cloudscape-design/components/box";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import ProgressBar from "@cloudscape-design/components/progress-bar";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import PieChart from "@cloudscape-design/components/pie-chart";
import LineChart from "@cloudscape-design/components/line-chart";
import Button from "@cloudscape-design/components/button";
import Select from "@cloudscape-design/components/select";
import Toggle from "@cloudscape-design/components/toggle";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import DatePicker from "@cloudscape-design/components/date-picker";
import { apiFetch, apiGet, apiJson } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";
import { useUrlState } from "../hooks/useUrlState.js";

const SEVERITY_OPTIONS = [
  { label: "All severities", value: null },
  { label: "CAT I", value: "CAT I" },
  { label: "CAT II", value: "CAT II" },
  { label: "CAT III", value: "CAT III" },
];

const SEVERITY_BADGE = {
  "CAT I": "red",
  "CAT II": "blue",
  "CAT III": "grey",
};

const STATUS_COLORS = {
  Open: "red",
  "Not a finding": "green",
  "Not applicable": "blue",
  "Not reviewed": "grey",
};

function pct(numer, denom) {
  if (!denom) return 0;
  return Math.round((numer / denom) * 1000) / 10; // one decimal
}

const AUDIT_FIELD_LABELS = {
  status: "status",
  finding_details: "finding details",
  comments: "comments",
  assignee_id: "assignee",
  due_date: "due date",
};

function auditFieldLabel(field) {
  return AUDIT_FIELD_LABELS[field] ?? field;
}

function formatAuditValue(v) {
  if (v == null) return "";
  if (v.length > 60) return v.slice(0, 60) + "…";
  return v;
}

function drilldownTitle(d) {
  if (d.ruleId) return "Rule drill-down";
  if (d.kind === "overdue") return "Overdue findings";
  if (d.kind === "stale") return "Stale findings";
  return "Open findings";
}

function describeDrilldown(d) {
  if (d.ruleId) return `Open instances of ${d.ruleId} across systems.`;
  if (d.kind === "overdue") {
    return "Open findings whose due date has already passed.";
  }
  if (d.kind === "stale") {
    return `Open findings with no activity in the last ${d.olderThanDays} days.`;
  }
  return "All currently-open findings across systems.";
}

export default function Dashboard() {
  const currentUser = useContext(AuthContext);
  const [data, setData] = useState(null);
  const [trend, setTrend] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Drill-down: { ruleId?: string } or null
  // Drill-down + filter state lives in `?dd=…&rule=…&stale=N&sev=…&me=true`
  // so the URL bar is a saveable, shareable view.
  // dd ∈ "" | "open" | "overdue" | "stale" | "rule"
  const [urlFilters, setUrlFilters] = useUrlState({
    dd: "",
    rule: "",
    stale: 0,
    sev: "",
    me: false,
  });
  const drilldown = useMemo(() => {
    if (!urlFilters.dd) return null;
    if (urlFilters.dd === "rule") return { ruleId: urlFilters.rule };
    if (urlFilters.dd === "stale") {
      return { kind: "stale", olderThanDays: urlFilters.stale || 30 };
    }
    return { kind: urlFilters.dd };
  }, [urlFilters.dd, urlFilters.rule, urlFilters.stale]);
  const severityFilter = useMemo(
    () => SEVERITY_OPTIONS.find((o) => o.value === urlFilters.sev) ?? null,
    [urlFilters.sev],
  );
  const mineOnly = urlFilters.me;

  const setDrilldown = useCallback(
    (d) => {
      if (!d) {
        setUrlFilters({ dd: "", rule: "", stale: 0 });
      } else if (d.ruleId) {
        setUrlFilters({ dd: "rule", rule: d.ruleId, stale: 0 });
      } else if (d.kind === "stale") {
        setUrlFilters({ dd: "stale", rule: "", stale: d.olderThanDays ?? 30 });
      } else {
        setUrlFilters({ dd: d.kind, rule: "", stale: 0 });
      }
    },
    [setUrlFilters],
  );
  const setSeverityFilter = useCallback(
    (opt) => setUrlFilters({ sev: opt?.value ?? "" }),
    [setUrlFilters],
  );
  const setMineOnly = useCallback(
    (v) => setUrlFilters({ me: !!v }),
    [setUrlFilters],
  );
  const [findings, setFindings] = useState([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState(null);

  // Inline expanded finding shown below the drill-down table.
  const [expandedFinding, setExpandedFinding] = useState(null);
  const [ruleHistory, setRuleHistory] = useState([]);

  // Drill-down multi-select + bulk-edit
  const [selectedFindings, setSelectedFindings] = useState([]);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkDraft, setBulkDraft] = useState({
    status: "",
    findingDetails: "",
    comments: "",
  });
  const [bulkSaving, setBulkSaving] = useState(false);
  const [bulkError, setBulkError] = useState(null);

  // Streamlined "Reassign" preset modal — covers the common "just change the
  // assignee" workflow without making power-users wade through the full
  // bulk-update form. Uses the same PATCH /api/findings/bulk endpoint with
  // an assignee-only patch (null = unassign).
  const [reassignOpen, setReassignOpen] = useState(false);
  const [reassignAssigneeId, setReassignAssigneeId] = useState(null);
  const [reassignSaving, setReassignSaving] = useState(false);
  const [reassignError, setReassignError] = useState(null);
  const [reassignFlash, setReassignFlash] = useState(null);
  const [users, setUsers] = useState([]);

  // Recent activity (loaded with the rest of the dashboard).
  const [activity, setActivity] = useState([]);

  // Bulk re-apply
  const [bulkReapplyOpen, setBulkReapplyOpen] = useState(false);
  const [bulkReapplyRunning, setBulkReapplyRunning] = useState(false);
  const [bulkReapplyError, setBulkReapplyError] = useState(null);
  const [bulkReapplyResults, setBulkReapplyResults] = useState(null);

  // Baselines
  const [baselines, setBaselines] = useState([]);
  const [selectedBaselineId, setSelectedBaselineId] = useState(null);
  const [baselineDiff, setBaselineDiff] = useState(null);
  const [diffLoading, setDiffLoading] = useState(false);
  // Bumped by the dashboard's Refresh button so the diff useEffect re-fires
  // even when selectedBaselineId is unchanged.
  const [refreshTick, setRefreshTick] = useState(0);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [newBaselineName, setNewBaselineName] = useState("");
  const [savingBaseline, setSavingBaseline] = useState(false);
  const [saveBaselineError, setSaveBaselineError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [d, t, a] = await Promise.all([
        apiGet("/api/dashboard"),
        apiGet("/api/dashboard/trend?days=30"),
        apiGet("/api/activity?limit=25").catch(() => []),
      ]);
      setData(d);
      setTrend(t);
      setActivity(a);
      setRefreshTick((n) => n + 1);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const refreshBaselines = useCallback(async () => {
    try {
      const rows = await apiGet("/api/baselines");
      setBaselines(rows);
      setSelectedBaselineId((curr) => {
        if (curr && rows.find((b) => b.id === curr)) return curr;
        return rows[0]?.id ?? null;
      });
    } catch {
      // Non-fatal — leave the picker empty.
    }
  }, []);

  useEffect(() => {
    refreshBaselines();
  }, [refreshBaselines]);

  // Load diff when a baseline is selected.
  useEffect(() => {
    if (!selectedBaselineId) {
      setBaselineDiff(null);
      return;
    }
    let cancelled = false;
    setDiffLoading(true);
    apiGet(`/api/baselines/${selectedBaselineId}/diff`)
      .then((d) => {
        if (!cancelled) setBaselineDiff(d);
      })
      .catch(() => {
        if (!cancelled) setBaselineDiff(null);
      })
      .finally(() => {
        if (!cancelled) setDiffLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedBaselineId, refreshTick]);

  const saveBaseline = useCallback(async () => {
    const name = newBaselineName.trim();
    if (!name) {
      setSaveBaselineError("Name is required.");
      return;
    }
    setSavingBaseline(true);
    setSaveBaselineError(null);
    try {
      const created = await apiJson("/api/baselines", "POST", { name });
      setSaveModalOpen(false);
      setNewBaselineName("");
      await refreshBaselines();
      setSelectedBaselineId(created.id);
    } catch (err) {
      setSaveBaselineError(err.message);
    } finally {
      setSavingBaseline(false);
    }
  }, [newBaselineName, refreshBaselines]);

  const runBulkReapply = useCallback(async () => {
    setBulkReapplyRunning(true);
    setBulkReapplyError(null);
    try {
      const res = await apiJson("/api/checklists/bulk-reapply", "POST", {});
      setBulkReapplyResults(res.results ?? []);
      setBulkReapplyOpen(false);
      await refresh();
    } catch (err) {
      setBulkReapplyError(err.message);
    } finally {
      setBulkReapplyRunning(false);
    }
  }, [refresh]);

  const deleteBaseline = useCallback(
    async (id) => {
      const res = await apiFetch(`/api/baselines/${id}`, { method: "DELETE" });
      if (!res.ok && res.status !== 204) return;
      await refreshBaselines();
    },
    [refreshBaselines],
  );

  // Clear selection when the drilldown filters change.
  useEffect(() => {
    setSelectedFindings([]);
  }, [drilldown, severityFilter, mineOnly]);

  // Load the user list for the Reassign modal's Select. One-shot — the user
  // directory is small and the dashboard is short-lived.
  useEffect(() => {
    let cancelled = false;
    apiGet("/api/users")
      .then((rows) => {
        if (!cancelled) setUsers(rows);
      })
      .catch(() => {
        // Non-fatal — the Select will just have an empty options list.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const openBulkModal = useCallback(() => {
    setBulkDraft({ status: "", findingDetails: "", comments: "" });
    setBulkError(null);
    setBulkOpen(true);
  }, []);

  const saveBulk = useCallback(async () => {
    if (selectedFindings.length === 0) return;
    // Build a patch object that only includes fields the user actually set.
    const patch = {};
    if (bulkDraft.status) patch.status = bulkDraft.status;
    if (bulkDraft.findingDetails) patch.findingDetails = bulkDraft.findingDetails;
    if (bulkDraft.comments) patch.comments = bulkDraft.comments;
    if (Object.keys(patch).length === 0) {
      setBulkError("Set at least one field to apply.");
      return;
    }
    setBulkSaving(true);
    setBulkError(null);
    try {
      await apiJson("/api/findings/bulk", "PATCH", {
        targets: selectedFindings.map((f) => ({
          checklistId: f.checklistId,
          ruleId: f.ruleId,
        })),
        patch,
      });
      setBulkOpen(false);
      setSelectedFindings([]);
      // Refetch the drill-down + the dashboard counters.
      setRefreshTick((n) => n + 1);
      await refresh();
    } catch (err) {
      setBulkError(err.message);
    } finally {
      setBulkSaving(false);
    }
  }, [selectedFindings, bulkDraft, refresh]);

  const openReassignModal = useCallback(() => {
    setReassignAssigneeId(null);
    setReassignError(null);
    setReassignOpen(true);
  }, []);

  const saveReassign = useCallback(async () => {
    if (selectedFindings.length === 0) return;
    setReassignSaving(true);
    setReassignError(null);
    try {
      // Explicit `null` reaches the backend as the JSON literal null, which
      // the bulk endpoint's tri-state assignee_id treats as "unassign". A
      // selected user id reassigns. `undefined` would be omitted by JSON.
      await apiJson("/api/findings/bulk", "PATCH", {
        targets: selectedFindings.map((f) => ({
          checklistId: f.checklistId,
          ruleId: f.ruleId,
        })),
        patch: { assigneeId: reassignAssigneeId },
      });
      const count = selectedFindings.length;
      const name = reassignAssigneeId
        ? users.find((u) => u.id === reassignAssigneeId)?.displayName ??
          "selected user"
        : null;
      setReassignFlash({
        count,
        text: name
          ? `Reassigned ${count} finding${count === 1 ? "" : "s"} to ${name}.`
          : `Unassigned ${count} finding${count === 1 ? "" : "s"}.`,
      });
      setReassignOpen(false);
      setSelectedFindings([]);
      setRefreshTick((n) => n + 1);
      await refresh();
    } catch (err) {
      setReassignError(err.message);
    } finally {
      setReassignSaving(false);
    }
  }, [selectedFindings, reassignAssigneeId, users, refresh]);

  // Close the expanded panel whenever the drill-down/filter changes.
  useEffect(() => {
    setExpandedFinding(null);
  }, [drilldown, severityFilter, mineOnly]);

  // Load the audit history for whichever rule is expanded.
  useEffect(() => {
    if (!expandedFinding) {
      setRuleHistory([]);
      return;
    }
    let cancelled = false;
    apiGet(
      `/api/checklists/${expandedFinding.checklistId}/rules/${encodeURIComponent(expandedFinding.ruleId)}/history`,
    )
      .then((rows) => {
        if (!cancelled) setRuleHistory(rows);
      })
      .catch(() => {
        if (!cancelled) setRuleHistory([]);
      });
    return () => {
      cancelled = true;
    };
  }, [expandedFinding]);

  // Load findings when drilldown is active or severity filter changes.
  useEffect(() => {
    if (!drilldown) {
      setFindings([]);
      setFindingsError(null);
      return;
    }
    let cancelled = false;
    const qs = new URLSearchParams({ status: "open" });
    if (drilldown.ruleId) qs.set("ruleId", drilldown.ruleId);
    if (severityFilter?.value) qs.set("severity", severityFilter.value);
    if (mineOnly) qs.set("assignee", "me");
    if (drilldown.kind === "overdue") qs.set("pastDue", "true");
    if (drilldown.kind === "stale" && drilldown.olderThanDays) {
      qs.set("olderThanDays", String(drilldown.olderThanDays));
    }
    setFindingsLoading(true);
    setFindingsError(null);
    apiGet(`/api/findings?${qs.toString()}`)
      .then((rows) => {
        if (!cancelled) setFindings(rows);
      })
      .catch((err) => {
        if (!cancelled) setFindingsError(err.message);
      })
      .finally(() => {
        if (!cancelled) setFindingsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [drilldown, severityFilter, mineOnly]);

  // Pre-flatten the per-asset / per-checklist rows for the table.
  // Sort assets by risk score descending so the most-at-risk system surfaces.
  const checklistRows = useMemo(() => {
    if (!data) return [];
    const sorted = [...data.byAsset].sort(
      (a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0),
    );
    return sorted.flatMap((a) =>
      a.checklists.length === 0
        ? [
            {
              assetId: a.id,
              assetName: a.name,
              ownerName: a.ownerName,
              riskScore: a.riskScore,
              weightedRiskScore: a.weightedRiskScore ?? 0,
              empty: true,
            },
          ]
        : a.checklists.map((c) => ({
            assetId: a.id,
            assetName: a.name,
            ownerName: a.ownerName,
            riskScore: a.riskScore,
            weightedRiskScore: a.weightedRiskScore ?? 0,
            ...c,
          })),
    );
  }, [data]);

  // Status pie chart data (only meaningful with at least some reviewed rules).
  const pieData = useMemo(() => {
    if (!data) return [];
    const t = data.totals;
    const notReviewed = Math.max(0, t.totalRules - t.reviewedRules);
    const open = t.openFindings;
    const reviewedNonOpen = Math.max(0, t.reviewedRules - open);
    // We don't break NaF / NA / explicit not_reviewed apart at the totals
    // level — sum to "Reviewed (compliant or N/A)" for the headline pie.
    return [
      { title: "Open", value: open, color: "red" },
      { title: "Reviewed", value: reviewedNonOpen, color: "green" },
      { title: "Not reviewed", value: notReviewed, color: "grey" },
    ].filter((s) => s.value > 0);
  }, [data]);

  if (loading) {
    return (
      <Box padding="xxl" textAlign="center">
        <StatusIndicator type="loading">Loading dashboard</StatusIndicator>
      </Box>
    );
  }

  if (error) {
    return (
      <Box padding="m">
        <Alert
          type="error"
          header="Failed to load dashboard"
          action={<Button onClick={refresh}>Retry</Button>}
        >
          {error}
        </Alert>
      </Box>
    );
  }

  const { totals } = data;
  const totalReviewedPct = pct(totals.reviewedRules, totals.totalRules);
  const compliantPct = pct(
    Math.max(0, totals.reviewedRules - totals.openFindings),
    totals.totalRules,
  );

  return (
    <Box padding="m">
      <SpaceBetween direction="vertical" size="l">
        <Header
          variant="h1"
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                disabled={(data?.totals?.outdatedChecklists ?? 0) === 0}
                onClick={() => {
                  setBulkReapplyError(null);
                  setBulkReapplyOpen(true);
                }}
              >
                {(data?.totals?.outdatedChecklists ?? 0) > 0
                  ? `Re-apply all (${data.totals.outdatedChecklists})`
                  : "Re-apply all"}
              </Button>
              <Button
                onClick={() => {
                  setNewBaselineName("");
                  setSaveBaselineError(null);
                  setSaveModalOpen(true);
                }}
              >
                Save baseline
              </Button>
              <Button iconName="refresh" onClick={refresh}>
                Refresh
              </Button>
            </SpaceBetween>
          }
        >
          Compliance dashboard
        </Header>

        {reassignFlash && (
          <Alert
            type="success"
            dismissible
            onDismiss={() => setReassignFlash(null)}
            data-testid="reassign-flash"
          >
            {reassignFlash.text}
          </Alert>
        )}

        {/* KPI row — 4-column grid; 7 cards wrap to 4 + 3. */}
        <ColumnLayout columns={4} variant="text-grid">
          <KpiCard label="Systems" value={totals.assets} />
          <KpiCard label="Applied STIGs" value={totals.checklists} />
          <KpiCard
            label="Open findings"
            value={totals.openFindings}
            tone={totals.openFindings > 0 ? "warning" : "ok"}
            onClick={
              totals.openFindings > 0
                ? () => setDrilldown({ kind: "open" })
                : undefined
            }
          />
          <KpiCard
            label="Compliant"
            value={`${compliantPct}%`}
            sub={`${totals.reviewedRules - totals.openFindings} of ${totals.totalRules} rules`}
            tone={totals.openFindings === 0 && totals.reviewedRules > 0 ? "ok" : null}
          />
          <KpiCard
            label="Compliance"
            value={`${(totals.complianceScore ?? 0).toFixed(1)}%`}
            sub="NaF + N/A across all rules"
            tone={
              (totals.complianceScore ?? 0) >= 80
                ? "ok"
                : (totals.complianceScore ?? 0) < 50
                  ? "warning"
                  : null
            }
          />
          <KpiCard
            label="Overdue"
            value={totals.overdueFindings}
            tone={totals.overdueFindings > 0 ? "warning" : null}
            onClick={
              totals.overdueFindings > 0
                ? () => setDrilldown({ kind: "overdue" })
                : undefined
            }
          />
          <KpiCard
            label={`Stale (>${totals.staleThresholdDays}d)`}
            value={totals.staleFindings}
            tone={totals.staleFindings > 0 ? "warning" : null}
            onClick={
              totals.staleFindings > 0
                ? () =>
                    setDrilldown({
                      kind: "stale",
                      olderThanDays: totals.staleThresholdDays,
                    })
                : undefined
            }
          />
          <KpiCard
            label="Highest risk"
            value={totals.highestRiskScore}
            sub={
              totals.highestRiskAssetName
                ? `on ${totals.highestRiskAssetName}`
                : undefined
            }
            tone={totals.highestRiskScore > 0 ? "warning" : "ok"}
          />
          <KpiCard
            label="Top weighted"
            value={(totals.highestWeightedScore ?? 0).toFixed(1)}
            sub={
              totals.highestWeightedAssetName
                ? totals.highestWeightedRuleId
                  ? `${totals.highestWeightedRuleId} on ${totals.highestWeightedAssetName}`
                  : `on ${totals.highestWeightedAssetName}`
                : undefined
            }
            tone={(totals.highestWeightedScore ?? 0) > 20 ? "warning" : "ok"}
          />
          <KpiCard
            label="STIG updates"
            value={totals.outdatedChecklists ?? 0}
            sub={
              (totals.outdatedChecklists ?? 0) > 0
                ? "checklists out of date"
                : "all up to date"
            }
            tone={
              (totals.outdatedChecklists ?? 0) > 0 ? "warning" : "ok"
            }
          />
          <KpiCard
            label="Stale baselines"
            value={totals.staleBaselines ?? 0}
            sub={`>${totals.staleBaselineDays ?? 90}d`}
            tone={(totals.staleBaselines ?? 0) > 0 ? "warning" : "ok"}
          />
        </ColumnLayout>

        {/* Status breakdown chart */}
        {pieData.length > 0 && (
          <Container header={<Header variant="h2">Overall status</Header>}>
            <PieChart
              data={pieData}
              detailPopoverContent={(datum, sum) => [
                { key: "Rules", value: datum.value },
                { key: "Share", value: `${pct(datum.value, sum)}%` },
              ]}
              segmentDescription={(datum, sum) =>
                `${datum.value} (${pct(datum.value, sum)}%)`
              }
              ariaDescription="Pie chart showing overall rule status across all systems"
              ariaLabel="Status breakdown"
              size="medium"
              hideFilter
              empty={
                <Box textAlign="center" color="inherit">
                  No data yet
                </Box>
              }
            />
          </Container>
        )}

        {/* Trend over time */}
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
              ariaLabel="Posture trend"
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

        {/* Compliance trend over time */}
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
              ariaLabel="Compliance trend"
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

        {/* Compliance heatmap: asset × STIG matrix */}
        {data.byAsset.length > 0 && <HeatmapSection byAsset={data.byAsset} />}

        {/* Rule-level diff: "what changed on every system since <date>" */}
        <DiffSection />

        {/* Per-asset / per-checklist progress */}
        <Table
          variant="container"
          items={checklistRows}
          trackBy={(r) => `${r.assetId}:${r.id ?? "empty"}`}
          columnDefinitions={[
            {
              id: "asset",
              header: "System",
              cell: (r) => r.assetName,
            },
            {
              id: "stig",
              header: "STIG",
              cell: (r) => {
                if (r.empty) return "—";
                if (!r.outdated) return r.stigTitle;
                return (
                  <SpaceBetween direction="horizontal" size="xs">
                    <span>{r.stigTitle}</span>
                    <Badge color="red">Out of date</Badge>
                  </SpaceBetween>
                );
              },
            },
            {
              id: "progress",
              header: "Review progress",
              cell: (r) =>
                r.empty ? (
                  <Box color="text-status-inactive">No STIGs applied</Box>
                ) : (
                  <ProgressBar
                    value={pct(r.reviewedCount, r.ruleCount)}
                    additionalInfo={`${r.reviewedCount} of ${r.ruleCount}`}
                  />
                ),
            },
            {
              id: "open",
              header: "Open",
              cell: (r) =>
                r.empty ? null : (
                  <Badge color={r.openCount > 0 ? "red" : "grey"}>
                    {r.openCount}
                  </Badge>
                ),
            },
            {
              id: "overdue",
              header: "Overdue",
              cell: (r) =>
                r.empty ? null : (
                  <Badge color={r.overdueCount > 0 ? "red" : "grey"}>
                    {r.overdueCount}
                  </Badge>
                ),
            },
            {
              id: "risk",
              header: "Risk",
              cell: (r) => (
                <Badge color={r.riskScore > 0 ? "red" : "grey"}>
                  {r.riskScore ?? 0}
                </Badge>
              ),
            },
            {
              id: "compliance",
              header: "Compliance score",
              cell: (r) =>
                r.empty ? (
                  <Box color="text-status-inactive">—</Box>
                ) : (
                  <ProgressBar
                    value={r.complianceScore ?? 0}
                    additionalInfo={`${(r.complianceScore ?? 0).toFixed(1)}%`}
                  />
                ),
            },
            {
              id: "weightedRisk",
              header: "Weighted risk",
              cell: (r) => {
                const w = r.weightedRiskScore ?? 0;
                // Match the formula's natural range:
                //   single CAT II open finding on unclassified ≈ 3.0
                //   anything ≥ 20 implies a CAT I on a classified system
                const color = w > 20 ? "red" : w > 5 ? "blue" : "grey";
                return <Badge color={color}>{w.toFixed(1)}</Badge>;
              },
            },
            {
              id: "naf",
              header: "NaF",
              cell: (r) =>
                r.empty ? null : (
                  <Badge color={r.nafCount > 0 ? "green" : "grey"}>
                    {r.nafCount}
                  </Badge>
                ),
            },
            {
              id: "na",
              header: "N/A",
              cell: (r) =>
                r.empty ? null : (
                  <Badge color={r.naCount > 0 ? "blue" : "grey"}>
                    {r.naCount}
                  </Badge>
                ),
            },
          ]}
          header={
            <Header counter={`(${data.byAsset.length})`}>By system</Header>
          }
          empty={
            <Box textAlign="center" padding="l">
              <Box variant="p" color="text-body-secondary">
                No systems yet. Add one from the Systems page to start tracking.
              </Box>
            </Box>
          }
        />

        {/* Top open rules */}
        {data.topOpenRules.length > 0 && (
          <Table
            variant="container"
            items={data.topOpenRules}
            trackBy="ruleId"
            columnDefinitions={[
              {
                id: "rule",
                header: "Rule",
                cell: (r) => (
                  <Button
                    variant="inline-link"
                    onClick={() => setDrilldown({ ruleId: r.ruleId })}
                  >
                    {r.ruleId}
                  </Button>
                ),
              },
              {
                id: "affected",
                header: "Affected systems",
                cell: (r) => (
                  <Badge color={r.affectedSystems > 1 ? "red" : "grey"}>
                    {r.affectedSystems}
                  </Badge>
                ),
              },
            ]}
            header={
              <Header
                description="Rules currently marked Open in the most systems — likely candidates for a fleet-wide fix."
                counter={`(${data.topOpenRules.length})`}
              >
                Top open rules
              </Header>
            }
          />
        )}

        {/* Drill-down panel */}
        {drilldown && (
          <Table
            variant="container"
            items={findings}
            loading={findingsLoading}
            loadingText="Loading findings"
            selectionType="multi"
            selectedItems={selectedFindings}
            onSelectionChange={({ detail }) =>
              setSelectedFindings(detail.selectedItems)
            }
            trackBy={(f) => `${f.checklistId}:${f.ruleId}`}
            columnDefinitions={[
              {
                id: "rule",
                header: "Rule",
                cell: (f) => (
                  <Button
                    variant="inline-link"
                    onClick={() =>
                      setExpandedFinding((curr) =>
                        curr &&
                        curr.checklistId === f.checklistId &&
                        curr.ruleId === f.ruleId
                          ? null
                          : f,
                      )
                    }
                  >
                    {f.ruleId}
                  </Button>
                ),
              },
              {
                id: "severity",
                header: "Severity",
                cell: (f) =>
                  f.severity ? (
                    <Badge color={SEVERITY_BADGE[f.severity] ?? "grey"}>
                      {f.severity}
                    </Badge>
                  ) : (
                    <Box color="text-status-inactive">—</Box>
                  ),
              },
              {
                id: "weight",
                header: "Weight",
                // Sortable so an auditor can pick the highest-impact
                // findings out of a large drill-down list.
                sortingField: "weightedScore",
                cell: (f) => {
                  const w = f.weightedScore ?? 0;
                  const color = w > 20 ? "red" : w > 5 ? "blue" : "grey";
                  return <Badge color={color}>{w.toFixed(1)}</Badge>;
                },
              },
              { id: "asset", header: "System", cell: (f) => f.assetName },
              { id: "stig", header: "STIG", cell: (f) => f.stigTitle },
              { id: "owner", header: "Owner", cell: (f) => f.ownerName },
              {
                id: "assignee",
                header: "Assignee",
                cell: (f) =>
                  f.assigneeName ? (
                    f.assigneeName
                  ) : (
                    <Box color="text-status-inactive">Unassigned</Box>
                  ),
              },
              {
                id: "due",
                header: "Due",
                cell: (f) => {
                  if (!f.dueDate) {
                    return <Box color="text-status-inactive">—</Box>;
                  }
                  const due = new Date(f.dueDate);
                  const overdue = due < new Date();
                  return (
                    <Box color={overdue ? "text-status-error" : "inherit"}>
                      {f.dueDate}
                    </Box>
                  );
                },
              },
              {
                id: "updated",
                header: "Last update",
                cell: (f) => new Date(f.updatedAt).toLocaleString(),
              },
            ]}
            header={
              <Header
                description={describeDrilldown(drilldown)}
                counter={`(${findings.length})`}
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button
                      disabled={selectedFindings.length === 0}
                      onClick={openBulkModal}
                    >
                      Bulk update
                      {selectedFindings.length > 0
                        ? ` (${selectedFindings.length})`
                        : ""}
                    </Button>
                    <Button
                      disabled={selectedFindings.length === 0}
                      onClick={openReassignModal}
                      data-testid="reassign-open"
                    >
                      Reassign
                      {selectedFindings.length > 0
                        ? ` (${selectedFindings.length})`
                        : ""}
                    </Button>
                    <Button onClick={() => setDrilldown(null)}>Close</Button>
                  </SpaceBetween>
                }
              >
                {drilldownTitle(drilldown)}
              </Header>
            }
            filter={
              <SpaceBetween direction="horizontal" size="m">
                <Select
                  selectedOption={severityFilter ?? SEVERITY_OPTIONS[0]}
                  onChange={({ detail }) =>
                    setSeverityFilter(
                      detail.selectedOption.value
                        ? detail.selectedOption
                        : null,
                    )
                  }
                  options={SEVERITY_OPTIONS}
                  ariaLabel="Filter by severity"
                />
                <Toggle
                  checked={mineOnly}
                  onChange={({ detail }) => setMineOnly(detail.checked)}
                >
                  Mine only
                </Toggle>
              </SpaceBetween>
            }
            empty={
              <Box textAlign="center" padding="l">
                <Box variant="p" color="text-body-secondary">
                  No matching findings.
                </Box>
              </Box>
            }
          />
        )}
        {findingsError && (
          <Alert type="error">{findingsError}</Alert>
        )}

        {drilldown && expandedFinding && (
          <Container
            header={
              <Header
                actions={
                  <Button onClick={() => setExpandedFinding(null)}>
                    Close
                  </Button>
                }
                description={
                  expandedFinding.title || expandedFinding.stigTitle
                }
              >
                {expandedFinding.ruleId}
                {expandedFinding.severity && (
                  <Box
                    display="inline"
                    margin={{ left: "s" }}
                    variant="span"
                  >
                    <Badge
                      color={SEVERITY_BADGE[expandedFinding.severity] ?? "grey"}
                    >
                      {expandedFinding.severity}
                    </Badge>
                  </Box>
                )}
              </Header>
            }
          >
            <SpaceBetween direction="vertical" size="m">
              {expandedFinding.description && (
                <RuleSection title="Description">
                  {expandedFinding.description}
                </RuleSection>
              )}
              {expandedFinding.checkText && (
                <RuleSection title="Check">
                  {expandedFinding.checkText}
                </RuleSection>
              )}
              {expandedFinding.fixText && (
                <RuleSection title="Fix">
                  {expandedFinding.fixText}
                </RuleSection>
              )}
              {expandedFinding.findingDetails && (
                <RuleSection title="Finding details (current)">
                  {expandedFinding.findingDetails}
                </RuleSection>
              )}
              {expandedFinding.comments && (
                <RuleSection title="Comments (current)">
                  {expandedFinding.comments}
                </RuleSection>
              )}
              <Box variant="small" color="text-body-secondary">
                {expandedFinding.assetName} ·{" "}
                {new Date(expandedFinding.updatedAt).toLocaleString()} ·
                owner {expandedFinding.ownerName}
              </Box>

              {ruleHistory.length > 0 && (
                <div>
                  <Box variant="awsui-key-label">History</Box>
                  <Box padding={{ top: "xs" }}>
                    {ruleHistory.map((h) => (
                      <Box key={h.id} padding={{ vertical: "xxs" }}>
                        <Box
                          variant="small"
                          color="text-body-secondary"
                          display="inline"
                        >
                          {new Date(h.occurredAt).toLocaleString()}
                        </Box>{" "}
                        <strong>{h.userName}</strong> changed{" "}
                        <em>{auditFieldLabel(h.field)}</em>:{" "}
                        <span style={{ opacity: 0.7 }}>
                          {formatAuditValue(h.fromValue) || "(empty)"}
                        </span>{" "}
                        →{" "}
                        <strong>
                          {formatAuditValue(h.toValue) || "(empty)"}
                        </strong>
                      </Box>
                    ))}
                  </Box>
                </div>
              )}
            </SpaceBetween>
          </Container>
        )}

        {/* Changes since baseline */}
        {baselines.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                description={
                  baselineDiff
                    ? `${baselineDiff.regressed.length} regressed · ${baselineDiff.improved.length} improved · ${baselineDiff.unchanged} unchanged`
                    : "Pick a baseline to see what changed since."
                }
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    <Select
                      selectedOption={
                        selectedBaselineId
                          ? (() => {
                              const sel = baselines.find(
                                (b) => b.id === selectedBaselineId,
                              );
                              return {
                                value: selectedBaselineId,
                                label: sel
                                  ? sel.isStale
                                    ? `${sel.name} (stale)`
                                    : sel.name
                                  : selectedBaselineId,
                              };
                            })()
                          : null
                      }
                      onChange={({ detail }) =>
                        setSelectedBaselineId(detail.selectedOption.value)
                      }
                      options={baselines.map((b) => ({
                        value: b.id,
                        label: b.isStale ? `${b.name} (stale)` : b.name,
                        description: b.isStale
                          ? `by ${b.createdByName} · ${b.ruleCount} rules · STALE`
                          : `by ${b.createdByName} · ${b.ruleCount} rules`,
                      }))}
                      placeholder="Choose a baseline"
                    />
                    {selectedBaselineId && (
                      <Button
                        variant="normal"
                        disabled={
                          !baselines.find(
                            (b) =>
                              b.id === selectedBaselineId &&
                              b.createdBy === currentUser?.id,
                          )
                        }
                        onClick={() => deleteBaseline(selectedBaselineId)}
                      >
                        Delete
                      </Button>
                    )}
                  </SpaceBetween>
                }
              >
                Changes since baseline
              </Header>
            }
          >
            {diffLoading && (
              <StatusIndicator type="loading">Loading…</StatusIndicator>
            )}
            {baselineDiff && (
              <SpaceBetween direction="vertical" size="m">
                {(() => {
                  const sel = baselines.find(
                    (b) => b.id === selectedBaselineId,
                  );
                  if (!sel?.isStale) return null;
                  const ageDays = Math.floor(
                    (Date.now() - new Date(sel.createdAt).getTime()) /
                      (1000 * 60 * 60 * 24),
                  );
                  return (
                    <Alert type="warning" header="Stale baseline">
                      This baseline is {ageDays} days old. Consider saving a
                      fresh one.
                    </Alert>
                  );
                })()}
                <ColumnLayout columns={2}>
                  <DiffTable
                    title="Regressed"
                    tone="red"
                    rows={baselineDiff.regressed}
                  />
                  <DiffTable
                    title="Improved"
                    tone="green"
                    rows={baselineDiff.improved}
                  />
                </ColumnLayout>
              </SpaceBetween>
            )}
          </Container>
        )}

        {/* Recent activity */}
        {activity.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                counter={`(${activity.length})`}
                description="The most recent rule-state changes across all systems."
              >
                Recent activity
              </Header>
            }
          >
            <SpaceBetween direction="vertical" size="xs">
              {activity.map((a) => (
                <Box key={a.id} variant="small">
                  <Box
                    display="inline"
                    color="text-body-secondary"
                    variant="span"
                  >
                    {new Date(a.occurredAt).toLocaleString()}
                  </Box>{" "}
                  <strong>{a.userName}</strong> changed{" "}
                  <em>{auditFieldLabel(a.field)}</em> on{" "}
                  <strong>{a.ruleId}</strong>
                  {a.assetName && (
                    <>
                      {" — "}
                      <span style={{ opacity: 0.7 }}>{a.assetName}</span>
                    </>
                  )}{" "}
                  <span style={{ opacity: 0.6 }}>
                    ({formatAuditValue(a.fromValue) || "—"} →{" "}
                    {formatAuditValue(a.toValue) || "—"})
                  </span>
                </Box>
              ))}
            </SpaceBetween>
          </Container>
        )}

        {/* Bulk-edit modal */}
        <Modal
          visible={bulkOpen}
          onDismiss={() => setBulkOpen(false)}
          header={`Bulk update — ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}`}
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setBulkOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  loading={bulkSaving}
                  onClick={saveBulk}
                >
                  Apply
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween direction="vertical" size="m">
            <Box variant="p" color="text-body-secondary">
              Leave a field blank to keep each finding's current value.
              At least one field must be set.
            </Box>
            <FormField label="Status">
              <Select
                selectedOption={
                  bulkDraft.status
                    ? {
                        value: bulkDraft.status,
                        label: bulkDraft.status,
                      }
                    : { value: "", label: "(leave unchanged)" }
                }
                onChange={({ detail }) =>
                  setBulkDraft((d) => ({
                    ...d,
                    status: detail.selectedOption.value,
                  }))
                }
                options={[
                  { value: "", label: "(leave unchanged)" },
                  { value: "open", label: "Open" },
                  { value: "not_a_finding", label: "Not a finding" },
                  { value: "not_applicable", label: "Not applicable" },
                  { value: "not_reviewed", label: "Not reviewed" },
                ]}
              />
            </FormField>
            <FormField
              label="Finding details"
              description="Replaces existing finding-details on every selected rule."
            >
              <Input
                value={bulkDraft.findingDetails}
                onChange={({ detail }) =>
                  setBulkDraft((d) => ({ ...d, findingDetails: detail.value }))
                }
                placeholder="e.g. closed by mitigation #42"
              />
            </FormField>
            <FormField label="Comments">
              <Input
                value={bulkDraft.comments}
                onChange={({ detail }) =>
                  setBulkDraft((d) => ({ ...d, comments: detail.value }))
                }
              />
            </FormField>
            {bulkError && <Alert type="error">{bulkError}</Alert>}
          </SpaceBetween>
        </Modal>

        {/* Reassign-only preset modal — single field, one action. */}
        <Modal
          visible={reassignOpen}
          onDismiss={() => setReassignOpen(false)}
          header={`Reassign ${selectedFindings.length} finding${selectedFindings.length === 1 ? "" : "s"}`}
          data-testid="reassign-modal"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setReassignOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  loading={reassignSaving}
                  onClick={saveReassign}
                  data-testid="reassign-submit"
                >
                  Reassign
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween direction="vertical" size="m">
            <Box variant="p" color="text-body-secondary">
              Pick a new assignee for every selected finding, or choose
              "Unassign" to clear the field.
            </Box>
            <FormField label="Assignee">
              <Select
                selectedOption={
                  reassignAssigneeId
                    ? {
                        value: reassignAssigneeId,
                        label:
                          users.find((u) => u.id === reassignAssigneeId)
                            ?.displayName ?? reassignAssigneeId,
                      }
                    : { value: "", label: "Unassign" }
                }
                onChange={({ detail }) =>
                  setReassignAssigneeId(detail.selectedOption.value || null)
                }
                options={[
                  { value: "", label: "Unassign" },
                  ...users.map((u) => ({
                    value: u.id,
                    label: u.displayName,
                  })),
                ]}
                data-testid="reassign-select"
              />
            </FormField>
            {reassignError && <Alert type="error">{reassignError}</Alert>}
          </SpaceBetween>
        </Modal>

        {/* Save baseline modal */}
        <Modal
          visible={saveModalOpen}
          onDismiss={() => setSaveModalOpen(false)}
          header="Save baseline"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setSaveModalOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  loading={savingBaseline}
                  onClick={saveBaseline}
                >
                  Save
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween direction="vertical" size="m">
            <Box variant="p" color="text-body-secondary">
              Capture the current compliance state as a named baseline.
              Future dashboard sessions can show which rules regressed
              or improved since this baseline was taken.
            </Box>
            <FormField label="Name">
              <Input
                value={newBaselineName}
                onChange={({ detail }) => setNewBaselineName(detail.value)}
                placeholder="e.g. Q2 2026 audit"
                autoFocus
              />
            </FormField>
            {saveBaselineError && (
              <Alert type="error">{saveBaselineError}</Alert>
            )}
          </SpaceBetween>
        </Modal>

        {/* Bulk re-apply confirm modal */}
        <Modal
          visible={bulkReapplyOpen}
          onDismiss={() => setBulkReapplyOpen(false)}
          header="Re-apply all outdated STIGs"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="link"
                  onClick={() => setBulkReapplyOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  loading={bulkReapplyRunning}
                  onClick={runBulkReapply}
                  data-testid="bulk-reapply-confirm"
                >
                  Re-apply
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween direction="vertical" size="m">
            <Box variant="p">
              This will re-apply the current catalog version onto{" "}
              <strong>
                {data?.totals?.outdatedChecklists ?? 0} checklist
                {(data?.totals?.outdatedChecklists ?? 0) === 1 ? "" : "s"}
              </strong>{" "}
              you own. Rule overrides for rules that still exist are
              preserved; overrides for rules removed in the new revision
              are pruned.
            </Box>
            {bulkReapplyError && <Alert type="error">{bulkReapplyError}</Alert>}
          </SpaceBetween>
        </Modal>

        {/* Bulk re-apply results modal */}
        <Modal
          visible={bulkReapplyResults !== null}
          onDismiss={() => setBulkReapplyResults(null)}
          header={`Re-apply complete — ${bulkReapplyResults?.length ?? 0} checklist${(bulkReapplyResults?.length ?? 0) === 1 ? "" : "s"}`}
          size="large"
          footer={
            <Box float="right">
              <Button
                variant="primary"
                onClick={() => setBulkReapplyResults(null)}
              >
                Close
              </Button>
            </Box>
          }
        >
          <Table
            variant="embedded"
            items={bulkReapplyResults ?? []}
            trackBy="checklistId"
            columnDefinitions={[
              {
                id: "asset",
                header: "System",
                cell: (r) => r.assetName,
              },
              {
                id: "stig",
                header: "STIG",
                cell: (r) => r.stigTitle,
              },
              {
                id: "version",
                header: "Version",
                cell: (r) =>
                  r.toVersion ? (
                    <span>
                      <span style={{ opacity: 0.7 }}>{r.fromVersion || "—"}</span>
                      {" → "}
                      <strong>{r.toVersion}</strong>
                    </span>
                  ) : (
                    <Box color="text-status-inactive">{r.fromVersion || "—"}</Box>
                  ),
              },
              {
                id: "pruned",
                header: "Pruned rules",
                cell: (r) => (
                  <Badge color={r.prunedRules > 0 ? "blue" : "grey"}>
                    {r.prunedRules}
                  </Badge>
                ),
              },
              {
                id: "status",
                header: "Status",
                cell: (r) => {
                  const color =
                    r.status === "reapplied"
                      ? "green"
                      : r.status === "skipped"
                        ? "grey"
                        : "red";
                  return (
                    <SpaceBetween direction="horizontal" size="xs">
                      <Badge color={color}>{r.status}</Badge>
                      {r.error && (
                        <Box variant="small" color="text-status-inactive">
                          {r.error}
                        </Box>
                      )}
                    </SpaceBetween>
                  );
                },
              },
            ]}
            empty={
              <Box textAlign="center" padding="l">
                <Box variant="p" color="text-body-secondary">
                  No outdated checklists were found.
                </Box>
              </Box>
            }
          />
        </Modal>
      </SpaceBetween>
    </Box>
  );
}

function DiffTable({ title, tone, rows }) {
  return (
    <div>
      <Box variant="awsui-key-label">
        <Badge color={tone}>{title}</Badge>{" "}
        <span style={{ marginLeft: 8 }}>({rows.length})</span>
      </Box>
      {rows.length === 0 ? (
        <Box color="text-body-secondary" padding={{ top: "xs" }}>
          None.
        </Box>
      ) : (
        <Box padding={{ top: "xs" }}>
          {rows.map((r) => (
            <Box
              key={`${r.checklistId}:${r.ruleId}`}
              padding={{ vertical: "xxs" }}
            >
              <strong>{r.ruleId}</strong> — {r.assetName} ·{" "}
              <span style={{ opacity: 0.7 }}>
                {r.fromStatus} → {r.toStatus}
              </span>
            </Box>
          ))}
        </Box>
      )}
    </div>
  );
}

function RuleSection({ title, children }) {
  return (
    <div>
      <Box variant="awsui-key-label">{title}</Box>
      <Box variant="p" color="text-body-secondary">
        <pre
          style={{
            whiteSpace: "pre-wrap",
            margin: 0,
            fontFamily: "inherit",
            fontSize: "inherit",
          }}
        >
          {children}
        </pre>
      </Box>
    </div>
  );
}

function KpiCard({ label, value, sub, tone, onClick }) {
  const indicator =
    tone === "ok" ? (
      <StatusIndicator type="success">{value}</StatusIndicator>
    ) : tone === "warning" ? (
      <StatusIndicator type="warning">{value}</StatusIndicator>
    ) : null;
  return (
    <Container>
      <Box variant="awsui-key-label">{label}</Box>
      {indicator ?? <Box variant="h1">{value}</Box>}
      {sub && (
        <Box variant="small" color="text-body-secondary">
          {sub}
        </Box>
      )}
      {onClick && (
        <Button variant="inline-link" onClick={onClick}>
          View details
        </Button>
      )}
    </Container>
  );
}

// ── Compliance heatmap ──────────────────────────────────────────────────────

function cellColor(c) {
  if (!c) return { bg: "transparent", fg: "var(--awsui-color-text-status-inactive)", label: "—" };
  if (c.openCount > 0) {
    return { bg: "#7a1c1c", fg: "#fff", label: String(c.openCount) };
  }
  if (c.reviewedCount === 0) {
    return { bg: "#444", fg: "#ccc", label: "·" };
  }
  if (c.reviewedCount < c.ruleCount) {
    return { bg: "#7a5e1c", fg: "#fff", label: "↻" };
  }
  return { bg: "#1c5e2d", fg: "#fff", label: "✓" };
}

// Cloudscape DatePicker emits YYYY-MM-DD strings; default to 7 days ago.
function defaultDiffSince() {
  const d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  return d.toISOString().slice(0, 10);
}

const DIFF_FIELD_LABELS = {
  status: "Status",
  finding_details: "Finding details",
  comments: "Comments",
  assignee_id: "Assignee",
  due_date: "Due date",
};

function diffValueDisplay(field, value) {
  if (value === null || value === undefined || value === "") return "(unset)";
  if (field === "status") {
    return STATUS_LABEL[value] ?? value;
  }
  if (value.length > 80) return value.slice(0, 80) + "…";
  return value;
}

const STATUS_LABEL = {
  open: "Open",
  not_a_finding: "Not a finding",
  not_applicable: "Not applicable",
  not_reviewed: "Not reviewed",
};

function DiffSection() {
  const [since, setSince] = useUrlState({ diffSince: defaultDiffSince() });
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    if (!since.diffSince) return undefined;
    setLoading(true);
    setError(null);
    apiGet(`/api/diff?since=${encodeURIComponent(since.diffSince)}`)
      .then((res) => {
        if (!cancelled) setRules(res.rules ?? []);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [since.diffSince]);

  // Flatten rules → per-field rows for the Table.
  const flatRows = useMemo(() => {
    const out = [];
    for (const r of rules) {
      for (const c of r.changes) {
        out.push({
          key: `${r.checklistId}:${r.ruleId}:${c.field}`,
          assetName: r.assetName,
          stigTitle: r.stigTitle,
          ruleId: r.ruleId,
          field: c.field,
          from: c.from,
          to: c.to,
          by: c.by,
          at: c.at,
        });
      }
    }
    return out;
  }, [rules]);

  return (
    <Container
      header={
        <Header
          variant="h2"
          description="Every rule whose status, assignee, due date, finding details, or comments changed inside the window. Repeated flips collapse to first → latest."
          actions={
            <Box float="right" padding={{ top: "xxs" }}>
              <DatePicker
                value={since.diffSince ?? ""}
                onChange={({ detail }) =>
                  setSince({ diffSince: detail.value || defaultDiffSince() })
                }
                placeholder="YYYY/MM/DD"
                data-testid="diff-since-picker"
              />
            </Box>
          }
        >
          Changes since {since.diffSince}
        </Header>
      }
    >
      {error && <Alert type="error">{error}</Alert>}
      <Table
        variant="embedded"
        items={flatRows}
        trackBy="key"
        loading={loading}
        loadingText="Loading diff…"
        empty={
          <Box textAlign="center" padding="l" color="text-body-secondary">
            No changes in the selected window.
          </Box>
        }
        columnDefinitions={[
          { id: "asset", header: "System", cell: (r) => r.assetName },
          { id: "stig", header: "STIG", cell: (r) => r.stigTitle },
          { id: "rule", header: "Rule", cell: (r) => r.ruleId },
          {
            id: "field",
            header: "Field",
            cell: (r) => DIFF_FIELD_LABELS[r.field] ?? r.field,
          },
          {
            id: "from",
            header: "From",
            cell: (r) =>
              r.field === "status" ? (
                <Badge color={STATUS_COLORS[STATUS_LABEL[r.from] ?? r.from] ?? "grey"}>
                  {diffValueDisplay(r.field, r.from)}
                </Badge>
              ) : (
                diffValueDisplay(r.field, r.from)
              ),
          },
          {
            id: "to",
            header: "To",
            cell: (r) =>
              r.field === "status" ? (
                <Badge color={STATUS_COLORS[STATUS_LABEL[r.to] ?? r.to] ?? "grey"}>
                  {diffValueDisplay(r.field, r.to)}
                </Badge>
              ) : (
                diffValueDisplay(r.field, r.to)
              ),
          },
          { id: "by", header: "By", cell: (r) => r.by },
          {
            id: "at",
            header: "When",
            cell: (r) => new Date(r.at).toLocaleString(),
          },
        ]}
      />
    </Container>
  );
}

function HeatmapSection({ byAsset }) {
  const [hmState, setHmState] = useUrlState({ grpTag: false });
  const groupByTag = hmState.grpTag;

  // Collect unique STIG titles across all assets, sorted alphabetically.
  const stigs = [];
  const seen = new Map();
  for (const a of byAsset) {
    for (const c of a.checklists) {
      if (!seen.has(c.stigId)) {
        seen.set(c.stigId, c.stigTitle);
        stigs.push({ id: c.stigId, title: c.stigTitle });
      }
    }
  }
  stigs.sort((a, b) => a.title.localeCompare(b.title));

  if (stigs.length === 0) {
    return null;
  }

  // Build display rows. In flat mode each row is one asset. In group-by-tag
  // mode each row is a tag bucket whose cell aggregates open/reviewed/rule
  // counts across all assets carrying that tag. Assets with no tags fall
  // into an "(untagged)" bucket. An asset with multiple tags shows up
  // under each.
  let rows;
  if (groupByTag) {
    const buckets = new Map(); // tag → { name, assets: [] }
    for (const a of byAsset) {
      const tags = a.tags && a.tags.length > 0 ? a.tags : ["(untagged)"];
      for (const t of tags) {
        if (!buckets.has(t)) buckets.set(t, { name: t, assets: [] });
        buckets.get(t).assets.push(a);
      }
    }
    rows = [...buckets.values()].sort((a, b) => a.name.localeCompare(b.name));
  } else {
    rows = byAsset.map((a) => ({ name: a.name, assets: [a] }));
  }

  // Aggregate the cell metrics across all assets in the row for a given STIG.
  function aggregateCell(rowAssets, stigId) {
    let any = false;
    let openCount = 0;
    let nafCount = 0;
    let naCount = 0;
    let reviewedCount = 0;
    let ruleCount = 0;
    for (const a of rowAssets) {
      const c = a.checklists.find((cc) => cc.stigId === stigId);
      if (!c) continue;
      any = true;
      openCount += c.openCount;
      nafCount += c.nafCount;
      naCount += c.naCount;
      reviewedCount += c.reviewedCount;
      ruleCount += c.ruleCount;
    }
    if (!any) return null;
    return { openCount, nafCount, naCount, reviewedCount, ruleCount };
  }

  return (
    <Container
      header={
        <Header
          variant="h2"
          description="Open count per (system, STIG). Green = all reviewed and compliant, yellow = in progress, red = open findings, grey = not started."
          actions={
            <Toggle
              checked={groupByTag}
              onChange={({ detail }) => setHmState({ grpTag: detail.checked })}
            >
              Group by tag
            </Toggle>
          }
        >
          Posture heatmap
        </Header>
      }
    >
      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr>
              <th
                style={{
                  textAlign: "left",
                  padding: "6px 10px",
                  borderBottom: "1px solid #444",
                  position: "sticky",
                  left: 0,
                  background: "var(--awsui-color-background-container-content)",
                }}
              >
                System
              </th>
              {stigs.map((s) => (
                <th
                  key={s.id}
                  style={{
                    padding: "6px 10px",
                    borderBottom: "1px solid #444",
                    fontWeight: 400,
                    fontSize: 11,
                    writingMode: "vertical-rl",
                    transform: "rotate(180deg)",
                    whiteSpace: "nowrap",
                    maxHeight: 180,
                  }}
                  title={s.title}
                >
                  {s.title.length > 30 ? s.title.slice(0, 30) + "…" : s.title}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.name}>
                <td
                  style={{
                    padding: "6px 10px",
                    borderBottom: "1px solid #2b2b2b",
                    position: "sticky",
                    left: 0,
                    background: "var(--awsui-color-background-container-content)",
                  }}
                >
                  {groupByTag ? (
                    <Badge color="grey">{row.name}</Badge>
                  ) : (
                    row.name
                  )}
                  {groupByTag && (
                    <span
                      style={{
                        marginLeft: 6,
                        color: "var(--awsui-color-text-status-inactive)",
                        fontSize: 11,
                      }}
                    >
                      {row.assets.length}
                    </span>
                  )}
                </td>
                {stigs.map((s) => {
                  const c = aggregateCell(row.assets, s.id);
                  const { bg, fg, label } = cellColor(c);
                  const tip = c
                    ? `${row.name} · ${s.title}\n${c.openCount} open / ${c.nafCount} NaF / ${c.naCount} N/A / ${c.reviewedCount} reviewed of ${c.ruleCount}`
                    : `${row.name} · ${s.title} — not applied`;
                  return (
                    <td
                      key={s.id}
                      title={tip}
                      style={{
                        padding: 0,
                        borderBottom: "1px solid #2b2b2b",
                      }}
                    >
                      <div
                        style={{
                          width: 32,
                          height: 28,
                          margin: 2,
                          background: bg,
                          color: fg,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: 600,
                          borderRadius: 3,
                        }}
                      >
                        {label}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Container>
  );
}
