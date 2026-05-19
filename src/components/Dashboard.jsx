import { useCallback, useEffect, useMemo, useState } from "react";
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
import Button from "@cloudscape-design/components/button";
import { apiGet } from "../utils/api.js";

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

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await apiGet("/api/dashboard");
      setData(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Pre-flatten the per-asset / per-checklist rows for the table.
  const checklistRows = useMemo(() => {
    if (!data) return [];
    return data.byAsset.flatMap((a) =>
      a.checklists.length === 0
        ? [{ assetId: a.id, assetName: a.name, ownerName: a.ownerName, empty: true }]
        : a.checklists.map((c) => ({
            assetId: a.id,
            assetName: a.name,
            ownerName: a.ownerName,
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
            <Button iconName="refresh" onClick={refresh}>
              Refresh
            </Button>
          }
        >
          Compliance dashboard
        </Header>

        {/* KPI row */}
        <ColumnLayout columns={4} variant="text-grid">
          <KpiCard label="Systems" value={totals.assets} />
          <KpiCard label="Applied STIGs" value={totals.checklists} />
          <KpiCard
            label="Open findings"
            value={totals.openFindings}
            tone={totals.openFindings > 0 ? "warning" : "ok"}
          />
          <KpiCard
            label="Compliant"
            value={`${compliantPct}%`}
            sub={`${totals.reviewedRules - totals.openFindings} of ${totals.totalRules} rules`}
            tone={totals.openFindings === 0 && totals.reviewedRules > 0 ? "ok" : null}
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
              cell: (r) => (r.empty ? "—" : r.stigTitle),
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
              { id: "rule", header: "Rule", cell: (r) => r.ruleId },
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
      </SpaceBetween>
    </Box>
  );
}

function KpiCard({ label, value, sub, tone }) {
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
    </Container>
  );
}
