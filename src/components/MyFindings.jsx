import { useCallback, useEffect, useMemo, useState } from "react";
import Box from "@cloudscape-design/components/box";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Button from "@cloudscape-design/components/button";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { apiGet } from "../utils/api.js";

const SEVERITY_BADGE = {
  "CAT I": "red",
  "CAT II": "blue",
  "CAT III": "grey",
};

const DUE_SOON_DAYS = 7;

function bucketOf(f, today, dueSoonCutoff) {
  if (!f.dueDate) return "open";
  const d = new Date(f.dueDate);
  if (d < today) return "overdue";
  if (d <= dueSoonCutoff) return "due_soon";
  return "open";
}

function FindingsTable({ title, items, tone, emptyText }) {
  return (
    <Table
      variant="container"
      items={items}
      trackBy={(f) => `${f.checklistId}:${f.ruleId}`}
      columnDefinitions={[
        { id: "rule", header: "Rule", cell: (f) => f.ruleId },
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
        { id: "system", header: "System", cell: (f) => f.assetName },
        { id: "stig", header: "STIG", cell: (f) => f.stigTitle },
        {
          id: "due",
          header: "Due",
          cell: (f) => {
            if (!f.dueDate) return <Box color="text-status-inactive">—</Box>;
            return (
              <Box color={tone === "red" ? "text-status-error" : "inherit"}>
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
          counter={`(${items.length})`}
          variant="h2"
        >
          <Badge color={tone}>{title}</Badge>
        </Header>
      }
      empty={
        <Box textAlign="center" padding="l" color="text-body-secondary">
          {emptyText}
        </Box>
      }
    />
  );
}

export default function MyFindings() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await apiGet("/api/findings?status=open&assignee=me");
      setFindings(rows);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const buckets = useMemo(() => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const dueSoonCutoff = new Date(today);
    dueSoonCutoff.setDate(dueSoonCutoff.getDate() + DUE_SOON_DAYS);

    const out = { overdue: [], due_soon: [], open: [] };
    for (const f of findings) {
      out[bucketOf(f, today, dueSoonCutoff)].push(f);
    }
    return out;
  }, [findings]);

  if (loading) {
    return (
      <Box padding="xxl" textAlign="center">
        <StatusIndicator type="loading">Loading my findings</StatusIndicator>
      </Box>
    );
  }

  return (
    <Box padding="m">
      <SpaceBetween direction="vertical" size="l">
        <Header
          variant="h1"
          description={`${findings.length} open finding${findings.length === 1 ? "" : "s"} assigned to you`}
          actions={
            <Button iconName="refresh" onClick={refresh}>
              Refresh
            </Button>
          }
        >
          My findings
        </Header>

        {error && <Alert type="error">{error}</Alert>}

        {findings.length === 0 ? (
          <Box padding="xxl" textAlign="center">
            <StatusIndicator type="success">
              Nothing assigned to you right now.
            </StatusIndicator>
          </Box>
        ) : (
          <SpaceBetween direction="vertical" size="l">
            {buckets.overdue.length > 0 && (
              <FindingsTable
                title="Overdue"
                tone="red"
                items={buckets.overdue}
                emptyText="None overdue."
              />
            )}
            {buckets.due_soon.length > 0 && (
              <FindingsTable
                title={`Due in the next ${DUE_SOON_DAYS} days`}
                tone="blue"
                items={buckets.due_soon}
                emptyText="None due soon."
              />
            )}
            {buckets.open.length > 0 && (
              <FindingsTable
                title="Open (no urgent due)"
                tone="grey"
                items={buckets.open}
                emptyText="None."
              />
            )}
          </SpaceBetween>
        )}
      </SpaceBetween>
    </Box>
  );
}
