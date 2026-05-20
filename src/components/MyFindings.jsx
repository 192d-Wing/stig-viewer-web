import { useCallback, useEffect, useMemo, useState } from "react";
import Box from "@cloudscape-design/components/box";
import Header from "@cloudscape-design/components/header";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Button from "@cloudscape-design/components/button";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Select from "@cloudscape-design/components/select";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import { apiFetch, apiGet, apiJson } from "../utils/api.js";
import { useUrlState } from "../hooks/useUrlState.js";

const SEVERITY_BADGE = {
  "CAT I": "red",
  "CAT II": "blue",
  "CAT III": "grey",
};

const SEVERITY_OPTIONS = [
  { label: "All severities", value: "" },
  { label: "CAT I", value: "CAT I" },
  { label: "CAT II", value: "CAT II" },
  { label: "CAT III", value: "CAT III" },
];

const SAVED_PAGE = "myfindings";

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
        {
          id: "weight",
          header: "Weight",
          sortingField: "weightedScore",
          cell: (f) => {
            const w = f.weightedScore ?? 0;
            const color = w > 20 ? "red" : w > 5 ? "blue" : "grey";
            return <Badge color={color}>{w.toFixed(1)}</Badge>;
          },
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

// Build the URL the user lands on after picking a saved search. We keep
// `view=myfindings` (so the top-level page doesn't change) and overwrite
// every other key with whatever the saved-params string carries.
function buildAppliedSearch(savedParamString) {
  const next = new URLSearchParams(savedParamString || "");
  // Drop any view= that snuck into the saved params; we set it ourselves.
  next.delete("view");
  next.set("view", SAVED_PAGE);
  return `?${next.toString()}`;
}

export default function MyFindings() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filter state synced to the URL so links are shareable + saved searches
  // can round-trip cleanly. `sev` mirrors the dashboard's encoding.
  const [filters, setFilters] = useUrlState({ sev: "" });
  const severityValue = filters.sev || "";
  const severityOption = useMemo(
    () =>
      SEVERITY_OPTIONS.find((o) => o.value === severityValue) ??
      SEVERITY_OPTIONS[0],
    [severityValue],
  );

  // ── Saved searches state ───────────────────────────────────────────────
  const [savedSearches, setSavedSearches] = useState([]);
  const [savedError, setSavedError] = useState(null);
  const [saveModalOpen, setSaveModalOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const [newSearchName, setNewSearchName] = useState("");
  const [savingSearch, setSavingSearch] = useState(false);
  const [saveSearchError, setSaveSearchError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const qs = new URLSearchParams({ status: "open", assignee: "me" });
      if (severityValue) qs.set("severity", severityValue);
      const rows = await apiGet(`/api/findings?${qs.toString()}`);
      setFindings(rows);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [severityValue]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const refreshSavedSearches = useCallback(async () => {
    try {
      const rows = await apiGet(
        `/api/saved-searches?page=${encodeURIComponent(SAVED_PAGE)}`,
      );
      setSavedSearches(rows);
      setSavedError(null);
    } catch (err) {
      // Non-fatal — leave the picker empty so the rest of the page still works.
      setSavedError(err.message);
    }
  }, []);

  useEffect(() => {
    refreshSavedSearches();
  }, [refreshSavedSearches]);

  const applySavedSearch = useCallback((s) => {
    window.history.pushState(null, "", buildAppliedSearch(s.params));
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, []);

  const saveCurrentView = useCallback(async () => {
    const name = newSearchName.trim();
    if (!name) {
      setSaveSearchError("Name is required.");
      return;
    }
    // Strip the leading `?` and drop the page-routing `view` key — that's
    // implicit in the saved-search row's `page` column.
    const liveParams = new URLSearchParams(window.location.search.slice(1));
    liveParams.delete("view");
    setSavingSearch(true);
    setSaveSearchError(null);
    try {
      await apiJson("/api/saved-searches", "POST", {
        page: SAVED_PAGE,
        name,
        params: liveParams.toString(),
      });
      setSaveModalOpen(false);
      setNewSearchName("");
      await refreshSavedSearches();
    } catch (err) {
      const msg = err?.message || String(err);
      if (msg.includes("409")) {
        setSaveSearchError("A saved search with that name already exists.");
      } else {
        setSaveSearchError(msg);
      }
    } finally {
      setSavingSearch(false);
    }
  }, [newSearchName, refreshSavedSearches]);

  const deleteSavedSearch = useCallback(
    async (id) => {
      const res = await apiFetch(`/api/saved-searches/${id}`, {
        method: "DELETE",
      });
      if (!res.ok && res.status !== 204) return;
      await refreshSavedSearches();
    },
    [refreshSavedSearches],
  );

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

  // Saved-search picker — keep empty option distinct so the Select stays
  // non-collapsed even when there are no saved rows yet.
  const savedOptions = savedSearches.map((s) => ({
    value: s.id,
    label: s.name,
    description: s.params ? `?${s.params}` : "(no filters)",
  }));

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
        {savedError && (
          <Alert type="warning" header="Saved searches">
            {savedError}
          </Alert>
        )}

        <SpaceBetween direction="horizontal" size="m">
          <Select
            selectedOption={severityOption}
            options={SEVERITY_OPTIONS}
            onChange={({ detail }) =>
              setFilters({ sev: detail.selectedOption.value })
            }
            ariaLabel="Filter by severity"
          />
          <Select
            selectedOption={null}
            options={savedOptions}
            onChange={({ detail }) => {
              const found = savedSearches.find(
                (s) => s.id === detail.selectedOption.value,
              );
              if (found) applySavedSearch(found);
            }}
            placeholder={
              savedSearches.length > 0
                ? "Apply saved search"
                : "No saved searches yet"
            }
            disabled={savedSearches.length === 0}
            ariaLabel="Apply a saved search"
          />
          <Button
            onClick={() => {
              setNewSearchName("");
              setSaveSearchError(null);
              setSaveModalOpen(true);
            }}
          >
            Save current view
          </Button>
          <Button
            disabled={savedSearches.length === 0}
            onClick={() => setManageOpen(true)}
          >
            Manage…
          </Button>
        </SpaceBetween>

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

        {/* Save current view modal */}
        <Modal
          visible={saveModalOpen}
          onDismiss={() => setSaveModalOpen(false)}
          header="Save current view"
          footer={
            <Box float="right">
              <SpaceBetween direction="horizontal" size="xs">
                <Button variant="link" onClick={() => setSaveModalOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  loading={savingSearch}
                  onClick={saveCurrentView}
                >
                  Save
                </Button>
              </SpaceBetween>
            </Box>
          }
        >
          <SpaceBetween direction="vertical" size="m">
            <Box variant="p" color="text-body-secondary">
              Capture the current filter set as a named saved search.
              Picking it later restores the same URL parameters.
            </Box>
            <FormField label="Name">
              <Input
                value={newSearchName}
                onChange={({ detail }) => setNewSearchName(detail.value)}
                placeholder="e.g. CAT I only"
                autoFocus
              />
            </FormField>
            {saveSearchError && (
              <Alert type="error">{saveSearchError}</Alert>
            )}
          </SpaceBetween>
        </Modal>

        {/* Manage saved searches modal */}
        <Modal
          visible={manageOpen}
          onDismiss={() => setManageOpen(false)}
          header="Manage saved searches"
          footer={
            <Box float="right">
              <Button onClick={() => setManageOpen(false)}>Close</Button>
            </Box>
          }
        >
          {savedSearches.length === 0 ? (
            <Box color="text-body-secondary">
              No saved searches yet.
            </Box>
          ) : (
            <SpaceBetween direction="vertical" size="xs">
              {savedSearches.map((s) => (
                <Box
                  key={s.id}
                  padding={{ vertical: "xxs" }}
                >
                  <SpaceBetween direction="horizontal" size="m">
                    <div style={{ flex: 1 }}>
                      <strong>{s.name}</strong>{" "}
                      <Box
                        variant="small"
                        color="text-body-secondary"
                        display="inline"
                      >
                        {s.params ? `?${s.params}` : "(no filters)"}
                      </Box>
                    </div>
                    <Button
                      variant="normal"
                      onClick={() => deleteSavedSearch(s.id)}
                    >
                      Delete
                    </Button>
                  </SpaceBetween>
                </Box>
              ))}
            </SpaceBetween>
          )}
        </Modal>
      </SpaceBetween>
    </Box>
  );
}
