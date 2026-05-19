import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Textarea from "@cloudscape-design/components/textarea";
import RadioGroup from "@cloudscape-design/components/radio-group";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import TextFilter from "@cloudscape-design/components/text-filter";
import { apiGet, apiJson } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";

const STATUSES = [
  { value: "not_reviewed", label: "Not reviewed", color: "grey" },
  { value: "open", label: "Open", color: "red" },
  { value: "not_a_finding", label: "Not a finding", color: "green" },
  { value: "not_applicable", label: "Not applicable", color: "blue" },
];

const STATUS_BY_VALUE = Object.fromEntries(STATUSES.map((s) => [s.value, s]));

function severityLabel(sev) {
  if (!sev) return "—";
  return sev.toUpperCase();
}

function severityColor(sev) {
  const s = (sev || "").toLowerCase();
  if (s.includes("i") && !s.includes("ii")) return "red"; // CAT I
  if (s.includes("ii") && !s.includes("iii")) return "blue"; // CAT II
  return "grey";
}

export default function ChecklistView({ checklistId, onBack }) {
  const currentUser = useContext(AuthContext);

  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [editing, setEditing] = useState(null); // the rule being edited
  const [draft, setDraft] = useState({
    status: "not_reviewed",
    findingDetails: "",
    comments: "",
  });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  const [filter, setFilter] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await apiGet(`/api/checklists/${checklistId}`);
      setDetail(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [checklistId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const isOwner = detail && currentUser?.id === detail.asset.ownerId;

  const counts = useMemo(() => {
    const c = { not_reviewed: 0, open: 0, not_a_finding: 0, not_applicable: 0 };
    if (!detail) return c;
    for (const r of detail.rules) c[r.state.status] = (c[r.state.status] ?? 0) + 1;
    return c;
  }, [detail]);

  const filteredRules = useMemo(() => {
    if (!detail) return [];
    if (!filter.trim()) return detail.rules;
    const f = filter.trim().toLowerCase();
    return detail.rules.filter(
      (r) =>
        (r.id ?? "").toLowerCase().includes(f) ||
        (r.title ?? "").toLowerCase().includes(f) ||
        (r.severity ?? "").toLowerCase().includes(f),
    );
  }, [detail, filter]);

  const startEdit = useCallback((rule) => {
    setDraft({
      status: rule.state.status,
      findingDetails: rule.state.findingDetails,
      comments: rule.state.comments,
    });
    setSaveError(null);
    setEditing(rule);
  }, []);

  const saveEdit = useCallback(async () => {
    if (!editing) return;
    setSaving(true);
    setSaveError(null);
    try {
      await apiJson(
        `/api/checklists/${checklistId}/rules/${encodeURIComponent(editing.id)}`,
        "PATCH",
        draft,
      );
      setEditing(null);
      await refresh();
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  }, [checklistId, editing, draft, refresh]);

  if (loading) {
    return (
      <Box padding="xxl" textAlign="center">
        <StatusIndicator type="loading">Loading checklist</StatusIndicator>
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
          <Button onClick={onBack}>Back</Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box padding="m">
      <SpaceBetween direction="vertical" size="l">
        <Button iconName="arrow-left" onClick={onBack}>
          Back to system
        </Button>

        <Container
          header={
            <Header
              variant="h1"
              description={`${detail.asset.name} · ${detail.rules.length} rules`}
            >
              {detail.stig?.title || detail.checklist.stigId}
            </Header>
          }
        >
          <ColumnLayout columns={4} variant="text-grid">
            {STATUSES.map((s) => (
              <div key={s.value}>
                <Box variant="awsui-key-label">{s.label}</Box>
                <Box variant="h2">{counts[s.value] ?? 0}</Box>
              </div>
            ))}
          </ColumnLayout>
        </Container>

        <Table
          variant="container"
          items={filteredRules}
          trackBy="id"
          columnDefinitions={[
            {
              id: "id",
              header: "Rule",
              cell: (r) => (
                <Button variant="inline-link" onClick={() => startEdit(r)}>
                  {r.id}
                </Button>
              ),
            },
            {
              id: "severity",
              header: "Severity",
              cell: (r) => (
                <Badge color={severityColor(r.severity)}>
                  {severityLabel(r.severity)}
                </Badge>
              ),
            },
            {
              id: "title",
              header: "Title",
              cell: (r) => r.title || "—",
            },
            {
              id: "status",
              header: "Status",
              cell: (r) => {
                const s = STATUS_BY_VALUE[r.state.status] ?? STATUSES[0];
                return <Badge color={s.color}>{s.label}</Badge>;
              },
            },
          ]}
          header={
            <Header counter={`(${filteredRules.length} of ${detail.rules.length})`}>
              Rules
            </Header>
          }
          filter={
            <TextFilter
              filteringText={filter}
              filteringPlaceholder="Filter rules"
              onChange={({ detail: d }) => setFilter(d.filteringText)}
            />
          }
        />
      </SpaceBetween>

      <Modal
        visible={editing !== null}
        onDismiss={() => setEditing(null)}
        size="large"
        header={editing?.id}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setEditing(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={saving}
                disabled={!isOwner}
                onClick={saveEdit}
              >
                Save
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {editing && (
          <SpaceBetween direction="vertical" size="m">
            <Box variant="h3">{editing.title}</Box>
            {editing.description && (
              <Box variant="small" color="text-body-secondary">
                {editing.description}
              </Box>
            )}
            {!isOwner && (
              <Alert type="info">
                Read-only — only the system owner can change rule status.
              </Alert>
            )}
            <FormField label="Status">
              <RadioGroup
                value={draft.status}
                onChange={({ detail: d }) =>
                  setDraft((f) => ({ ...f, status: d.value }))
                }
                items={STATUSES.map((s) => ({ value: s.value, label: s.label }))}
              />
            </FormField>
            <FormField label="Finding details" description="What was observed?">
              <Textarea
                value={draft.findingDetails}
                disabled={!isOwner}
                onChange={({ detail: d }) =>
                  setDraft((f) => ({ ...f, findingDetails: d.value }))
                }
                rows={4}
              />
            </FormField>
            <FormField label="Comments" description="Notes for future reviewers">
              <Textarea
                value={draft.comments}
                disabled={!isOwner}
                onChange={({ detail: d }) =>
                  setDraft((f) => ({ ...f, comments: d.value }))
                }
                rows={3}
              />
            </FormField>
            {saveError && <Alert type="error">{saveError}</Alert>}
          </SpaceBetween>
        )}
      </Modal>
    </Box>
  );
}
