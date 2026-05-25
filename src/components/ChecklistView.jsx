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
import Select from "@cloudscape-design/components/select";
import DatePicker from "@cloudscape-design/components/date-picker";
import { apiFetch, apiGet, apiJson, apiUpload, BACKEND } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";

function formatBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const STATUSES = [
  { value: "not_reviewed", label: "Not reviewed", color: "grey" },
  { value: "open", label: "Open", color: "red" },
  { value: "not_a_finding", label: "Not a finding", color: "green" },
  { value: "not_applicable", label: "Not applicable", color: "blue" },
];

const STATUS_BY_VALUE = Object.fromEntries(STATUSES.map((s) => [s.value, s]));

// Emoji-style reactions surfaced under each rule comment. Keep the
// `key` values in sync with the allowlist in
// backend/src/api/rule_comments.rs (ALLOWED_REACTIONS).
const REACTION_TYPES = [
  { key: "thumbs_up", emoji: "\u{1F44D}" },
  { key: "check", emoji: "✅" },
  { key: "question", emoji: "❓" },
];

// Closing statuses require a written justification in `findingDetails`.
// Keep in sync with `requires_finding_details` in
// backend/src/api/checklists.rs.
const CLOSING_STATUSES = new Set(["not_a_finding", "not_applicable"]);

function findingDetailsRequired(status, findingDetails) {
  return (
    CLOSING_STATUSES.has(status) && (findingDetails ?? "").trim().length === 0
  );
}

// Try to parse the JSON error body thrown by apiJson; fall back to the raw
// message if the server didn't return JSON.
function parseSaveError(message) {
  if (!message) return null;
  try {
    const obj = JSON.parse(message);
    if (obj && typeof obj.error === "string") return obj.error;
  } catch {
    // not JSON — use as-is
  }
  return message;
}

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
    assigneeId: null,
    dueDate: "",
  });
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);
  const [users, setUsers] = useState([]);

  const [filter, setFilter] = useState("");

  // Attachment state — both the per-rule list shown in the Evidence
  // section of the editor modal, and a checklist-wide count map used
  // to decorate the rule list with a paperclip indicator.
  const [attachments, setAttachments] = useState([]);
  const [attachmentsLoading, setAttachmentsLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [counts2, setCounts2] = useState({}); // ruleId -> count

  // Per-rule comment thread state — keyed off (checklistId, ruleId).
  // `comments` lives independently of the status-note `comments` field on
  // checklist_rules; this is the threaded discussion.
  const [comments, setComments] = useState([]);
  const [commentsLoading, setCommentsLoading] = useState(false);
  const [commentDraft, setCommentDraft] = useState("");
  const [postingComment, setPostingComment] = useState(false);
  const [commentError, setCommentError] = useState(null);
  const [editingCommentId, setEditingCommentId] = useState(null);
  const [editingCommentBody, setEditingCommentBody] = useState("");

  // Bulk CSV import modal state. `step` is "pick" (choose file + dry-run)
  // or "preview" (review parsed rows, click Import to commit).
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkStep, setBulkStep] = useState("pick");
  const [bulkFile, setBulkFile] = useState(null);
  const [bulkPreview, setBulkPreview] = useState(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkError, setBulkError] = useState(null);
  const [bulkSuccess, setBulkSuccess] = useState(null);

  // Rule IDs in this checklist that currently have an open approval
  // request. Used to render a "Pending review" pill in the rule list.
  const [pendingApprovalIds, setPendingApprovalIds] = useState(new Set());

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const d = await apiGet(`/api/checklists/${checklistId}`);
      setDetail(d);
      // Best-effort fetch of pending approvals scoped to this checklist.
      // Non-fatal — the rule list still renders without the pill.
      try {
        const rows = await apiGet(`/api/approvals?status=pending`);
        const ids = new Set(
          (Array.isArray(rows) ? rows : [])
            .filter((r) => r.checklistId === checklistId)
            .map((r) => r.ruleId),
        );
        setPendingApprovalIds(ids);
      } catch {
        setPendingApprovalIds(new Set());
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [checklistId]);

  const refreshCounts = useCallback(async () => {
    try {
      const rows = await apiGet(`/api/checklists/${checklistId}/attachments`);
      const map = {};
      for (const r of rows) map[r.ruleId] = r.count;
      setCounts2(map);
    } catch {
      // Non-fatal — just leave counts empty.
    }
  }, [checklistId]);

  const refreshAttachments = useCallback(
    async (ruleId) => {
      if (!ruleId) return;
      setAttachmentsLoading(true);
      try {
        const rows = await apiGet(
          `/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/attachments`,
        );
        setAttachments(rows);
      } catch (err) {
        setAttachments([]);
        setUploadError(err.message);
      } finally {
        setAttachmentsLoading(false);
      }
    },
    [checklistId],
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Load attachment counts once per checklist for the paperclip
  // indicator in the rule list.
  useEffect(() => {
    refreshCounts();
  }, [refreshCounts]);

  // Load the user list once for the Assignee Select.
  useEffect(() => {
    let cancelled = false;
    apiGet("/api/users")
      .then((rows) => {
        if (!cancelled) setUsers(rows);
      })
      .catch(() => {
        // Non-fatal — the Select just won't have options.
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

  const refreshComments = useCallback(
    async (ruleId) => {
      if (!ruleId) return;
      setCommentsLoading(true);
      try {
        const rows = await apiGet(
          `/api/checklists/${checklistId}/rules/${encodeURIComponent(ruleId)}/comments`,
        );
        setComments(rows);
      } catch (err) {
        setComments([]);
        setCommentError(err.message);
      } finally {
        setCommentsLoading(false);
      }
    },
    [checklistId],
  );

  const startEdit = useCallback(
    (rule) => {
      setDraft({
        status: rule.state.status,
        findingDetails: rule.state.findingDetails,
        comments: rule.state.comments,
        assigneeId: rule.state.assigneeId ?? null,
        dueDate: rule.state.dueDate ?? "",
      });
      setSaveError(null);
      setUploadError(null);
      setAttachments([]);
      setComments([]);
      setCommentDraft("");
      setCommentError(null);
      setEditingCommentId(null);
      setEditingCommentBody("");
      setEditing(rule);
      refreshAttachments(rule.id);
      refreshComments(rule.id);
    },
    [refreshAttachments, refreshComments],
  );

  const postComment = useCallback(async () => {
    if (!editing) return;
    const trimmed = commentDraft.trim();
    if (!trimmed) return;
    setPostingComment(true);
    setCommentError(null);
    try {
      await apiJson(
        `/api/checklists/${checklistId}/rules/${encodeURIComponent(editing.id)}/comments`,
        "POST",
        { body: trimmed },
      );
      setCommentDraft("");
      await refreshComments(editing.id);
    } catch (err) {
      setCommentError(parseSaveError(err.message));
    } finally {
      setPostingComment(false);
    }
  }, [checklistId, editing, commentDraft, refreshComments]);

  const startEditComment = useCallback((comment) => {
    setEditingCommentId(comment.id);
    setEditingCommentBody(comment.body);
    setCommentError(null);
  }, []);

  const cancelEditComment = useCallback(() => {
    setEditingCommentId(null);
    setEditingCommentBody("");
  }, []);

  const saveEditComment = useCallback(async () => {
    if (!editing || !editingCommentId) return;
    const trimmed = editingCommentBody.trim();
    if (!trimmed) return;
    setCommentError(null);
    try {
      await apiJson(`/api/comments/${editingCommentId}`, "PATCH", {
        body: trimmed,
      });
      setEditingCommentId(null);
      setEditingCommentBody("");
      await refreshComments(editing.id);
    } catch (err) {
      setCommentError(parseSaveError(err.message));
    }
  }, [editing, editingCommentId, editingCommentBody, refreshComments]);

  const deleteComment = useCallback(
    async (commentId) => {
      if (!editing) return;
      setCommentError(null);
      try {
        const res = await apiFetch(`/api/comments/${commentId}`, {
          method: "DELETE",
        });
        if (!res.ok) throw new Error(`${res.status}`);
        await refreshComments(editing.id);
      } catch (err) {
        setCommentError(err.message);
      }
    },
    [editing, refreshComments],
  );

  // Toggle one of the three emoji reactions on a comment. If `mine` is
  // true we DELETE; otherwise we POST. After the request we refresh the
  // comment list so the new count/mine flag are reflected.
  const toggleReaction = useCallback(
    async (commentId, reaction, mine) => {
      if (!editing) return;
      setCommentError(null);
      try {
        // Both endpoints return 204 No Content, so we use apiFetch
        // directly — apiJson assumes a JSON body and would swallow the
        // success path through its "Unexpected end of JSON input" catch.
        const path = mine
          ? `/api/comments/${commentId}/reactions/${reaction}`
          : `/api/comments/${commentId}/reactions`;
        const opts = mine
          ? { method: "DELETE" }
          : {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ reaction }),
            };
        const res = await apiFetch(path, opts);
        if (!res.ok) throw new Error(`${res.status}`);
        await refreshComments(editing.id);
      } catch (err) {
        setCommentError(parseSaveError(err.message));
      }
    },
    [editing, refreshComments],
  );

  const uploadAttachment = useCallback(
    async (file) => {
      if (!editing || !file) return;
      setUploading(true);
      setUploadError(null);
      try {
        await apiUpload(
          `/api/checklists/${checklistId}/rules/${encodeURIComponent(editing.id)}/attachments`,
          file,
        );
        await refreshAttachments(editing.id);
        await refreshCounts();
      } catch (err) {
        // The backend returns 413 for files over the size cap; surface a
        // friendlier message in that case.
        const msg = /413/.test(err.message)
          ? "File too large (max 25 MB)."
          : err.message;
        setUploadError(msg);
      } finally {
        setUploading(false);
      }
    },
    [checklistId, editing, refreshAttachments, refreshCounts],
  );

  const deleteAttachment = useCallback(
    async (attachmentId) => {
      if (!editing) return;
      try {
        const res = await apiFetch(`/api/attachments/${attachmentId}`, {
          method: "DELETE",
        });
        if (!res.ok) throw new Error(`${res.status}`);
        await refreshAttachments(editing.id);
        await refreshCounts();
      } catch (err) {
        setUploadError(err.message);
      }
    },
    [editing, refreshAttachments, refreshCounts],
  );

  const gateViolated = useMemo(
    () => findingDetailsRequired(draft.status, draft.findingDetails),
    [draft.status, draft.findingDetails],
  );

  // Reset the bulk-import modal state. Memoised so the open callback can
  // safely cycle the modal closed→open without races on the inner state.
  const closeBulk = useCallback(() => {
    setBulkOpen(false);
    setBulkStep("pick");
    setBulkFile(null);
    setBulkPreview(null);
    setBulkError(null);
    setBulkSuccess(null);
    setBulkBusy(false);
  }, []);

  const openBulk = useCallback(() => {
    closeBulk();
    setBulkOpen(true);
  }, [closeBulk]);

  // Upload + parse the chosen CSV via a dry-run POST. The response drives
  // the preview table; commit re-uploads the same file with dry_run=false.
  const onBulkFileChange = useCallback(
    async (file) => {
      setBulkFile(file);
      setBulkPreview(null);
      setBulkError(null);
      setBulkSuccess(null);
      if (!file) return;
      setBulkBusy(true);
      try {
        const fd = new FormData();
        fd.append("file", file, file.name);
        const res = await apiFetch(
          `/api/checklists/${checklistId}/rules/bulk-import?dry_run=true`,
          { method: "POST", body: fd },
        );
        if (!res.ok) {
          const text = await res.text().catch(() => res.statusText);
          throw new Error(text || `${res.status}`);
        }
        const data = await res.json();
        setBulkPreview(data);
        setBulkStep("preview");
      } catch (err) {
        setBulkError(err.message);
      } finally {
        setBulkBusy(false);
      }
    },
    [checklistId],
  );

  const commitBulk = useCallback(async () => {
    if (!bulkFile) return;
    setBulkBusy(true);
    setBulkError(null);
    try {
      const fd = new FormData();
      fd.append("file", bulkFile, bulkFile.name);
      const res = await apiFetch(
        `/api/checklists/${checklistId}/rules/bulk-import?dry_run=false`,
        { method: "POST", body: fd },
      );
      if (!res.ok) {
        const text = await res.text().catch(() => res.statusText);
        throw new Error(text || `${res.status}`);
      }
      const data = await res.json();
      setBulkSuccess(data);
      await refresh();
      // Auto-close shortly after success so the user sees the alert.
      setTimeout(() => closeBulk(), 800);
    } catch (err) {
      setBulkError(err.message);
    } finally {
      setBulkBusy(false);
    }
  }, [bulkFile, checklistId, refresh, closeBulk]);

  // Inline data: URL for the "Download template" link. Three columns +
  // one example row keep the CSV tiny and self-documenting.
  const bulkTemplateHref = useMemo(() => {
    const csv =
      "rule_id,status,finding_details\n" +
      "V-12345,not_a_finding,Patched per vendor guidance.\n";
    return `data:text/csv;charset=utf-8,${encodeURIComponent(csv)}`;
  }, []);

  const [pendingApproval, setPendingApproval] = useState(null);

  const saveEdit = useCallback(async () => {
    if (!editing) return;
    setSaving(true);
    setSaveError(null);
    setPendingApproval(null);
    try {
      // DatePicker yields YYYY/MM/DD or YYYY-MM-DD; backend wants YYYY-MM-DD,
      // and an empty string should mean "no due date" → null.
      const dueDate = draft.dueDate
        ? draft.dueDate.replace(/\//g, "-")
        : null;
      const result = await apiJson(
        `/api/checklists/${checklistId}/rules/${encodeURIComponent(editing.id)}`,
        "PATCH",
        { ...draft, dueDate },
      );
      // The server returns 202 + { status: 'pending_approval', ... } when
      // the asset has requires_approval = TRUE and the proposed status is
      // a closing one. Keep the editor open and surface a banner instead
      // of closing it like a normal save.
      if (result && result.status === "pending_approval") {
        setPendingApproval(result);
        await refresh();
      } else {
        setEditing(null);
        await refresh();
      }
    } catch (err) {
      setSaveError(parseSaveError(err.message));
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
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button
                    onClick={openBulk}
                    disabled={!isOwner}
                    data-testid="bulk-import-button"
                  >
                    Bulk import
                  </Button>
                </SpaceBetween>
              }
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
              cell: (r) => {
                const n = counts2[r.id] || 0;
                return (
                  <SpaceBetween direction="horizontal" size="xxs">
                    <Button variant="inline-link" onClick={() => startEdit(r)}>
                      {r.id}
                    </Button>
                    {n > 0 && (
                      <span
                        title={`${n} attachment${n === 1 ? "" : "s"}`}
                        aria-label={`${n} attachment${n === 1 ? "" : "s"}`}
                        data-testid="attachment-indicator"
                        style={{ opacity: 0.7 }}
                      >
                        {"\u{1F4CE}"}
                        {n > 1 ? ` ${n}` : ""}
                      </span>
                    )}
                  </SpaceBetween>
                );
              },
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
                if (pendingApprovalIds.has(r.id)) {
                  return (
                    <Badge color="blue" data-testid="status-pending-review">
                      Pending review
                    </Badge>
                  );
                }
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
                disabled={!isOwner || gateViolated}
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
            <ColumnLayout columns={2}>
              <FormField label="Assignee">
                <Select
                  selectedOption={
                    draft.assigneeId
                      ? {
                          value: draft.assigneeId,
                          label:
                            users.find((u) => u.id === draft.assigneeId)
                              ?.displayName ?? draft.assigneeId,
                        }
                      : { value: null, label: "Unassigned" }
                  }
                  onChange={({ detail: d }) =>
                    setDraft((f) => ({
                      ...f,
                      assigneeId: d.selectedOption.value || null,
                    }))
                  }
                  options={[
                    { value: null, label: "Unassigned" },
                    ...users.map((u) => ({
                      value: u.id,
                      label: u.displayName,
                    })),
                  ]}
                  disabled={!isOwner}
                />
              </FormField>
              <FormField label="Due date">
                <DatePicker
                  value={draft.dueDate}
                  onChange={({ detail: d }) =>
                    setDraft((f) => ({ ...f, dueDate: d.value }))
                  }
                  placeholder="YYYY/MM/DD"
                  disabled={!isOwner}
                />
              </FormField>
            </ColumnLayout>
            <FormField
              label="Finding details"
              description="What was observed?"
              errorText={
                gateViolated ? "Required when closing this finding." : undefined
              }
            >
              <Textarea
                value={draft.findingDetails}
                disabled={!isOwner}
                onChange={({ detail: d }) =>
                  setDraft((f) => ({ ...f, findingDetails: d.value }))
                }
                rows={4}
                invalid={gateViolated}
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
            {pendingApproval && (
              <Alert
                type="success"
                header="Submitted for review"
                data-testid="pending-approval-alert"
              >
                This asset requires reviewer approval before closing findings.
                Your request has been queued and a reviewer will see it in
                the approvals queue.
              </Alert>
            )}

            <FormField
              label="Evidence"
              description="Attach screenshots, logs, or scan output as supporting evidence."
            >
              <SpaceBetween direction="vertical" size="s">
                {attachmentsLoading ? (
                  <StatusIndicator type="loading">
                    Loading attachments
                  </StatusIndicator>
                ) : attachments.length === 0 ? (
                  <Box variant="small" color="text-body-secondary">
                    No attachments yet.
                  </Box>
                ) : (
                  <Table
                    variant="embedded"
                    items={attachments}
                    trackBy="id"
                    columnDefinitions={[
                      {
                        id: "filename",
                        header: "File",
                        cell: (a) => a.filename,
                      },
                      {
                        id: "size",
                        header: "Size",
                        cell: (a) => formatBytes(a.sizeBytes),
                      },
                      {
                        id: "uploaded",
                        header: "Uploaded",
                        cell: (a) =>
                          new Date(a.uploadedAt).toLocaleString(),
                      },
                      {
                        id: "actions",
                        header: "",
                        cell: (a) => (
                          <SpaceBetween direction="horizontal" size="xxs">
                            <Button
                              variant="inline-link"
                              iconName="download"
                              ariaLabel={`Download ${a.filename}`}
                              href={`${BACKEND}/api/attachments/${a.id}`}
                              target="_blank"
                              data-testid="attachment-download"
                            >
                              Download
                            </Button>
                            <Button
                              variant="inline-link"
                              iconName="close"
                              ariaLabel={`Delete ${a.filename}`}
                              disabled={!isOwner}
                              onClick={() => deleteAttachment(a.id)}
                              data-testid="attachment-delete"
                            >
                              Delete
                            </Button>
                          </SpaceBetween>
                        ),
                      },
                    ]}
                  />
                )}
                {isOwner && (
                  <Box>
                    <input
                      type="file"
                      data-testid="attachment-file-input"
                      disabled={uploading}
                      onChange={(e) => {
                        const f = e.target.files && e.target.files[0];
                        if (f) {
                          uploadAttachment(f);
                          // Reset so the same file can be picked again.
                          e.target.value = "";
                        }
                      }}
                    />
                    {uploading && (
                      <Box variant="small" padding={{ top: "xs" }}>
                        <StatusIndicator type="in-progress">
                          Uploading…
                        </StatusIndicator>
                      </Box>
                    )}
                  </Box>
                )}
                {uploadError && <Alert type="error">{uploadError}</Alert>}
              </SpaceBetween>
            </FormField>

            <FormField
              label="Comments"
              description="Threaded discussion for this rule."
            >
              <SpaceBetween direction="vertical" size="s">
                {commentsLoading ? (
                  <StatusIndicator type="loading">
                    Loading comments
                  </StatusIndicator>
                ) : comments.length === 0 ? (
                  <Box variant="small" color="text-body-secondary">
                    No comments yet.
                  </Box>
                ) : (
                  <SpaceBetween direction="vertical" size="xs">
                    {comments.map((c) => {
                      const isAuthor = currentUser?.id === c.userId;
                      const isEditingThis = editingCommentId === c.id;
                      return (
                        <Box
                          key={c.id}
                          padding="s"
                          data-testid="rule-comment"
                        >
                          <SpaceBetween direction="vertical" size="xxs">
                            <Box variant="small" color="text-body-secondary">
                              <strong>{c.userName}</strong>
                              {" · "}
                              {new Date(c.createdAt).toLocaleString()}
                              {c.editedAt ? " (edited)" : ""}
                            </Box>
                            {isEditingThis ? (
                              <SpaceBetween direction="vertical" size="xs">
                                <Textarea
                                  value={editingCommentBody}
                                  onChange={({ detail: d }) =>
                                    setEditingCommentBody(d.value)
                                  }
                                  rows={3}
                                />
                                <SpaceBetween
                                  direction="horizontal"
                                  size="xs"
                                >
                                  <Button
                                    variant="primary"
                                    onClick={saveEditComment}
                                    data-testid="rule-comment-save-edit"
                                  >
                                    Save
                                  </Button>
                                  <Button
                                    variant="link"
                                    onClick={cancelEditComment}
                                  >
                                    Cancel
                                  </Button>
                                </SpaceBetween>
                              </SpaceBetween>
                            ) : (
                              <>
                                <Box>{c.body}</Box>
                                <SpaceBetween
                                  direction="horizontal"
                                  size="xxs"
                                >
                                  {REACTION_TYPES.map((rt) => {
                                    const summary =
                                      c.reactions?.[rt.key] ?? {
                                        count: 0,
                                        mine: false,
                                      };
                                    return (
                                      <Button
                                        key={rt.key}
                                        variant={
                                          summary.mine
                                            ? "primary"
                                            : "inline-link"
                                        }
                                        onClick={() =>
                                          toggleReaction(
                                            c.id,
                                            rt.key,
                                            summary.mine,
                                          )
                                        }
                                        data-testid={`rule-comment-reaction-${rt.key}`}
                                      >
                                        {rt.emoji} {summary.count}
                                      </Button>
                                    );
                                  })}
                                </SpaceBetween>
                                <SpaceBetween
                                  direction="horizontal"
                                  size="xxs"
                                >
                                  <Button
                                    variant="inline-link"
                                    disabled={!isAuthor}
                                    onClick={() => startEditComment(c)}
                                    data-testid="rule-comment-edit"
                                  >
                                    Edit
                                  </Button>
                                  <Button
                                    variant="inline-link"
                                    disabled={!isAuthor}
                                    onClick={() => deleteComment(c.id)}
                                    data-testid="rule-comment-delete"
                                  >
                                    Delete
                                  </Button>
                                </SpaceBetween>
                              </>
                            )}
                          </SpaceBetween>
                        </Box>
                      );
                    })}
                  </SpaceBetween>
                )}

                <Textarea
                  value={commentDraft}
                  onChange={({ detail: d }) => setCommentDraft(d.value)}
                  placeholder="Add a comment…"
                  rows={3}
                  data-testid="rule-comment-input"
                />
                <Box>
                  <Button
                    variant="primary"
                    loading={postingComment}
                    disabled={!commentDraft.trim()}
                    onClick={postComment}
                    data-testid="rule-comment-add"
                  >
                    Add comment
                  </Button>
                </Box>
                {commentError && <Alert type="error">{commentError}</Alert>}
              </SpaceBetween>
            </FormField>
          </SpaceBetween>
        )}
      </Modal>

      <Modal
        visible={bulkOpen}
        onDismiss={closeBulk}
        header="Bulk import rule statuses"
        size="large"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeBulk}>
                Cancel
              </Button>
              {bulkStep === "preview" && bulkPreview && (
                <Button
                  variant="primary"
                  loading={bulkBusy}
                  disabled={
                    bulkBusy ||
                    bulkPreview.rows.every((r) => r.status === "error")
                  }
                  onClick={commitBulk}
                  data-testid="bulk-import-commit"
                >
                  {`Apply ${bulkPreview.rows.filter((r) => r.status === "ok").length} rows`}
                </Button>
              )}
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <Box>
            CSV columns: <code>rule_id, status, finding_details</code>.
            Status must be one of <code>not_reviewed</code>,{" "}
            <code>open</code>, <code>not_a_finding</code>,{" "}
            <code>not_applicable</code>.{" "}
            <a
              href={bulkTemplateHref}
              download="rule-bulk-import-template.csv"
              data-testid="bulk-import-template"
            >
              Download template
            </a>
          </Box>
          <FormField label="CSV file">
            <input
              type="file"
              accept=".csv,text/csv"
              data-testid="bulk-import-input"
              onChange={(e) => {
                const f = e.target.files && e.target.files[0];
                if (f) onBulkFileChange(f);
              }}
            />
          </FormField>
          {bulkBusy && bulkStep === "pick" && (
            <StatusIndicator type="loading">Parsing…</StatusIndicator>
          )}
          {bulkError && <Alert type="error">{bulkError}</Alert>}
          {bulkSuccess && (
            <Alert type="success" data-testid="bulk-import-success">
              {`Applied ${bulkSuccess.appliedCount} rule${bulkSuccess.appliedCount === 1 ? "" : "s"}.`}
            </Alert>
          )}
          {bulkPreview && (
            <>
              {bulkPreview.rows.some((r) => r.status === "error") && (
                <Alert type="warning">
                  {`${bulkPreview.rows.filter((r) => r.status === "error").length} rows have errors and will be skipped.`}
                </Alert>
              )}
              <Table
                variant="embedded"
                items={bulkPreview.rows}
                trackBy="rowNumber"
                columnDefinitions={[
                  {
                    id: "row",
                    header: "Row",
                    cell: (r) => r.rowNumber,
                  },
                  {
                    id: "ruleId",
                    header: "Rule",
                    cell: (r) => r.ruleId || "—",
                  },
                  {
                    id: "ruleStatus",
                    header: "Status",
                    cell: (r) => r.ruleStatus || "—",
                  },
                  {
                    id: "findingDetails",
                    header: "Finding details",
                    cell: (r) => r.findingDetails || "—",
                  },
                  {
                    id: "status",
                    header: "Result",
                    cell: (r) => {
                      const color = r.status === "ok" ? "green" : "red";
                      return (
                        <Badge
                          color={color}
                          data-testid={`bulk-status-${r.rowNumber}`}
                        >
                          {r.status}
                        </Badge>
                      );
                    },
                  },
                  {
                    id: "error",
                    header: "Note",
                    cell: (r) => r.error || "",
                  },
                ]}
                empty={<Box>No rows.</Box>}
              />
            </>
          )}
        </SpaceBetween>
      </Modal>
    </Box>
  );
}
