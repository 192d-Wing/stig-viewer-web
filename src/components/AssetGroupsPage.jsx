import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Box from "@cloudscape-design/components/box";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import Textarea from "@cloudscape-design/components/textarea";
import Multiselect from "@cloudscape-design/components/multiselect";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { apiGet, apiJson, apiFetch } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";

// "view" is either "list" or { type: "members", id, name } — pivoting to a
// dedicated members sub-page keeps the membership editor focused (the
// list table is full-page so an inline expander would fight Cloudscape's
// sticky header).
const EMPTY_FORM = { name: "", description: "" };

export default function AssetGroupsPage() {
  const currentUser = useContext(AuthContext);

  const [view, setView] = useState("list");
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [modal, setModal] = useState(null); // { mode: "create" | "edit", group? }
  const [form, setForm] = useState(EMPTY_FORM);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);

  const [deleteTarget, setDeleteTarget] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await apiGet("/api/asset-groups");
      setGroups(rows);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const openCreate = useCallback(() => {
    setForm(EMPTY_FORM);
    setSubmitError(null);
    setModal({ mode: "create" });
  }, []);

  const openEdit = useCallback((group) => {
    setForm({ name: group.name, description: group.description ?? "" });
    setSubmitError(null);
    setModal({ mode: "edit", group });
  }, []);

  const closeModal = useCallback(() => {
    setModal(null);
    setSubmitError(null);
  }, []);

  const submit = useCallback(async () => {
    if (!form.name.trim()) {
      setSubmitError("Name is required.");
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      if (modal.mode === "create") {
        await apiJson("/api/asset-groups", "POST", form);
      } else {
        await apiJson(`/api/asset-groups/${modal.group.id}`, "PATCH", form);
      }
      setModal(null);
      await refresh();
    } catch (err) {
      setSubmitError(err.message);
    } finally {
      setSubmitting(false);
    }
  }, [form, modal, refresh]);

  const confirmDelete = useCallback(async () => {
    if (!deleteTarget) return;
    try {
      const res = await apiFetch(`/api/asset-groups/${deleteTarget.id}`, {
        method: "DELETE",
      });
      if (!res.ok && res.status !== 204) {
        throw new Error(`Delete failed: ${res.status}`);
      }
      setDeleteTarget(null);
      await refresh();
    } catch (err) {
      setSubmitError(err.message);
    }
  }, [deleteTarget, refresh]);

  const columns = useMemo(
    () => [
      {
        id: "name",
        header: "Name",
        cell: (g) => (
          <Button
            variant="inline-link"
            onClick={() => setView({ type: "members", id: g.id, name: g.name })}
            data-testid={`group-name-${g.name}`}
          >
            {g.name}
          </Button>
        ),
        sortingField: "name",
      },
      {
        id: "description",
        header: "Description",
        cell: (g) => g.description || "—",
      },
      {
        id: "owner",
        header: "Owner",
        cell: (g) => g.ownerName,
      },
      {
        id: "members",
        header: "Members",
        cell: (g) => g.memberCount,
      },
      {
        id: "updated",
        header: "Created",
        cell: (g) => new Date(g.createdAt).toLocaleString(),
      },
      {
        id: "actions",
        header: "",
        cell: (g) => {
          const canEdit =
            currentUser?.id === g.ownerId || currentUser?.role === "admin";
          return (
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                variant="inline-link"
                onClick={() =>
                  setView({ type: "members", id: g.id, name: g.name })
                }
              >
                View
              </Button>
              <Button
                variant="inline-link"
                disabled={!canEdit}
                onClick={() => openEdit(g)}
              >
                Edit
              </Button>
              <Button
                variant="inline-link"
                disabled={!canEdit}
                onClick={() => setDeleteTarget(g)}
              >
                Delete
              </Button>
            </SpaceBetween>
          );
        },
      },
    ],
    [currentUser, openEdit],
  );

  if (view?.type === "members") {
    const group = groups.find((g) => g.id === view.id);
    return (
      <GroupMembersView
        groupId={view.id}
        groupName={view.name}
        canEdit={
          !!group &&
          (currentUser?.id === group.ownerId || currentUser?.role === "admin")
        }
        onBack={() => {
          setView("list");
          refresh();
        }}
      />
    );
  }

  return (
    <>
      <Table
        variant="full-page"
        stickyHeader
        items={groups}
        columnDefinitions={columns}
        loading={loading}
        loadingText="Loading groups"
        empty={
          <Box textAlign="center" padding="l">
            <SpaceBetween direction="vertical" size="m">
              <StatusIndicator type="info">No groups yet</StatusIndicator>
              <Button variant="primary" onClick={openCreate}>
                Create your first group
              </Button>
            </SpaceBetween>
          </Box>
        }
        header={
          <Header
            counter={`(${groups.length})`}
            actions={
              <Button
                variant="primary"
                onClick={openCreate}
                data-testid="create-group-button"
              >
                Create group
              </Button>
            }
          >
            Asset groups
          </Header>
        }
      />

      {error && (
        <Box padding="m">
          <Alert type="error">{error}</Alert>
        </Box>
      )}

      <Modal
        visible={modal !== null}
        onDismiss={closeModal}
        header={modal?.mode === "edit" ? "Edit group" : "Create group"}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeModal}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={submitting}
                onClick={submit}
                data-testid="group-modal-submit"
              >
                {modal?.mode === "edit" ? "Save" : "Create"}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="Name">
            <Input
              value={form.name}
              data-testid="group-name-input"
              onChange={({ detail }) =>
                setForm((f) => ({ ...f, name: detail.value }))
              }
              autoFocus
            />
          </FormField>
          <FormField label="Description">
            <Textarea
              value={form.description}
              data-testid="group-description-input"
              onChange={({ detail }) =>
                setForm((f) => ({ ...f, description: detail.value }))
              }
              rows={3}
            />
          </FormField>
          {submitError && <Alert type="error">{submitError}</Alert>}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={deleteTarget !== null}
        onDismiss={() => setDeleteTarget(null)}
        header="Delete group?"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setDeleteTarget(null)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={confirmDelete}>
                Delete
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <Alert type="warning">
          {`Deleting "${deleteTarget?.name ?? ""}" removes the group and all of its memberships. Member assets themselves are not deleted.`}
        </Alert>
      </Modal>
    </>
  );
}

// ── Members sub-view ────────────────────────────────────────────────────────

function GroupMembersView({ groupId, groupName, canEdit, onBack }) {
  const [members, setMembers] = useState([]);
  const [allAssets, setAllAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState([]);
  const [adding, setAdding] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [m, a] = await Promise.all([
        apiGet(`/api/asset-groups/${groupId}/members`),
        apiGet("/api/assets"),
      ]);
      setMembers(m);
      setAllAssets(a);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Candidate options = assets not already in the group.
  const memberIds = useMemo(
    () => new Set(members.map((m) => m.assetId)),
    [members],
  );
  const options = useMemo(
    () =>
      allAssets
        .filter((a) => !memberIds.has(a.id))
        .map((a) => ({ label: a.name, value: a.id, description: a.hostname })),
    [allAssets, memberIds],
  );

  const addSelected = useCallback(async () => {
    if (selected.length === 0) return;
    setAdding(true);
    setError(null);
    try {
      for (const opt of selected) {
        // POST is idempotent server-side, so a retry on partial failure
        // is safe — but stop on the first hard error to avoid spamming
        // the user with one toast per asset.
        // eslint-disable-next-line no-await-in-loop
        const res = await apiFetch(`/api/asset-groups/${groupId}/members`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ assetId: opt.value }),
        });
        if (!res.ok && res.status !== 204) {
          const text = await res.text().catch(() => res.statusText);
          throw new Error(text || `${res.status}`);
        }
      }
      setSelected([]);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setAdding(false);
    }
  }, [selected, groupId, refresh]);

  const removeMember = useCallback(
    async (assetId) => {
      try {
        const res = await apiFetch(
          `/api/asset-groups/${groupId}/members/${assetId}`,
          { method: "DELETE" },
        );
        if (!res.ok && res.status !== 204) {
          throw new Error(`Remove failed: ${res.status}`);
        }
        await refresh();
      } catch (err) {
        setError(err.message);
      }
    },
    [groupId, refresh],
  );

  const columns = [
    { id: "name", header: "Name", cell: (m) => m.name },
    { id: "hostname", header: "Hostname", cell: (m) => m.hostname || "—" },
    {
      id: "added",
      header: "Added",
      cell: (m) => new Date(m.addedAt).toLocaleString(),
    },
    {
      id: "actions",
      header: "",
      cell: (m) => (
        <Button
          variant="inline-link"
          disabled={!canEdit}
          onClick={() => removeMember(m.assetId)}
          data-testid={`remove-member-${m.name}`}
        >
          Remove
        </Button>
      ),
    },
  ];

  return (
    <Table
      variant="full-page"
      stickyHeader
      items={members}
      columnDefinitions={columns}
      loading={loading}
      loadingText="Loading members"
      empty={
        <Box textAlign="center" padding="l">
          <StatusIndicator type="info">
            No assets in this group yet.
          </StatusIndicator>
        </Box>
      }
      filter={
        canEdit ? (
          <SpaceBetween direction="horizontal" size="xs">
            <Box variant="span" color="text-status-inactive">
              Add assets:
            </Box>
            <div
              style={{ minWidth: 320 }}
              data-testid="add-member-multiselect"
            >
              <Multiselect
                selectedOptions={selected}
                onChange={({ detail }) =>
                  setSelected(detail.selectedOptions ?? [])
                }
                options={options}
                placeholder="Select assets to add…"
                empty="All assets already in this group"
              />
            </div>
            <Button
              variant="primary"
              loading={adding}
              disabled={selected.length === 0}
              onClick={addSelected}
              data-testid="add-member-button"
            >
              Add
            </Button>
          </SpaceBetween>
        ) : null
      }
      header={
        <Header
          counter={`(${members.length})`}
          actions={<Button onClick={onBack}>Back to groups</Button>}
          description={
            error ? <Box color="text-status-error">{error}</Box> : undefined
          }
        >
          {`Members of ${groupName}`}
        </Header>
      }
    />
  );
}
