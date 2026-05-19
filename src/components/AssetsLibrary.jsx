import { useCallback, useContext, useEffect, useMemo, useState } from "react";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import Select from "@cloudscape-design/components/select";
import Textarea from "@cloudscape-design/components/textarea";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import TokenGroup from "@cloudscape-design/components/token-group";
import { apiGet, apiJson, apiFetch } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";
import AssetDetail from "./AssetDetail.jsx";
import ChecklistView from "./ChecklistView.jsx";
import AssetCompare from "./AssetCompare.jsx";

const CLASSIFICATIONS = [
  { label: "Unclassified", value: "unclassified" },
  { label: "CUI", value: "cui" },
  { label: "Secret", value: "secret" },
  { label: "Top Secret", value: "top-secret" },
];

const CLASSIFICATION_BADGE = {
  unclassified: "green",
  cui: "blue",
  secret: "red",
  "top-secret": "red",
};

const EMPTY_FORM = {
  name: "",
  hostname: "",
  description: "",
  classification: "unclassified",
  tags: [],
};

function classificationLabel(value) {
  return CLASSIFICATIONS.find((c) => c.value === value)?.label ?? value;
}

export default function AssetsLibrary() {
  const currentUser = useContext(AuthContext);

  // view = "list" | {type: "asset", id} | {type: "checklist", id, assetId}
  const [view, setView] = useState("list");

  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [modal, setModal] = useState(null); // { mode: "create" | "edit", asset? }
  const [form, setForm] = useState(EMPTY_FORM);
  const [tagDraft, setTagDraft] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);

  const [deleteTarget, setDeleteTarget] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await apiGet("/api/assets");
      setAssets(rows);
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
    setTagDraft("");
    setSubmitError(null);
    setModal({ mode: "create" });
  }, []);

  const openEdit = useCallback((asset) => {
    setForm({
      name: asset.name,
      hostname: asset.hostname,
      description: asset.description ?? "",
      classification: asset.classification,
      tags: asset.tags ?? [],
    });
    setTagDraft("");
    setSubmitError(null);
    setModal({ mode: "edit", asset });
  }, []);

  const closeModal = useCallback(() => {
    setModal(null);
    setTagDraft("");
    setSubmitError(null);
  }, []);

  const commitTagDraft = useCallback(() => {
    const t = tagDraft.trim();
    if (!t) return;
    setForm((f) =>
      f.tags.includes(t) ? f : { ...f, tags: [...f.tags, t] },
    );
    setTagDraft("");
  }, [tagDraft]);

  const removeTag = useCallback((idx) => {
    setForm((f) => ({
      ...f,
      tags: f.tags.filter((_, i) => i !== idx),
    }));
  }, []);

  const submit = useCallback(async () => {
    if (!form.name.trim()) {
      setSubmitError("Name is required.");
      return;
    }
    // Capture any tag the user typed but didn't press Enter on.
    const pending = tagDraft.trim();
    const body =
      pending && !form.tags.includes(pending)
        ? { ...form, tags: [...form.tags, pending] }
        : form;
    setSubmitting(true);
    setSubmitError(null);
    try {
      if (modal.mode === "create") {
        await apiJson("/api/assets", "POST", body);
      } else {
        await apiJson(`/api/assets/${modal.asset.id}`, "PUT", body);
      }
      setModal(null);
      setTagDraft("");
      await refresh();
    } catch (err) {
      setSubmitError(err.message);
    } finally {
      setSubmitting(false);
    }
  }, [form, modal, refresh, tagDraft]);

  const confirmDelete = useCallback(async () => {
    if (!deleteTarget) return;
    try {
      const res = await apiFetch(`/api/assets/${deleteTarget.id}`, {
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
        cell: (a) => (
          <Button
            variant="inline-link"
            onClick={() => setView({ type: "asset", id: a.id })}
          >
            {a.name}
          </Button>
        ),
        sortingField: "name",
      },
      {
        id: "hostname",
        header: "Hostname",
        cell: (a) => a.hostname || "—",
      },
      {
        id: "classification",
        header: "Classification",
        cell: (a) => (
          <Badge color={CLASSIFICATION_BADGE[a.classification] ?? "grey"}>
            {classificationLabel(a.classification)}
          </Badge>
        ),
      },
      {
        id: "tags",
        header: "Tags",
        cell: (a) =>
          a.tags && a.tags.length > 0 ? (
            <SpaceBetween direction="horizontal" size="xxs">
              {a.tags.map((t) => (
                <Badge key={t} color="grey">
                  {t}
                </Badge>
              ))}
            </SpaceBetween>
          ) : (
            "—"
          ),
      },
      {
        id: "owner",
        header: "Owner",
        cell: (a) => a.ownerName,
      },
      {
        id: "updated",
        header: "Updated",
        cell: (a) => new Date(a.updatedAt).toLocaleString(),
      },
      {
        id: "actions",
        header: "",
        cell: (a) => {
          const isOwner = currentUser?.id === a.ownerId;
          return (
            <SpaceBetween direction="horizontal" size="xs">
              <Button
                variant="inline-link"
                disabled={!isOwner}
                onClick={() => openEdit(a)}
              >
                Edit
              </Button>
              <Button
                variant="inline-link"
                disabled={!isOwner}
                onClick={() => setDeleteTarget(a)}
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

  if (view?.type === "asset") {
    return (
      <AssetDetail
        assetId={view.id}
        onBack={() => setView("list")}
        onOpenChecklist={(cid) =>
          setView({ type: "checklist", id: cid, assetId: view.id })
        }
      />
    );
  }

  if (view?.type === "checklist") {
    return (
      <ChecklistView
        checklistId={view.id}
        onBack={() => setView({ type: "asset", id: view.assetId })}
      />
    );
  }

  if (view === "compare") {
    return <AssetCompare onBack={() => setView("list")} />;
  }

  return (
    <>
      <Table
        variant="full-page"
        stickyHeader
        items={assets}
        columnDefinitions={columns}
        loading={loading}
        loadingText="Loading systems"
        empty={
          <Box textAlign="center" padding="l">
            <SpaceBetween direction="vertical" size="m">
              <StatusIndicator type="info">No systems yet</StatusIndicator>
              <Button variant="primary" onClick={openCreate}>
                Add your first system
              </Button>
            </SpaceBetween>
          </Box>
        }
        header={
          <Header
            counter={`(${assets.length})`}
            actions={
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  onClick={() => setView("compare")}
                  disabled={assets.length < 2}
                >
                  Compare
                </Button>
                <Button variant="primary" onClick={openCreate}>
                  Add system
                </Button>
              </SpaceBetween>
            }
          >
            Systems
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
        header={modal?.mode === "edit" ? "Edit system" : "Add system"}
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={closeModal}>
                Cancel
              </Button>
              <Button variant="primary" loading={submitting} onClick={submit}>
                {modal?.mode === "edit" ? "Save" : "Create"}
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="Name" description="Friendly identifier, e.g. web-prod-01">
            <Input
              value={form.name}
              onChange={({ detail }) =>
                setForm((f) => ({ ...f, name: detail.value }))
              }
              autoFocus
            />
          </FormField>
          <FormField label="Hostname" description="DNS name or IP">
            <Input
              value={form.hostname}
              onChange={({ detail }) =>
                setForm((f) => ({ ...f, hostname: detail.value }))
              }
            />
          </FormField>
          <FormField label="Description">
            <Textarea
              value={form.description}
              onChange={({ detail }) =>
                setForm((f) => ({ ...f, description: detail.value }))
              }
              rows={3}
            />
          </FormField>
          <FormField label="Classification">
            <Select
              selectedOption={
                CLASSIFICATIONS.find((c) => c.value === form.classification) ??
                CLASSIFICATIONS[0]
              }
              onChange={({ detail }) =>
                setForm((f) => ({
                  ...f,
                  classification: detail.selectedOption.value,
                }))
              }
              options={CLASSIFICATIONS}
            />
          </FormField>
          <FormField
            label="Tags"
            description="Press Enter to add. Use tags to group systems (e.g. production, pii)."
          >
            <SpaceBetween direction="vertical" size="xs">
              <Input
                value={tagDraft}
                onChange={({ detail }) => setTagDraft(detail.value)}
                onKeyDown={(e) => {
                  if (e.detail.key === "Enter") {
                    e.preventDefault();
                    commitTagDraft();
                  }
                }}
                placeholder="Add tag…"
              />
              {form.tags.length > 0 && (
                <TokenGroup
                  items={form.tags.map((t) => ({ label: t, value: t }))}
                  onDismiss={({ detail }) => removeTag(detail.itemIndex)}
                />
              )}
            </SpaceBetween>
          </FormField>
          {submitError && <Alert type="error">{submitError}</Alert>}
        </SpaceBetween>
      </Modal>

      <Modal
        visible={deleteTarget !== null}
        onDismiss={() => setDeleteTarget(null)}
        header="Delete system?"
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
          {`Deleting "${deleteTarget?.name ?? ""}" cannot be undone.`}
        </Alert>
      </Modal>
    </>
  );
}
