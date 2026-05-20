import { useCallback, useEffect, useMemo, useState } from "react";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Modal from "@cloudscape-design/components/modal";
import Box from "@cloudscape-design/components/box";
import Badge from "@cloudscape-design/components/badge";
import Select from "@cloudscape-design/components/select";
import FormField from "@cloudscape-design/components/form-field";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Alert from "@cloudscape-design/components/alert";
import Container from "@cloudscape-design/components/container";
import { apiGet, apiJson } from "../utils/api.js";

const ROLE_OPTIONS = [
  { label: "Author", value: "author" },
  { label: "Reviewer", value: "reviewer" },
  { label: "Admin", value: "admin" },
];

const ROLE_BADGE = {
  author: "blue",
  reviewer: "green",
  admin: "red",
};

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

export default function AdminConsole() {
  const [users, setUsers] = useState([]);
  const [assets, setAssets] = useState([]);
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

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [u, a] = await Promise.all([
        apiGet("/api/admin/users"),
        apiGet("/api/assets"),
      ]);
      setUsers(u);
      setAssets(a);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

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

  return (
    <SpaceBetween direction="vertical" size="l">
      {error && <Alert type="error">{error}</Alert>}

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
    </SpaceBetween>
  );
}
