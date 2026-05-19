import { useCallback, useContext, useEffect, useState } from "react";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Table from "@cloudscape-design/components/table";
import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Select from "@cloudscape-design/components/select";
import Alert from "@cloudscape-design/components/alert";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { apiGet, apiJson, apiFetch } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";

export default function AssetDetail({ assetId, onBack, onOpenChecklist }) {
  const currentUser = useContext(AuthContext);

  const [asset, setAsset] = useState(null);
  const [checklists, setChecklists] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [applyOpen, setApplyOpen] = useState(false);
  const [selectedStig, setSelectedStig] = useState(null);
  const [applyError, setApplyError] = useState(null);
  const [applying, setApplying] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [a, cls, cat] = await Promise.all([
        apiGet(`/api/assets/${assetId}`),
        apiGet(`/api/assets/${assetId}/checklists`),
        // catalog is public — but apiGet sends creds anyway, no harm
        apiGet("/api/catalog"),
      ]);
      setAsset(a);
      setChecklists(cls);
      setCatalog(cat);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const isOwner = asset && currentUser?.id === asset.ownerId;

  const appliedStigIds = new Set(checklists.map((c) => c.stigId));
  const availableStigs = catalog.filter((s) => !appliedStigIds.has(s.id));

  const apply = useCallback(async () => {
    if (!selectedStig) return;
    setApplying(true);
    setApplyError(null);
    try {
      await apiJson(`/api/assets/${assetId}/checklists`, "POST", {
        stigId: selectedStig.value,
      });
      setApplyOpen(false);
      setSelectedStig(null);
      await refresh();
    } catch (err) {
      setApplyError(err.message);
    } finally {
      setApplying(false);
    }
  }, [assetId, selectedStig, refresh]);

  const removeChecklist = useCallback(
    async (cid) => {
      const res = await apiFetch(`/api/checklists/${cid}`, { method: "DELETE" });
      if (!res.ok && res.status !== 204) {
        setError(`Delete failed: ${res.status}`);
        return;
      }
      await refresh();
    },
    [refresh],
  );

  if (loading) {
    return (
      <Box padding="xxl" textAlign="center">
        <StatusIndicator type="loading">Loading system</StatusIndicator>
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
          <Button onClick={onBack}>Back to systems</Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box padding="m">
      <SpaceBetween direction="vertical" size="l">
        <Button iconName="arrow-left" onClick={onBack}>
          Back to systems
        </Button>

        <Container
          header={
            <Header variant="h1" description={asset.description || undefined}>
              {asset.name}
            </Header>
          }
        >
          <ColumnLayout columns={3} variant="text-grid">
            <div>
              <Box variant="awsui-key-label">Hostname</Box>
              <div>{asset.hostname || "—"}</div>
            </div>
            <div>
              <Box variant="awsui-key-label">Classification</Box>
              <Badge>{asset.classification}</Badge>
            </div>
            <div>
              <Box variant="awsui-key-label">Owner</Box>
              <div>{isOwner ? "You" : asset.ownerId}</div>
            </div>
          </ColumnLayout>
        </Container>

        <Table
          variant="container"
          items={checklists}
          columnDefinitions={[
            {
              id: "stig",
              header: "STIG",
              cell: (c) => {
                const meta = catalog.find((s) => s.id === c.stigId);
                return (
                  <Button
                    variant="inline-link"
                    onClick={() => onOpenChecklist(c.id)}
                  >
                    {meta?.title || c.stigId}
                  </Button>
                );
              },
            },
            {
              id: "status",
              header: "Status",
              cell: (c) => <Badge>{c.status}</Badge>,
            },
            {
              id: "updated",
              header: "Last activity",
              cell: (c) => new Date(c.updatedAt).toLocaleString(),
            },
            {
              id: "actions",
              header: "",
              cell: (c) => (
                <Button
                  variant="inline-link"
                  disabled={!isOwner}
                  onClick={() => removeChecklist(c.id)}
                >
                  Remove
                </Button>
              ),
            },
          ]}
          empty={
            <Box textAlign="center" padding="l">
              <Box variant="p" color="text-body-secondary">
                No STIGs applied to this system yet.
              </Box>
            </Box>
          }
          header={
            <Header
              counter={`(${checklists.length})`}
              actions={
                <Button
                  variant="primary"
                  disabled={!isOwner || availableStigs.length === 0}
                  onClick={() => {
                    setSelectedStig(null);
                    setApplyError(null);
                    setApplyOpen(true);
                  }}
                >
                  Apply STIG
                </Button>
              }
            >
              Applied STIGs
            </Header>
          }
        />
      </SpaceBetween>

      <Modal
        visible={applyOpen}
        onDismiss={() => setApplyOpen(false)}
        header="Apply STIG to this system"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setApplyOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={applying}
                disabled={!selectedStig}
                onClick={apply}
              >
                Apply
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <SpaceBetween direction="vertical" size="m">
          <FormField label="STIG">
            <Select
              selectedOption={selectedStig}
              onChange={({ detail }) => setSelectedStig(detail.selectedOption)}
              options={availableStigs.map((s) => ({
                label: s.title,
                value: s.id,
                description: `${s.category} · v${s.version}`,
              }))}
              placeholder="Choose a STIG"
              filteringType="auto"
              empty="All STIGs have already been applied."
            />
          </FormField>
          {applyError && <Alert type="error">{applyError}</Alert>}
        </SpaceBetween>
      </Modal>
    </Box>
  );
}
