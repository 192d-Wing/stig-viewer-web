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
import LineChart from "@cloudscape-design/components/line-chart";
import Toggle from "@cloudscape-design/components/toggle";
import { apiGet, apiJson, apiFetch, BACKEND } from "../utils/api.js";
import { AuthContext } from "./AuthGate.jsx";

export default function AssetDetail({ assetId, onBack, onOpenChecklist }) {
  const currentUser = useContext(AuthContext);

  const [asset, setAsset] = useState(null);
  const [checklists, setChecklists] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [trend, setTrend] = useState(null);
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
      const [a, cls, cat, tr] = await Promise.all([
        apiGet(`/api/assets/${assetId}`),
        apiGet(`/api/assets/${assetId}/checklists`),
        // catalog is public — but apiGet sends creds anyway, no harm
        apiGet("/api/catalog"),
        apiGet(`/api/assets/${assetId}/trend?days=30`).catch(() => null),
      ]);
      setAsset(a);
      setChecklists(cls);
      setCatalog(cat);
      setTrend(tr);
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

  const [approvalToggleBusy, setApprovalToggleBusy] = useState(false);
  const toggleApprovalPolicy = useCallback(
    async (next) => {
      if (!asset) return;
      setApprovalToggleBusy(true);
      try {
        const updated = await apiJson(
          `/api/assets/${asset.id}/approval-policy`,
          "PATCH",
          { requiresApproval: next },
        );
        setAsset(updated);
      } catch (err) {
        setError(err.message);
      } finally {
        setApprovalToggleBusy(false);
      }
    },
    [asset],
  );

  const [reapplyTarget, setReapplyTarget] = useState(null);
  const [reapplying, setReapplying] = useState(false);
  const reapply = useCallback(async () => {
    if (!reapplyTarget) return;
    setReapplying(true);
    try {
      await apiJson(
        `/api/checklists/${reapplyTarget.id}/reapply`,
        "POST",
        {},
      );
      setReapplyTarget(null);
      await refresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setReapplying(false);
    }
  }, [reapplyTarget, refresh]);

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
            <Header
              variant="h1"
              description={asset.description || undefined}
              actions={
                <SpaceBetween direction="horizontal" size="xs">
                  <Button
                    iconName="download"
                    href={`${BACKEND}/api/assets/${asset.id}/report.pdf`}
                    target="_blank"
                    download
                  >
                    Download PDF report
                  </Button>
                  <Button
                    iconName="download"
                    href={`${BACKEND}/api/assets/${asset.id}/bundle.zip`}
                    target="_blank"
                    download
                    ariaLabel="Download bundle (includes CKL files and evidence attachments)"
                  >
                    Download bundle
                  </Button>
                </SpaceBetween>
              }
            >
              {asset.name}
            </Header>
          }
        >
          <ColumnLayout columns={4} variant="text-grid">
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
            <div>
              <Box variant="awsui-key-label">
                Require approval to close findings
              </Box>
              <Toggle
                checked={!!asset.requiresApproval}
                disabled={!isOwner || approvalToggleBusy}
                onChange={({ detail }) =>
                  toggleApprovalPolicy(detail.checked)
                }
                data-testid="approval-policy-toggle"
              >
                {asset.requiresApproval ? "Enabled" : "Disabled"}
              </Toggle>
            </div>
          </ColumnLayout>
        </Container>

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
              ariaLabel={`${asset.name} posture trend`}
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
              ariaLabel={`${asset.name} compliance trend`}
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

        <Table
          variant="container"
          items={checklists}
          columnDefinitions={[
            {
              id: "stig",
              header: "STIG",
              cell: (c) => {
                const meta = catalog.find((s) => s.id === c.stigId);
                const outdated =
                  c.appliedVersion &&
                  meta &&
                  (meta.version !== c.appliedVersion ||
                    meta.releaseInfo !== c.appliedRelease);
                return (
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button
                      variant="inline-link"
                      onClick={() => onOpenChecklist(c.id)}
                    >
                      {meta?.title || c.stigId}
                    </Button>
                    {outdated && (
                      <>
                        <Badge color="red">Out of date</Badge>
                        <Button
                          variant="inline-link"
                          disabled={!isOwner}
                          onClick={() =>
                            setReapplyTarget({
                              id: c.id,
                              title: meta?.title || c.stigId,
                              fromVersion: c.appliedVersion,
                              fromRelease: c.appliedRelease,
                              toVersion: meta?.version ?? "",
                              toRelease: meta?.releaseInfo ?? "",
                            })
                          }
                        >
                          Re-apply
                        </Button>
                      </>
                    )}
                  </SpaceBetween>
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

      <Modal
        visible={reapplyTarget !== null}
        onDismiss={() => setReapplyTarget(null)}
        header="Re-apply STIG"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setReapplyTarget(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={reapplying}
                onClick={reapply}
              >
                Re-apply
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        {reapplyTarget && (
          <SpaceBetween direction="vertical" size="m">
            <Box>
              <strong>{reapplyTarget.title}</strong>
              <Box variant="p" color="text-body-secondary">
                {`v${reapplyTarget.fromVersion} (${reapplyTarget.fromRelease}) → v${reapplyTarget.toVersion} (${reapplyTarget.toRelease})`}
              </Box>
            </Box>
            <Alert type="info">
              Existing rule statuses are preserved where rule IDs still exist
              in the new revision. Overrides for rules that no longer exist
              will be dropped.
            </Alert>
          </SpaceBetween>
        )}
      </Modal>
    </Box>
  );
}
