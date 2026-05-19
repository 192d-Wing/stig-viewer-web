import { useCallback, useEffect, useMemo, useState } from "react";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Box from "@cloudscape-design/components/box";
import Badge from "@cloudscape-design/components/badge";
import Alert from "@cloudscape-design/components/alert";
import Select from "@cloudscape-design/components/select";
import SpaceBetween from "@cloudscape-design/components/space-between";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { apiGet } from "../utils/api.js";

const STATUS_COLORS = {
  open: "red",
  not_a_finding: "green",
  not_applicable: "blue",
  not_reviewed: "grey",
};

const STATUS_LABELS = {
  open: "Open",
  not_a_finding: "Not a finding",
  not_applicable: "Not applicable",
  not_reviewed: "Not reviewed",
};

function StatusBadge({ value }) {
  return (
    <Badge color={STATUS_COLORS[value] ?? "grey"}>
      {STATUS_LABELS[value] ?? value}
    </Badge>
  );
}

export default function AssetCompare({ onBack }) {
  const [assets, setAssets] = useState([]);
  const [leftId, setLeftId] = useState(null);
  const [rightId, setRightId] = useState(null);
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    apiGet("/api/assets")
      .then((rows) => setAssets(rows))
      .catch(() => setAssets([]));
  }, []);

  const refresh = useCallback(async () => {
    if (!leftId || !rightId || leftId === rightId) {
      setDiff(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const d = await apiGet(`/api/assets/${leftId}/diff/${rightId}`);
      setDiff(d);
    } catch (err) {
      setError(err.message);
      setDiff(null);
    } finally {
      setLoading(false);
    }
  }, [leftId, rightId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const options = useMemo(
    () => assets.map((a) => ({ value: a.id, label: a.name })),
    [assets],
  );

  const selectedLeft = options.find((o) => o.value === leftId) ?? null;
  const selectedRight = options.find((o) => o.value === rightId) ?? null;

  const totalDiverged = diff
    ? diff.shared.reduce((n, s) => n + s.diverged.length, 0)
    : 0;

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
              description="Pick two systems to see which rules they handle differently in the STIGs they both have applied."
            >
              Compare systems
            </Header>
          }
        >
          <ColumnLayout columns={2}>
            <div>
              <Box variant="awsui-key-label">Left system</Box>
              <Select
                selectedOption={selectedLeft}
                onChange={({ detail }) => setLeftId(detail.selectedOption.value)}
                options={options}
                placeholder="Choose a system"
                filteringType="auto"
              />
            </div>
            <div>
              <Box variant="awsui-key-label">Right system</Box>
              <Select
                selectedOption={selectedRight}
                onChange={({ detail }) => setRightId(detail.selectedOption.value)}
                options={options}
                placeholder="Choose a system"
                filteringType="auto"
              />
            </div>
          </ColumnLayout>
        </Container>

        {leftId && rightId && leftId === rightId && (
          <Alert type="info">Pick two different systems to compare.</Alert>
        )}

        {error && <Alert type="error">{error}</Alert>}

        {loading && (
          <Box padding="xxl" textAlign="center">
            <StatusIndicator type="loading">Loading diff</StatusIndicator>
          </Box>
        )}

        {diff && !loading && (
          <Container
            header={
              <Header
                variant="h2"
                description={
                  diff.shared.length === 0
                    ? "These systems don't share any applied STIGs."
                    : `${diff.shared.length} shared STIG${diff.shared.length === 1 ? "" : "s"} · ${totalDiverged} diverged rule${totalDiverged === 1 ? "" : "s"}`
                }
              >
                {diff.left.name} vs {diff.right.name}
              </Header>
            }
          >
            <SpaceBetween direction="vertical" size="m">
              {diff.shared.map((s) => (
                <div key={s.stigId}>
                  <Box variant="awsui-key-label">{s.stigTitle}</Box>
                  {s.diverged.length === 0 ? (
                    <Box
                      padding={{ top: "xs" }}
                      color="text-status-success"
                    >
                      All shared rules agree.
                    </Box>
                  ) : (
                    <Box padding={{ top: "xs" }}>
                      <SpaceBetween direction="vertical" size="xxs">
                        {s.diverged.map((r) => (
                          <Box key={r.ruleId}>
                            <strong>{r.ruleId}</strong>{" "}
                            <StatusBadge value={r.leftStatus} /> →{" "}
                            <StatusBadge value={r.rightStatus} />
                          </Box>
                        ))}
                      </SpaceBetween>
                    </Box>
                  )}
                </div>
              ))}
              {diff.shared.length === 0 && (
                <Box color="text-body-secondary">
                  No shared STIGs to compare. Apply the same STIG to both
                  systems to see a diff.
                </Box>
              )}
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>
    </Box>
  );
}
