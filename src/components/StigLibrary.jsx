import { useState, useEffect, useCallback, useMemo } from "react";
import { useUrlState } from "../hooks/useUrlState.js";
import Table from "@cloudscape-design/components/table";
import Header from "@cloudscape-design/components/header";
import Button from "@cloudscape-design/components/button";
import Toggle from "@cloudscape-design/components/toggle";
import Badge from "@cloudscape-design/components/badge";
import Alert from "@cloudscape-design/components/alert";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import Select from "@cloudscape-design/components/select";
import FileUpload from "@cloudscape-design/components/file-upload";
import TextFilter from "@cloudscape-design/components/text-filter";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Box from "@cloudscape-design/components/box";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import Pagination from "@cloudscape-design/components/pagination";
import CollectionPreferences from "@cloudscape-design/components/collection-preferences";
import Link from "@cloudscape-design/components/link";
import Container from "@cloudscape-design/components/container";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Modal from "@cloudscape-design/components/modal";
import { BACKEND, apiJson, apiFetch } from "../utils/api.js";
const CATEGORIES = ["Windows", "Linux", "Browser", "Network"];

/** Trim long body fields for the diff table cells so a 4 KB
 * description doesn't blow up the row height. The full text is still
 * available in the API response if a future "expand" UI wants it. */
function truncate(s, max = 80) {
  if (!s) return "—";
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

/** One section of the diff modal — Added / Removed / Changed each get
 * a labeled mini-table that renders an em-dash when empty. */
function DiffSection({ title, testId, items, columns, colorBadge: _color }) {
  return (
    <Box data-testid={testId}>
      <Header variant="h3">{title}</Header>
      {items.length === 0 ? (
        <Box padding={{ vertical: "s" }}>—</Box>
      ) : (
        <Table
          variant="embedded"
          items={items}
          columnDefinitions={columns}
          ariaLabels={{
            tableLabel: title,
          }}
        />
      )}
    </Box>
  );
}

const CATEGORY_OPTIONS = CATEGORIES.map((c) => ({ label: c, value: c }));

const CATEGORY_BADGE_COLOR = {
  Windows: "blue",
  Linux: "green",
  Browser: "grey",
  Network: "red",
};

/** Extract the numeric release from releaseInfo, e.g. "Release: 4 Benchmark …" → 4 */
function parseRelease(releaseInfo) {
  const m = releaseInfo?.match(/Release:\s*(\d+)/i);
  return m ? Number(m[1]) : 0;
}

/**
 * Mark entries that are superseded by a newer version of the same STIG.
 * Two entries are "same STIG" when their titles match exactly.
 * The entry with the higher version (then higher release) wins.
 * Returns a Set of superseded entry IDs.
 */
function findSuperseded(catalog) {
  const byTitle = new Map();
  for (const entry of catalog) {
    const key = entry.title;
    if (!byTitle.has(key)) byTitle.set(key, []);
    byTitle.get(key).push(entry);
  }

  const superseded = new Set();
  for (const entries of byTitle.values()) {
    if (entries.length < 2) continue;
    const sorted = [...entries].sort((a, b) => {
      const vDiff = Number(b.version || 0) - Number(a.version || 0);
      if (vDiff !== 0) return vDiff;
      return parseRelease(b.releaseInfo) - parseRelease(a.releaseInfo);
    });
    for (let i = 1; i < sorted.length; i++) {
      superseded.add(sorted[i].id);
    }
  }
  return superseded;
}

export default function StigLibrary({ onLoad, onUploadTab, onStartDraft }) {
  const [activeTab, setActiveTab] = useState("library");
  const [catalog, setCatalog] = useState([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState(null);
  const [loadingId, setLoadingId] = useState(null);
  const [draftingId, setDraftingId] = useState(null);
  // Filter + sort + columns + pagination all live in the URL so a library
  // view is bookmarkable and shareable.
  const [urlState, setUrlState] = useUrlState({
    cat: "",
    q: "",
    super: false,
    sort: "title",
    dir: "asc",
    page: 1,
    size: 25,
    cols: ["title", "version", "release", "category", "rules"],
  });
  const categoryFilter = urlState.cat || null;
  const searchText = urlState.q;
  const showSuperseded = urlState.super;
  const sortCol = urlState.sort;
  const sortDir = urlState.dir;
  const currentPage = urlState.page;
  const preferences = useMemo(
    () => ({
      pageSize: urlState.size,
      stripedRows: true,
      visibleContent: urlState.cols,
    }),
    [urlState.size, urlState.cols],
  );

  const setCategoryFilter = useCallback(
    (v) => setUrlState({ cat: v ?? "" }),
    [setUrlState],
  );
  const setSearchText = useCallback(
    (v) => setUrlState({ q: v }),
    [setUrlState],
  );
  const setShowSuperseded = useCallback(
    (v) => setUrlState({ super: !!v }),
    [setUrlState],
  );
  const setSortCol = useCallback((v) => setUrlState({ sort: v }), [setUrlState]);
  const setSortDir = useCallback((v) => setUrlState({ dir: v }), [setUrlState]);
  const setCurrentPage = useCallback(
    (v) => setUrlState({ page: v }),
    [setUrlState],
  );
  const setPreferences = useCallback(
    (p) => setUrlState({ size: p.pageSize, cols: p.visibleContent }),
    [setUrlState],
  );

  // Add-to-library form state (single STIG)
  const [addFiles, setAddFiles] = useState([]);
  const [addId, setAddId] = useState("");
  const [addCategory, setAddCategory] = useState("Windows");
  const [addStatus, setAddStatus] = useState("idle");
  const [addResult, setAddResult] = useState(null);
  // Lint state for the staged JSON file. `lintReport` is null when nothing
  // has been linted yet (e.g. file is a .zip, or no file picked).
  const [lintReport, setLintReport] = useState(null);
  const [lintStatus, setLintStatus] = useState("idle");
  const [lintExpanded, setLintExpanded] = useState(false);

  // Library bundle import state
  const [libFiles, setLibFiles] = useState([]);
  const [libStatus, setLibStatus] = useState("idle");
  const [libResult, setLibResult] = useState(null);

  // Catalog version diff modal — opened from the per-row "Diff vs
  // previous" button. `diffStigId` is the STIG being diffed; status is
  // "loading" while the GET is in flight, "ready" once we have data,
  // "empty" when the backend says there's no archived version yet,
  // "error" on transport / 500 failures.
  const [diffStigId, setDiffStigId] = useState(null);
  const [diffStatus, setDiffStatus] = useState("idle");
  const [diffData, setDiffData] = useState(null);
  const [diffError, setDiffError] = useState(null);

  const openDiff = useCallback(async (stigId) => {
    setDiffStigId(stigId);
    setDiffStatus("loading");
    setDiffData(null);
    setDiffError(null);
    try {
      // Use apiFetch so the X-User-Id test-bypass header is sent in E2E,
      // not just the session cookie that real OIDC sessions carry.
      const r = await apiFetch(
        `/api/stigs/${encodeURIComponent(stigId)}/diff`,
      );
      if (r.status === 404) {
        setDiffStatus("empty");
        return;
      }
      if (!r.ok) throw new Error(`Backend returned ${r.status}`);
      const data = await r.json();
      setDiffData(data);
      setDiffStatus("ready");
    } catch (err) {
      setDiffError(err.message);
      setDiffStatus("error");
    }
  }, []);

  const closeDiff = useCallback(() => {
    setDiffStigId(null);
    setDiffStatus("idle");
    setDiffData(null);
    setDiffError(null);
  }, []);

  const fetchCatalog = useCallback(() => {
    setCatalogLoading(true);
    setCatalogError(null);
    let cancelled = false;
    fetch(`${BACKEND}/api/catalog`)
      .then((r) => {
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        return r.json();
      })
      .then((data) => {
        if (!cancelled) setCatalog(data);
      })
      .catch((err) => {
        if (!cancelled) setCatalogError(err.message);
      })
      .finally(() => {
        if (!cancelled) setCatalogLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => fetchCatalog(), [fetchCatalog]);

  const supersededIds = useMemo(() => findSuperseded(catalog), [catalog]);

  const displayList = useMemo(() => {
    let list = catalog;
    if (categoryFilter)
      list = list.filter((e) => e.category === categoryFilter);
    if (!showSuperseded) list = list.filter((e) => !supersededIds.has(e.id));
    if (searchText) {
      const term = searchText.toLowerCase();
      list = list.filter((e) => e.title.toLowerCase().includes(term));
    }
    return [...list].sort((a, b) => {
      const mul = sortDir === "asc" ? 1 : -1;
      let av, bv;
      switch (sortCol) {
        case "category":
          return mul * a.category.localeCompare(b.category);
        case "title":
          return mul * a.title.localeCompare(b.title);
        case "version":
          av = Number(a.version || 0);
          bv = Number(b.version || 0);
          if (av !== bv) return mul * (av - bv);
          return (
            mul * (parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo))
          );
        case "release":
          return (
            mul * (parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo))
          );
        case "rules":
          return mul * (a.ruleCount - b.ruleCount);
        default:
          return 0;
      }
    });
  }, [
    catalog,
    categoryFilter,
    searchText,
    showSuperseded,
    supersededIds,
    sortCol,
    sortDir,
  ]);

  const pageCount = Math.max(
    1,
    Math.ceil(displayList.length / preferences.pageSize),
  );
  const paginatedItems = displayList.slice(
    (currentPage - 1) * preferences.pageSize,
    currentPage * preferences.pageSize,
  );

  const handleLoad = useCallback(
    async (id) => {
      setLoadingId(id);
      try {
        const r = await fetch(`${BACKEND}/api/stigs/${encodeURIComponent(id)}`);
        if (!r.ok) throw new Error(`Backend returned ${r.status}`);
        const stig = await r.json();
        onLoad(stig);
      } catch (err) {
        setCatalogError(`Failed to load STIG: ${err.message}`);
      } finally {
        setLoadingId(null);
      }
    },
    [onLoad],
  );

  const handleStartDraft = useCallback(
    async (id) => {
      if (!onStartDraft) return;
      setDraftingId(id);
      try {
        const result = await apiJson(
          `/api/drafts/from-stig/${encodeURIComponent(id)}`,
          "POST",
        );
        onStartDraft(result.id);
      } catch (err) {
        setCatalogError(`Failed to create draft: ${err.message}`);
      } finally {
        setDraftingId(null);
      }
    },
    [onStartDraft],
  );

  // Lint a staged JSON file via /api/stigs/lint. Only runs for *.json — ZIP
  // uploads still go through the XCCDF parser server-side. Sets
  // `lintReport` so the UI can render the issue list and decide whether to
  // disable the upload button.
  const runLint = useCallback(async (file) => {
    if (!file) {
      setLintReport(null);
      setLintStatus("idle");
      return;
    }
    const isJson =
      file.name.toLowerCase().endsWith(".json") ||
      file.type === "application/json";
    if (!isJson) {
      setLintReport(null);
      setLintStatus("idle");
      return;
    }
    setLintStatus("loading");
    setLintReport(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const r = await fetch(`${BACKEND}/api/stigs/lint`, {
        method: "POST",
        body,
        credentials: "include",
      });
      if (!r.ok) throw new Error(`Lint failed: ${r.status}`);
      const report = await r.json();
      setLintReport(report);
      setLintStatus("done");
    } catch (err) {
      setLintReport({
        rulesCount: 0,
        errors: [{ severity: "error", path: "", message: err.message }],
        warnings: [],
      });
      setLintStatus("done");
    }
  }, []);

  const handleAddSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      if (addFiles.length === 0 || !addId.trim()) return;
      setAddStatus("loading");
      setAddResult(null);
      try {
        const body = new FormData();
        body.append("file", addFiles[0]);
        body.append("id", addId.trim());
        body.append("category", addCategory);
        const r = await fetch(`${BACKEND}/api/upload`, {
          method: "POST",
          body,
        });
        const json = await r.json();
        if (!r.ok)
          throw new Error(json?.message ?? `Server returned ${r.status}`);
        setAddResult(json);
        setAddStatus("success");
        setAddFiles([]);
        setAddId("");
        setLintReport(null);
        setLintStatus("idle");
        setLintExpanded(false);
        fetchCatalog();
      } catch (err) {
        setAddResult({ error: err.message });
        setAddStatus("error");
      }
    },
    [addFiles, addId, addCategory, fetchCatalog],
  );

  const handleLibSubmit = useCallback(
    async (e) => {
      e.preventDefault();
      if (libFiles.length === 0) return;
      setLibStatus("loading");
      setLibResult(null);
      try {
        const body = new FormData();
        body.append("file", libFiles[0]);
        const r = await fetch(`${BACKEND}/api/upload/library`, {
          method: "POST",
          body,
        });
        const json = await r.json();
        if (!r.ok)
          throw new Error(json?.message ?? `Server returned ${r.status}`);
        setLibResult(json);
        setLibStatus("success");
        setLibFiles([]);
        fetchCatalog();
      } catch (err) {
        setLibResult({ error: err.message });
        setLibStatus("error");
      }
    },
    [libFiles, fetchCatalog],
  );

  // Column definitions for Cloudscape Table
  const columnDefinitions = [
    {
      id: "title",
      header: "Title",
      cell: (item) => {
        const dimmed = supersededIds.has(item.id);
        return (
          <span style={dimmed ? { opacity: 0.5 } : undefined}>
            <Link
              onFollow={(e) => {
                e.preventDefault();
                handleLoad(item.id);
              }}
            >
              {loadingId === item.id ? "Loading…" : item.title}
            </Link>
            {dimmed && (
              <>
                {" "}
                <StatusIndicator type="warning">Superseded</StatusIndicator>
              </>
            )}
          </span>
        );
      },
      sortingComparator: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "version",
      header: "Version",
      cell: (item) => item.version || "—",
      sortingComparator: (a, b) => {
        const vDiff = Number(a.version || 0) - Number(b.version || 0);
        if (vDiff !== 0) return vDiff;
        return parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo);
      },
      width: 110,
    },
    {
      id: "release",
      header: "Release",
      cell: (item) => parseRelease(item.releaseInfo) || "—",
      sortingComparator: (a, b) =>
        parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo),
      width: 110,
    },
    {
      id: "category",
      header: "Category",
      cell: (item) => (
        <Badge color={CATEGORY_BADGE_COLOR[item.category] || "grey"}>
          {item.category}
        </Badge>
      ),
      sortingComparator: (a, b) => a.category.localeCompare(b.category),
      width: 130,
    },
    {
      id: "rules",
      header: "Rules",
      cell: (item) => item.ruleCount,
      sortingComparator: (a, b) => a.ruleCount - b.ruleCount,
      width: 110,
    },
    {
      id: "diff",
      header: "Diff",
      cell: (item) => (
        <Button
          variant="inline-link"
          loading={diffStigId === item.id && diffStatus === "loading"}
          onClick={(e) => {
            e.stopPropagation();
            openDiff(item.id);
          }}
          data-testid={`diff-button-${item.id}`}
        >
          Diff vs previous
        </Button>
      ),
      width: 160,
    },
    ...(onStartDraft
      ? [
          {
            id: "actions",
            header: "Actions",
            cell: (item) => (
              <Button
                variant="inline-link"
                loading={draftingId === item.id}
                onClick={(e) => {
                  e.stopPropagation();
                  handleStartDraft(item.id);
                }}
              >
                Start Draft
              </Button>
            ),
            width: 130,
          },
        ]
      : []),
  ];

  const visibleColumns = columnDefinitions.filter(
    (c) =>
      preferences.visibleContent.includes(c.id) ||
      c.id === "actions" ||
      c.id === "diff",
  );
  const sortingColumn = columnDefinitions.find((c) => c.id === sortCol);

  // Renders the diff modal. Identical in both library / form views so
  // it lives in a local helper. Cloudscape Modal mounts via a portal so
  // it doesn't disrupt the AppLayout `full-page` Table contract.
  const renderDiffModal = () => (
    <Modal
      visible={diffStigId != null}
      onDismiss={closeDiff}
      header={`Diff vs previous — ${diffStigId ?? ""}`}
      size="large"
      data-testid="catalog-diff-modal"
    >
      {diffStatus === "loading" && <Box>Loading diff…</Box>}
      {diffStatus === "empty" && (
        <Alert
          type="info"
          data-testid="catalog-diff-empty"
        >
          No previous version archived for this STIG yet.
        </Alert>
      )}
      {diffStatus === "error" && (
        <Alert type="error">Failed to load diff: {diffError}</Alert>
      )}
      {diffStatus === "ready" && diffData && (
        <SpaceBetween size="l">
          <Box>
            <strong>From:</strong> v{diffData.fromVersion} ·{" "}
            {diffData.fromReleaseInfo} → <strong>To:</strong>{" "}
            v{diffData.toVersion} · {diffData.toReleaseInfo}
          </Box>
          <DiffSection
            title={`Added (${diffData.added.length})`}
            testId="catalog-diff-added"
            items={diffData.added}
            columns={[
              { id: "id", header: "Rule", cell: (r) => r.id },
              { id: "title", header: "Title", cell: (r) => r.title },
              {
                id: "severity",
                header: "Severity",
                cell: (r) => r.severity,
              },
            ]}
            colorBadge="green"
          />
          <DiffSection
            title={`Removed (${diffData.removed.length})`}
            testId="catalog-diff-removed"
            items={diffData.removed}
            columns={[
              { id: "id", header: "Rule", cell: (r) => r.id },
              { id: "title", header: "Title", cell: (r) => r.title },
            ]}
            colorBadge="red"
          />
          <DiffSection
            title={`Changed (${diffData.changed.length})`}
            testId="catalog-diff-changed"
            items={diffData.changed}
            columns={[
              { id: "id", header: "Rule", cell: (r) => r.id },
              { id: "field", header: "Field", cell: (r) => r.field },
              {
                id: "from",
                header: "From",
                cell: (r) => truncate(r.from),
              },
              { id: "to", header: "To", cell: (r) => truncate(r.to) },
            ]}
            colorBadge="grey"
          />
        </SpaceBetween>
      )}
    </Modal>
  );

  if (activeTab === "library") {
    return (
      <>
      <Table
        variant="full-page"
        stickyHeader
        stripedRows={preferences.stripedRows}
        loading={catalogLoading}
        loadingText="Connecting to backend"
        resizableColumns
        items={paginatedItems}
        columnDefinitions={visibleColumns}
        sortingColumn={sortingColumn}
        sortingDescending={sortDir === "desc"}
        onSortingChange={({ detail }) => {
          setSortCol(detail.sortingColumn.id);
          setSortDir(detail.isDescending ? "desc" : "asc");
          setCurrentPage(1);
        }}
        pagination={
          <Pagination
            currentPageIndex={currentPage}
            pagesCount={pageCount}
            onChange={({ detail }) => setCurrentPage(detail.currentPageIndex)}
          />
        }
        preferences={
          <CollectionPreferences
            title="Preferences"
            confirmLabel="Confirm"
            cancelLabel="Cancel"
            preferences={preferences}
            onConfirm={({ detail }) => {
              setPreferences(detail);
              setCurrentPage(1);
            }}
            pageSizePreference={{
              title: "Page size",
              options: [
                { value: 10, label: "10 items" },
                { value: 25, label: "25 items" },
                { value: 50, label: "50 items" },
                { value: 100, label: "100 items" },
              ],
            }}
            stripedRowsPreference={{
              label: "Striped rows",
              description: "Select to add alternating shaded rows",
            }}
            visibleContentPreference={{
              title: "Visible columns",
              options: [
                {
                  label: "STIG properties",
                  options: [
                    { id: "title", label: "Title" },
                    { id: "version", label: "Version" },
                    { id: "release", label: "Release" },
                    { id: "category", label: "Category" },
                    { id: "rules", label: "Rules" },
                  ],
                },
              ],
            }}
          />
        }
        header={
          <Header
            variant="awsui-h1-sticky"
            counter={`(${displayList.length})`}
            actions={
              <SpaceBetween
                direction="horizontal"
                size="xs"
                alignItems="center"
              >
                {supersededIds.size > 0 && (
                  <Toggle
                    checked={showSuperseded}
                    onChange={({ detail }) => {
                      setShowSuperseded(detail.checked);
                      setCurrentPage(1);
                    }}
                  >
                    Show superseded ({supersededIds.size})
                  </Toggle>
                )}
                <Button onClick={() => setActiveTab("add")}>
                  Add to Library
                </Button>
                <Button onClick={() => setActiveTab("upload")}>
                  Open Local File
                </Button>
              </SpaceBetween>
            }
          >
            STIG Library
          </Header>
        }
        filter={
          <SpaceBetween direction="horizontal" size="m" alignItems="center">
            <TextFilter
              filteringText={searchText}
              onChange={({ detail }) => {
                setSearchText(detail.filteringText);
                setCurrentPage(1);
              }}
              filteringPlaceholder="Search by title"
              countText={`${displayList.length} matches`}
            />
            <SegmentedControl
              selectedId={categoryFilter || "all"}
              onChange={({ detail }) => {
                setCategoryFilter(
                  detail.selectedId === "all" ? null : detail.selectedId,
                );
                setCurrentPage(1);
              }}
              options={[
                { text: "All", id: "all" },
                ...CATEGORIES.map((c) => ({ text: c, id: c })),
              ]}
            />
          </SpaceBetween>
        }
        empty={
          <Box textAlign="center" padding={{ vertical: "l" }}>
            {catalog.length === 0 ? (
              <SpaceBetween size="xs">
                <b>No STIGs cached yet</b>
                <Box>
                  Use the{" "}
                  <Link onFollow={() => setActiveTab("add")}>
                    Add to Library
                  </Link>{" "}
                  tab to upload a STIG ZIP.
                </Box>
              </SpaceBetween>
            ) : (
              <b>No STIGs match the current filters.</b>
            )}
          </Box>
        }
      />
      {renderDiffModal()}
      </>
    );
  }

  // Add to Library / Open Local File views
  return (
    <div style={{ maxWidth: 960, margin: "0 auto", paddingTop: 24 }}>
      <SpaceBetween size="l">
        <Button
          variant="link"
          iconName="arrow-left"
          onClick={() => setActiveTab("library")}
        >
          Back to Library
        </Button>

        {catalogError && (
          <Alert
            type="error"
            dismissible
            onDismiss={() => setCatalogError(null)}
          >
            {catalogError}
          </Alert>
        )}

        {activeTab === "add" && (
          <SpaceBetween size="l">
            {addStatus === "success" && addResult && (
              <Alert
                type="success"
                dismissible
                onDismiss={() => { setAddStatus("idle"); setAddResult(null); }}
              >
                <strong>{addResult.title}</strong> added &mdash;{" "}
                {addResult.ruleCount} rules ({addResult.version}).{" "}
                <Link onFollow={() => setActiveTab("library")}>
                  View in Library
                </Link>
              </Alert>
            )}
            {addStatus === "error" && addResult && (
              <Alert
                type="error"
                dismissible
                onDismiss={() => { setAddStatus("idle"); setAddResult(null); }}
              >
                {addResult.error}
              </Alert>
            )}
            <Container
              header={
                <Header
                  variant="h2"
                  description={
                    <>
                      Download a STIG ZIP from{" "}
                      <Link
                        href="https://public.cyber.mil/stigs/downloads/"
                        external
                      >
                        public.cyber.mil
                      </Link>
                      , then upload it here.
                    </>
                  }
                >
                  Add Single STIG
                </Header>
              }
            >
              <form onSubmit={handleAddSubmit}>
                <SpaceBetween size="l">
                  <FileUpload
                    value={addFiles}
                    onChange={({ detail }) => {
                      setAddFiles(detail.value);
                      runLint(detail.value[0]);
                    }}
                    accept=".zip,.json"
                    showFileSize
                    showFileLastModified
                    i18nStrings={{
                      uploadButtonText: (multiple) => multiple ? "Choose files" : "Choose file",
                      dropzoneText: (multiple) => multiple ? "Drop files to upload" : "Drop file to upload",
                      removeFileAriaLabel: (e) => `Remove file ${e + 1}`,
                      limitShowFewer: "Show fewer files",
                      limitShowMore: "Show more files",
                      errorIconAriaLabel: "Error",
                    }}
                    data-testid="add-stig-file-input"
                  />
                  {lintStatus === "loading" && (
                    <Alert type="info" data-testid="stig-lint-loading">
                      Validating STIG JSON…
                    </Alert>
                  )}
                  {lintStatus === "done" && lintReport &&
                    lintReport.errors.length === 0 &&
                    lintReport.warnings.length === 0 && (
                      <Alert type="success" data-testid="stig-lint-clean">
                        {lintReport.rulesCount} rules · no issues
                      </Alert>
                    )}
                  {lintStatus === "done" && lintReport &&
                    (lintReport.errors.length > 0 ||
                      lintReport.warnings.length > 0) && (
                      <Alert
                        type={lintReport.errors.length > 0 ? "error" : "warning"}
                        data-testid={
                          lintReport.errors.length > 0
                            ? "stig-lint-errors"
                            : "stig-lint-warnings"
                        }
                        header={
                          <span>
                            {lintReport.errors.length} errors,{" "}
                            {lintReport.warnings.length} warnings
                          </span>
                        }
                        action={
                          <Button
                            variant="inline-link"
                            onClick={() => setLintExpanded((v) => !v)}
                          >
                            {lintExpanded ? "Hide details" : "Show details"}
                          </Button>
                        }
                      >
                        {lintExpanded && (
                          <Box data-testid="stig-lint-details">
                            <ul style={{ margin: 0, paddingLeft: 20 }}>
                              {[
                                ...lintReport.errors.map((i) => ({
                                  ...i,
                                  kind: "error",
                                })),
                                ...lintReport.warnings.map((i) => ({
                                  ...i,
                                  kind: "warning",
                                })),
                              ].map((issue, idx) => (
                                <li
                                  key={idx}
                                  data-testid={`stig-lint-issue-${idx}`}
                                >
                                  <strong>{issue.kind}</strong>{" "}
                                  <code>{issue.path || "/"}</code> ·{" "}
                                  {issue.message}
                                </li>
                              ))}
                            </ul>
                          </Box>
                        )}
                      </Alert>
                    )}
                  <ColumnLayout columns={2}>
                    <FormField label="ID" description="Slug, e.g. windows-11">
                      <Input
                        value={addId}
                        onChange={({ detail }) => setAddId(detail.value)}
                        placeholder="e.g. windows-11"
                      />
                    </FormField>
                    <FormField label="Category" description="Used for filtering">
                      <Select
                        selectedOption={
                          CATEGORY_OPTIONS.find((o) => o.value === addCategory) ||
                          CATEGORY_OPTIONS[0]
                        }
                        onChange={({ detail }) =>
                          setAddCategory(detail.selectedOption.value)
                        }
                        options={CATEGORY_OPTIONS}
                      />
                    </FormField>
                  </ColumnLayout>
                  <Button
                    variant="primary"
                    loading={addStatus === "loading"}
                    disabled={
                      addFiles.length === 0 ||
                      !addId.trim() ||
                      (lintReport && lintReport.errors.length > 0) ||
                      lintStatus === "loading"
                    }
                    formAction="submit"
                    data-testid="add-stig-upload-button"
                  >
                    Upload to Library
                  </Button>
                </SpaceBetween>
              </form>
            </Container>

            {libStatus === "success" && libResult && (
              <Alert
                type="success"
                dismissible
                onDismiss={() => { setLibStatus("idle"); setLibResult(null); }}
              >
                Imported <strong>{libResult.imported}</strong> STIGs
                {libResult.errors > 0 && <> ({libResult.errors} skipped)</>}.{" "}
                <Link onFollow={() => setActiveTab("library")}>
                  View in Library
                </Link>
              </Alert>
            )}
            {libStatus === "error" && libResult && (
              <Alert
                type="error"
                dismissible
                onDismiss={() => { setLibStatus("idle"); setLibResult(null); }}
              >
                {libResult.error}
              </Alert>
            )}
            <Container
              header={
                <Header
                  variant="h2"
                  description={
                    <>
                      Download the all-in-one <strong>SRG-STIG Library</strong>{" "}
                      bundle (~350 MB) from{" "}
                      <Link
                        href="https://public.cyber.mil/stigs/downloads/"
                        external
                      >
                        public.cyber.mil
                      </Link>
                      . IDs and categories are inferred automatically.
                    </>
                  }
                >
                  Import Library Bundle
                </Header>
              }
            >
              <form onSubmit={handleLibSubmit}>
                <SpaceBetween size="l">
                  <FileUpload
                    value={libFiles}
                    onChange={({ detail }) => setLibFiles(detail.value)}
                    accept=".zip"
                    showFileSize
                    showFileLastModified
                    i18nStrings={{
                      uploadButtonText: (multiple) => multiple ? "Choose files" : "Choose file",
                      dropzoneText: (multiple) => multiple ? "Drop files to upload" : "Drop file to upload",
                      removeFileAriaLabel: (e) => `Remove file ${e + 1}`,
                      limitShowFewer: "Show fewer files",
                      limitShowMore: "Show more files",
                      errorIconAriaLabel: "Error",
                    }}
                  />
                  <Button
                    variant="primary"
                    loading={libStatus === "loading"}
                    disabled={libFiles.length === 0}
                    formAction="submit"
                  >
                    Import Bundle
                  </Button>
                </SpaceBetween>
              </form>
            </Container>
          </SpaceBetween>
        )}

        {activeTab === "upload" && (
          <Box padding={{ vertical: "l" }}>{onUploadTab}</Box>
        )}
      </SpaceBetween>
    </div>
  );
}
