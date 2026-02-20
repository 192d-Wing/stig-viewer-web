import { useState, useEffect, useCallback, useMemo } from "react";
import Table from "@cloudscape-design/components/table";
import Tabs from "@cloudscape-design/components/tabs";
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
import Container from "@cloudscape-design/components/container";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Box from "@cloudscape-design/components/box";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import SegmentedControl from "@cloudscape-design/components/segmented-control";
import Link from "@cloudscape-design/components/link";

const BACKEND = "http://localhost:8080";
const CATEGORIES = ["Windows", "Linux", "Browser", "Network"];
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

/** Comparator for sortable columns */
function comparator(col, dir) {
  const mul = dir === "asc" ? 1 : -1;
  return (a, b) => {
    let av, bv;
    switch (col) {
      case "category":
        av = a.category;
        bv = b.category;
        return mul * av.localeCompare(bv);
      case "title":
        av = a.title;
        bv = b.title;
        return mul * av.localeCompare(bv);
      case "version":
        av = Number(a.version || 0);
        bv = Number(b.version || 0);
        if (av !== bv) return mul * (av - bv);
        return (
          mul * (parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo))
        );
      case "release":
        av = parseRelease(a.releaseInfo);
        bv = parseRelease(b.releaseInfo);
        return mul * (av - bv);
      case "rules":
        return mul * (a.ruleCount - b.ruleCount);
      default:
        return 0;
    }
  };
}

export default function StigLibrary({ onLoad, onUploadTab }) {
  const [activeTab, setActiveTab] = useState("library");
  const [catalog, setCatalog] = useState([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState(null);
  const [loadingId, setLoadingId] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState(null);
  const [searchText, setSearchText] = useState("");
  const [showSuperseded, setShowSuperseded] = useState(false);
  const [sortCol, setSortCol] = useState("title");
  const [sortDir, setSortDir] = useState("asc");

  // Add-to-library form state (single STIG)
  const [addFiles, setAddFiles] = useState([]);
  const [addId, setAddId] = useState("");
  const [addCategory, setAddCategory] = useState("Windows");
  const [addStatus, setAddStatus] = useState("idle");
  const [addResult, setAddResult] = useState(null);

  // Library bundle import state
  const [libFiles, setLibFiles] = useState([]);
  const [libStatus, setLibStatus] = useState("idle");
  const [libResult, setLibResult] = useState(null);

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
    return [...list].sort(comparator(sortCol, sortDir));
  }, [
    catalog,
    categoryFilter,
    searchText,
    showSuperseded,
    supersededIds,
    sortCol,
    sortDir,
  ]);

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
              {loadingId === item.id ? "Loading\u2026" : item.title}
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
      header: "Ver",
      cell: (item) => item.version || "\u2014",
      sortingComparator: (a, b) => {
        const vDiff = Number(a.version || 0) - Number(b.version || 0);
        if (vDiff !== 0) return vDiff;
        return parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo);
      },
      width: 70,
    },
    {
      id: "release",
      header: "Rel",
      cell: (item) => parseRelease(item.releaseInfo) || "\u2014",
      sortingComparator: (a, b) =>
        parseRelease(a.releaseInfo) - parseRelease(b.releaseInfo),
      width: 70,
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
      width: 80,
    },
  ];

  const sortingColumn = columnDefinitions.find((c) => c.id === sortCol);

  return (
    <div style={{ maxWidth: 960, margin: "0 auto" }}>
      <Tabs
        activeTabId={activeTab}
        onChange={({ detail }) => setActiveTab(detail.activeTabId)}
        tabs={[
          {
            id: "library",
            label: "STIG Library",
            content: (
              <SpaceBetween size="l">
                {catalogError && (
                  <Alert
                    type="error"
                    dismissible
                    onDismiss={() => setCatalogError(null)}
                  >
                    {catalogError}
                  </Alert>
                )}

                <Table
                  variant="embedded"
                  stickyHeader
                  stripedRows
                  loading={catalogLoading}
                  loadingText="Connecting to backend"
                  resizableColumns
                  items={displayList}
                  columnDefinitions={columnDefinitions}
                  sortingColumn={sortingColumn}
                  sortingDescending={sortDir === "desc"}
                  onSortingChange={({ detail }) => {
                    setSortCol(detail.sortingColumn.id);
                    setSortDir(detail.isDescending ? "desc" : "asc");
                  }}
                  header={
                    <Header
                      counter={`(${displayList.length})`}
                      actions={
                        supersededIds.size > 0 ? (
                          <Toggle
                            checked={showSuperseded}
                            onChange={({ detail }) =>
                              setShowSuperseded(detail.checked)
                            }
                          >
                            Show superseded ({supersededIds.size})
                          </Toggle>
                        ) : undefined
                      }
                    >
                      STIG Library
                    </Header>
                  }
                  filter={
                    <SpaceBetween
                      direction="horizontal"
                      size="m"
                      alignItems="center"
                    >
                      <TextFilter
                        filteringText={searchText}
                        onChange={({ detail }) =>
                          setSearchText(detail.filteringText)
                        }
                        filteringPlaceholder="Search by title"
                        countText={`${displayList.length} matches`}
                      />
                      <SegmentedControl
                        selectedId={categoryFilter || "all"}
                        onChange={({ detail }) =>
                          setCategoryFilter(
                            detail.selectedId === "all"
                              ? null
                              : detail.selectedId,
                          )
                        }
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
              </SpaceBetween>
            ),
          },
          {
            id: "add",
            label: "Add to Library",
            content: (
              <SpaceBetween size="l">
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
                      <FormField label="STIG ZIP file">
                        <FileUpload
                          value={addFiles}
                          onChange={({ detail }) => setAddFiles(detail.value)}
                          accept=".zip"
                          constraintText="ZIP files only"
                          i18nStrings={{
                            uploadButtonText: () => "Choose file",
                            dropzoneText: () => "Drop file to upload",
                            removeFileAriaLabel: (e) => `Remove file ${e + 1}`,
                            limitShowFewer: "Show fewer files",
                            limitShowMore: "Show more files",
                            errorIconAriaLabel: "Error",
                          }}
                        />
                      </FormField>
                      <FormField label="ID" description="Slug, e.g. windows-11">
                        <Input
                          value={addId}
                          onChange={({ detail }) => setAddId(detail.value)}
                          placeholder="e.g. windows-11"
                        />
                      </FormField>
                      <FormField label="Category">
                        <Select
                          selectedOption={
                            CATEGORY_OPTIONS.find(
                              (o) => o.value === addCategory,
                            ) || CATEGORY_OPTIONS[0]
                          }
                          onChange={({ detail }) =>
                            setAddCategory(detail.selectedOption.value)
                          }
                          options={CATEGORY_OPTIONS}
                        />
                      </FormField>
                      <Button
                        variant="primary"
                        loading={addStatus === "loading"}
                        disabled={addFiles.length === 0 || !addId.trim()}
                        formAction="submit"
                        onClick={handleAddSubmit}
                      >
                        Upload to Library
                      </Button>
                    </SpaceBetween>
                  </form>
                  {addStatus === "success" && addResult && (
                    <Box margin={{ top: "l" }}>
                      <Alert type="success">
                        <strong>{addResult.title}</strong> added &mdash;{" "}
                        {addResult.ruleCount} rules ({addResult.version}).{" "}
                        <Link onFollow={() => setActiveTab("library")}>
                          View in Library
                        </Link>
                      </Alert>
                    </Box>
                  )}
                  {addStatus === "error" && addResult && (
                    <Box margin={{ top: "l" }}>
                      <Alert type="error">{addResult.error}</Alert>
                    </Box>
                  )}
                </Container>

                <Container
                  header={
                    <Header
                      variant="h2"
                      description={
                        <>
                          Download the all-in-one{" "}
                          <strong>SRG-STIG Library</strong> bundle (~350 MB)
                          from{" "}
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
                      <FormField label="Library bundle ZIP">
                        <FileUpload
                          value={libFiles}
                          onChange={({ detail }) => setLibFiles(detail.value)}
                          accept=".zip"
                          constraintText="ZIP files only"
                          i18nStrings={{
                            uploadButtonText: () => "Choose file",
                            dropzoneText: () => "Drop file to upload",
                            removeFileAriaLabel: (e) => `Remove file ${e + 1}`,
                            limitShowFewer: "Show fewer files",
                            limitShowMore: "Show more files",
                            errorIconAriaLabel: "Error",
                          }}
                        />
                      </FormField>
                      <Button
                        variant="primary"
                        loading={libStatus === "loading"}
                        disabled={libFiles.length === 0}
                        formAction="submit"
                        onClick={handleLibSubmit}
                      >
                        Import Library Bundle
                      </Button>
                    </SpaceBetween>
                  </form>
                  {libStatus === "success" && libResult && (
                    <Box margin={{ top: "l" }}>
                      <Alert type="success">
                        Imported <strong>{libResult.imported}</strong> STIGs
                        {libResult.errors > 0 && (
                          <> ({libResult.errors} skipped)</>
                        )}
                        .{" "}
                        <Link onFollow={() => setActiveTab("library")}>
                          View in Library
                        </Link>
                      </Alert>
                    </Box>
                  )}
                  {libStatus === "error" && libResult && (
                    <Box margin={{ top: "l" }}>
                      <Alert type="error">{libResult.error}</Alert>
                    </Box>
                  )}
                </Container>
              </SpaceBetween>
            ),
          },
          {
            id: "upload",
            label: "Open Local File",
            content: <Box padding={{ vertical: "l" }}>{onUploadTab}</Box>,
          },
        ]}
      />
    </div>
  );
}
