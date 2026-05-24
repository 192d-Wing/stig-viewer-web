import { useState, useEffect, useMemo, useRef, useCallback, useContext } from "react";
import { useStigTabs } from "./hooks/useStigTabs.js";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import AppLayout from "@cloudscape-design/components/app-layout";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import SplitPanel from "@cloudscape-design/components/split-panel";
import Button from "@cloudscape-design/components/button";
import Modal from "@cloudscape-design/components/modal";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Alert from "@cloudscape-design/components/alert";
import Badge from "@cloudscape-design/components/badge";
import { exportCKL } from "./utils/exportCKL.js";
import DropZone from "./components/DropZone.jsx";
import StigLibrary from "./components/StigLibrary.jsx";
import STIGView from "./components/STIGView.jsx";
import DiffView from "./components/DiffView.jsx";
import RuleDetail from "./components/RuleDetail.jsx";
import STIGWriter from "./components/STIGWriter.jsx";
import AssetsLibrary from "./components/AssetsLibrary.jsx";
import Dashboard from "./components/Dashboard.jsx";
import MyFindings from "./components/MyFindings.jsx";
import AdminConsole from "./components/AdminConsole.jsx";
import { AuthContext } from "./components/AuthGate.jsx";
import { apiFetch, apiGet } from "./utils/api.js";

export default function App() {
  const currentUser = useContext(AuthContext);

  const handleSignOut = useCallback(async () => {
    try {
      await apiFetch("/auth/logout", { method: "POST" });
    } finally {
      window.location.reload();
    }
  }, []);

  const {
    tabs,
    activeTabId,
    diffPair,
    addTabs,
    addSampleTab,
    addStigFromBackend,
    removeTab,
    setActiveTab,
    updateRule,
    setAssetInfo,
    setSelectedRule,
    setAllStatus,
    setDiffPair,
  } = useStigTabs();

  // Top-level "view" is encoded in `?view=` so the URL is shareable. On
  // initial load we honor the param; subsequent clicks call `navigateTo`,
  // which pushState's a new history entry and clears stale page-specific
  // params from the previous view.
  const [appMode, setAppMode] = useState(() => {
    const v = new URLSearchParams(window.location.search).get("view");
    return [
      "viewer",
      "writer",
      "systems",
      "dashboard",
      "myfindings",
      "admin",
    ].includes(v)
      ? v
      : "viewer";
  });

  const navigateTo = useCallback((mode) => {
    setAppMode(mode);
    const params = new URLSearchParams();
    if (mode !== "viewer") params.set("view", mode);
    const qs = params.toString();
    window.history.pushState(
      null,
      "",
      `${window.location.pathname}${qs ? `?${qs}` : ""}`,
    );
  }, []);

  // Pick up browser back/forward.
  useEffect(() => {
    const onPop = () => {
      const v = new URLSearchParams(window.location.search).get("view");
      setAppMode(
        [
          "viewer",
          "writer",
          "systems",
          "dashboard",
          "myfindings",
          "admin",
        ].includes(v)
          ? v
          : "viewer",
      );
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  const [navOpen, setNavOpen] = useState(true);
  const [splitPanelOpen, setSplitPanelOpen] = useState(true);
  const [showLibrary, setShowLibrary] = useState(false);
  const [closingTabId, setClosingTabId] = useState(null);
  const [writerDraftId, setWriterDraftId] = useState(null);
  const fileInputRef = useRef(null);

  const isWriter = appMode === "writer";
  const isSystems = appMode === "systems";
  const isDashboard = appMode === "dashboard";
  const isMyFindings = appMode === "myfindings";
  const isAdmin = appMode === "admin";
  const isLibraryMode =
    !isWriter && !isSystems && !isDashboard && !isMyFindings && !isAdmin;

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? null;
  const isDiffMode = diffPair !== null;
  const hasTabs = tabs.length > 0;

  const selectedRule = useMemo(() => {
    if (!activeTab) return null;
    return (
      activeTab.stig.rules.find((r) => r.id === activeTab.selectedRuleId) ??
      null
    );
  }, [activeTab]);

  const handleDiffToggle = useCallback(() => {
    if (isDiffMode) {
      setDiffPair(null);
    } else {
      setDiffPair([tabs[0]?.id ?? null, tabs[1]?.id ?? null]);
    }
  }, [isDiffMode, tabs, setDiffPair]);

  const handleFileInput = useCallback(
    (e) => {
      if (e.target.files && e.target.files.length > 0) addTabs(e.target.files);
    },
    [addTabs],
  );

  const handleSplitPanelToggle = useCallback(
    ({ detail }) => {
      if (!detail.open) {
        // User closed the split panel — deselect rule
        if (activeTab) setSelectedRule(activeTab.id, null);
      }
      setSplitPanelOpen(detail.open);
    },
    [activeTab, setSelectedRule],
  );

  // Open split panel automatically when a rule is selected
  const effectiveSplitOpen = selectedRule ? splitPanelOpen : false;

  // ── Notifications ────────────────────────────────────────────────────────
  // Poll the bell endpoint every 30s so the badge stays roughly fresh.
  // Opening the panel calls /mark-read, which clears the unread counter
  // server-side and lets future events count as unread again.
  const [notifData, setNotifData] = useState({
    assigned: [],
    overdue: [],
    mentions: [],
    unreadCount: 0,
  });
  const [notifOpen, setNotifOpen] = useState(false);

  const refreshNotifications = useCallback(async () => {
    try {
      const d = await apiGet("/api/notifications");
      // Defensive defaults in case an older backend doesn't include the
      // mentions bucket yet.
      setNotifData({
        assigned: d.assigned ?? [],
        overdue: d.overdue ?? [],
        mentions: d.mentions ?? [],
        unreadCount: d.unreadCount ?? 0,
        lastSeen: d.lastSeen ?? null,
      });
    } catch {
      // non-fatal; bell stays empty
    }
  }, []);

  useEffect(() => {
    if (!currentUser) return undefined;
    refreshNotifications();
    const t = setInterval(refreshNotifications, 30_000);
    return () => clearInterval(t);
  }, [currentUser, refreshNotifications]);

  const openNotifications = useCallback(async () => {
    setNotifOpen(true);
    // Use apiFetch (not apiJson) — mark-read returns 204 No Content and
    // apiJson would throw trying to parse an empty body, swallowing the
    // local state update that clears the bell counter.
    try {
      await apiFetch("/api/notifications/mark-read", { method: "POST" });
    } catch {
      // non-fatal — local clear below still runs
    }
    setNotifData((d) => ({
      ...d,
      unreadCount: 0,
      assigned: d.assigned.map((a) => ({ ...a, unread: false })),
      mentions: (d.mentions ?? []).map((m) => ({ ...m, unread: false })),
    }));
  }, []);

  // Build TopNavigation utilities
  const utilities = [
    {
      type: "button",
      text: "Viewer",
      variant: isLibraryMode ? "primary-button" : undefined,
      onClick: () => navigateTo("viewer"),
    },
    {
      type: "button",
      text: "Writer",
      variant: isWriter ? "primary-button" : undefined,
      onClick: () => navigateTo("writer"),
    },
    {
      type: "button",
      text: "Systems",
      variant: isSystems ? "primary-button" : undefined,
      onClick: () => navigateTo("systems"),
    },
    {
      type: "button",
      text: "Dashboard",
      variant: isDashboard ? "primary-button" : undefined,
      onClick: () => navigateTo("dashboard"),
    },
    {
      type: "button",
      text: "My findings",
      variant: isMyFindings ? "primary-button" : undefined,
      onClick: () => navigateTo("myfindings"),
    },
  ];
  if (currentUser?.role === "admin") {
    utilities.push({
      type: "button",
      text: "Admin",
      variant: isAdmin ? "primary-button" : undefined,
      onClick: () => navigateTo("admin"),
    });
  }
  if (isLibraryMode && hasTabs) {
    utilities.push({
      type: "button",
      text: "Open File",
      iconName: "upload",
      onClick: () => fileInputRef.current?.click(),
    });
    if (tabs.length >= 2) {
      utilities.push({
        type: "button",
        text: isDiffMode ? "Exit Diff" : "Diff",
        variant: isDiffMode ? "primary-button" : undefined,
        onClick: handleDiffToggle,
      });
    }
  }
  const isViewer = currentUser?.role === "viewer";
  if (currentUser) {
    utilities.push(
      {
        type: "button",
        ariaLabel: "Notifications",
        iconName: "notification",
        text:
          notifData.unreadCount > 0
            ? `Notifications (${notifData.unreadCount})`
            : "Notifications",
        onClick: openNotifications,
      },
      {
        type: "menu-dropdown",
        text: currentUser.display_name || "Account",
        iconName: "user-profile",
        items: [{ id: "signout", text: "Sign out" }],
        onItemClick: ({ detail }) => {
          if (detail.id === "signout") handleSignOut();
        },
      },
    );
  }

  const handleLoadFromLibrary = useCallback(
    (stigJson) => {
      addStigFromBackend(stigJson);
      setShowLibrary(false);
    },
    [addStigFromBackend],
  );

  const handleStartDraft = useCallback(
    (draftId) => {
      setWriterDraftId(draftId);
      navigateTo("writer");
    },
    [navigateTo],
  );

  // Build SideNavigation items
  const navItems = tabs.map((tab) => ({
    type: "link",
    text: tab.stig.title,
    href: `#${tab.id}`,
    info: (
      <Button
        variant="icon"
        iconName="close"
        ariaLabel={`Close ${tab.stig.title}`}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setClosingTabId(tab.id);
        }}
      />
    ),
  }));

  // Determine content
  let content;
  if (isAdmin) {
    content = <AdminConsole />;
  } else if (isDashboard) {
    content = <Dashboard />;
  } else if (isMyFindings) {
    content = <MyFindings />;
  } else if (isSystems) {
    content = <AssetsLibrary />;
  } else if (isWriter) {
    content = (
      <STIGWriter
        initialDraftId={writerDraftId}
        onClearDraftId={() => setWriterDraftId(null)}
      />
    );
  } else if (!hasTabs || showLibrary) {
    content = (
      <StigLibrary
        onLoad={handleLoadFromLibrary}
        onStartDraft={handleStartDraft}
        onUploadTab={
          <DropZone onFilesLoad={addTabs} onLoadSample={addSampleTab} />
        }
      />
    );
  } else if (isDiffMode) {
    content = (
      <DiffView
        tabs={tabs}
        diffPair={diffPair}
        onSetDiffPair={setDiffPair}
        onExitDiff={() => setDiffPair(null)}
      />
    );
  } else if (activeTab) {
    content = (
      <STIGView
        tab={activeTab}
        onUpdateRule={(ruleId, updates) =>
          updateRule(activeTabId, ruleId, updates)
        }
        onSetAssetInfo={(info) => setAssetInfo(activeTabId, info)}
        onSetSelectedRule={(ruleId) => setSelectedRule(activeTabId, ruleId)}
        onSetAllStatus={(status) => setAllStatus(activeTabId, status)}
        onAddFiles={addTabs}
      />
    );
  }

  return (
    <>
      <div id="h">
        <TopNavigation
          identity={{
            href: "#",
            title: "STIG Tools",
            logo: {
              src:
                "data:image/svg+xml," +
                encodeURIComponent(
                  '<svg width="40" height="40" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">' +
                    '<rect width="40" height="40" rx="8" fill="#539fe5"/>' +
                    '<path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1b2e"/>' +
                    '<path d="M28 22l4 4-4 4" stroke="#0f1b2e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>' +
                    "</svg>",
                ),
              alt: "STIG Tools",
            },
          }}
          utilities={utilities}
        />
        {isViewer && (
          <div
            data-testid="viewer-badge"
            style={{
              position: "absolute",
              top: 14,
              right: 220,
              zIndex: 1001,
              pointerEvents: "none",
            }}
          >
            <Badge color="grey">Read-only</Badge>
          </div>
        )}
      </div>

      {/* Hidden file input for Open File utility */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".xml,.ckl"
        multiple
        style={{ display: "none" }}
        aria-hidden="true"
        tabIndex={-1}
        onChange={handleFileInput}
      />

      <AppLayout
        headerSelector="#h"
        contentType={isWriter || !hasTabs || showLibrary ? "table" : "default"}
        navigationHide={isWriter || !hasTabs || isDiffMode}
        navigationOpen={!isWriter && navOpen && hasTabs && !isDiffMode}
        onNavigationChange={({ detail }) => setNavOpen(detail.open)}
        navigationWidth={280}
        navigation={
          <SideNavigation
            header={{ text: "Open STIGs", href: "#" }}
            activeHref={showLibrary ? "#library" : `#${activeTabId}`}
            onFollow={(e) => {
              e.preventDefault();
              const id = e.detail.href.slice(1);
              if (id === "library") {
                setShowLibrary(true);
              } else if (id && tabs.some((t) => t.id === id)) {
                setShowLibrary(false);
                setActiveTab(id);
              }
            }}
            items={[
              {
                type: "link",
                text: "Browse Library",
                href: "#library",
                iconName: "add-plus",
              },
              { type: "divider" },
              ...navItems,
            ]}
          />
        }
        toolsHide
        splitPanel={
          selectedRule && !isDiffMode && !isWriter ? (
            <SplitPanel header={selectedRule.stigId} closeBehavior="hide">
              <RuleDetail
                rule={selectedRule}
                onUpdateRule={(updates) =>
                  updateRule(activeTabId, selectedRule.id, updates)
                }
                onClose={() => setSelectedRule(activeTabId, null)}
              />
            </SplitPanel>
          ) : undefined
        }
        splitPanelOpen={effectiveSplitOpen}
        splitPanelPreferences={{ position: "side" }}
        onSplitPanelToggle={handleSplitPanelToggle}
        onSplitPanelPreferencesChange={() => {}}
        content={content}
      />

      <Modal
        visible={closingTabId !== null}
        onDismiss={() => setClosingTabId(null)}
        header="Close checklist"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="link" onClick={() => setClosingTabId(null)}>
                Cancel
              </Button>
              <Button
                onClick={() => {
                  const tab = tabs.find((t) => t.id === closingTabId);
                  if (tab) {
                    const { stig, assetInfo } = tab;
                    const xml = exportCKL(
                      stig,
                      assetInfo.hostname,
                      assetInfo.ip,
                      assetInfo.mac,
                      assetInfo.fqdn,
                    );
                    const blob = new Blob([xml], { type: "application/xml" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `${stig.title.replace(/[^a-zA-Z0-9]/g, "_")}.ckl`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }
                  removeTab(closingTabId);
                  setClosingTabId(null);
                }}
              >
                Export .ckl & Close
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  removeTab(closingTabId);
                  setClosingTabId(null);
                }}
              >
                Close without saving
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <Alert type="warning">
          Any unsaved progress on this checklist will be lost. Export your work
          first if you need to keep it.
        </Alert>
      </Modal>

      <Modal
        visible={notifOpen}
        onDismiss={() => setNotifOpen(false)}
        header="Notifications"
        size="medium"
      >
        <SpaceBetween direction="vertical" size="l">
          <Box>
            <Box variant="h4">Newly assigned</Box>
            {notifData.assigned.length === 0 ? (
              <Box color="text-status-inactive" padding={{ top: "xs" }}>
                Nothing assigned to you recently.
              </Box>
            ) : (
              <ul style={{ paddingLeft: 18, margin: 0 }}>
                {notifData.assigned.map((a) => (
                  <li key={`${a.checklistId}:${a.ruleId}:${a.occurredAt}`}>
                    <strong>{a.ruleId}</strong> on{" "}
                    <em>{a.assetName}</em> · {a.stigTitle}
                    <Box variant="span" color="text-status-inactive">
                      {" "}— {new Date(a.occurredAt).toLocaleString()}
                    </Box>
                  </li>
                ))}
              </ul>
            )}
          </Box>
          <Box>
            <Box variant="h4">
              Overdue
              {notifData.overdue.length > 0 &&
                ` (${notifData.overdue.length})`}
            </Box>
            {notifData.overdue.length === 0 ? (
              <Box color="text-status-inactive" padding={{ top: "xs" }}>
                Nothing assigned to you is past due.
              </Box>
            ) : (
              <ul style={{ paddingLeft: 18, margin: 0 }}>
                {notifData.overdue.map((o) => (
                  <li key={`${o.checklistId}:${o.ruleId}`}>
                    <strong>{o.ruleId}</strong> on{" "}
                    <em>{o.assetName}</em> · {o.stigTitle}
                    <Box variant="span" color="text-status-inactive">
                      {" "}— due {o.dueDate}
                    </Box>
                  </li>
                ))}
              </ul>
            )}
          </Box>
          <Box>
            <Box variant="h4">
              Mentions
              {(notifData.mentions?.length ?? 0) > 0 &&
                ` (${notifData.mentions.length})`}
            </Box>
            {(notifData.mentions?.length ?? 0) === 0 ? (
              <Box color="text-status-inactive" padding={{ top: "xs" }}>
                No one has @-mentioned you in a comment.
              </Box>
            ) : (
              <ul
                style={{ paddingLeft: 18, margin: 0 }}
                data-testid="mentions-list"
              >
                {notifData.mentions.map((m) => (
                  <li
                    key={m.commentId}
                    data-testid="mention-item"
                    style={{ cursor: "pointer" }}
                    onClick={() => {
                      setNotifOpen(false);
                      navigateTo("systems");
                    }}
                  >
                    <strong>{m.byName}</strong> mentioned you on{" "}
                    <em>{m.ruleId}</em>: "{m.body}"
                    <Box variant="span" color="text-status-inactive">
                      {" "}— {new Date(m.at).toLocaleString()}
                    </Box>
                  </li>
                ))}
              </ul>
            )}
          </Box>
        </SpaceBetween>
      </Modal>
    </>
  );
}
