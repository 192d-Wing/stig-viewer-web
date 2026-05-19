import { useState, useEffect, useCallback } from "react";
import Modal from "@cloudscape-design/components/modal";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import Button from "@cloudscape-design/components/button";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { apiFetch, BACKEND } from "../utils/api.js";

/**
 * Checks localStorage for a userId. If absent, shows a modal to
 * enter a display name and creates a user via the backend.
 * Wraps children — only renders them once auth is ready.
 */
export default function UserSetup({ children }) {
  const [ready, setReady] = useState(() => !!localStorage.getItem("userId"));
  const [displayName, setDisplayName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // On mount, verify stored user still works
  useEffect(() => {
    const id = localStorage.getItem("userId");
    if (!id) return;
    apiFetch("/api/users/me")
      .then((r) => {
        if (!r.ok) {
          localStorage.removeItem("userId");
          setReady(false);
        }
      })
      .catch(() => {
        // Backend might be down — keep stored ID, will retry on API calls
      });
  }, []);

  const handleCreate = useCallback(async () => {
    const name = displayName.trim();
    if (!name) return;
    setLoading(true);
    setError(null);
    try {
      // Use the display name as the user ID for now
      // The auth middleware auto-creates the user
      localStorage.setItem("userId", name);
      const r = await apiFetch("/api/users/me");
      if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(text || `Server returned ${r.status}`);
      }
      setReady(true);
    } catch (err) {
      localStorage.removeItem("userId");
      const msg = err.message?.includes("Failed to fetch")
        ? `Cannot connect to backend at ${BACKEND}. Make sure the server is running.`
        : err.message;
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [displayName]);

  if (ready) return children;

  return (
    <>
      {children}
      <Modal
        visible
        header="Welcome to STIG Tools"
        closeAriaLabel="Close"
        footer={
          <Box float="right">
            <Button
              variant="primary"
              loading={loading}
              disabled={!displayName.trim()}
              onClick={handleCreate}
            >
              Get Started
            </Button>
          </Box>
        }
      >
        <SpaceBetween size="m">
          <Box variant="p">
            Enter your name to get started. This will be used to identify you as
            an author or reviewer on STIG drafts.
          </Box>
          {error && <Box color="text-status-error">{error}</Box>}
          <FormField label="Display Name">
            <Input
              value={displayName}
              onChange={({ detail }) => setDisplayName(detail.value)}
              placeholder="e.g. John Doe"
              onKeyDown={({ detail }) => {
                if (detail.key === "Enter") handleCreate();
              }}
              autoFocus
            />
          </FormField>
        </SpaceBetween>
      </Modal>
    </>
  );
}
