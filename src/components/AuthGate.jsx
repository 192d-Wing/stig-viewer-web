import { useState, useEffect, createContext } from "react";
import Spinner from "@cloudscape-design/components/spinner";
import Button from "@cloudscape-design/components/button";
import Box from "@cloudscape-design/components/box";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Alert from "@cloudscape-design/components/alert";
import { apiFetch, BACKEND } from "../utils/api.js";

export const AuthContext = createContext(null);

/**
 * On mount, calls /api/users/me with credentials.
 * - 200: stores user in context, renders children.
 * - 401: shows a Sign in button that redirects to /auth/login.
 * - other: shows a connection error.
 */
export default function AuthGate({ children }) {
  const [state, setState] = useState({
    status: "loading",
    user: null,
    error: null,
  });

  useEffect(() => {
    let cancelled = false;
    apiFetch("/api/users/me")
      .then(async (r) => {
        if (cancelled) return;
        if (r.ok) {
          const user = await r.json();
          setState({ status: "authed", user, error: null });
        } else if (r.status === 401) {
          setState({ status: "unauthed", user: null, error: null });
        } else {
          setState({
            status: "error",
            user: null,
            error: `Server returned ${r.status}`,
          });
        }
      })
      .catch((err) => {
        if (cancelled) return;
        setState({ status: "error", user: null, error: err.message });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state.status === "loading") {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }

  if (state.status === "error") {
    return (
      <Box padding="xxl">
        <Alert type="error" header="Cannot connect to backend">
          {state.error}. Make sure the server is running at {BACKEND}.
        </Alert>
      </Box>
    );
  }

  if (state.status === "unauthed") {
    return (
      <Box textAlign="center" padding="xxl">
        <SpaceBetween direction="vertical" size="l">
          <Box variant="h1">STIG Tools</Box>
          <Box variant="p" color="text-body-secondary">
            Sign in with your organization account.
          </Box>
          <Button
            variant="primary"
            onClick={() => {
              window.location.href = `${BACKEND}/auth/login`;
            }}
          >
            Sign in
          </Button>
        </SpaceBetween>
      </Box>
    );
  }

  return (
    <AuthContext.Provider value={state.user}>{children}</AuthContext.Provider>
  );
}
