import { useCallback, useEffect, useState } from "react";

// Coerce a raw string from the URL into the same JS type as `defaultValue`.
// Anything not matching the default's type falls back to the default so a
// hand-typed `?pastDue=garbage` doesn't crash a component expecting bool.
function decode(raw, defaultValue) {
  if (raw === null || raw === undefined) return defaultValue;
  if (typeof defaultValue === "boolean") {
    if (raw === "true") return true;
    if (raw === "false") return false;
    return defaultValue;
  }
  if (typeof defaultValue === "number") {
    const n = Number(raw);
    return Number.isFinite(n) ? n : defaultValue;
  }
  if (Array.isArray(defaultValue)) {
    return raw === "" ? [] : raw.split(",");
  }
  return raw;
}

function encode(value) {
  if (Array.isArray(value)) return value.join(",");
  return String(value);
}

// True if `value` is the same as `defaultValue` (so we can omit it from
// the URL and keep links short).
function isDefault(value, defaultValue) {
  if (Array.isArray(value) && Array.isArray(defaultValue)) {
    if (value.length !== defaultValue.length) return false;
    for (let i = 0; i < value.length; i += 1) {
      if (value.at(i) !== defaultValue.at(i)) return false;
    }
    return true;
  }
  return value === defaultValue;
}

/**
 * Sync a state object to `window.location.search`. The hook owns the keys
 * listed in `defaults` and ignores all others — multiple pages can each
 * read/write their own slice without trampling each other.
 *
 * - Reads initial values from the URL on mount (with type coercion).
 * - Writes back via `history.replaceState` (no new history entry per
 *   keystroke) so back/forward navigates between pages, not filter edits.
 * - Listens for popstate so external URL changes update local state.
 */
export function useUrlState(defaults) {
  const readFromUrl = useCallback(() => {
    const params = new URLSearchParams(window.location.search);
    return Object.fromEntries(
      Object.entries(defaults).map(([k, dv]) => [k, decode(params.get(k), dv)]),
    );
    // defaults is expected to be a stable literal in the caller; we
    // intentionally don't depend on it to avoid render loops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const [state, setState] = useState(readFromUrl);

  // Push state changes into the URL.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    for (const [k, dv] of Object.entries(defaults)) {
      const v = Object.prototype.hasOwnProperty.call(state, k)
        ? Reflect.get(state, k)
        : dv;
      if (isDefault(v, dv)) {
        params.delete(k);
      } else {
        params.set(k, encode(v));
      }
    }
    const qs = params.toString();
    const search = qs ? `?${qs}` : "";
    const next = `${window.location.pathname}${search}${window.location.hash}`;
    const current = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    if (next !== current) {
      window.history.replaceState(null, "", next);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  // Pick up back/forward navigation.
  useEffect(() => {
    const onPop = () => setState(readFromUrl());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [readFromUrl]);

  const patch = useCallback((updates) => {
    setState((s) => ({ ...s, ...updates }));
  }, []);

  return [state, patch];
}
