import { useSyncExternalStore, useCallback } from 'react'

// Dead-simple pub/sub store shared across the app. Usable from anywhere
// (including non-component code) via the exported `notify.*` helpers.

let items = []
const listeners = new Set()
let nextId = 1

function emit() {
  for (const l of listeners) l()
}

function push(type, content, opts = {}) {
  const id = `n-${nextId++}`
  const item = {
    id,
    type,
    content,
    dismissible: true,
    dismissLabel: 'Dismiss',
    onDismiss: () => dismiss(id),
    ...opts,
  }
  items = [...items, item]
  emit()
  return id
}

function dismiss(id) {
  items = items.filter((n) => n.id !== id)
  emit()
}

export const notify = {
  info: (content, opts) => push('info', content, opts),
  success: (content, opts) => push('success', content, opts),
  warning: (content, opts) => push('warning', content, opts),
  error: (content, opts) => push('error', content, opts),
  dismiss,
}

export function useNotifications() {
  const subscribe = useCallback((cb) => {
    listeners.add(cb)
    return () => listeners.delete(cb)
  }, [])
  const snapshot = useCallback(() => items, [])
  return useSyncExternalStore(subscribe, snapshot, snapshot)
}
