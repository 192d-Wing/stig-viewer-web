import { useSyncExternalStore } from 'react'

// navigator.onLine + online/offline events. useSyncExternalStore keeps the
// React tree consistent across concurrent renders without the setInterval
// polling some online/offline hooks resort to.

function subscribe(callback) {
  window.addEventListener('online', callback)
  window.addEventListener('offline', callback)
  return () => {
    window.removeEventListener('online', callback)
    window.removeEventListener('offline', callback)
  }
}

function getSnapshot() {
  // navigator.onLine can legitimately be undefined on non-browser runtimes.
  return typeof navigator === 'undefined' ? true : navigator.onLine
}

function getServerSnapshot() {
  // Server renders assume online so SSR markup matches the first client
  // render when there's network.
  return true
}

export function useOnline() {
  return useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)
}
