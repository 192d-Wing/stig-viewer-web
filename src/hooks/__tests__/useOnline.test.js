import { describe, it, expect, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useOnline } from '../useOnline.js'

const originalDescriptor = Object.getOwnPropertyDescriptor(
  window.navigator,
  'onLine',
)

function setOnLine(value) {
  Object.defineProperty(window.navigator, 'onLine', {
    configurable: true,
    get: () => value,
  })
}

describe('useOnline', () => {
  afterEach(() => {
    if (originalDescriptor) {
      Object.defineProperty(window.navigator, 'onLine', originalDescriptor)
    }
  })

  it('returns the current navigator.onLine value', () => {
    setOnLine(true)
    const { result: a } = renderHook(() => useOnline())
    expect(a.current).toBe(true)

    setOnLine(false)
    const { result: b } = renderHook(() => useOnline())
    expect(b.current).toBe(false)
  })

  it('updates when an offline event fires', () => {
    setOnLine(true)
    const { result } = renderHook(() => useOnline())
    expect(result.current).toBe(true)

    act(() => {
      setOnLine(false)
      window.dispatchEvent(new Event('offline'))
    })
    expect(result.current).toBe(false)

    act(() => {
      setOnLine(true)
      window.dispatchEvent(new Event('online'))
    })
    expect(result.current).toBe(true)
  })
})
