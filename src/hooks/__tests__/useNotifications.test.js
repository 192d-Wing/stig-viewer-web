import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { notify, useNotifications } from '../useNotifications.js'

beforeEach(() => {
  notify._reset()
})

describe('useNotifications', () => {
  it('starts with an empty list', () => {
    const { result } = renderHook(() => useNotifications())
    expect(result.current).toEqual([])
  })

  it('appends items and assigns the correct type', () => {
    const { result } = renderHook(() => useNotifications())
    act(() => {
      notify.success('Uploaded')
      notify.error('Boom')
    })
    expect(result.current).toHaveLength(2)
    expect(result.current[0].type).toBe('success')
    expect(result.current[0].content).toBe('Uploaded')
    expect(result.current[1].type).toBe('error')
  })

  it('marks items dismissible and fires the onDismiss callback', () => {
    const { result } = renderHook(() => useNotifications())
    let id
    act(() => {
      id = notify.info('hello')
    })
    expect(result.current).toHaveLength(1)
    expect(result.current[0].dismissible).toBe(true)
    act(() => {
      result.current[0].onDismiss()
    })
    expect(result.current).toEqual([])
    // explicit dismiss by id is a no-op if already gone
    act(() => notify.dismiss(id))
    expect(result.current).toEqual([])
  })

  it('re-renders subscribed consumers when a notification fires from outside', () => {
    const { result } = renderHook(() => useNotifications())
    expect(result.current).toHaveLength(0)
    act(() => notify.warning('heads up'))
    expect(result.current).toHaveLength(1)
    expect(result.current[0].type).toBe('warning')
  })
})
