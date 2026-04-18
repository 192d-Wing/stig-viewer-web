import { describe, it, expect, beforeEach } from 'vitest'
import 'fake-indexeddb/auto'
import {
  cacheCatalog,
  readCachedCatalog,
  cacheStig,
  readCachedStig,
  clearCache,
} from '../offlineCache.js'

describe('offlineCache', () => {
  beforeEach(async () => {
    await clearCache()
  })

  it('returns null before anything is cached', async () => {
    expect(await readCachedCatalog()).toBeNull()
    expect(await readCachedStig('windows-11')).toBeNull()
  })

  it('round-trips the catalog list', async () => {
    const list = [
      { id: 'windows-11', title: 'Windows 11 STIG', category: 'Windows' },
    ]
    await cacheCatalog(list)
    const read = await readCachedCatalog()
    expect(read).not.toBeNull()
    expect(read.list).toEqual(list)
    expect(typeof read.cachedAt).toBe('string')
  })

  it('round-trips an individual STIG payload by id', async () => {
    const stig = { title: 'W11', version: '1', releaseInfo: '', rules: [] }
    await cacheStig('windows-11', stig)
    const read = await readCachedStig('windows-11')
    expect(read).not.toBeNull()
    expect(read.stig).toEqual(stig)
  })

  it('overwrites on repeat write and isolates by id', async () => {
    await cacheStig('a', { title: 'a1', rules: [] })
    await cacheStig('b', { title: 'b1', rules: [] })
    await cacheStig('a', { title: 'a2', rules: [] })
    expect((await readCachedStig('a')).stig.title).toBe('a2')
    expect((await readCachedStig('b')).stig.title).toBe('b1')
  })

  it('clearCache() wipes both stores', async () => {
    await cacheCatalog([{ id: 'x' }])
    await cacheStig('x', { title: 'x', rules: [] })
    await clearCache()
    expect(await readCachedCatalog()).toBeNull()
    expect(await readCachedStig('x')).toBeNull()
  })
})
