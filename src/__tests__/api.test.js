import { describe, it, expect } from 'vitest'
import { ApiError, readApiError } from '../api.js'

function mockResponse({ status = 500, statusText = 'Internal Server Error', body }) {
  return {
    status,
    statusText,
    json: async () => {
      if (body === undefined) throw new Error('not json')
      return body
    },
  }
}

describe('readApiError', () => {
  it('parses the structured error body into an ApiError', async () => {
    const res = mockResponse({
      status: 413,
      body: {
        error: {
          code: 'payload_too_large',
          message: 'file exceeds MAX_UPLOAD_BYTES',
          details: { limitBytes: 100, actualBytes: 200 },
        },
      },
    })
    const err = await readApiError(res)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(413)
    expect(err.code).toBe('payload_too_large')
    expect(err.message).toBe('file exceeds MAX_UPLOAD_BYTES')
    expect(err.details).toEqual({ limitBytes: 100, actualBytes: 200 })
  })

  it('falls back to http_<status> when body is not JSON', async () => {
    const res = mockResponse({ status: 502, statusText: 'Bad Gateway' })
    const err = await readApiError(res)
    expect(err.code).toBe('http_502')
    expect(err.message).toBe('Bad Gateway')
    expect(err.details).toBeNull()
  })

  it('tolerates an empty or malformed error body', async () => {
    const res = mockResponse({ status: 400, body: {} })
    const err = await readApiError(res)
    expect(err.code).toBe('unknown')
    expect(err.status).toBe(400)
  })
})
