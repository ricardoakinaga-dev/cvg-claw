import type { PostgresPoolClient } from '@cvg/persistence'
import { describe, expect, it, vi } from 'vitest'
import { PostgresRateLimiter } from '../postgres-rate-limit.ts'
import { buildServer } from '../server.ts'

describe('shared rate-limit HTTP boundary', () => {
  it('awaits the configured store before accepting an HTTP request', async () => {
    const app = buildServer({
      rateLimiter: {
        check: async () => ({ allowed: false, retryAfterSeconds: 7 })
      }
    })
    try {
      const response = await app.inject({ method: 'GET', url: '/health' })
      expect(response.statusCode).toBe(429)
      expect(response.headers['retry-after']).toBe('7')
      expect(response.json().error.code).toBe('rate_limited')
    } finally {
      await app.close()
    }
  })

  it('fails closed and does not expose store errors', async () => {
    const app = buildServer({
      rateLimiter: {
        check: async () => {
          throw new Error('SYNTHETIC_STORE_ERROR_CANARY')
        }
      }
    })
    try {
      const response = await app.inject({ method: 'GET', url: '/health' })
      expect(response.statusCode).toBe(503)
      expect(response.json().error.code).toBe('rate_limit_unavailable')
      expect(response.body).not.toContain('SYNTHETIC_STORE_ERROR_CANARY')
    } finally {
      await app.close()
    }
  })
})

describe('quota connection acquisition deadline', () => {
  it('returns generic HTTP 503 within the acquisition deadline for a stalled pool', async () => {
    const app = buildServer({
      rateLimiter: new PostgresRateLimiter({
        connect: () => new Promise(() => undefined)
      })
    })
    try {
      const started = Date.now()
      const response = await app.inject({ method: 'GET', url: '/health' })
      expect(response.statusCode).toBe(503)
      expect(response.json().error.code).toBe('rate_limit_unavailable')
      expect(response.body).not.toContain('acquisition')
      expect(Date.now() - started).toBeLessThan(3500)
    } finally {
      await app.close()
    }
  }, 5000)

  it.each(['check', 'assertReady'] as const)(
    'bounds %s and releases a late connection without queries',
    async (method) => {
      vi.useFakeTimers()
      let resolve!: (client: PostgresPoolClient) => void
      const client = {
        query: vi.fn(async () => ({
          rows: [],
          rowCount: 0,
          command: 'SELECT',
          oid: 0,
          fields: []
        })),
        release: vi.fn(() => undefined)
      }
      const store = new PostgresRateLimiter({
        connect: () =>
          new Promise((done) => {
            resolve = done
          })
      })
      const operation =
        method === 'check'
          ? store.check('fixture', { max: 1, windowMs: 1000 })
          : store.assertReady()
      const observed = expect(operation).rejects.toThrow(
        'Rate limit connection acquisition timed out'
      )
      try {
        await vi.advanceTimersByTimeAsync(2000)
        await observed
        resolve(client)
        await vi.advanceTimersByTimeAsync(0)
        expect(client.release).toHaveBeenCalledOnce()
        expect(client.query).not.toHaveBeenCalled()
        expect(vi.getTimerCount()).toBe(0)
      } finally {
        vi.useRealTimers()
      }
    }
  )

  it('handles acquisition rejection after expiry without an unhandled rejection', async () => {
    vi.useFakeTimers()
    let reject!: (reason: Error) => void
    const store = new PostgresRateLimiter({
      connect: () =>
        new Promise((_done, fail) => {
          reject = fail
        })
    })
    const observed = expect(store.assertReady()).rejects.toThrow(
      'acquisition timed out'
    )
    try {
      await vi.advanceTimersByTimeAsync(2000)
      await observed
      reject(new Error('SYNTHETIC_LATE_POOL_ERROR'))
      await Promise.resolve()
      expect(vi.getTimerCount()).toBe(0)
    } finally {
      vi.useRealTimers()
    }
  })
})
