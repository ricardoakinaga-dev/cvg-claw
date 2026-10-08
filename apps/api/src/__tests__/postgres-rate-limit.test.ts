import { randomBytes } from 'node:crypto'
import { Client, Pool } from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { readPostgresMigrationSql } from '@cvg/persistence'
import { PostgresRateLimiter } from '../postgres-rate-limit.ts'
import { buildServer, buildServerFromEnv } from '../server.ts'

const databaseUrl = process.env.TEST_DATABASE_URL
const postgres = databaseUrl ? describe : describe.skip

describe('shared rate-limit configuration', () => {
  it('rejects an unsupported store or PostgreSQL quota with memory persistence', async () => {
    await expect(
      buildServerFromEnv({
        NODE_ENV: 'test',
        API_RATE_LIMIT_STORE: 'unknown'
      })
    ).rejects.toThrow('API_RATE_LIMIT_STORE')
    await expect(
      buildServerFromEnv({
        NODE_ENV: 'test',
        API_RATE_LIMIT_STORE: 'postgres',
        API_PERSISTENCE_MODE: 'memory'
      })
    ).rejects.toThrow('Shared rate limits require PostgreSQL persistence')
  })
})

postgres('PostgreSQL quota across API instances (synthetic)', () => {
  const schema = `cvg_rate_${Date.now()}_${randomBytes(3).toString('hex')}`
  let admin: Client
  let pool: Pool

  beforeAll(async () => {
    admin = new Client({ connectionString: databaseUrl })
    await admin.connect()
    await admin.query(`CREATE SCHEMA ${schema}`)
    await admin.query(`SET search_path TO ${schema}`)
    await admin.query(await readPostgresMigrationSql('0030_api_rate_limits'))
    pool = new Pool({
      connectionString: databaseUrl,
      options: `-c search_path=${schema}`,
      max: 12
    })
  })

  beforeEach(async () => {
    await admin.query('TRUNCATE api_rate_limit_buckets')
  })

  afterAll(async () => {
    await pool?.end()
    if (admin) {
      await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`)
      await admin.end()
    }
  })

  it('admits exactly the quota under concurrent traffic through two APIs', async () => {
    const stores = [
      new PostgresRateLimiter(pool),
      new PostgresRateLimiter(pool)
    ]
    await stores[0]!.assertReady()
    const apps = stores.map((store) =>
      buildServer({
        rateLimiter: {
          check: (key) => store.check(key, { max: 5, windowMs: 60_000 })
        }
      })
    )
    try {
      const results = await Promise.all(
        Array.from({ length: 16 }, (_, index) =>
          apps[index % 2]!.inject({ method: 'GET', url: '/health' })
        )
      )
      expect(
        results.filter((response) => response.statusCode === 200)
      ).toHaveLength(5)
      expect(
        results.filter((response) => response.statusCode === 429)
      ).toHaveLength(11)
      const restarted = new PostgresRateLimiter(pool)
      expect(
        (await restarted.check('ip:127.0.0.1', { max: 5, windowMs: 60_000 }))
          .allowed
      ).toBe(false)
      const rows = await admin.query(
        'SELECT bucket_key, request_count FROM api_rate_limit_buckets'
      )
      expect(rows.rows).toHaveLength(1)
      expect(rows.rows[0].bucket_key).toMatch(/^[0-9a-f]{64}$/)
      // Includes the denied request through the restarted replica above.
      expect(rows.rows[0].request_count).toBe(results.length + 1)
    } finally {
      await Promise.all(apps.map((app) => app.close()))
    }
  })

  it('bounds capacity without evicting live quotas and reclaims expired entries', async () => {
    const store = new PostgresRateLimiter(pool, 'capacity-test', 2)
    expect((await store.check('a', { max: 1, windowMs: 60_000 })).allowed).toBe(
      true
    )
    expect((await store.check('b', { max: 1, windowMs: 60_000 })).allowed).toBe(
      true
    )
    expect((await store.check('c', { max: 1, windowMs: 60_000 })).allowed).toBe(
      false
    )
    expect((await store.check('a', { max: 1, windowMs: 60_000 })).allowed).toBe(
      false
    )
    await admin.query(
      "UPDATE api_rate_limit_buckets SET reset_at = clock_timestamp() - interval '1 second'"
    )
    expect((await store.check('c', { max: 1, windowMs: 60_000 })).allowed).toBe(
      true
    )
    expect(
      Number(
        (await admin.query('SELECT count(*) FROM api_rate_limit_buckets'))
          .rows[0].count
      )
    ).toBe(1)
  })

  it('never reduces an active counter when replicas use different policy limits', async () => {
    const first = new PostgresRateLimiter(pool)
    const second = new PostgresRateLimiter(pool)
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(
        (await first.check('same-client', { max: 5, windowMs: 60_000 })).allowed
      ).toBe(true)
    }
    expect(
      (await second.check('same-client', { max: 1, windowMs: 60_000 })).allowed
    ).toBe(false)
    expect(
      (await first.check('same-client', { max: 5, windowMs: 60_000 })).allowed
    ).toBe(false)
  })

  it('denies HTTP on unavailable storage without fallback or diagnostic leakage', async () => {
    const store = new PostgresRateLimiter(pool)
    const app = buildServer({ rateLimiter: store })
    await admin.query(
      'ALTER TABLE api_rate_limit_buckets RENAME TO rate_storage_unavailable'
    )
    try {
      await expect(store.assertReady()).rejects.toThrow()
      const response = await app.inject({ method: 'GET', url: '/health' })
      expect(response.statusCode).toBe(503)
      expect(response.json().error.code).toBe('rate_limit_unavailable')
      expect(response.body).not.toContain('api_rate_limit_buckets')
      expect(response.body).not.toContain(schema)
    } finally {
      await admin.query(
        'ALTER TABLE rate_storage_unavailable RENAME TO api_rate_limit_buckets'
      )
      await app.close()
    }
  })

  it('denies a saturated real pool and releases the connection that arrives after expiry', async () => {
    const saturated = new Pool({
      connectionString: databaseUrl,
      options: `-c search_path=${schema}`,
      max: 1
    })
    const held = await saturated.connect()
    const app = buildServer({ rateLimiter: new PostgresRateLimiter(saturated) })
    try {
      const started = Date.now()
      const response = await app.inject({ method: 'GET', url: '/health' })
      expect(response.statusCode).toBe(503)
      expect(response.json().error.code).toBe('rate_limit_unavailable')
      expect(Date.now() - started).toBeLessThan(3500)
      expect(saturated.waitingCount).toBe(1)
      held.release()
      // end waits for all borrowed clients; a leaked late client would hang here.
      await saturated.end()
      expect(saturated.totalCount).toBe(0)
      expect(
        Number(
          (await admin.query('SELECT count(*) FROM api_rate_limit_buckets'))
            .rows[0].count
        )
      ).toBe(0)
    } finally {
      await app.close()
    }
  })

  it('separates deployment namespaces and rejects malformed input', async () => {
    const first = new PostgresRateLimiter(pool, 'first')
    const second = new PostgresRateLimiter(pool, 'second')
    expect(
      (await first.check('same', { max: 1, windowMs: 1000 })).allowed
    ).toBe(true)
    expect(
      (await second.check('same', { max: 1, windowMs: 1000 })).allowed
    ).toBe(true)
    await expect(first.check('', { max: 1, windowMs: 1000 })).rejects.toThrow()
    await expect(
      first.check('same', { max: Infinity, windowMs: 1000 })
    ).rejects.toThrow()
    expect(() => new PostgresRateLimiter(pool, 'invalid namespace')).toThrow()
    expect(() => new PostgresRateLimiter(pool, 'valid', 0)).toThrow()
  })
})
