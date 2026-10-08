import { createHash } from 'node:crypto'
import type { PostgresPoolClient, PostgresPoolLike } from '@cvg/persistence'
import {
  DEFAULT_MAX_BUCKETS,
  RATE_LIMIT_ACQUISITION_TIMEOUT_MS,
  MAX_ALLOWED_BUCKETS,
  MAX_RATE_LIMIT_REQUESTS,
  normalizeRateLimitKey,
  validateRateLimitPolicy,
  type RateLimiter,
  type RateLimitPolicy,
  type RateLimitResult
} from './rate-limit.ts'

/**
 * Shared, bounded pre-authentication quota. A namespace is deployment-owned,
 * never selected from a request header. Database time avoids replica clock skew.
 * Errors propagate to the HTTP boundary, which denies the request with 503.
 */
export class PostgresRateLimiter implements RateLimiter {
  constructor(
    private readonly pool: PostgresPoolLike,
    private readonly namespace = 'api-http-v1',
    private readonly maxBuckets = DEFAULT_MAX_BUCKETS
  ) {
    if (!/^[a-zA-Z0-9_.:-]{1,64}$/.test(namespace)) {
      throw new RangeError('Rate limit namespace is invalid')
    }
    if (
      !Number.isSafeInteger(maxBuckets) ||
      maxBuckets < 1 ||
      maxBuckets > MAX_ALLOWED_BUCKETS
    ) {
      throw new RangeError('Rate limit bucket capacity is invalid')
    }
  }

  private acquire(): Promise<PostgresPoolClient> {
    return new Promise((resolve, reject) => {
      let expired = false
      const timeoutError = new Error(
        'Rate limit connection acquisition timed out'
      )
      const timer = setTimeout(() => {
        expired = true
        reject(timeoutError)
      }, RATE_LIMIT_ACQUISITION_TIMEOUT_MS)
      // Observe late resolution/rejection so expiry never leaks a borrowed client.
      Promise.resolve()
        .then(() => this.pool.connect())
        .then(
          (client) => {
            clearTimeout(timer)
            if (expired) client.release(timeoutError)
            else resolve(client)
          },
          (error: unknown) => {
            clearTimeout(timer)
            if (!expired) reject(error)
          }
        )
        .catch(reject)
    })
  }

  async assertReady(): Promise<void> {
    const client = await this.acquire()
    try {
      await client.query(
        'SELECT namespace, bucket_key, request_count, reset_at FROM api_rate_limit_buckets LIMIT 0'
      )
    } finally {
      client.release()
    }
  }

  async check(key: string, policy: RateLimitPolicy): Promise<RateLimitResult> {
    const normalized = normalizeRateLimitKey(key)
    validateRateLimitPolicy(policy)
    const digest = createHash('sha256').update(normalized).digest('hex')
    const client = await this.acquire()
    try {
      await client.query('BEGIN')
      await client.query("SET LOCAL lock_timeout = '1000ms'")
      await client.query("SET LOCAL statement_timeout = '2000ms'")
      await client.query(
        "SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':api-rate:' || $1, 0))",
        [this.namespace]
      )
      // Capacity is bounded at insertion, so cleanup cannot grow without bound.
      await client.query(
        'DELETE FROM api_rate_limit_buckets WHERE namespace = $1 AND reset_at <= clock_timestamp()',
        [this.namespace]
      )
      const capacity = await client.query<{
        present: boolean
        bucket_count: string
      }>(
        `SELECT EXISTS (
           SELECT 1 FROM api_rate_limit_buckets
           WHERE namespace = $1 AND bucket_key = $2
         ) AS present,
         (SELECT count(*) FROM api_rate_limit_buckets WHERE namespace = $1)::text AS bucket_count`,
        [this.namespace, digest]
      )
      const row = capacity.rows[0]
      const bucketCount = Number(row?.bucket_count)
      if (!row || !Number.isSafeInteger(bucketCount) || bucketCount < 0) {
        throw new Error('Invalid rate limit storage response')
      }
      if (!row.present && bucketCount >= this.maxBuckets) {
        await client.query('COMMIT')
        return { allowed: false, retryAfterSeconds: 1 }
      }
      const updated = await client.query<{
        request_count: number
        retry_seconds: number
      }>(
        `INSERT INTO api_rate_limit_buckets
           (namespace, bucket_key, request_count, reset_at)
         VALUES ($1, $2, 1, clock_timestamp() + $3::double precision * interval '1 millisecond')
         ON CONFLICT (namespace, bucket_key) DO UPDATE
           SET request_count = LEAST(api_rate_limit_buckets.request_count + 1, $4::integer)
         RETURNING request_count,
           GREATEST(1, CEIL(EXTRACT(EPOCH FROM (reset_at - clock_timestamp()))))::integer AS retry_seconds`,
        // The ceiling is invariant across replicas and configuration changes.
        // Capping at the request's policy.max could reduce an active counter.
        [this.namespace, digest, policy.windowMs, MAX_RATE_LIMIT_REQUESTS + 1]
      )
      const result = updated.rows[0]
      if (
        !result ||
        !Number.isSafeInteger(result.request_count) ||
        result.request_count < 1 ||
        !Number.isSafeInteger(result.retry_seconds) ||
        result.retry_seconds < 1
      ) {
        throw new Error('Invalid rate limit storage decision')
      }
      await client.query('COMMIT')
      return {
        allowed: result.request_count <= policy.max,
        retryAfterSeconds:
          result.request_count <= policy.max ? 0 : result.retry_seconds
      }
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined)
      throw error
    } finally {
      client.release()
    }
  }
}
