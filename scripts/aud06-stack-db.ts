import { createHash } from 'node:crypto'
import { Client, Pool } from 'pg'
import { TenantIdSchema } from '@cvg/platform'
import { TenantScopedPostgresRuntimeRepository } from '@cvg/persistence'

const tenantId = TenantIdSchema.parse(
  'tenant_00000000-0000-4000-8000-000000000006'
)
const schema = 'cvg_aud06'
const hash = (text: string): string =>
  createHash('sha256').update(text).digest('hex')

function connection(variable: string, host = 'db'): string {
  const url = new URL(process.env[variable] ?? '')
  if (
    process.env.NODE_ENV !== 'test' ||
    process.env.CVG_AUD06_SYNTHETIC !== 'true' ||
    url.hostname !== host ||
    url.pathname !== '/cvg_aud06' ||
    !['cvg_aud06_admin', 'cvg_aud06_runtime'].includes(url.username)
  ) {
    throw new Error('AUD06 helper refuses a non-synthetic database')
  }
  return url.toString()
}

async function main(): Promise<void> {
  const action = process.argv[2]
  if (action === 'seed') {
    const slot = process.argv[3]
    if (slot !== 'before' && slot !== 'after')
      throw new Error('Invalid fixture slot')
    const pool = new Pool({
      connectionString: connection('DATABASE_URL'),
      options: `-c search_path=${schema}`,
      connectionTimeoutMillis: 5_000
    })
    try {
      const repository = new TenantScopedPostgresRuntimeRepository(pool)
      const row = await repository.enqueue({
        tenantId,
        type: 'message.outbound',
        payload: {
          fixture: `AUD06-SYNTHETIC-${slot}`,
          secret: 'SENSITIVE-AUD06-TELEMETRY-FIXTURE',
          externalEffects: false
        },
        idempotencyKey: `aud06-stack-${slot}`,
        correlationId: 'corr_00000000-0000-4000-8000-000000000006'
      })
      console.log(JSON.stringify({ kind: 'AUD06_SYNTHETIC_OUTBOX', slot, row }))
    } finally {
      await pool.end()
    }
    return
  }
  const restore = action === 'fingerprint-restore'
  const client = new Client({
    connectionString: connection(
      restore ? 'AUD06_RESTORE_URL' : 'AUD06_ADMIN_URL',
      restore ? 'db-restore' : 'db'
    ),
    options: `-c search_path=${schema}`,
    connectionTimeoutMillis: 5_000
  })
  await client.connect()
  try {
    if (action === 'queue') {
      const result = await client.query(
        `SELECT e.id, e.idempotency_key, e.status, e.attempts,
          (SELECT count(*)::int FROM outbox_effects x WHERE x.event_id = e.id) AS effects
         FROM outbox_events e ORDER BY e.idempotency_key`
      )
      console.log(JSON.stringify({ rows: result.rows }))
    } else if (action === 'quota-reset') {
      await client.query('DELETE FROM api_rate_limit_buckets')
      console.log(JSON.stringify({ quotaReset: true }))
    } else if (action === 'quota-deny' || action === 'quota-allow') {
      await client.query(
        action === 'quota-deny'
          ? 'REVOKE SELECT ON api_rate_limit_buckets FROM cvg_aud06_runtime'
          : 'GRANT SELECT ON api_rate_limit_buckets TO cvg_aud06_runtime'
      )
      console.log(
        JSON.stringify({ storageAvailable: action === 'quota-allow' })
      )
    } else if (action === 'quota') {
      const result = await client.query(
        'SELECT * FROM api_rate_limit_buckets ORDER BY bucket_key'
      )
      console.log(JSON.stringify({ rows: result.rows }))
    } else if (action === 'fingerprint' || restore) {
      // All writers are stopped by the runner. A transaction also fixes the view.
      await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
      const tables = await client.query<{
        relname: string
        rls: boolean
        force_rls: boolean
        owner: string
      }>(
        `SELECT relname, relrowsecurity AS rls, relforcerowsecurity AS force_rls,
           pg_get_userbyid(relowner) AS owner FROM pg_class
         WHERE relnamespace = 'cvg_aud06'::regnamespace AND relkind = 'r' ORDER BY relname`
      )
      const fingerprints = []
      for (const table of tables.rows) {
        const identifier = `"${table.relname.replaceAll('"', '""')}"`
        const result = await client.query<{ row: string }>(
          `SELECT to_jsonb(t)::text AS row FROM ${identifier} t ORDER BY to_jsonb(t)::text COLLATE "C"`
        )
        fingerprints.push({
          ...table,
          count: result.rows.length,
          sha256: hash(result.rows.map((row) => `${row.row}\n`).join(''))
        })
      }
      const rawConstraints = await client.query(
        `SELECT conrelid::regclass::text AS relation, conname, convalidated,
           pg_get_constraintdef(oid) AS definition FROM pg_constraint
         WHERE connamespace = 'cvg_aud06'::regnamespace ORDER BY relation, conname`
      )
      // pg_dump can flatten the nested AND produced by BETWEEN during parse.
      // PostgreSQL's own pretty deparser preserves operator precedence while
      // omitting those redundant parentheses. Retain the raw form as evidence;
      // do not strip arbitrary parentheses or ignore changed constraint text.
      console.error(
        JSON.stringify({
          kind: 'AUD06_RAW_CONSTRAINT_DEFINITIONS',
          constraints: rawConstraints.rows
        })
      )
      const constraints = await client.query(
        `SELECT conrelid::regclass::text AS relation, conname, convalidated,
           pg_get_constraintdef(oid, true) AS definition FROM pg_constraint
         WHERE connamespace = 'cvg_aud06'::regnamespace ORDER BY relation, conname`
      )
      const policies = await client.query(
        `SELECT * FROM pg_policies WHERE schemaname = 'cvg_aud06' ORDER BY tablename, policyname`
      )
      const indexes = await client.query(
        `SELECT * FROM pg_indexes WHERE schemaname = 'cvg_aud06' ORDER BY tablename, indexname`
      )
      await client.query('COMMIT')
      const content = {
        tables: fingerprints,
        constraints: constraints.rows,
        policies: policies.rows,
        indexes: indexes.rows
      }
      console.log(
        JSON.stringify({
          kind: 'AUD06_SYNTHETIC_DATABASE_FINGERPRINT',
          sha256: hash(JSON.stringify(content)),
          ...content
        })
      )
    } else {
      throw new Error('Unknown AUD06 database action')
    }
  } finally {
    await client.end()
  }
}

main().catch((error: unknown) => {
  console.error(
    error instanceof Error ? error.message : 'AUD06 database helper failed'
  )
  process.exitCode = 1
})
