import { createHash } from 'node:crypto'
import { Client } from 'pg'
import { runPostgresMigrations } from '@cvg/persistence'

async function main(): Promise<void> {
  const url = new URL(process.env.DATABASE_URL ?? '')
  if (
    process.env.NODE_ENV !== 'test' ||
    process.env.CVG_AUD06_SYNTHETIC !== 'true' ||
    url.hostname !== 'db' ||
    url.pathname !== '/cvg_aud06' ||
    url.username !== 'cvg_aud06_migration'
  ) {
    throw new Error(
      'AUD06 migration requires its disposable synthetic database'
    )
  }
  const client = new Client({
    connectionString: url.toString(),
    connectionTimeoutMillis: 5_000,
    options: '-c search_path=cvg_aud06'
  })
  await client.connect()
  try {
    await runPostgresMigrations(client, {
      schemaName: 'cvg_aud06',
      createSchema: false
    })
    // Grant only the migrated, tenant-protected tables. Quarantine stays denied.
    const tables = await client.query<{ relname: string }>(
      `SELECT relname FROM pg_class
       WHERE relnamespace = 'cvg_aud06'::regnamespace AND relkind = 'r'
         AND relrowsecurity AND relforcerowsecurity
         AND relname NOT IN ('tenant_isolation_quarantine', 'outbox_quarantine')`
    )
    await client.query('BEGIN')
    await client.query('GRANT USAGE ON SCHEMA cvg_aud06 TO cvg_aud06_runtime')
    for (const { relname } of tables.rows) {
      const identifier = `"${relname.replaceAll('"', '""')}"`
      await client.query(
        `GRANT SELECT, INSERT, UPDATE ON cvg_aud06.${identifier} TO cvg_aud06_runtime`
      )
    }
    await client.query('GRANT SELECT ON schema_migrations TO cvg_aud06_runtime')
    await client.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_replay_events,
       operator_replay_events, api_rate_limit_buckets TO cvg_aud06_runtime`
    )
    await client.query('COMMIT')
    const result = await client.query(
      'SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version'
    )
    if (!result.rows.some((row) => row.version === '0030_api_rate_limits')) {
      throw new Error('Shared quota migration 0030 is missing')
    }
    console.log(
      JSON.stringify({
        kind: 'AUD06_SYNTHETIC_MIGRATION',
        count: result.rows.length,
        sha256: createHash('sha256')
          .update(JSON.stringify(result.rows))
          .digest('hex'),
        migrations: result.rows
      })
    )
  } finally {
    await client.end()
  }
}

main().catch((error: unknown) => {
  console.error(
    error instanceof Error ? error.message : 'AUD06 migration failed'
  )
  process.exitCode = 1
})
