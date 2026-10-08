import { execFileSync, spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

const roots = []
const quotaFile = 'apps/api/src/postgres-rate-limit.ts'
const scanner = path.resolve(
  import.meta.dirname,
  '../scripts/phase11-bypass-audit.mjs'
)

function scan(file, source, tracked = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-bypass-audit-'))
  roots.push(root)
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true })
  fs.copyFileSync(scanner, path.join(root, 'scripts/phase11-bypass-audit.mjs'))
  fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true })
  fs.writeFileSync(path.join(root, file), source)
  execFileSync('git', ['init', '-q'], { cwd: root })
  if (tracked) execFileSync('git', ['add', file], { cwd: root })
  const result = spawnSync(
    process.execPath,
    ['scripts/phase11-bypass-audit.mjs'],
    {
      cwd: root,
      encoding: 'utf8'
    }
  )
  return { exitCode: result.status, report: JSON.parse(result.stdout) }
}

afterEach(() => {
  for (const root of roots.splice(0))
    fs.rmSync(root, { recursive: true, force: true })
})

describe('public bypass audit security boundaries', () => {
  it.each([
    'INSERT INTO api_rate_limit_buckets (namespace) VALUES ($1) ON CONFLICT (namespace) DO UPDATE SET request_count = 2',
    'DELETE FROM api_rate_limit_buckets WHERE reset_at <= clock_timestamp()',
    'UPDATE api_rate_limit_buckets SET request_count = 2',
    'iNsErT /* reviewed quota */ INTO\n api_rate_limit_buckets (namespace) VALUES ($1)'
  ])('admits static quota metadata only: %s', (sql) => {
    const result = scan(quotaFile, `client.query(\`${sql}\`)`)
    expect(result.exitCode).toBe(0)
    expect(result.report.findings).toEqual([])
  })

  it.each([
    'INSERT INTO patient_records (id) VALUES ($1)',
    'UPDATE appointments SET status = $1',
    'DELETE FROM billing_items WHERE id = $1',
    'INSERT INTO api_rate_limit_buckets VALUES ($1); INSERT INTO billing_items VALUES ($2)',
    'WITH deleted AS (DELETE FROM patient_records RETURNING id) INSERT INTO api_rate_limit_buckets SELECT id FROM deleted',
    'INSERT INTO ${table} VALUES ($1)',
    'UPDATE ${table} SET value = $1',
    'UPDATE ${ tableName } SET value = $1',
    'UPDATE "patient records" SET value = $1',
    'UPDATE "public"."billing items" AS target SET value = $1',
    'DELETE FROM ${table} WHERE id = $1',
    'INSERT INTO public.api_rate_limit_buckets VALUES ($1)',
    'INSERT INTO api_rate_limit_buckets_evil VALUES ($1)',
    'uPdAtE /* disguised */ patient_records SET value = $1',
    'DELETE /* disguised */ FROM\n appointments WHERE id = $1',
    'INSERT INTO "billing_items" VALUES ($1)'
  ])('rejects domain, mixed or unknown SQL within quota file: %s', (sql) => {
    const result = scan(quotaFile, `client.query(\`${sql}\`)`)
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some(
        (finding) => finding.id === 'direct_sql_write'
      )
    ).toBe(true)
  })

  it('rejects quota SQL in another source file', () => {
    expect(
      scan(
        'apps/api/src/unsafe.ts',
        "client.query('INSERT INTO api_rate_limit_buckets VALUES ($1)')"
      ).exitCode
    ).toBe(1)
  })

  it.each(['fetch("https://example.invalid")', 'sendMessage("synthetic")'])(
    'rejects external effects in quota file: %s',
    (source) => {
      expect(scan(quotaFile, source).exitCode).toBe(1)
    }
  )

  it.each([
    'apps/api/src/webhook-security.ts',
    'apps/api/src/operator-replay-store.ts'
  ])('preserves existing replay store exception: %s', (file) => {
    expect(
      scan(file, "client.query('INSERT INTO replay_claims VALUES ($1)')")
        .exitCode
    ).toBe(0)
  })

  it('includes untracked source files in the governed inventory', () => {
    const result = scan(
      'apps/worker/src/unsafe-new.ts',
      'fetch("https://example.invalid")',
      false
    )
    expect(result.exitCode).toBe(1)
    expect(result.report.scannedFiles).toBe(1)
  })

  it('ignores comments without masking following domain writes', () => {
    const result = scan(
      quotaFile,
      "// INSERT INTO billing_items\nclient.query('DELETE FROM billing_items WHERE id = $1')"
    )
    expect(result.exitCode).toBe(1)
  })

  it('does not mistake a read-only privilege diagnostic for UPDATE SQL', () => {
    expect(
      scan(
        'apps/worker/src/postgres-role-preflight.ts',
        "throw new Error('PostgreSQL worker table privileges must be minimal (select/insert/update only)')"
      ).exitCode
    ).toBe(0)
  })

  it('fails closed when Git inventory cannot be read', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-bypass-no-git-'))
    roots.push(root)
    fs.mkdirSync(path.join(root, 'scripts'))
    fs.copyFileSync(
      scanner,
      path.join(root, 'scripts/phase11-bypass-audit.mjs')
    )
    const result = spawnSync(
      process.execPath,
      ['scripts/phase11-bypass-audit.mjs'],
      { cwd: root, encoding: 'utf8' }
    )
    expect(result.status).toBe(1)
    expect(
      JSON.parse(result.stdout).findings.some(
        (finding) => finding.id === 'source_inventory_failed'
      )
    ).toBe(true)
  })
})
