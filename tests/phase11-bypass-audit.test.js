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
const typescriptPackage = path.resolve(
  import.meta.dirname,
  '../node_modules/typescript'
)

function copyScanner(root) {
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true })
  fs.copyFileSync(scanner, path.join(root, 'scripts/phase11-bypass-audit.mjs'))
  // Parser only: no framework runner or writable target cache is shared.
  fs.mkdirSync(path.join(root, 'node_modules'), { recursive: true })
  fs.symlinkSync(
    typescriptPackage,
    path.join(root, 'node_modules/typescript'),
    'dir'
  )
}

function scan(file, source, tracked = true) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cvg-bypass-audit-'))
  roots.push(root)
  copyScanner(root)
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
    copyScanner(root)
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

// Independent critic reproductions: retained as public-path regressions.
describe('independent Q13 adversarial reproductions', () => {
  it.each([
    {
      name: 'positive-quota',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`INSERT INTO api_rate_limit_buckets (namespace) VALUES ($1) ON CONFLICT (namespace) DO UPDATE SET request_count=2`)',
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'plain-domain-update',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query(`UPDATE billing_items SET value=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'mixed-quoted-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`INSERT INTO api_rate_limit_buckets VALUES ($1); UPDATE billing_items AS "b" SET value=$2`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'update-quoted-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query(`UPDATE patient_records AS "p" SET value=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'delete-sql-line-comment',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`DELETE -- reviewed operation\nFROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'update-sql-line-comment',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`UPDATE -- reviewed operation\npatient_records SET value=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'url-mask-domain',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const endpoint="https://example.invalid"; client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'mixed-cte-quoted-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`WITH changed AS (UPDATE billing_items AS "b" SET value=$1 RETURNING id) INSERT INTO api_rate_limit_buckets SELECT id FROM changed`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'dynamic-quoted-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query(`UPDATE ${table} AS "target" SET value=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'positive-comment-only',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: '// client.query(`DELETE FROM billing_items`)\nconst a=1',
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'untracked-domain',
      file: 'apps/worker/src/new-unsafe.ts',
      source: 'client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: false
    },
    {
      name: 'path-test-substring',
      file: 'apps/api/src/new.test.helper/domain.ts',
      source: 'client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: false
    },
    {
      name: 'quota-quoted-target',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`UPDATE "api_rate_limit_buckets" SET request_count=2`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'quota-schema-target',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`UPDATE public.api_rate_limit_buckets SET request_count=2`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'positive-benign-url',
      file: 'apps/api/src/helper.ts',
      source: 'const endpoint="https://example.invalid"; const a=1;',
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'domain-after-block-comment',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        '/* DELETE FROM patient_records */ client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'tracked-path-test-substring',
      file: 'apps/api/src/new.test.helper/domain.ts',
      source: 'client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 1,
      tracked: true
    },
    {
      name: 'real-test-ignored',
      file: 'apps/api/src/example.test.ts',
      source: 'client.query(`DELETE FROM billing_items WHERE id=$1`)',
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'read-only-diagnostic',
      file: 'apps/worker/src/preflight.ts',
      source:
        "throw new Error('PostgreSQL worker table privileges must be minimal (select/insert/update only)')",
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'positive-plain-quota-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`UPDATE api_rate_limit_buckets AS bucket SET request_count=$1`)',
      expectedScannerExit: 0,
      tracked: true
    },
    {
      name: 'domain-quoted-alias-outside-exception',
      file: 'apps/worker/src/direct.ts',
      source: 'client.query(`UPDATE patient_records AS "p" SET value=$1`)',
      expectedScannerExit: 1,
      tracked: true
    }
  ])('$name', ({ file, source, tracked, expectedScannerExit }) => {
    expect(scan(file, source, tracked).exitCode).toBe(expectedScannerExit)
  })
})

describe('host syntax and SQL literal preservation', () => {
  it.each([
    'const expression = /["\']/; client.query(`DELETE FROM billing_items WHERE id=$1`)',
    'const marker = "/*"; client.query(`INSERT INTO appointments VALUES ($1)`)',
    'client.query("UPDATE patient_records AS \\"target\\" SET value=$1")',
    "client.query(`INSERT INTO api_rate_limit_buckets VALUES ('-- literal'); DELETE FROM billing_items WHERE id=$1`)",
    'const value = `${fetch("https://example.invalid")}`'
  ])('retains forbidden effects after lexical normalization: %s', (source) => {
    const result = scan(quotaFile, source)
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some(
        (finding) => finding.id === 'source_parse_failed'
      )
    ).toBe(false)
  })

  it.each([
    'client.query(`UPDATE patient_records * SET value=$1`)',
    'client.query(`UPDATE ONLY (patient_records) SET value=$1`)',
    'client.query("UPDATE " + table + " SET value=$1")'
  ])('rejects recognized writes with unresolved targets: %s', (source) => {
    const result = scan(quotaFile, source)
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some(
        (finding) => finding.id === 'direct_sql_write'
      )
    ).toBe(true)
  })

  it('ignores SQL comment prose while retaining read-only SQL', () => {
    expect(
      scan(
        quotaFile,
        'client.query(`/* UPDATE patient_records SET value=$1 */ SELECT 1`)'
      ).exitCode
    ).toBe(0)
  })

  it.each([
    "client.query(`SELECT has_table_privilege(current_user, 'patient_records', 'UPDATE')`)",
    "client.query(`INSERT INTO api_rate_limit_buckets VALUES ('DELETE FROM billing_items')`)",
    'const method = "DELETE"; const endpoint = "https://example.invalid"'
  ])('preserves SQL values and ordinary constants: %s', (source) => {
    expect(scan(quotaFile, source).exitCode).toBe(0)
  })

  it('fails closed on syntactically invalid source', () => {
    const result = scan(quotaFile, 'const broken = "unterminated')
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some(
        (finding) => finding.id === 'source_parse_failed'
      )
    ).toBe(true)
  })
})

describe('independent v7 template/SQL reproductions', () => {
  it.each([
    {
      name: 'sql-value-fetch-expression',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`INSERT INTO api_rate_limit_buckets (bucket_key) VALUES (\'${fetch("https://example.invalid")}\')`)',
      tracked: true,
      expectedScannerExit: 1
    },
    {
      name: 'sql-comment-fetch-expression',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query(`SELECT 1 -- ${fetch("https://example.invalid")}\\n`)',
      tracked: true,
      expectedScannerExit: 1
    },
    {
      name: 'sql-blockcomment-send-expression',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query(`SELECT /* ${sendMessage("synthetic")} */ 1`)',
      tracked: true,
      expectedScannerExit: 1
    },
    {
      name: 'sql-value-pure-expression',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        "client.query(`INSERT INTO api_rate_limit_buckets (bucket_key) VALUES ('${safeValue}')`)",
      tracked: true,
      expectedScannerExit: 0
    },
    {
      name: 'SQL-standard-backslash-value',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        "client.query(`INSERT INTO api_rate_limit_buckets VALUES ('literal\\\\'); DELETE FROM billing_items WHERE id=$1`)",
      tracked: true,
      expectedScannerExit: 1
    },
    {
      name: 'SQL-escaped-value-positive',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        "client.query(`INSERT INTO api_rate_limit_buckets VALUES ('a''DELETE FROM billing_items')`)",
      tracked: true,
      expectedScannerExit: 0
    }
  ])('$name', ({ file, source, tracked, expectedScannerExit }) => {
    const result = scan(file, source, tracked)
    expect(result.exitCode).toBe(expectedScannerExit)
    expect(
      result.report.findings.some((f) => f.id === 'source_parse_failed')
    ).toBe(false)
  })
})

describe('separate executable templates and SQL lexical modes', () => {
  it.each([
    'client.query(`SELECT \'${`inner${fetch("https://example.invalid")}`}\'`)',
    'sqlTag`SELECT /* ${sendMessage("synthetic")} */ 1`',
    'fetch`https://example.invalid`',
    'globalThis.fetch`https://example.invalid`',
    'client.query(`INSERT INTO api_rate_limit_buckets VALUES ($1); UPDATE api_rate_limit_buckets AS "b\'x" SET request_count=2; DELETE FROM billing_items WHERE id=$1`)'
  ])('rejects real expressions and following writes: %s', (source) => {
    const result = scan(quotaFile, source)
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some((f) => f.id === 'source_parse_failed')
    ).toBe(false)
  })

  it('retains inert explicitly escaped SQL strings', () => {
    const source = String.raw`client.query("INSERT INTO api_rate_limit_buckets VALUES (E'a\\'DELETE FROM billing_items')")`
    expect(scan(quotaFile, source).exitCode).toBe(0)
  })

  it('preserves a pure tagged-template interpolation', () => {
    expect(scan(quotaFile, 'sqlTag`SELECT ${safeValue}`').exitCode).toBe(0)
  })
})
