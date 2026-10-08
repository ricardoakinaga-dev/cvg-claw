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
  fs.mkdirSync(path.join(root, 'scripts/lib'), { recursive: true })
  fs.copyFileSync(
    path.resolve(import.meta.dirname, '../scripts/lib/bypass-sql-audit.mjs'),
    path.join(root, 'scripts/lib/bypass-sql-audit.mjs')
  )
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

describe('AST calls and transparent SQL forwarding', () => {
  it('expands every identifier in a fixed readiness table list', () => {
    expect(
      scan(
        'apps/worker/src/kernel-composition.ts',
        'const tables = ["effect_journal", "outbox_events"] as const; for (const table of tables) { client.query(`SELECT 1 FROM ${table} LIMIT 0`) }'
      ).exitCode
    ).toBe(0)
  })

  it.each([
    'const tables = ["api_rate_limit_buckets", "billing_items"] as const; for (const table of tables) { client.query(`DELETE FROM ${table} WHERE id=$1`) }',
    'const tables = ["api_rate_limit_buckets"]; tables.push("billing_items"); for (const table of tables) { client.query(`DELETE FROM ${table} WHERE id=$1`) }',
    'let sql = "SELECT 1"; sql = "DELETE FROM billing_items"; client.query(sql)',
    'const config = {text:"SELECT 1"}; config.text = "DELETE FROM billing_items"; client.query(config)'
  ])(
    'does not grant mutable or mixed-table SQL a static exemption: %s',
    (source) => {
      expect(scan(quotaFile, source).exitCode).toBe(1)
    }
  )
  it.each([
    String.raw`f\u0065tch("https://example.invalid")`,
    String.raw`globalThis["f\u0065tch"]("https://example.invalid")`,
    'const fn = fetch; fn("https://example.invalid")',
    'const fn = fetch.bind(globalThis); fn("https://example.invalid")',
    'const run = client.query; run("DELETE FROM billing_items")',
    '(fetch as typeof fetch)("https://example.invalid")',
    'fetch!.apply(globalThis,["https://example.invalid"])',
    'client.query({text:"DELETE FROM billing_items", values:[]})',
    'client.query(unknownStatement)'
  ])('rejects actual executable effects or unresolved query: %s', (source) => {
    const result = scan(quotaFile, source)
    expect(result.exitCode).toBe(1)
    expect(
      result.report.findings.some((f) => f.id === 'source_parse_failed')
    ).toBe(false)
  })

  it('recognizes only the existing pure parameter forwarder', () => {
    const result = scan(
      'apps/api/src/server/bootstrap-persistence.ts',
      'const adapter = {query: (text, values) => client.query(text, values)}'
    )
    expect(result.exitCode).toBe(0)
    expect(result.report.forwardingQueries).toHaveLength(1)
    expect(result.report.forwardingQueries[0].sqlTargetExemption).toBe(false)
  })

  it.each([
    'const adapter = {query: (text, values) => client.query("DELETE FROM billing_items", values)}',
    'const adapter = {query: (text, values) => client.query(text + " DELETE FROM billing_items", values)}',
    'const adapter = {query: (text, values) => { fetch("https://example.invalid"); return client.query(text, values) }}'
  ])('does not exempt writes/effects in the forwarding file: %s', (source) => {
    expect(
      scan('apps/api/src/server/bootstrap-persistence.ts', source).exitCode
    ).toBe(1)
  })
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

describe('fresh I1 v8 structural reproductions', () => {
  it.each([
    {
      name: 'host-optional-fetch',
      source: 'fetch?.("https://example.invalid")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-parenthesized-fetch',
      source: '(fetch)("https://example.invalid")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-bracket-fetch',
      source: 'globalThis["fetch"]("https://example.invalid")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-generic-fetch',
      source: 'fetch<Response>("https://example.invalid")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-optional-message',
      source: 'sendMessage?.("synthetic")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-parenthesized-message',
      source: '(sendMessage)("synthetic")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-axios-post',
      source: 'axios.post("https://example.invalid", {})',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-fetch-call',
      source: 'fetch.call(globalThis,"https://example.invalid")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'host-sql-value-optional',
      source:
        'client.query(`INSERT INTO api_rate_limit_buckets VALUES (\'${fetch?.("https://example.invalid")}\')`)',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'benign-fetch-string',
      source: 'const example=\'fetch("https://example.invalid")\'',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'benign-message-string',
      source: 'const example=\'sendMessage("synthetic")\'',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'benign-plain-template',
      source: 'const example=`fetch("https://example.invalid")`',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'unknown-opaque-quota-update',
      source:
        'client.query(`UPDATE api_rate_limit_buckets ${unresolvedGrammar}`)',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'unknown-incomplete-quota-update',
      source: 'client.query("UPDATE api_rate_limit_buckets")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'dollar-comment-value-domain-definitive',
      source: 'client.query("SELECT $$--$$; DELETE FROM patient_records")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'dollar-comment-domain',
      source:
        'client.query("INSERT INTO api_rate_limit_buckets VALUES ($$--$$); DELETE FROM billing_items WHERE id=$1")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'dollar-select-domain',
      source:
        'client.query("SELECT $$--$$; DELETE FROM patient_records WHERE id=$1")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'tagged-dollar-comment-domain',
      source:
        'client.query("INSERT INTO api_rate_limit_buckets VALUES ($value$--$value$); DELETE FROM billing_items WHERE id=$1")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'dollar-inert-value',
      source:
        'client.query("INSERT INTO api_rate_limit_buckets VALUES ($$DELETE FROM billing_items$$)")',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'read-only-quoted-identifier',
      source:
        'client.query("SELECT \\"DELETE FROM billing_items\\" FROM api_rate_limit_buckets")',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'read-only-quoted-update-identifier',
      source:
        'client.query("SELECT \\"UPDATE appointments SET status\\" FROM api_rate_limit_buckets")',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'quota-comment-external-call',
      source:
        'client.query(`SELECT /* ${(fetch)("https://example.invalid")} */ 1`)',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'unknown-leading-semicolon',
      source:
        'client.query("; INSERT INTO api_rate_limit_buckets VALUES ($$--$$); DELETE FROM billing_items")',
      expected: 1,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'read-only-select-for-update',
      source: 'client.query("SELECT * FROM api_rate_limit_buckets FOR UPDATE")',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    },
    {
      name: 'read-only-select-for-update-of',
      source:
        'client.query("SELECT * FROM api_rate_limit_buckets AS q FOR UPDATE OF q")',
      expected: 0,
      file: 'apps/api/src/postgres-rate-limit.ts',
      tracked: true
    }
  ])('$name', ({ file, source, tracked, expected }) => {
    const result = scan(file, source, tracked)
    expect(result.exitCode).toBe(expected)
    expect(
      result.report.findings.some((f) => f.id === 'source_parse_failed')
    ).toBe(false)
  })
})

describe('fresh I1 v9 lexical identity and composition reproductions', () => {
  it.each([
    {
      name: 'inert_host_literals',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const a="fetch(; sendMessage(; axios("; const r=/fetch(/; // fetch("x")',
      expected: 0
    },
    {
      name: 'sql_shadow_param',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const sql="SELECT 1"; function run(sql:string){ client.query(sql) }; run("DELETE FROM patient_records")',
      expected: 1
    },
    {
      name: 'sql_shadow_catch',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const sql="SELECT 1"; try { throw "DELETE FROM patient_records" } catch(sql) { client.query(sql) }',
      expected: 1
    },
    {
      name: 'sql_destructure_shadow',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const sql="SELECT 1"; function run({sql}: {sql:string}){ client.query(sql) }; run({sql:"DELETE FROM patient_records"})',
      expected: 1
    },
    {
      name: 'sql_config_duplicate',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query({text:"SELECT 1", text:"DELETE FROM patient_records"})',
      expected: 1
    },
    {
      name: 'sql_config_spread_later',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const unsafe={text:"DELETE FROM patient_records"}; client.query({text:"SELECT 1", ...unsafe})',
      expected: 1
    },
    {
      name: 'sql_config_static_computed',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query({text:"SELECT 1", ["text"]:"DELETE FROM patient_records"})',
      expected: 1
    },
    {
      name: 'sql_config_alias_mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const cfg={text:"SELECT 1"}; const alias=cfg; alias.text="DELETE FROM patient_records"; client.query(cfg)',
      expected: 1
    },
    {
      name: 'sql_config_assign',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const cfg={text:"SELECT 1"}; Object.assign(cfg,{text:"DELETE FROM patient_records"}); client.query(cfg)',
      expected: 1
    },
    {
      name: 'finite_loop_direct_mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"]; tables.push("billing_items"); for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'finite_loop_alias_mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"]; const alias=tables; alias.push("billing_items"); for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'finite_loop_computed_mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"]; tables["push"]("billing_items"); for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'finite_loop_assign_mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"]; Object.assign(tables,{0:"billing_items"}); for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'finite_loop_shadow',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"]; function run(tables:string[]){for(const table of tables){client.query(`DELETE FROM ${table}`)}}; run(["billing_items"])',
      expected: 1
    },
    {
      name: 'static_object_alias_effect',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const effects={f:fetch}; effects.f("https://example.invalid")',
      expected: 1
    },
    {
      name: 'destructure_global_effect',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const {fetch:f}=globalThis; f("https://example.invalid")',
      expected: 1
    },
    {
      name: 'import_renamed_effect',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'import {fetch as external} from "undici"; external("https://example.invalid")',
      expected: 1
    },
    {
      name: 'query_destructure',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const {query:q}=client; q("DELETE FROM patient_records")',
      expected: 1
    },
    {
      name: 'query_wrapper_known',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const wrapper={q:client.query}; wrapper.q("DELETE FROM patient_records")',
      expected: 1
    },
    {
      name: 'literal_method_shadow',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const sendMessage=()=>42; sendMessage()',
      expected: 0
    },
    {
      name: 'literal_query_shadow',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function query(x:string){ return x }; query("DELETE FROM patient_records")',
      expected: 0
    },
    {
      name: 'shadow_param_no_outer_binding',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function run(sql:string){ client.query(sql) }; run("DELETE FROM patient_records")',
      expected: 1
    },
    {
      name: 'config_spread_before_good',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query({...unsafe,text:"SELECT 1"})',
      expected: 0
    },
    {
      name: 'config_unknown_spread_after',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query({text:"SELECT 1",...unsafe})',
      expected: 1
    },
    {
      name: 'config_getter_overrides',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query({text:"SELECT 1",get text(){return "DELETE FROM patient_records"}})',
      expected: 1
    },
    {
      name: 'finite_loop_alias_benign',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"];const alias=tables;for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 0
    },
    {
      name: 'finite_loop_indirect_splice',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"];const alias=tables;alias.splice(0,1,"billing_items");for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'host_import_unaliased',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'import {fetch} from "undici";fetch("https://example.invalid")',
      expected: 1
    },
    {
      name: 'host_import_axios_renamed',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'import http from "axios";http.get("https://example.invalid")',
      expected: 1
    },
    {
      name: 'host_static_member_alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const external=globalThis.fetch;external("https://example.invalid")',
      expected: 1
    },
    {
      name: 'nested_static_template_concat',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("SELECT \'" + `${"x\'; DELETE FROM patient_records; --"}` + "\'")',
      expected: 1
    },
    {
      name: 'nested_static_template_concat_control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("SELECT \'" + "x\'; DELETE FROM patient_records; --" + "\'")',
      expected: 1
    },
    {
      name: 'nested_static_template_in_config',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        "client.query({text:`SELECT '${\"x'; DELETE FROM patient_records; --\"}'`})",
      expected: 1
    },
    {
      name: 'nested_static_template_top_level',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        "client.query(`SELECT '${\"x'; DELETE FROM patient_records; --\"}'`)",
      expected: 1
    }
  ])('$name', ({ file, source, expected }) => {
    const result = scan(file, source)
    expect(
      result.report.findings.some((f) => f.id === 'source_parse_failed')
    ).toBe(false)
    expect(result.exitCode).toBe(expected)
  })
})

describe('fresh I1 v9 SQL command class public controls', () => {
  it.each([
    {
      name: 'quota_insert',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("INSERT INTO api_rate_limit_buckets VALUES ($1)")',
      expected: 0
    },
    {
      name: 'domain_delete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("DELETE FROM patient_records")',
      expected: 1
    },
    {
      name: 'sql_truncate',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("TRUNCATE patient_records")',
      expected: 1
    },
    {
      name: 'sql_drop',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("DROP TABLE patient_records")',
      expected: 1
    },
    {
      name: 'sql_copy',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("COPY patient_records FROM STDIN")',
      expected: 1
    },
    {
      name: 'sql_create_as',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("CREATE TABLE copied_records AS SELECT * FROM patient_records")',
      expected: 1
    },
    {
      name: 'sql_select_into',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("SELECT * INTO copied_records FROM patient_records")',
      expected: 1
    },
    {
      name: 'sql_do',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("DO $$BEGIN DELETE FROM patient_records; END$$")',
      expected: 1
    },
    {
      name: 'outside_quota_25',
      file: 'apps/worker/src/probe.ts',
      source:
        'client.query("TRUNCATE TABLE patient_records RESTART IDENTITY CASCADE")',
      expected: 1
    },
    {
      name: 'quota_mixed_26',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("INSERT INTO api_rate_limit_buckets VALUES (1); TRUNCATE TABLE patient_records RESTART IDENTITY CASCADE")',
      expected: 1
    },
    {
      name: 'outside_quota_31',
      file: 'apps/worker/src/probe.ts',
      source: 'client.query("DO $$BEGIN DELETE FROM patient_records; END$$")',
      expected: 1
    },
    {
      name: 'quota_mixed_32',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("INSERT INTO api_rate_limit_buckets VALUES (1); DO $$BEGIN DELETE FROM patient_records; END$$")',
      expected: 1
    },
    {
      name: 'dollar_block_inert',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'client.query("SELECT $$BEGIN DELETE FROM patient_records; END$$")',
      expected: 0
    }
  ])('$name', ({ file, source, expected }) => {
    const result = scan(file, source)
    expect(result.exitCode).toBe(expected)
  })
})

describe('binding identity and conservative mutation controls', () => {
  it.each([
    {
      name: 'pure-object-method',
      source: 'const local={sendMessage:()=>42};local.sendMessage()',
      expected: 0
    },
    {
      name: 'read-shorthand',
      source: 'const text="SELECT 1";client.query({text})',
      expected: 0
    },
    {
      name: 'numeric-static',
      source:
        'const n=2; client.query(`INSERT INTO api_rate_limit_buckets VALUES (${n})`)',
      expected: 0
    },
    {
      name: 'destructured-array-mutation',
      source:
        'const tables=["api_rate_limit_buckets"];const holder={tables};const {tables:alias}=holder;alias.push("billing_items");for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'bound-array-mutator',
      source:
        'const tables=["api_rate_limit_buckets"];const change=tables["push"].bind(tables);change("billing_items");for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'config-assignment-escape',
      source:
        'const config={text:"SELECT 1"};Object.assign(config,{text:"DELETE FROM billing_items"});client.query(config)',
      expected: 1
    },
    {
      name: 'config-unmodeled-escape',
      source:
        'const config={text:"SELECT 1"};mutate(config);client.query(config)',
      expected: 1
    },
    {
      name: 'mutable-callee-assignment',
      source:
        'let request=()=>42;request=fetch;request("https://example.invalid")',
      expected: 1
    },
    {
      name: 'scoped-local-pure',
      source: 'const query=(x)=>x;query("DELETE FROM billing_items")',
      expected: 0
    },
    {
      name: 'nested-spread-effective',
      source:
        'const unsafe={text:"DELETE FROM billing_items"};const known={...unsafe,text:"SELECT 1"};client.query({...known})',
      expected: 0
    },
    {
      name: 'computed-static-effect',
      source: 'globalThis["fe"+"tch"]("https://example.invalid")',
      expected: 1
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('consumers of the existing transparent SQL forwarder', () => {
  it.each([
    ['DELETE FROM billing_items', 1],
    ['SELECT 1', 0]
  ])('inspects forwarded SQL %s', (sql, expected) => {
    const source =
      'const adapter={query:(text,values)=>client.query(text,values)};adapter.query(' +
      JSON.stringify(sql) +
      ',[])'
    expect(
      scan('apps/api/src/server/bootstrap-persistence.ts', source).exitCode
    ).toBe(expected)
  })
})

describe('literal module aliases and lexical local require', () => {
  it.each([
    ['const run=require("node-fetch");run("https://example.invalid")', 1],
    ['const {fetch:run}=require("undici");run("https://example.invalid")', 1],
    ['const run=require("axios");run.get("https://example.invalid")', 1],
    [
      'const {fetch:run}=await import("undici");run("https://example.invalid")',
      1
    ],
    [
      'function require(x){return ()=>42};const run=require("node-fetch");run()',
      0
    ]
  ])('keeps static module call provenance %s', (source, expected) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('fresh I1 v10 transitive origins and invocation controls', () => {
  it.each([
    {
      name: 'escape-array-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(a){a[0].text="DELETE FROM billing_items"};const c={text:"SELECT 1"};mutate([c]);client.query(c)',
      expected: 1
    },
    {
      name: 'escape-object-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(a){a.c.text="DELETE FROM billing_items"};const c={text:"SELECT 1"};mutate({c});client.query(c)',
      expected: 1
    },
    {
      name: 'escape-spread-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(a){a.text="DELETE FROM billing_items"};const c={text:"SELECT 1"};mutate(...[c]);client.query(c)',
      expected: 1
    },
    {
      name: 'escape-tag-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(strings,c){c.text="DELETE FROM billing_items"};const c={text:"SELECT 1"};mutate`${c}`;client.query(c)',
      expected: 1
    },
    {
      name: 'escape-new-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'class Mutator {constructor(c){c.text="DELETE FROM billing_items"}};const c={text:"SELECT 1"};new Mutator(c);client.query(c)',
      expected: 1
    },
    {
      name: 'array-escape-concrete',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(a){a[0][0]="billing_items"};const tables=["api_rate_limit_buckets"];mutate([tables]);for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'config-alias-positive',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const c={text:"SELECT 1"};const d=c;client.query(d)',
      expected: 0
    },
    {
      name: 'escape-inert-template-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1"};const note=`value ${c}`;client.query(c)',
      expected: 0
    },
    {
      name: 'array-alias-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"];const a=tables;for(const table of a){client.query(`DELETE FROM ${table}`)}',
      expected: 0
    },
    {
      name: 'escape-direct-concrete-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'function mutate(c){c.text="DELETE FROM billing_items"};const c={text:"SELECT 1"};mutate(c);client.query(c)',
      expected: 1
    },
    {
      name: 'config-destructure-object-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1"};({text:c.text}={text:"DELETE FROM billing_items"});client.query(c)',
      expected: 1
    },
    {
      name: 'config-destructure-array-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1"};[c.text]=["DELETE FROM billing_items"];client.query(c)',
      expected: 1
    },
    {
      name: 'array-destructure-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"];[tables[0]]=["billing_items"];for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'destructure-copy-positive',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const c={text:"SELECT 1"};const {text}=c;client.query(text)',
      expected: 0
    },
    {
      name: 'config-alias-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1"};const d=c;d.text="DELETE FROM billing_items";client.query(c)',
      expected: 1
    },
    {
      name: 'array-own-join-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const tables=["api_rate_limit_buckets"];tables.join=()=>{tables[0]="billing_items"}; tables.join();for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'config-own-join-write',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",join(){this.text="DELETE FROM billing_items"}};c.join();client.query(c)',
      expected: 1
    },
    {
      name: 'own-slice-mutation',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",slice(){this.text="DELETE FROM billing_items"}};c.slice();client.query(c)',
      expected: 1
    },
    {
      name: 'own-join-via-alias',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",join(){this.text="DELETE FROM billing_items"}};const a=c;a.join();client.query(c)',
      expected: 1
    },
    {
      name: 'config-own-join-pure',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",join(){return 1}};c.join();client.query(c)',
      expected: 0
    },
    {
      name: 'own-other-pure-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",change(){return 1}};c.change();client.query(c)',
      expected: 0
    },
    {
      name: 'own-other-method-mutation-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const c={text:"SELECT 1",change(){this.text="DELETE FROM billing_items"}};c.change();client.query(c)',
      expected: 1
    },
    {
      name: 'nodefetch-namespace-default',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'import * as nf from "node-fetch"; nf.default("https://example.invalid")',
      expected: 1
    },
    {
      name: 'namespace-default-call',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'import * as nf from "node-fetch"; const f=nf.default;f("https://example.invalid")',
      expected: 1
    },
    {
      name: 'namespace-destructure-default',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'import * as nf from "node-fetch";const {default:f}=nf;f("https://example.invalid")',
      expected: 1
    },
    {
      name: 'dynamic-nodefetch-default',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const nf=await import("node-fetch");nf.default("https://example.invalid")',
      expected: 1
    },
    {
      name: 'local-default-pure-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const nf={default:()=>42};nf.default()',
      expected: 0
    },
    {
      name: 'nodefetch-default-import',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'import nf from "node-fetch"; nf("https://example.invalid")',
      expected: 1
    },
    {
      name: 'nodefetch-named-default',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'import { default as nf } from "node-fetch"; nf("https://example.invalid")',
      expected: 1
    },
    {
      name: 'local-default-real-effect-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const nf={default:()=>fetch("https://example.invalid")};nf.default()',
      expected: 1
    },
    {
      name: 'sql-bind-unused',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const q=client.query.bind(client,"SELECT 1")',
      expected: 0
    },
    {
      name: 'sql-bind-select',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const q=client.query.bind(client,"SELECT 1");q()',
      expected: 0
    },
    {
      name: 'bind-sql-benign-no-preargs',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const q=client.query.bind(client);q("SELECT 1")',
      expected: 0
    },
    {
      name: 'bind-fetch-unused-control',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const f=fetch.bind(globalThis,"https://example.invalid")',
      expected: 0
    },
    {
      name: 'bind-local-function-unused',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'const query=()=>1;const f=query.bind(null)',
      expected: 0
    },
    {
      name: 'select-positive',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("SELECT 1")',
      expected: 0
    },
    {
      name: 'sql-bind-domain',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const q=client.query.bind(client,"DELETE FROM billing_items");q()',
      expected: 1
    },
    {
      name: 'bind-sql-domain-no-preargs',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source:
        'const q=client.query.bind(client);q("DELETE FROM billing_items")',
      expected: 1
    },
    {
      name: 'domain-negative',
      file: 'apps/api/src/postgres-rate-limit.ts',
      source: 'client.query("DELETE FROM billing_items")',
      expected: 1
    },
    {
      name: 'forwarder-parameters-default',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source:
        'const adapter={query:(text="DELETE FROM billing_items",values=[])=>client.query(text,values)}',
      expected: 1
    },
    {
      name: 'forwarder-parameters-rest',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source:
        'const adapter={query:(text,...values)=>client.query(text,values)}',
      expected: 1
    },
    {
      name: 'forwarder-exact-control',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source: 'const adapter={query:(text,values)=>client.query(text,values)}',
      expected: 0
    },
    {
      name: 'forwarder-consumer-select',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source:
        'const adapter={query:(text,values)=>client.query(text,values)};adapter.query("SELECT 1",[])',
      expected: 0
    },
    {
      name: 'forwarder-body-transform',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source:
        'const adapter={query:(text,values)=>client.query(text+";DELETE FROM billing_items",values)}',
      expected: 1
    },
    {
      name: 'forwarder-consumer-write',
      file: 'apps/api/src/server/bootstrap-persistence.ts',
      source:
        'const adapter={query:(text,values)=>client.query(text,values)};adapter.query("DELETE FROM billing_items",[])',
      expected: 1
    }
  ])('$name', ({ file, source, expected }) => {
    expect(scan(file, source).exitCode).toBe(expected)
  })
})

describe('exposed references versus primitive data and closed callbacks', () => {
  it.each([
    {
      name: 'closed-readiness-callback',
      source:
        'const tables=["api_rate_limit_buckets"];withContext(async(client)=>{for(const table of tables){client.query(`SELECT 1 FROM ${table} LIMIT 0`)}})',
      expected: 0
    },
    {
      name: 'returned-closure-reference',
      source:
        'function mutate(fn){fn().text="DELETE FROM billing_items"};const c={text:"SELECT 1"};const fn=()=>c;mutate(fn);client.query(c)',
      expected: 1
    },
    {
      name: 'returned-closure-array',
      source:
        'function mutate(fn){fn().push("billing_items")};const tables=["api_rate_limit_buckets"];mutate(()=>tables);for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 1
    },
    {
      name: 'function-carried-reference',
      source:
        'function mutate(fn){fn.c.text="DELETE FROM billing_items"};const c={text:"SELECT 1"};function holder(){return 1};holder.c=c;mutate(holder);client.query(c)',
      expected: 1
    },
    {
      name: 'pure-local-return-alias',
      source:
        'const c={text:"SELECT 1"};function same(){return c};const alias=same();client.query(c)',
      expected: 0
    },
    {
      name: 'primitive-value-read',
      source: 'const c={text:"SELECT 1"};observe(c.text);client.query(c)',
      expected: 0
    },
    {
      name: 'primitive-array-native-read',
      source:
        'const tables=["api_rate_limit_buckets"];tables.join("/");for(const table of tables){client.query(`DELETE FROM ${table}`)}',
      expected: 0
    },
    {
      name: 'literal-object-sql-interpolation',
      source:
        'const c={text:"SELECT 1",toString(){return "x\'; DELETE FROM billing_items; --"}};client.query(`SELECT \'${c}\'`)',
      expected: 1
    },
    {
      name: 'implicit-coercion-mutation',
      source:
        'const c={text:"SELECT 1",toString(){this.text="DELETE FROM billing_items";return "safe"}};const note=`${c}`;client.query(c)',
      expected: 1
    },
    {
      name: 'implicit-coercion-pure',
      source:
        'const c={text:"SELECT 1",toString(){return "safe"}};const note=`${c}`;client.query(c)',
      expected: 0
    },
    {
      name: 'bound-sql-call-prefix',
      source:
        'const q=client.query.bind(client,"DELETE FROM billing_items");q.call(client,"SELECT 1")',
      expected: 1
    },
    {
      name: 'bound-sql-apply-prefix',
      source: 'const q=client.query.bind(client,"SELECT 1");q.apply(client,[])',
      expected: 0
    },
    {
      name: 'bound-sql-nested',
      source:
        'const q=client.query.bind(client).bind(client,"DELETE FROM billing_items");q()',
      expected: 1
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('function expando identity', () => {
  it.each([
    [
      'const c={text:"SELECT 1"};const holder=()=>1;holder.c=c;mutate(holder);client.query(c)',
      1
    ],
    [
      'const c={text:"SELECT 1"};function holder(){return 1};holder.note="readonly";client.query(c)',
      0
    ]
  ])(
    'preserves declaration identity across property writes %s',
    (source, expected) => {
      expect(scan(quotaFile, source).exitCode).toBe(expected)
    }
  )
})

describe('structural selection and stored reference exposure', () => {
  it.each([
    [
      'array-effect-member',
      'const calls=[fetch];calls[0]("https://synthetic.invalid")',
      1
    ],
    [
      'array-effect-binding',
      'const [http]=[fetch];http("https://synthetic.invalid")',
      1
    ],
    [
      'array-import-binding',
      'import f from "node-fetch";const [http]=[f];http("https://synthetic.invalid")',
      1
    ],
    [
      'array-query-member',
      'const calls=[client.query];calls[0]("DELETE FROM patients")',
      1
    ],
    [
      'array-query-binding',
      'const [run]=[client.query];run("DELETE FROM patients")',
      1
    ],
    [
      'nested-array-effect',
      'const box={a:[fetch]};box.a[0]("https://synthetic.invalid")',
      1
    ],
    [
      'spread-array-effect',
      'const a=[fetch];const b=[...a];b[0]("https://synthetic.invalid")',
      1
    ],
    [
      'nested-binding-effect',
      'const {a:[http]}={a:[fetch]};http("https://synthetic.invalid")',
      1
    ],
    ['array-pure-member', 'const calls=[()=>1];calls[0]()', 0],
    ['array-pure-binding', 'const [http]=[()=>1];http()', 0],
    ['array-import-inert', 'import f from "node-fetch";const [http]=[f]', 0],
    ['array-query-read', 'const calls=[client.query];calls[0]("SELECT 1")', 0],
    ['nested-array-pure', 'const box={a:[()=>1]};box.a[0]()', 0],
    [
      'array-assigned-effect',
      'let http;[http]=[fetch];http("https://synthetic.invalid")',
      1
    ],
    [
      'object-assigned-effect',
      'let http;({h:http}={h:fetch});http("https://synthetic.invalid")',
      1
    ],
    ['array-assigned-pure', 'let http;[http]=[()=>1];http()', 0],
    [
      'array-assignment-alias',
      'const cfg={text:"SELECT 1"};function mutate(x){x.text="DELETE FROM patients"};let alias;[alias]=[cfg];mutate(alias);client.query(cfg)',
      1
    ],
    [
      'object-assignment-alias',
      'const cfg={text:"SELECT 1"};function mutate(x){x.text="DELETE FROM patients"};let alias;({value:alias}={value:cfg});mutate(alias);client.query(cfg)',
      1
    ],
    [
      'nested-assignment-alias',
      'const cfg={text:"SELECT 1"};let alias;({value:[alias]}={value:[cfg]});mutate(alias);client.query(cfg)',
      1
    ],
    [
      'assignment-distinct-object',
      'const cfg={text:"SELECT 1"};function mutate(x){x.text="DELETE FROM patients"};let alias;[alias]=[{text:"SELECT 1"}];mutate(alias);client.query(cfg)',
      0
    ],
    [
      'assignment-primitive',
      'const cfg={text:"SELECT 1"};let alias;({value:alias}={value:cfg.text});consume(alias);client.query(cfg)',
      0
    ],
    [
      'assigned-alias-direct-write',
      'const cfg={text:"SELECT 1"};let alias;[alias]=[cfg];alias.text="DELETE FROM patients";client.query(cfg)',
      1
    ],
    [
      'closure-stored-reference',
      'const cfg={text:"SELECT 1"};const mailbox={};function publish(){mailbox.value=cfg};function consume(fn){fn();mailbox.value.text="DELETE FROM patients"};consume(publish);client.query(cfg)',
      1
    ],
    [
      'arrow-stored-reference',
      'const cfg={text:"SELECT 1"};const mailbox={};const publish=()=>{mailbox.value=cfg};function consume(fn){fn();mailbox.value.text="DELETE FROM patients"};consume(publish);client.query(cfg)',
      1
    ],
    [
      'closure-exposed-store-only',
      'const cfg={text:"SELECT 1"};const mailbox={};function publish(){mailbox.value=cfg};consume(publish);client.query(cfg)',
      1
    ],
    [
      'closure-stored-copy',
      'const cfg={text:"SELECT 1"};const mailbox={};function publish(){mailbox.value={text:cfg.text}};function consume(fn){fn();mailbox.value.text="DELETE FROM patients"};consume(publish);client.query(cfg)',
      0
    ],
    [
      'closure-local-store',
      'const cfg={text:"SELECT 1"};function publish(){const local={};local.value=cfg;return 1};consume(publish);client.query(cfg)',
      0
    ],
    [
      'closure-read-primitive',
      'const cfg={text:"SELECT 1"};function publish(){return cfg.text};consume(publish);client.query(cfg)',
      0
    ],
    [
      'getter-exposed-reference',
      'const cfg={text:"SELECT 1"};const box={get value(){return cfg}};function mutate(o){o.value.text="DELETE FROM patients"};mutate(box);client.query(cfg)',
      1
    ],
    [
      'getter-distinct-copy',
      'const cfg={text:"SELECT 1"};const box={get value(){return {text:cfg.text}}};function mutate(o){o.value.text="DELETE FROM patients"};mutate(box);client.query(cfg)',
      0
    ],
    [
      'closure-list-length',
      'const tables=["api_rate_limit_buckets"];function expose(){return tables.length};function consume(fn){return fn()};consume(expose);for(const t of tables)client.query(`DELETE FROM ${t}`)',
      0
    ],
    [
      'closure-list-index',
      'const tables=["api_rate_limit_buckets"];function expose(){return tables[0]};function consume(fn){return fn()};consume(expose);for(const t of tables)client.query(`DELETE FROM ${t}`)',
      0
    ],
    [
      'closure-native-join',
      'const tables=["api_rate_limit_buckets"];function expose(){return tables.join(",")};function consume(fn){return fn()};consume(expose);for(const t of tables)client.query(`DELETE FROM ${t}`)',
      0
    ],
    [
      'closure-reference-escape',
      'const tables=["api_rate_limit_buckets"];function expose(){return tables};function consume(fn){fn()[0]="patients"};consume(expose);for(const t of tables)client.query(`DELETE FROM ${t}`)',
      1
    ],
    [
      'array-contained-reference',
      'const cfg={text:"SELECT 1"};const values=[cfg];consume(values[0]);client.query(cfg)',
      1
    ]
  ])('%s', (name, source, expected) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('rest and default selection controls', () => {
  it.each([
    ['const {...box}={http:fetch};box.http("https://synthetic.invalid")', 1],
    ['const {omit,...box}={omit:fetch,run:()=>1};box.run()', 0],
    ['const [,...calls]=[0,fetch];calls[0]("https://synthetic.invalid")', 1],
    ['const [,...calls]=[0,()=>1];calls[0]()', 0],
    [
      'let box;({...box}={http:fetch});box.http("https://synthetic.invalid")',
      1
    ],
    ['let box;({omit,...box}={omit:fetch,run:()=>1});box.run()', 0],
    ['const [http=fetch]=[undefined];http("https://synthetic.invalid")', 1],
    ['const [http=fetch]=[()=>1];http()', 0],
    ['let http;[http=fetch]=[()=>1];http()', 0],
    ['let http;[http=fetch]=[undefined];http("https://synthetic.invalid")', 1],
    [
      'const cfg={text:"SELECT 1"};const box={get value(){return cfg}};box.value.text="DELETE FROM patients";client.query(cfg)',
      1
    ],
    [
      'const cfg={text:"SELECT 1"};const box={get value(){return {text:cfg.text}}};box.value.text="DELETE FROM patients";client.query(cfg)',
      0
    ],
    [
      'const data=[1];data.join=fetch;data.join("https://synthetic.invalid")',
      1
    ],
    ['const data=[1];data.join=()=>"one";data.join()', 0]
  ])('%s', (source, expected) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('v13 shared origin projection and stable allocations', () => {
  it.each([
    {
      name: 'F1-default-empty',
      source: 'let f; ({f=fetch}={}); f("https://synthetic.invalid");\n',
      expected: 1
    },
    {
      name: 'F1-default-undefined',
      source:
        'let f; ({f=fetch}={f:undefined}); f("https://synthetic.invalid");\n',
      expected: 1
    },
    {
      name: 'F1-default-query',
      source:
        'let q; ({q=client.query}={}); q("UPDATE appointments SET status = 1");\n',
      expected: 1
    },
    {
      name: 'F1-default-benign',
      source: 'let f; ({f=()=>1}={}); f();\n',
      expected: 0
    },
    {
      name: 'F1-present-benign',
      source: 'let f; ({f=fetch}={f:()=>1}); f();\n',
      expected: 0
    },
    {
      name: 'F2-property-domain-prefix',
      source:
        'const holder={q:client.query.bind(client,"UPDATE appointments SET status = 1")};holder.q("UPDATE api_rate_limit_buckets SET count = 1");\n',
      expected: 1
    },
    {
      name: 'F2-array-domain-prefix',
      source:
        'const holder=[client.query.bind(client,"UPDATE appointments SET status = 1")];holder[0]("UPDATE api_rate_limit_buckets SET count = 1");\n',
      expected: 1
    },
    {
      name: 'F2-property-read-arg',
      source:
        'const holder={q:client.query.bind(client,"UPDATE appointments SET status = 1")};holder.q("SELECT 1");\n',
      expected: 1
    },
    {
      name: 'F2-property-allowed-prefix',
      source:
        'const holder={q:client.query.bind(client,"UPDATE api_rate_limit_buckets SET count = 1")};holder.q("SELECT 1");\n',
      expected: 0
    },
    {
      name: 'F2-member-call',
      source:
        'const o={q:client.query.bind(client,"UPDATE appointments SET status = 1")};o.q.call(null,"SELECT 1");\n',
      expected: 1
    },
    {
      name: 'F2-member-apply',
      source:
        'const o={q:client.query.bind(client,"UPDATE appointments SET status = 1")};o.q.apply(null,["SELECT 1"]);\n',
      expected: 1
    },
    {
      name: 'F2-direct-bound',
      source:
        'const q=client.query.bind(client,"UPDATE appointments SET status = 1");q("UPDATE api_rate_limit_buckets SET count = 1");\n',
      expected: 1
    },
    {
      name: 'F2-bound-inert',
      source:
        'const holder={q:client.query.bind(client,"UPDATE appointments SET status = 1")};\n',
      expected: 0
    },
    {
      name: 'F3-stored-destruct-alias',
      source:
        'function overwrite(x){x.text="UPDATE appointments SET status = 1";} const c={text:"UPDATE api_rate_limit_buckets SET count = 1"}; const holder={};holder.x=c;const {x}=holder;overwrite(x);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F3-assigned-destruct',
      source:
        'function overwrite(x){x.text="UPDATE appointments SET status = 1";}const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};const holder={};holder.x=c;let x;({x}=holder);overwrite(x);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F3-stored-direct-alias',
      source:
        'function overwrite(x){x.text="UPDATE appointments SET status = 1";} const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};const holder={};holder.x=c;overwrite(holder.x);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F3-literal-destruct-alias',
      source:
        'function overwrite(x){x.text="UPDATE appointments SET status = 1";} const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};const holder={x:c};const {x}=holder;overwrite(x);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F3-stored-primitive',
      source:
        'function consume(x){return x;} const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};const holder={};holder.x=c.text;const {x}=holder;consume(x);client.query(c);\n',
      expected: 0
    },
    {
      name: 'F3-unexposed-store',
      source:
        'const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};const holder={};holder.x=c;client.query(c);\n',
      expected: 0
    },
    {
      name: 'F4-closure-default',
      source:
        'function alter(f){f().text="UPDATE appointments SET status = 1";}const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};alter((out=c)=>out);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F4-closure-explicit',
      source:
        'function alter(f){f().text="UPDATE appointments SET status = 1";}const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};alter(()=>c);client.query(c);\n',
      expected: 1
    },
    {
      name: 'F4-closure-primitive',
      source:
        'function read(f){return f();}const c={text:"UPDATE api_rate_limit_buckets SET count = 1"};read((out=c.text)=>out);client.query(c);\n',
      expected: 0
    },
    {
      name: 'F5-array-selected-mutation',
      source:
        'const tables=["api_rate_limit_buckets"];const [a]=[tables];a[0]="appointments";for(const t of tables){client.query(`UPDATE ${t} SET count=1`);}\n',
      expected: 1
    },
    {
      name: 'F5-array-selected-unmutated',
      source:
        'const tables=["api_rate_limit_buckets"];const [a]=[tables];for(const t of tables){client.query(`UPDATE ${t} SET count=1`);}\n',
      expected: 0
    },
    {
      name: 'P2-native-slice-copy',
      source:
        'const tables=["api_rate_limit_buckets"];function mutate(a){a[0]="appointments";} mutate(tables.slice());for(const t of tables){client.query(`UPDATE ${t} SET count=1`);}\n',
      expected: 0
    },
    {
      name: 'P2-original-ref-mutation',
      source:
        'const tables=["api_rate_limit_buckets"];function mutate(a){a[0]="appointments";} mutate(tables);for(const t of tables){client.query(`UPDATE ${t} SET count=1`);}\n',
      expected: 1
    },
    {
      name: 'rest-config-mutated',
      source:
        'const {...c}={text:"UPDATE api_rate_limit_buckets SET count=1"};mutate(c);client.query(c)',
      expected: 1
    },
    {
      name: 'rest-config-unmutated',
      source:
        'const {...c}={text:"UPDATE api_rate_limit_buckets SET count=1"};client.query(c)',
      expected: 0
    },
    {
      name: 'rest-config-direct-write',
      source:
        'const {...c}={text:"SELECT 1"};c.text="DELETE FROM patients";client.query(c)',
      expected: 1
    },
    {
      name: 'rest-assigned-config-mutated',
      source: 'let c;({...c}={text:"SELECT 1"});mutate(c);client.query(c)',
      expected: 1
    },
    {
      name: 'rest-config-independent-copy',
      source:
        'const c={text:"UPDATE api_rate_limit_buckets SET count=1"};const {...copy}=c;mutate(copy);client.query(c)',
      expected: 0
    },
    {
      name: 'rest-distinct-allocation',
      source:
        'const c={text:"SELECT 1"};const {...a}=c;const {...b}=c;mutate(a);client.query(b)',
      expected: 0
    },
    {
      name: 'rest-source-mutated-before-copy',
      source:
        'const c={text:"SELECT 1"};mutate(c);const {...copy}=c;client.query(copy)',
      expected: 1
    },
    {
      name: 'array-rest-mutated',
      source:
        'const [,...tables]=[0,"api_rate_limit_buckets"];tables[0]="patients";for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'array-rest-unmutated',
      source:
        'const [,...tables]=[0,"api_rate_limit_buckets"];for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-shallow-config-ref',
      source:
        'const c={text:"SELECT 1"};const a=[c];mutate(a.slice());client.query(c)',
      expected: 1
    },
    {
      name: 'slice-shallow-config-ref-binding',
      source:
        'const c={text:"SELECT 1"};const a=[c];const [alias]=a.slice();mutate(alias);client.query(c)',
      expected: 1
    },
    {
      name: 'slice-primitive-source-independent',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=tables.slice();mutate(copy);for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-primitive-copy-mutated',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=tables.slice();mutate(copy);for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'slice-source-mutated-before-copy',
      source:
        'const tables=["api_rate_limit_buckets"];mutate(tables);const copy=tables.slice();for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'slice-unmutated-copy',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=tables.slice();for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-distinct-copies',
      source:
        'const tables=["api_rate_limit_buckets"];const a=tables.slice();const b=tables.slice();mutate(a);for(const t of b)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-static-bounds',
      source:
        'const tables=["patients","api_rate_limit_buckets"];const copy=tables.slice(1);for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-override',
      source:
        'const tables=["api_rate_limit_buckets"];tables.slice=()=>tables;mutate(tables.slice());for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'stored-bound-config',
      source:
        'const holder={};holder.q=client.query.bind(client,"DELETE FROM patients");const {q}=holder;q("SELECT 1")',
      expected: 1
    },
    {
      name: 'stored-bound-read',
      source:
        'const holder={};holder.q=client.query.bind(client,"SELECT 1");const {q}=holder;q("DELETE FROM patients")',
      expected: 0
    },
    {
      name: 'default-nested-bound',
      source:
        'let q;({q=client.query.bind(client,"DELETE FROM patients")}={});q("SELECT 1")',
      expected: 1
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('v13 copy provenance and uncertain callable controls', () => {
  it.each([
    {
      name: 'rest-mutated-in-hoisted-body',
      source:
        'const source={text:"SELECT 1"};change();const {...copy}=source;client.query(copy);function change(){source.text="DELETE FROM patients"}',
      expected: 1
    },
    {
      name: 'slice-mutated-in-hoisted-body',
      source:
        'const tables=["api_rate_limit_buckets"];change();const copy=tables.slice();for(const t of copy)client.query(`DELETE FROM ${t}`);function change(){tables[0]="patients"}',
      expected: 1
    },
    {
      name: 'rest-source-write-body-first',
      source:
        'function change(){source.text="DELETE FROM patients"};const source={text:"SELECT 1"};change();const {...copy}=source;client.query(copy)',
      expected: 1
    },
    {
      name: 'slice-source-write-body-first',
      source:
        'function change(){tables[0]="patients"};const tables=["api_rate_limit_buckets"];change();const copy=tables.slice();for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'rest-alias-mutation',
      source:
        'const {...copy}={text:"SELECT 1"};const alias=copy;mutate(alias);client.query(copy)',
      expected: 1
    },
    {
      name: 'rest-shallow-cfg-ref',
      source:
        'const c={text:"SELECT 1"};const {...copy}={c};mutate(copy);client.query(c)',
      expected: 1
    },
    {
      name: 'rest-primitive-copy-only',
      source:
        'const c={text:"SELECT 1"};const {...copy}={text:c.text};mutate(copy);client.query(c)',
      expected: 0
    },
    {
      name: 'slice-shallow-copy-unexposed',
      source:
        'const c={text:"SELECT 1"};const copy=[c].slice();client.query(c)',
      expected: 0
    },
    {
      name: 'slice-shallow-copy-read',
      source:
        'const c={text:"SELECT 1"};const copy=[c].slice();const alias=copy[0];client.query(alias)',
      expected: 0
    },
    {
      name: 'slice-copy-write-source-primitive',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=tables.slice();copy[0]="patients";for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 0
    },
    {
      name: 'slice-copy-write-own-primitive',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=tables.slice();copy[0]="patients";for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'array-rest-assignment-mutated',
      source:
        'let tables;[,...tables]=[0,"api_rate_limit_buckets"];tables[0]="patients";for(const t of tables)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'stored-config-hoisted-body',
      source:
        'const c={text:"SELECT 1"};const holder={};store();const {x}=holder;mutate(x);client.query(c);function store(){holder.x=c}',
      expected: 1
    },
    {
      name: 'stored-config-pure-primitive-hoisted',
      source:
        'const c={text:"SELECT 1"};const holder={};store();const {x}=holder;consume(x);client.query(c);function store(){holder.x=c.text}',
      expected: 0
    },
    {
      name: 'bound-prefix-mutated-holder',
      source:
        'const holder={q:client.query.bind(client,"SELECT 1")};mutate(holder);holder.q("DELETE FROM patients")',
      expected: 1
    },
    {
      name: 'bound-prefix-mutated-array',
      source:
        'const calls=[client.query.bind(client,"SELECT 1")];mutate(calls);calls[0]("DELETE FROM patients")',
      expected: 1
    },
    {
      name: 'bound-prefix-untouched-holder',
      source:
        'const holder={q:client.query.bind(client,"SELECT 1")};holder.q("DELETE FROM patients")',
      expected: 0
    },
    {
      name: 'closure-default-nested-ref',
      source:
        'const c={text:"SELECT 1"};alter((out=c)=>({value:out}));client.query(c)',
      expected: 1
    },
    {
      name: 'closure-default-read-scalar',
      source:
        'const c={text:"SELECT 1"};consume((out=c)=>out.text);client.query(c)',
      expected: 0
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('v13 copy spread source dependencies', () => {
  it.each([
    {
      name: 'rest-spread-source-mutated',
      source:
        'const src={text:"SELECT 1"};mutate(src);const {...copy}={...src};client.query(copy)',
      expected: 1
    },
    {
      name: 'rest-spread-source-safe',
      source:
        'const src={text:"SELECT 1"};const {...copy}={...src};client.query(copy)',
      expected: 0
    },
    {
      name: 'slice-spread-source-mutated',
      source:
        'const tables=["api_rate_limit_buckets"];mutate(tables);const copy=[...tables].slice();for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 1
    },
    {
      name: 'slice-spread-source-safe',
      source:
        'const tables=["api_rate_limit_buckets"];const copy=[...tables].slice();for(const t of copy)client.query(`DELETE FROM ${t}`)',
      expected: 0
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})

describe('v14 stored member materialization and spread copies', () => {
  it.each([
    {
      name: 'paired-array-direct',
      source: 'const a=[fetch]; const [f]=a; f("x");',
      expected: 1
    },
    {
      name: 'paired-array-pure-stored',
      source: 'const a=[]; a[0]=()=>1; const [f]=a; f("x");',
      expected: 0
    },
    {
      name: 'replay-assignment-1',
      source: 'const a=[]; a[0]=fetch; const [f]=a; f("x");',
      expected: 1
    },
    {
      name: 'replay-benign-rest-array',
      source:
        'const q={text:"SELECT 1"};\nconst box=[]; box[0]=q.text; const [...copy]=box;\nfunction rewrite(b){b.x="DELETE FROM appointments"; b[0]="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 0
    },
    {
      name: 'replay-benign-rest-object',
      source:
        'const q={text:"SELECT 1"};\nconst box={}; box.x=q.text; const {...copy}=box;\nfunction rewrite(b){b.x="DELETE FROM appointments"; b[0]="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 0
    },
    {
      name: 'replay-benign-stored-default-array',
      source:
        'const b=[]; b[0]=()=>1; const [...c]=b;\nconst [f=()=>1]=c;\nf("x");',
      expected: 0
    },
    {
      name: 'replay-benign-stored-default-object',
      source:
        'const b={}; b.f=()=>1; const {...c}=b;\nconst {f=()=>1}=c;\nf("x");',
      expected: 0
    },
    {
      name: 'replay-proof-literal-rest-array',
      source:
        'const q={text:"SELECT 1"};\nconst box=[q]; const [...copy]=box;\nfunction rewrite(b){b[0].text="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 1
    },
    {
      name: 'replay-proof-literal-rest-object',
      source:
        'const q={text:"SELECT 1"};\nconst box={x:q}; const {...copy}=box;\nfunction rewrite(b){b.x.text="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 1
    },
    {
      name: 'replay-proof-object-rest',
      source:
        'const q={text:"SELECT 1"};\nconst {...b}=q;\nfunction change(x){x.text="DELETE FROM appointments";}\nchange(b);\nclient.query(q);',
      expected: 0
    },
    {
      name: 'replay-proof-object-spread',
      source:
        'const q={text:"SELECT 1"};\nconst b={...q};\nfunction change(x){x.text="DELETE FROM appointments";}\nchange(b);\nclient.query(q);',
      expected: 0
    },
    {
      name: 'replay-proof-primitive-rest',
      source:
        'const a=["appointments"];\nconst [...b]=a;\nfunction change(xs){ xs[0]="DELETE FROM appointments"; }\nchange(b);\nfor(const t of a){client.query(`SELECT 1 FROM ${t}`);}',
      expected: 0
    },
    {
      name: 'replay-proof-primitive-spread',
      source:
        'const a=["appointments"];\nconst b=[...a];\nfunction change(xs){ xs[0]="DELETE FROM appointments"; }\nchange(b);\nfor(const t of a){client.query(`SELECT 1 FROM ${t}`);}',
      expected: 0
    },
    {
      name: 'replay-proof-rest-array',
      source:
        'const q={text:"SELECT 1"};\nconst box=[]; box[0]=q; const [...copy]=box;\nfunction rewrite(b){b[0].text="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 1
    },
    {
      name: 'replay-proof-rest-object',
      source:
        'const q={text:"SELECT 1"};\nconst box={}; box.x=q; const {...copy}=box;\nfunction rewrite(b){b.x.text="DELETE FROM appointments";}\nrewrite(copy);\nclient.query(q);',
      expected: 1
    },
    {
      name: 'replay-proof-stored-default-array',
      source:
        'const b=[]; b[0]=fetch; const [...c]=b;\nconst [f=()=>1]=c;\nf("x");',
      expected: 1
    },
    {
      name: 'replay-proof-stored-default-object',
      source:
        'const b={}; b.f=fetch; const {...c}=b;\nconst {f=()=>1}=c;\nf("x");',
      expected: 1
    },
    {
      name: 'stored-object-bound-prefix',
      source:
        'const b={};b.q=client.query.bind(client,"DELETE FROM appointments");const {...c}=b;const {q=()=>1}=c;q("SELECT 1")',
      expected: 1
    },
    {
      name: 'stored-array-bound-prefix',
      source:
        'const b=[];b[0]=client.query.bind(client,"DELETE FROM appointments");const [...c]=b;const [q=()=>1]=c;q("SELECT 1")',
      expected: 1
    },
    {
      name: 'stored-object-pure-present-default',
      source: 'const b={};b.f=()=>1;const {...c}=b;const {f=fetch}=c;f()',
      expected: 0
    },
    {
      name: 'stored-array-pure-present-default',
      source: 'const b=[];b[0]=()=>1;const [...c]=b;const [f=fetch]=c;f()',
      expected: 0
    },
    {
      name: 'object-unknown-spread-not-absent',
      source: 'const b={...unknown};const {f=()=>1}=b;f()',
      expected: 1
    },
    {
      name: 'array-unknown-spread-not-absent',
      source: 'const b=[...unknown];const [f=()=>1]=b;f()',
      expected: 1
    },
    {
      name: 'object-unknown-override-not-absent',
      source: 'const b={f:fetch,...unknown};const {f=()=>1}=b;f()',
      expected: 1
    },
    {
      name: 'array-unknown-stored-not-absent',
      source: 'const b=[];b[0]=unknown;const [f=()=>1]=b;f()',
      expected: 1
    },
    {
      name: 'object-known-absent-default',
      source: 'const b={};const {f=()=>1}=b;f()',
      expected: 0
    },
    {
      name: 'array-known-absent-default',
      source: 'const b=[];const [f=()=>1]=b;f()',
      expected: 0
    },
    {
      name: 'stored-object-spread-ref',
      source:
        'const q={text:"SELECT 1"};const b={};b.x=q;mutate({...b});client.query(q)',
      expected: 1
    },
    {
      name: 'stored-array-spread-ref',
      source:
        'const q={text:"SELECT 1"};const b=[];b[0]=q;mutate([...b]);client.query(q)',
      expected: 1
    },
    {
      name: 'stored-object-spread-primitive',
      source:
        'const q={text:"SELECT 1"};const b={};b.x=q.text;mutate({...b});client.query(q)',
      expected: 0
    },
    {
      name: 'stored-array-spread-primitive',
      source:
        'const q={text:"SELECT 1"};const b=[];b[0]=q.text;mutate([...b]);client.query(q)',
      expected: 0
    },
    {
      name: 'object-spread-shallow-ref',
      source:
        'const q={text:"SELECT 1"};const b={x:q};mutate({...b});client.query(q)',
      expected: 1
    },
    {
      name: 'array-spread-shallow-ref',
      source:
        'const q={text:"SELECT 1"};const b=[q];mutate([...b]);client.query(q)',
      expected: 1
    },
    {
      name: 'object-spread-mutated-copy',
      source:
        'const q={text:"SELECT 1"};const b={...q};mutate(b);client.query(b)',
      expected: 1
    },
    {
      name: 'object-spread-mutated-source',
      source:
        'const q={text:"SELECT 1"};mutate(q);const b={...q};client.query(b)',
      expected: 1
    },
    {
      name: 'object-spread-distinct-copies',
      source:
        'const q={text:"SELECT 1"};const a={...q};const b={...q};mutate(a);client.query(b)',
      expected: 0
    },
    {
      name: 'object-rest-mutated-stored-source',
      source:
        'const b={};b.text="SELECT 1";mutate(b);const {...c}=b;client.query(c)',
      expected: 1
    },
    {
      name: 'object-unknown-slot-not-absent',
      source: 'const b={};b[key]=fetch;const {f=()=>1}=b;f()',
      expected: 1
    },
    {
      name: 'array-unknown-slot-not-absent',
      source: 'const b=[];b[key]=fetch;const [f=()=>1]=b;f()',
      expected: 1
    },
    {
      name: 'object-spread-explicit-present',
      source: 'const b={...unknown,f:()=>1};const {f=fetch}=b;f()',
      expected: 0
    },
    {
      name: 'object-over-limit-not-absent',
      source:
        'const b={k0:0,k1:0,k2:0,k3:0,k4:0,k5:0,k6:0,k7:0,k8:0,k9:0,k10:0,k11:0,k12:0,k13:0,k14:0,k15:0,k16:0,k17:0,k18:0,k19:0,k20:0,k21:0,k22:0,k23:0,k24:0,k25:0,k26:0,k27:0,k28:0,k29:0,k30:0,k31:0,k32:0,k33:0,k34:0,k35:0,k36:0,k37:0,k38:0,k39:0,k40:0,k41:0,k42:0,k43:0,k44:0,k45:0,k46:0,k47:0,k48:0,k49:0,k50:0,k51:0,k52:0,k53:0,k54:0,k55:0,k56:0,k57:0,k58:0,k59:0,k60:0,k61:0,k62:0,k63:0,k64:0};const {f=()=>1}=b;f()',
      expected: 1
    },
    {
      name: 'array-over-limit-not-absent',
      source:
        'const b=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];const [f=()=>1]=b;f()',
      expected: 1
    },
    {
      name: 'array-stored-slot-literal-index',
      source: 'const a=[()=>1];a[0]=fetch;const [f]=a;f()',
      expected: 1
    },
    {
      name: 'object-stored-slot-spread-callable',
      source: 'const a={};a.f=fetch;const b={...a};b.f()',
      expected: 1
    }
  ])('$name', ({ source, expected }) => {
    expect(scan(quotaFile, source).exitCode).toBe(expected)
  })
})
