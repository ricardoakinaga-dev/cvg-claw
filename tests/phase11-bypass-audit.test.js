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
