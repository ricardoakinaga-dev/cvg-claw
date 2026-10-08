// @vitest-environment node
import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import ts from 'typescript'
import { auditSqlWrites } from '../scripts/lib/bypass-sql-audit.mjs'

const quota = { allowQuota: true }
const unsupportedCommands = [
  'TRUNCATE patient_records',
  'truncate /* nested /* comment */ here */ TABLE api_rate_limit_buckets',
  'DROP TABLE patient_records',
  "COPY patient_records FROM '/synthetic.csv'",
  'COPY api_rate_limit_buckets FROM STDIN',
  'SELECT 1 INTO patient_records',
  'SELECT 1 INTO TEMP TABLE api_rate_limit_buckets',
  'CREATE TABLE patient_records AS SELECT 1',
  'CREATE TEMP TABLE api_rate_limit_buckets AS SELECT 1',
  'DO $$BEGIN DELETE FROM patient_records; END$$',
  'DO LANGUAGE plpgsql $body$BEGIN NULL; END$body$',
  "DO 'BEGIN NULL; END'",
  'CALL purge_records()',
  'MERGE INTO patient_records USING source ON TRUE WHEN MATCHED THEN DO NOTHING',
  'VACUUM patient_records',
  'GRANT ALL ON patient_records TO someone',
  'UNKNOWN_COMMAND patient_records',
  '"SELECT" 1',
  "'SELECT' 1",
  '$$SELECT 1$$',
  'SET search_path = public',
  "SET LOCAL role = 'owner'",
  'EXPLAIN ANALYZE DELETE FROM patient_records'
]
const deny = [
  ['domain INSERT', 'INSERT INTO patient_records VALUES ($1)'],
  ['domain quoted alias UPDATE', 'UPDATE billing_items AS "b" SET amount=$1'],
  [
    'domain DELETE line comment',
    'DELETE -- comment\n FROM appointments WHERE id=$1'
  ],
  [
    'domain CTE',
    'WITH b AS (DELETE FROM billing_items RETURNING id) INSERT INTO api_rate_limit_buckets SELECT id FROM b'
  ],
  [
    'domain reverse CTE',
    'WITH q AS (INSERT INTO api_rate_limit_buckets VALUES ($1) RETURNING id) UPDATE appointments SET status=$2'
  ],
  [
    'ordinary backslash closes quote',
    String.raw`INSERT INTO api_rate_limit_buckets VALUES ('literal\'); DELETE FROM billing_items WHERE id=$1`
  ],
  [
    'dollar comment marker',
    'INSERT INTO api_rate_limit_buckets VALUES ($$--$$); DELETE FROM billing_items WHERE id=$1'
  ],
  [
    'dollar block marker',
    'INSERT INTO api_rate_limit_buckets VALUES ($$/*$$); DELETE FROM appointments WHERE id=$1'
  ],
  ['dollar read then write', 'SELECT $$--$$; DELETE FROM patient_records'],
  [
    'named dollar read then write',
    'SELECT $value$--$value$; DELETE FROM patient_records'
  ],
  [
    'leading semicolon dollar then write',
    ';SELECT $value$--$value$; DELETE FROM patient_records'
  ],
  [
    'named dollar then UPDATE',
    'INSERT INTO api_rate_limit_buckets VALUES ($value$/*$value$); UPDATE appointments SET status=$1'
  ],
  ['quoted quota', 'UPDATE "api_rate_limit_buckets" SET request_count=2'],
  [
    'qualified quota',
    'UPDATE public.api_rate_limit_buckets SET request_count=2'
  ],
  [
    'quoted qualified quota',
    'DELETE FROM "public"."api_rate_limit_buckets" WHERE request_count=2'
  ],
  ['quota suffix', 'INSERT INTO api_rate_limit_buckets_extra VALUES ($1)'],
  ['ONLY modifier', 'UPDATE ONLY api_rate_limit_buckets SET request_count=2'],
  [
    'ONLY parenthesized target',
    'UPDATE ONLY (api_rate_limit_buckets) SET request_count=2'
  ],
  [
    'star inheritance target',
    'UPDATE api_rate_limit_buckets * SET request_count=2'
  ],
  [
    'unknown alias grammar',
    'UPDATE api_rate_limit_buckets weird extra SET request_count=2'
  ],
  ['missing AS alias', 'UPDATE api_rate_limit_buckets AS SET request_count=2'],
  ['dynamic target', 'UPDATE ${table} AS "p" SET amount=$1'],
  ['parameter target', 'UPDATE $1 SET request_count=2'],
  ['opaque UPDATE', 'UPDATE api_rate_limit_buckets ${unknown}'],
  ['incomplete UPDATE', 'UPDATE api_rate_limit_buckets'],
  ['incomplete INSERT', 'INSERT INTO api_rate_limit_buckets'],
  ['incomplete DELETE', 'DELETE FROM'],
  ['missing SET', 'UPDATE api_rate_limit_buckets request_count=2'],
  ['missing assignment', 'UPDATE api_rate_limit_buckets SET'],
  [
    'missing assignment value',
    'UPDATE api_rate_limit_buckets SET request_count='
  ],
  ['trailing comma', 'UPDATE api_rate_limit_buckets SET request_count=1,'],
  [
    'unknown suffix',
    'UPDATE api_rate_limit_buckets SET request_count=1 nonsense'
  ],
  ['missing WHERE expression', 'DELETE FROM api_rate_limit_buckets WHERE'],
  [
    'unfinished condition',
    'DELETE FROM api_rate_limit_buckets WHERE request_count=1 AND'
  ],
  [
    'missing RETURNING expression',
    'DELETE FROM api_rate_limit_buckets RETURNING'
  ],
  ['empty VALUES', 'INSERT INTO api_rate_limit_buckets VALUES ()'],
  ['missing VALUES row', 'INSERT INTO api_rate_limit_buckets VALUES'],
  ['VALUES trailing comma', 'INSERT INTO api_rate_limit_buckets VALUES (1),'],
  ['empty columns', 'INSERT INTO api_rate_limit_buckets () VALUES (1)'],
  [
    'unknown INSERT modifier',
    'INSERT INTO api_rate_limit_buckets OVERRIDING SYSTEM VALUE VALUES (1)'
  ],
  ['unterminated comment', 'INSERT INTO api_rate_limit_buckets /* unfinished'],
  [
    'unterminated value',
    "INSERT INTO api_rate_limit_buckets VALUES ('unfinished)"
  ],
  [
    'unterminated identifier',
    'UPDATE "api_rate_limit_buckets SET request_count=1'
  ],
  [
    'unterminated dollar value',
    'INSERT INTO api_rate_limit_buckets VALUES ($value$unfinished)'
  ],
  ['unclosed parenthesis', 'INSERT INTO api_rate_limit_buckets VALUES (1'],
  ['unmatched parenthesis', 'INSERT INTO api_rate_limit_buckets VALUES (1))'],
  ['orphan DO UPDATE', 'DO UPDATE SET request_count=2'],
  [
    'ON CONFLICT without INSERT',
    'SELECT 1 ON CONFLICT (id) DO UPDATE SET request_count=2'
  ],
  [
    'conflict across statements',
    'INSERT INTO api_rate_limit_buckets VALUES (1); ON CONFLICT (id) DO UPDATE SET request_count=2'
  ],
  [
    'conflict without target',
    'INSERT INTO api_rate_limit_buckets VALUES (1) ON CONFLICT DO UPDATE SET request_count=2'
  ],
  [
    'conflict missing SET',
    'INSERT INTO api_rate_limit_buckets VALUES (1) ON CONFLICT (id) DO UPDATE request_count=2'
  ],
  [
    'conflict empty assignment',
    'INSERT INTO api_rate_limit_buckets VALUES (1) ON CONFLICT (id) DO UPDATE SET'
  ],
  [
    'WHERE after INSERT VALUES',
    'INSERT INTO api_rate_limit_buckets VALUES (1) WHERE TRUE'
  ],
  [
    'WHERE after conflict DO NOTHING',
    'INSERT INTO api_rate_limit_buckets VALUES (1) ON CONFLICT DO NOTHING WHERE TRUE'
  ],
  [
    'unsupported IS right operand',
    'UPDATE api_rate_limit_buckets SET request_count=1 WHERE request_count IS 2'
  ],
  [
    'unknown interpolation body',
    'INSERT INTO api_rate_limit_buckets VALUES (${unknown})'
  ],
  [
    'known quota then domain without semicolon',
    'UPDATE api_rate_limit_buckets SET request_count=1 DELETE FROM patient_records'
  ],
  [
    'lock tail cannot hide write',
    'SELECT 1 FOR UPDATE patient_records SET amount=1'
  ],
  ['unfinished lock OF', 'SELECT 1 FOR UPDATE OF'],
  [
    'lock then real UPDATE',
    'SELECT 1 FOR NO KEY UPDATE; UPDATE patient_records SET amount=1'
  ]
]

const allow = [
  ['simple INSERT', 'INSERT INTO api_rate_limit_buckets VALUES ($1)'],
  [
    'quota UPSERT',
    'INSERT INTO api_rate_limit_buckets VALUES ($1) ON CONFLICT (bucket_key) DO UPDATE SET request_count=2'
  ],
  [
    'quota DO NOTHING',
    'INSERT INTO api_rate_limit_buckets VALUES ($1) ON CONFLICT DO NOTHING'
  ],
  [
    'expiry DELETE',
    'DELETE FROM api_rate_limit_buckets WHERE reset_at <= clock_timestamp()'
  ],
  ['simple UPDATE', 'UPDATE api_rate_limit_buckets SET request_count=2'],
  [
    'unquoted UPDATE alias',
    'UPDATE api_rate_limit_buckets q SET request_count=2'
  ],
  [
    'quoted UPDATE alias',
    'UPDATE api_rate_limit_buckets "q" SET request_count=2'
  ],
  [
    'AS quoted UPDATE alias',
    'UPDATE api_rate_limit_buckets AS "b" SET request_count=2'
  ],
  [
    'doubled quoted alias',
    'UPDATE api_rate_limit_buckets AS "b""quoted" SET request_count=2'
  ],
  [
    'unquoted DELETE alias',
    'DELETE FROM api_rate_limit_buckets q WHERE q.reset_at <= clock_timestamp()'
  ],
  [
    'quoted DELETE alias',
    'DELETE FROM api_rate_limit_buckets AS "q" WHERE "q".reset_at <= clock_timestamp()'
  ],
  [
    'INSERT alias',
    'INSERT INTO api_rate_limit_buckets AS "q" (bucket_key) VALUES ($1)'
  ],
  [
    'multiple values',
    'INSERT INTO api_rate_limit_buckets (bucket_key) VALUES ($1), ($2)'
  ],
  [
    'case and nested comment',
    'iNsErT /* a /* nested */ b */ INTO\nAPI_RATE_LIMIT_BUCKETS VALUES ($1)'
  ],
  [
    'comment separates target',
    'UPDATE/*comment*/api_rate_limit_buckets -- line\r\n SET request_count=2'
  ],
  [
    'ordinary doubled quotes',
    "INSERT INTO api_rate_limit_buckets VALUES ('it''s -- /* DELETE FROM billing_items')"
  ],
  [
    'explicit E escaped value',
    String.raw`INSERT INTO api_rate_limit_buckets VALUES (E'it\'s -- DELETE FROM billing_items')`
  ],
  [
    'lowercase explicit E',
    String.raw`INSERT INTO api_rate_limit_buckets VALUES (e'it\'s /* UPDATE patient_records')`
  ],
  [
    'dollar inert DELETE value',
    'INSERT INTO api_rate_limit_buckets VALUES ($$DELETE FROM billing_items$$)'
  ],
  [
    'named dollar inert value',
    'INSERT INTO api_rate_limit_buckets VALUES ($value$-- /* DELETE FROM billing_items$value$)'
  ],
  [
    'dollar quote containing ordinary quotes',
    `INSERT INTO api_rate_limit_buckets VALUES ($value$'"-- /*$value$)`
  ],
  [
    'dollar other tags inert',
    'INSERT INTO api_rate_limit_buckets VALUES ($value$$$DELETE $other$ FROM billing_items$value$)'
  ],
  ['benign SQL comment', '/* DELETE FROM billing_items */ SELECT 1'],
  ['benign line comment', 'SELECT 1 -- DELETE FROM billing_items'],
  [
    'benign nested block comment',
    'SELECT /* a /* DELETE FROM billing_items */ b */ 1'
  ],
  [
    'read-only quoted identifier',
    'SELECT "DELETE FROM billing_items" FROM api_rate_limit_buckets'
  ],
  [
    'read-only quoted UPDATE identifier',
    'SELECT "UPDATE appointments SET status" FROM api_rate_limit_buckets'
  ],
  [
    'read-only string words',
    "SELECT 'INSERT INTO appointments; DELETE FROM billing_items'"
  ],
  ['read-only dollar words', 'SELECT $$UPDATE appointments SET status=1$$'],
  ['read-only dollar comment', 'SELECT $$--$$'],
  ['read-only FOR UPDATE', 'SELECT * FROM api_rate_limit_buckets FOR UPDATE'],
  [
    'read-only FOR UPDATE OF',
    'SELECT * FROM api_rate_limit_buckets AS q FOR UPDATE OF q'
  ],
  [
    'read-only FOR NO KEY UPDATE',
    'SELECT * FROM api_rate_limit_buckets FOR NO KEY UPDATE'
  ],
  [
    'read-only lock OF with NOWAIT',
    'SELECT * FROM api_rate_limit_buckets q FOR UPDATE OF q NOWAIT'
  ],
  [
    'read-only lock with SKIP LOCKED',
    'SELECT * FROM api_rate_limit_buckets FOR NO KEY UPDATE SKIP LOCKED'
  ],
  [
    'read-only CTE lock',
    'WITH q AS (SELECT * FROM api_rate_limit_buckets FOR UPDATE) SELECT * FROM q'
  ],
  [
    'quota CTE write',
    'WITH q AS (INSERT INTO api_rate_limit_buckets VALUES ($1) RETURNING bucket_key) SELECT * FROM q'
  ],
  [
    'two quota statements',
    'INSERT INTO api_rate_limit_buckets VALUES (1); DELETE FROM api_rate_limit_buckets WHERE reset_at <= clock_timestamp()'
  ],
  [
    'IS NULL metadata condition',
    'UPDATE api_rate_limit_buckets SET request_count=1 WHERE reset_at IS NOT NULL'
  ],
  [
    'quoted identifier apostrophe',
    'SELECT "DELETE FROM patient_records\'still identifier"'
  ],
  [
    'host words inert value',
    "INSERT INTO api_rate_limit_buckets VALUES ('fetch(; sendMessage(; axios(')"
  ],
  [
    'quoted pure placeholder is value',
    "INSERT INTO api_rate_limit_buckets VALUES ('${unknown}')"
  ]
]

// Inspect the real module read-only. Only already literal SQL is passed to the
// helper; no query/client/host expression is evaluated or executed.
function literalWrites(path) {
  const parsed = ts.createSourceFile(
    path,
    readFileSync(path, 'utf8'),
    ts.ScriptTarget.Latest,
    true
  )
  const sql = []
  function visit(node) {
    if (
      ts.isTemplateExpression(node) &&
      /^\s*(INSERT|UPDATE|DELETE)\b/i.test(node.head.text)
    ) {
      sql.push(
        node.head.text +
          node.templateSpans
            .map((span) => '${unknown}' + span.literal.text)
            .join('')
      )
    }
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      /^\s*(INSERT|UPDATE|DELETE)\b/i.test(node.text)
    )
      sql.push(node.text)
    ts.forEachChild(node, visit)
  }
  visit(parsed)
  return sql
}

describe('bounded SQL write audit', () => {
  describe.each([
    ['no exception', {}],
    ['quota exception', quota],
    ['legacy replay exception', { allowSecurityStore: true }],
    ['both exceptions', { ...quota, allowSecurityStore: true }]
  ])('statement classes with %s', (_name, options) => {
    it.each(unsupportedCommands)('refuses unsupported executable %s', (sql) => {
      expect(auditSqlWrites(sql, options)).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ id: 'direct_sql_write', offset: 0 })
        ])
      )
    })

    it.each([
      'SELECT truncate, drop, copy, create, do, call, unknown_command FROM diagnostics',
      'SELECT diagnostics.truncate, diagnostics.drop, diagnostics.copy FROM diagnostics',
      'SELECT 1 AS truncate, 2 AS drop, 3 AS copy, 4 AS do, 5 AS call',
      'SELECT (truncate), coalesce(drop, copy) FROM diagnostics',
      'SELECT "INTO", "DO", "CALL", "DROP TABLE patient_records" FROM diagnostics',
      "SELECT 'DO $$BEGIN DELETE FROM patient_records; END$$'",
      'SELECT $$BEGIN DELETE FROM patient_records; END$$',
      'SELECT $body$DROP TABLE patient_records; CALL purge_records()$body$',
      '/* TRUNCATE patient_records */ SELECT 1 -- DO $$DROP TABLE patient_records$$',
      'SELECT (SELECT $$DROP TABLE patient_records$$) AS "INTO"',
      'WITH "DO" AS (SELECT 1 AS truncate) SELECT truncate FROM "DO"',
      'WITH RECURSIVE q(n) AS (SELECT 1 UNION SELECT n+1 FROM q WHERE n<2) SELECT * FROM q',
      'WITH q AS NOT MATERIALIZED (WITH r AS MATERIALIZED (SELECT 1) SELECT * FROM r) SELECT * FROM q',
      'SELECT * FROM (WITH q AS (SELECT 1) SELECT * FROM q) AS nested',
      'SELECT * FROM diagnostics FOR UPDATE',
      'SELECT * FROM diagnostics FOR NO KEY UPDATE OF diagnostics SKIP LOCKED',
      'SELECT * FROM diagnostics FOR KEY SHARE',
      'BEGIN; SELECT current_user, current_schema(); COMMIT',
      'BEGIN TRANSACTION; SELECT 1; ROLLBACK WORK',
      'BEGIN WORK; COMMIT TRANSACTION; ROLLBACK',
      "SET LOCAL lock_timeout = '1000ms'; SET LOCAL statement_timeout = '2000ms'",
      "SELECT has_table_privilege(current_user, $1, 'SELECT'), $2::text[]"
    ])('preserves inert/query/transaction context %s', (sql) => {
      expect(auditSqlWrites(sql, options)).toEqual([])
    })

    it.each([
      'WITH q AS (TRUNCATE patient_records) SELECT * FROM q',
      'WITH q AS (DO $$BEGIN NULL; END$$) SELECT * FROM q',
      'WITH q AS (WITH r AS (CALL purge_records()) SELECT * FROM r) SELECT * FROM q',
      'WITH q AS (SELECT 1 INTO patient_records) SELECT * FROM q',
      'WITH q AS (SELECT 1) DROP TABLE patient_records',
      'WITH q AS (SELECT 1) UNKNOWN_COMMAND patient_records',
      'WITH q AS (SELECT 1), r AS (UNKNOWN_COMMAND) SELECT * FROM q',
      'SELECT * FROM (WITH q AS (SELECT 1) SELECT 1 INTO patient_records) AS nested',
      'SELECT (SELECT 1 INTO patient_records)',
      '(SELECT 1 INTO patient_records)',
      'WITH q AS () SELECT 1',
      'WITH q SELECT 1',
      'WITH q AS (SELECT 1)',
      'WITH q AS (SELECT 1; TRUNCATE patient_records) SELECT * FROM q',
      'WITH q AS (BEGIN) SELECT * FROM q',
      'WITH q AS (SELECT 1) COMMIT',
      "WITH q AS (SET LOCAL lock_timeout = '1000ms') SELECT * FROM q",
      'SELECT (SELECT 1; CALL purge_records())',
      'SELECT',
      'BEGIN DROP TABLE patient_records',
      'COMMIT AND CHAIN; DO $$BEGIN NULL; END$$',
      "SET LOCAL lock_timeout = '1000ms' DROP TABLE patient_records"
    ])('refuses nested or uncertain statement grammar %s', (sql) => {
      expect(auditSqlWrites(sql, options).length).toBeGreaterThan(0)
    })
  })

  it.each(unsupportedCommands)('quota does not admit a mixed %s', (command) => {
    const prefix = 'INSERT INTO api_rate_limit_buckets VALUES ($1); '
    const sql = prefix + command
    expect(auditSqlWrites(sql, quota)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'direct_sql_write',
          offset: prefix.length
        })
      ])
    )
    expect(auditSqlWrites(command + '; ' + prefix, quota)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'direct_sql_write', offset: 0 })
      ])
    )
  })

  it('does not expand quota inside nested CTEs', () => {
    const allowed =
      'WITH q AS (WITH r AS (INSERT INTO api_rate_limit_buckets VALUES ($1) RETURNING bucket_key) SELECT * FROM r) SELECT * FROM q'
    expect(auditSqlWrites(allowed, quota)).toEqual([])
    const mixed = allowed.replace(
      'SELECT * FROM r',
      'SELECT * INTO patient_records FROM r'
    )
    expect(auditSqlWrites(mixed, quota)).toEqual([
      expect.objectContaining({
        id: 'direct_sql_write',
        offset: mixed.indexOf('SELECT * INTO')
      })
    ])
  })

  it('retains class offsets after inert tokens and independent mixed commands', () => {
    const sql =
      '/* DO $$DROP$$ */ ; SELECT $$TRUNCATE$$; -- COPY FROM\n CALL purge_records(); DROP TABLE patient_records'
    expect(auditSqlWrites(sql, quota)).toEqual([
      expect.objectContaining({
        id: 'direct_sql_write',
        offset: sql.indexOf('CALL')
      }),
      expect.objectContaining({
        id: 'direct_sql_write',
        offset: sql.indexOf('DROP TABLE')
      })
    ])
  })

  it('preserves literal production query classes read-only', () => {
    const paths = [
      'apps/api/src/postgres-rate-limit.ts',
      'apps/api/src/operator-replay-store.ts',
      'apps/api/src/webhook-security.ts',
      'apps/api/src/server/postgres-role-checks.ts'
    ]
    let count = 0
    const classes = new Set()
    for (const path of paths) {
      const parsed = ts.createSourceFile(
        path,
        readFileSync(path, 'utf8'),
        ts.ScriptTarget.Latest,
        true
      )
      function visit(node) {
        if (
          (ts.isStringLiteral(node) ||
            ts.isNoSubstitutionTemplateLiteral(node)) &&
          /^\s*(SELECT|WITH|BEGIN|COMMIT|ROLLBACK|SET)\b/i.test(node.text)
        ) {
          expect(auditSqlWrites(node.text)).toEqual([])
          classes.add(node.text.trim().split(/\s/)[0].toUpperCase())
          count += 1
        }
        ts.forEachChild(node, visit)
      }
      visit(parsed)
    }
    expect(count).toBeGreaterThan(20)
    expect([...classes].sort()).toEqual([
      'BEGIN',
      'COMMIT',
      'ROLLBACK',
      'SELECT',
      'SET',
      'WITH'
    ])
  })

  it.each([
    'SELECT table_name FROM information_schema.tables WHERE table_name = ANY($1::text[])',
    'SELECT has_table_privilege(current_user, tablename, ANY($1::text[]))',
    'SELECT fields[1], fields[2] FROM api_rate_limit_buckets',
    'SELECT $1::text[][]',
    'INSERT INTO api_rate_limit_buckets VALUES ($1::text[])',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text[]'
  ])('recognizes ordinary array syntax in %s', (sql) => {
    expect(auditSqlWrites(sql, quota)).toEqual([])
  })

  it('preserves the actual replay readiness SELECT excerpts', () => {
    const path = 'apps/api/src/operator-replay-store.ts'
    const parsed = ts.createSourceFile(
      path,
      readFileSync(path, 'utf8'),
      ts.ScriptTarget.Latest,
      true
    )
    const queries = []
    function visit(node) {
      if (
        ts.isMethodDeclaration(node) &&
        node.name.getText(parsed) === 'assertReady'
      ) {
        function collect(child) {
          if (
            (ts.isStringLiteral(child) ||
              ts.isNoSubstitutionTemplateLiteral(child)) &&
            /^\s*SELECT\b/i.test(child.text)
          )
            queries.push(child.text)
          ts.forEachChild(child, collect)
        }
        ts.forEachChild(node, collect)
      } else ts.forEachChild(node, visit)
    }
    visit(parsed)
    expect(queries).toHaveLength(3)
    expect(queries.some((sql) => sql.includes('ANY($1::text[])'))).toBe(true)
    expect(queries.some((sql) => sql.includes('has_table_privilege'))).toBe(
      true
    )
    for (const sql of queries) expect(auditSqlWrites(sql)).toEqual([])
  })

  it('preserves actual array casts in API privilege SELECT queries', () => {
    const path = 'apps/api/src/server/postgres-role-checks.ts'
    const parsed = ts.createSourceFile(
      path,
      readFileSync(path, 'utf8'),
      ts.ScriptTarget.Latest,
      true
    )
    const queries = []
    function visit(node) {
      if (
        (ts.isStringLiteral(node) ||
          ts.isNoSubstitutionTemplateLiteral(node)) &&
        /^\s*SELECT\b/i.test(node.text) &&
        node.text.includes('::text[]')
      )
        queries.push(node.text)
      ts.forEachChild(node, visit)
    }
    visit(parsed)
    expect(queries.length).toBeGreaterThan(0)
    for (const sql of queries) expect(auditSqlWrites(sql)).toEqual([])
  })

  it.each([
    'SELECT fields[1] FROM api_rate_limit_buckets; DELETE FROM patient_records',
    'SELECT $1::text[]; UPDATE appointments SET status=$2',
    'SELECT ANY($1::text[]); INSERT INTO billing_items VALUES ($2)',
    'SELECT fields[DELETE FROM patient_records]',
    'INSERT INTO api_rate_limit_buckets VALUES ($1::text[]); DELETE FROM patient_records',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text[${unknown}]',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text[',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text]',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text[1]',
    'UPDATE api_rate_limit_buckets [] SET request_count=1',
    'UPDATE api_rate_limit_buckets SET bucket_key=$1::text[] ${unknown}'
  ])('array syntax never masks or admits an unknown write in %s', (sql) => {
    expect(
      auditSqlWrites(sql, quota).some((f) => f.id === 'direct_sql_write')
    ).toBe(true)
  })

  it('retains the exact following write offset after array fields', () => {
    const sql =
      'SELECT fields[1], fields[2] FROM api_rate_limit_buckets; DELETE FROM patient_records'
    expect(
      auditSqlWrites(sql, quota).filter((f) => f.id === 'direct_sql_write')
    ).toEqual([
      expect.objectContaining({
        offset: sql.indexOf('DELETE'),
        target: 'patient_records'
      })
    ])
  })

  it.each(deny)('rejects %s', (_name, sql) => {
    const findings = auditSqlWrites(sql, quota)
    expect(findings.some((f) => f.id === 'direct_sql_write')).toBe(true)
    for (const finding of findings) {
      expect(['direct_sql_write', 'sql_lexical_unresolved']).toContain(
        finding.id
      )
      expect(finding.reason.length).toBeGreaterThan(0)
      expect(Number.isInteger(finding.offset)).toBe(true)
      expect(finding.offset).toBeGreaterThanOrEqual(0)
      expect(finding.offset).toBeLessThan(sql.length)
    }
  })

  it.each(allow)('preserves %s', (_name, sql) => {
    expect(auditSqlWrites(sql, quota)).toEqual([])
  })

  it('requires the caller to authorize quota', () => {
    expect(auditSqlWrites(allow[0][1])).toEqual([
      {
        id: 'direct_sql_write',
        reason: expect.any(String),
        offset: 0,
        target: 'api_rate_limit_buckets'
      }
    ])
  })

  it('finds every separate domain command with exact offsets', () => {
    const sql =
      'INSERT INTO patient_records VALUES (1); UPDATE billing_items SET amount=2; DELETE FROM appointments'
    expect(
      auditSqlWrites(sql)
        .filter((f) => f.id === 'direct_sql_write')
        .map((f) => [f.offset, f.target])
    ).toEqual([
      [sql.indexOf('INSERT'), 'patient_records'],
      [sql.indexOf('UPDATE'), 'billing_items'],
      [sql.indexOf('DELETE'), 'appointments']
    ])
  })

  it('detects the following actual write despite ordinary backslash uncertainty', () => {
    const sql = deny.find(
      ([name]) => name === 'ordinary backslash closes quote'
    )[1]
    expect(auditSqlWrites(sql, quota)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'sql_lexical_unresolved',
          offset: sql.indexOf('\\')
        }),
        expect.objectContaining({
          id: 'direct_sql_write',
          target: 'billing_items',
          offset: sql.indexOf('DELETE')
        })
      ])
    )
  })

  it('reports unresolved incomplete quota UPDATE independently of direct writes', () => {
    expect(auditSqlWrites('UPDATE api_rate_limit_buckets', quota)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'sql_lexical_unresolved', offset: 0 })
      ])
    )
  })

  it('suppresses only the validated UPSERT UPDATE index', () => {
    const sql = allow[1][1] + '; UPDATE patient_records SET amount=3'
    expect(
      auditSqlWrites(sql, quota).filter((f) => f.id === 'direct_sql_write')
    ).toEqual([
      expect.objectContaining({
        target: 'patient_records',
        offset: sql.lastIndexOf('UPDATE')
      })
    ])
  })

  it('audits both actual quota writes from the full-context module', () => {
    const sql = literalWrites('apps/api/src/postgres-rate-limit.ts')
    expect(sql).toHaveLength(2)
    expect(sql.some((text) => text.includes('ON CONFLICT'))).toBe(true)
    expect(sql.some((text) => text.startsWith('DELETE'))).toBe(true)
    for (const text of sql) expect(auditSqlWrites(text, quota)).toEqual([])
  })

  it.each([
    'apps/api/src/operator-replay-store.ts',
    'apps/api/src/webhook-security.ts'
  ])('preserves the legacy caller-owned exception for %s', (path) => {
    const sql = literalWrites(path)
    expect(sql.length).toBeGreaterThan(0)
    for (const text of sql) {
      expect(auditSqlWrites(text, { allowSecurityStore: true })).toEqual([])
      expect(
        auditSqlWrites(text, quota).some((f) => f.id === 'direct_sql_write')
      ).toBe(true)
    }
  })

  it('does not let the replay exception hide lexical uncertainty', () => {
    expect(
      auditSqlWrites("INSERT INTO webhook_replay_events VALUES ('unfinished)", {
        allowSecurityStore: true
      })
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'sql_lexical_unresolved' })
      ])
    )
  })

  it('does not let the replay exception hide unresolved write grammar', () => {
    expect(
      auditSqlWrites('UPDATE webhook_replay_events', {
        allowSecurityStore: true
      })
    ).toEqual([
      {
        id: 'sql_lexical_unresolved',
        reason: expect.any(String),
        offset: 0,
        target: 'webhook_replay_events'
      }
    ])
  })

  it('does not inspect host effects in an opaque placeholder', () => {
    const findings = auditSqlWrites(
      'UPDATE ${fetch("https://example.invalid")} SET n=1',
      quota
    )
    expect(findings.map((f) => f.id)).not.toContain('direct_fetch')
    expect(findings.some((f) => f.id === 'sql_lexical_unresolved')).toBe(true)
  })

  it('fails closed on standalone unresolved read SQL', () => {
    expect(auditSqlWrites('SELECT $value$unfinished')).toEqual([
      { id: 'sql_lexical_unresolved', reason: expect.any(String), offset: 7 }
    ])
  })

  it('rejects non-string input without coercion or effects', () => {
    expect(() =>
      auditSqlWrites({
        toString() {
          throw new Error('must not run')
        }
      })
    ).toThrow('SQL input must be a string')
  })
})
