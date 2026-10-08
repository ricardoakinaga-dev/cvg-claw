#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const scopedPrefixes = [
  'apps/api/src',
  'apps/worker/src',
  'packages/agent-core/src'
]
const ignoredName = /(?:\.test|\.spec)\.[cm]?[jt]sx?$/
const forbidden = [
  { id: 'direct_fetch', pattern: /\bfetch\s*\(/g },
  { id: 'direct_evolution', pattern: /EvolutionAPI/g },
  { id: 'direct_chatwoot', pattern: /Chatwoot/g },
  { id: 'direct_channel_send', pattern: /\bsendMessage\s*\(/g },
  { id: 'direct_external_http', pattern: /\b(?:axios|got|undici)\s*\(/g },
  {
    id: 'direct_sql_write',
    pattern: /\bINSERT\s+INTO\s+((?:\$\{[^}]+\}|"(?:[^"]|"")*"|[^\s(;"])+)/gi
  },
  {
    id: 'direct_sql_write',
    // Require SET so prose and an UPSERT's DO UPDATE SET aren't table writes.
    pattern:
      /\bUPDATE\s+((?:\$\{[^}]+\}|"(?:[^"]|"")*"|[^\s(;"])+)(?:\s+(?:AS\s+)?(?:"(?:[^"]|"")*"|[A-Za-z_]\w*))?\s+SET\b/gi
  },
  {
    id: 'direct_sql_write',
    pattern: /\bDELETE\s+FROM\s+((?:\$\{[^}]+\}|"(?:[^"]|"")*"|[^\s(;"])+)/gi
  }
]

// Infrastructure/security stores that own their tables directly and never
// execute a governed business effect. Every entry must stay narrowly scoped.
const allowedSqlWriteInfrastructure = new Map([
  [
    'apps/api/src/webhook-security.ts',
    'webhook signature replay store (pre-kernel security boundary)'
  ],
  [
    'apps/api/src/operator-replay-store.ts',
    'distributed operator token replay claims (pre-kernel security boundary)'
  ]
])

const quotaStore = 'apps/api/src/postgres-rate-limit.ts'
const quotaTable = 'api_rate_limit_buckets'

// SQL comments are recognized only inside decoded host-language literals.
// SQL quoted values/identifiers retain comment markers as ordinary text.
function normalizeSql(text) {
  let sql = ''
  let writeView = ''
  let quote = null
  let escapeString = false
  let unresolved = false
  function append(char, value = false) {
    sql += char
    writeView += value && char !== '\n' ? ' ' : char
  }
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    const next = text[index + 1]
    if (quote) {
      append(char, quote === "'")
      if (char === quote && next === quote) append(text[++index], quote === "'")
      else if (char === '\\' && quote === "'" && escapeString && next)
        append(text[++index], true)
      else if (char === quote) quote = null
      else if (char === '\\' && quote === "'") unresolved = true
    } else if (char === "'" || char === '"') {
      quote = char
      escapeString =
        char === "'" &&
        /[eE]/.test(text[index - 1] ?? '') &&
        !/[\w$]/.test(text[index - 2] ?? '')
      append(char, quote === "'")
    } else if (char === '-' && next === '-') {
      while (index < text.length && text[index] !== '\n') index += 1
      append('\n')
    } else if (char === '/' && next === '*') {
      let depth = 1
      index += 2
      append(' ')
      while (index < text.length && depth > 0) {
        if (text[index] === '/' && text[index + 1] === '*') {
          depth += 1
          index += 2
        } else if (text[index] === '*' && text[index + 1] === '/') {
          depth -= 1
          index += 2
        } else {
          if (text[index] === '\n') append('\n')
          index += 1
        }
      }
      if (depth > 0) unresolved = true
      index -= 1
    } else append(char)
  }
  return { sql, writeView, unresolved: unresolved || quote !== null }
}

// The repository's pinned TypeScript parser owns host syntax: comments are
// trivia, while URLs, escapes, regexes and template expressions stay intact.
function normalizeSource(file) {
  const sqlLiterals = []
  const hostExpressions = []
  let unresolvedSql = false
  function normalizeLiteral(text) {
    const { sql, writeView, unresolved } = normalizeSql(text)
    if (/^\s*(?:WITH|SELECT|INSERT|UPDATE|DELETE)\s/i.test(sql)) {
      unresolvedSql ||= unresolved
      sqlLiterals.push(writeView)
      return '`' + writeView + '`'
    }
    return '`' + sql + '`'
  }
  function visit(node) {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return normalizeLiteral(node.text)
    }
    if (ts.isTemplateExpression(node)) {
      let literal = node.head.text
      for (const span of node.templateSpans) {
        hostExpressions.push(visit(span.expression))
        // SQL values/comments may mask placeholders, never executable ASTs.
        literal +=
          '${__cvg_expression_' +
          hostExpressions.length +
          '__}' +
          span.literal.text
      }
      return normalizeLiteral(literal)
    }
    if (ts.isTaggedTemplateExpression(node)) {
      const tag = ts.isIdentifier(node.tag)
        ? node.tag.text
        : ts.isPropertyAccessExpression(node.tag)
          ? node.tag.name.text
          : null
      if (['fetch', 'sendMessage', 'axios', 'got', 'undici'].includes(tag))
        hostExpressions.push(tag + '(')
    }
    const children = node.getChildren(file)
    return children.length ? children.map(visit).join(' ') : node.getText(file)
  }
  const source = visit(file)
  return {
    source: [source, ...hostExpressions].join('\n'),
    sqlLiterals,
    unresolvedSql
  }
}

const allowedBoundary = (relativePath, findingId, sqlTarget) => {
  if (findingId === 'direct_fetch') return false
  if (findingId === 'direct_evolution' || findingId === 'direct_chatwoot')
    return false
  if (findingId === 'direct_channel_send') return false
  if (findingId === 'direct_external_http') return false
  if (findingId === 'direct_sql_write') {
    if (relativePath === quotaStore) {
      // An unqualified literal table is the only admitted quota target.
      // Dynamic, quoted, schema-qualified and mixed targets fail closed.
      return sqlTarget?.toLowerCase() === quotaTable
    }
    return allowedSqlWriteInfrastructure.has(relativePath)
  }
  return relativePath.startsWith('packages/channel-gateway/src/adapters/')
}

const listed = spawnSync(
  'git',
  [
    'ls-files',
    '-z',
    '--cached',
    '--others',
    '--exclude-standard',
    '--',
    ...scopedPrefixes
  ],
  {
    cwd: root,
    encoding: 'utf8'
  }
)
const files = [
  ...new Set(
    (listed.stdout ?? '')
      .split('\0')
      .filter(Boolean)
      .filter((file) => !ignoredName.test(path.basename(file)))
      .filter((file) => /\.(?:ts|tsx|js|mjs|cjs)$/.test(file))
  )
]

const findings = listed.status === 0 ? [] : [{ id: 'source_inventory_failed' }]
for (const relativePath of files) {
  const parsed = ts.createSourceFile(
    relativePath,
    fs.readFileSync(path.join(root, relativePath), 'utf8'),
    ts.ScriptTarget.Latest,
    true
  )
  if (parsed.parseDiagnostics.length > 0) {
    findings.push({ id: 'source_parse_failed', path: relativePath })
    continue
  }
  const { source, sqlLiterals, unresolvedSql } = normalizeSource(parsed)
  if (unresolvedSql)
    findings.push({ id: 'sql_lexical_unresolved', path: relativePath })
  for (const rule of forbidden) {
    rule.pattern.lastIndex = 0
    let match
    while ((match = rule.pattern.exec(source)) !== null) {
      if (allowedBoundary(relativePath, rule.id, match[1])) continue
      const line = source.slice(0, match.index).split('\n').length
      findings.push({ id: rule.id, path: relativePath, line })
    }
  }
  // In SQL-shaped literals, a recognized write with unresolved grammar/target
  // must reject too. This covers modifiers, parentheses and constructed targets
  // without treating diagnostic prose as an ordinary UPDATE statement.
  const writeIntent =
    /\b(?:INSERT(?:\s+INTO)?|DELETE(?:\s+FROM)?|UPDATE(?!\s+SET\b))\b(?:\s+([^\s;]+))?/gi
  for (const sql of sqlLiterals) {
    for (const match of sql.matchAll(writeIntent)) {
      const target = match[1]?.replace(/\(.*/, '')
      if (!allowedBoundary(relativePath, 'direct_sql_write', target)) {
        findings.push({
          id: 'direct_sql_write',
          path: relativePath,
          grammar: 'write_intent'
        })
      }
    }
  }
}

const report = {
  schemaVersion: 1,
  kind: 'phase11-bypass-audit',
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  scannedFiles: files.length,
  findings,
  allowedEffectBoundaries: [
    'packages/channel-gateway/src/adapters/',
    'packages/model-gateway/src/providers/',
    'packages/adapters/src/fake/'
  ],
  allowedSqlWriteInfrastructure: [...allowedSqlWriteInfrastructure]
    .map(([file, rationale]) => ({ file, rationale }))
    .concat([
      {
        file: quotaStore,
        table: quotaTable,
        rationale:
          'bounded pre-authentication HTTP quota metadata; exact literal table only'
      }
    ]),
  note: 'Application and worker entrypoints must route through the governed kernel; adapter implementations are the only outbound boundary. Comments are stripped before scanning; replay store exceptions remain scoped to their named files, and quota writes require both the exact file and literal table. Tracked and untracked source inventory failures reject the gate. Static scanning does not prove the absence of constructed SQL.'
}
console.log(JSON.stringify(report, null, 2))
process.exitCode = findings.length === 0 ? 0 : 1
