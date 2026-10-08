#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const scopedPrefixes = [
  'apps/api/src',
  'apps/worker/src',
  'packages/agent-core/src'
]
const ignoredName = /(?:\.test\.|\.spec\.)/
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
      /\bUPDATE\s+((?:\$\{[^}]+\}|"(?:[^"]|"")*"|[^\s(;"])+)(?:\s+(?:AS\s+)?[A-Za-z_]\w*)?\s+SET\b/gi
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

const stripComments = (source) =>
  source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ')

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
      .filter((file) => !ignoredName.test(file))
      .filter((file) => /\.(?:ts|tsx|js|mjs|cjs)$/.test(file))
  )
]

const findings = listed.status === 0 ? [] : [{ id: 'source_inventory_failed' }]
for (const relativePath of files) {
  const source = stripComments(
    fs.readFileSync(path.join(root, relativePath), 'utf8')
  )
  for (const rule of forbidden) {
    rule.pattern.lastIndex = 0
    let match
    while ((match = rule.pattern.exec(source)) !== null) {
      if (allowedBoundary(relativePath, rule.id, match[1])) continue
      const line = source.slice(0, match.index).split('\n').length
      findings.push({ id: rule.id, path: relativePath, line })
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
