#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'
import { auditSqlWrites } from './lib/bypass-sql-audit.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const scopedPrefixes = [
  'apps/api/src',
  'apps/worker/src',
  'packages/agent-core/src'
]
const ignoredName = /(?:\.test|\.spec)\.[cm]?[jt]sx?$/
const quotaStore = 'apps/api/src/postgres-rate-limit.ts'
const replayStores = new Map([
  [
    'apps/api/src/webhook-security.ts',
    'webhook signature replay store (pre-kernel security boundary)'
  ],
  [
    'apps/api/src/operator-replay-store.ts',
    'distributed operator token replay claims (pre-kernel security boundary)'
  ]
])
const effects = new Map([
  ['fetch', 'direct_fetch'],
  ['sendMessage', 'direct_channel_send'],
  ['axios', 'direct_external_http'],
  ['got', 'direct_external_http'],
  ['undici', 'direct_external_http']
])
const placeholder = '$' + '{__cvg_unknown__}'

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
  { cwd: root, encoding: 'utf8' }
)
const files = [...new Set((listed.stdout ?? '').split('\0').filter(Boolean))]
  .filter((file) => !ignoredName.test(path.basename(file)))
  .filter((file) => /\.(?:ts|tsx|js|mjs|cjs)$/.test(file))
const findings = listed.status === 0 ? [] : [{ id: 'source_inventory_failed' }]
const forwardingQueries = []

function unwrap(node) {
  while (
    node &&
    (ts.isParenthesizedExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isTypeAssertionExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isSatisfiesExpression(node))
  )
    node = node.expression
  return node
}

for (const relativePath of files) {
  const file = ts.createSourceFile(
    relativePath,
    fs.readFileSync(path.join(root, relativePath), 'utf8'),
    ts.ScriptTarget.Latest,
    true
  )
  function finding(id, node, extra = {}) {
    findings.push({
      id,
      path: relativePath,
      line: file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1,
      ...extra
    })
  }
  if (file.parseDiagnostics.length) {
    findings.push({ id: 'source_parse_failed', path: relativePath })
    continue
  }
  const bindings = new Map()
  const constantBindings = new Set()
  const mutatedBindings = new Set()
  function receiverName(node) {
    node = unwrap(node)
    while (
      node &&
      (ts.isPropertyAccessExpression(node) ||
        ts.isElementAccessExpression(node))
    )
      node = unwrap(node.expression)
    return node && ts.isIdentifier(node) ? node.text : null
  }
  function collect(node) {
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer
    ) {
      const entries = bindings.get(node.name.text) ?? []
      entries.push(node.initializer)
      bindings.set(node.name.text, entries)
      if (
        ts.isVariableDeclarationList(node.parent) &&
        node.parent.flags & ts.NodeFlags.Const
      )
        constantBindings.add(node.name.text)
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    )
      mutatedBindings.add(receiverName(node.left))
    if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(
        node.operator
      )
    )
      mutatedBindings.add(receiverName(node.operand))
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(unwrap(node.expression)) &&
      [
        'push',
        'pop',
        'shift',
        'unshift',
        'splice',
        'sort',
        'reverse',
        'fill',
        'copyWithin'
      ].includes(unwrap(node.expression).name.text)
    )
      mutatedBindings.add(receiverName(unwrap(node.expression).expression))
    ts.forEachChild(node, collect)
  }
  collect(file)
  function bound(name, forSql = false) {
    if (forSql && (!constantBindings.has(name) || mutatedBindings.has(name)))
      return null
    const entries = bindings.get(name)
    return entries?.length === 1 ? entries[0] : null
  }
  function member(node) {
    if (ts.isPropertyAccessExpression(node)) return node.name.text
    if (ts.isElementAccessExpression(node)) {
      const key = unwrap(node.argumentExpression)
      return key && ts.isStringLiteralLike(key) ? key.text : null
    }
    return null
  }
  function callee(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) {
      if (effects.has(node.text) || node.text === 'query') return node.text
      const initializer = bound(node.text)
      return initializer ? callee(initializer, seen) : node.text
    }
    if (ts.isCallExpression(node) && member(unwrap(node.expression)) === 'bind')
      return callee(unwrap(node.expression).expression, seen)
    const name = member(node)
    if (!name) return null
    const base = callee(node.expression, seen)
    if (name === 'call' || name === 'apply') return base
    if (['axios', 'got', 'undici'].includes(base)) return base
    return name
  }
  function sqlText(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isStringLiteralLike(node)) return node.text
    if (ts.isTemplateExpression(node))
      return (
        node.head.text +
        node.templateSpans
          .map((span) => placeholder + span.literal.text)
          .join('')
      )
    if (ts.isIdentifier(node)) return sqlText(bound(node.text, true), seen)
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const left = sqlText(node.left, new Set(seen))
      const right = sqlText(node.right, new Set(seen))
      if (left !== null || right !== null)
        return (left ?? placeholder) + (right ?? placeholder)
    }
    if (ts.isObjectLiteralExpression(node)) {
      const text = node.properties.find(
        (property) =>
          ts.isPropertyAssignment(property) &&
          ((ts.isIdentifier(property.name) && property.name.text === 'text') ||
            (ts.isStringLiteral(property.name) &&
              property.name.text === 'text'))
      )
      if (text) return sqlText(text.initializer, seen)
    }
    return null
  }
  function finiteLoopValues(expression) {
    expression = unwrap(expression)
    if (!expression || !ts.isIdentifier(expression)) return null
    for (
      let ancestor = expression.parent;
      ancestor;
      ancestor = ancestor.parent
    ) {
      if (ts.isFunctionLike(ancestor)) return null
      if (
        !ts.isForOfStatement(ancestor) ||
        !ts.isVariableDeclarationList(ancestor.initializer) ||
        !(ancestor.initializer.flags & ts.NodeFlags.Const) ||
        ancestor.initializer.declarations.length !== 1
      )
        continue
      const declaration = ancestor.initializer.declarations[0]
      if (
        !ts.isIdentifier(declaration.name) ||
        declaration.name.text !== expression.text ||
        !ts.isIdentifier(unwrap(ancestor.expression))
      )
        continue
      const array = unwrap(bound(unwrap(ancestor.expression).text, true))
      if (
        !array ||
        !ts.isArrayLiteralExpression(array) ||
        array.elements.length === 0 ||
        array.elements.length > 64 ||
        !array.elements.every(
          (item) =>
            ts.isStringLiteralLike(item) &&
            /^[A-Za-z_][A-Za-z_0-9]*$/.test(item.text)
        )
      )
        return null
      return array.elements.map((item) => item.text)
    }
    return null
  }
  function sqlVariants(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) return sqlVariants(bound(node.text, true), seen)
    if (ts.isTemplateExpression(node)) {
      let result = [node.head.text]
      for (const span of node.templateSpans) {
        const staticText = sqlText(span.expression)
        const choices =
          staticText !== null
            ? [staticText]
            : (finiteLoopValues(span.expression) ?? [placeholder])
        if (result.length * choices.length > 64) return null
        result = result.flatMap((prefix) =>
          choices.map((choice) => prefix + choice + span.literal.text)
        )
      }
      return result
    }
    const text = sqlText(node)
    return text === null ? null : [text]
  }
  function transparentForwarder(node) {
    if (
      relativePath !== 'apps/api/src/server/bootstrap-persistence.ts' ||
      !ts.isCallExpression(node)
    )
      return false
    const arrow = node.parent
    if (
      !ts.isArrowFunction(arrow) ||
      arrow.body !== node ||
      !ts.isPropertyAssignment(arrow.parent) ||
      arrow.parent.initializer !== arrow ||
      arrow.parent.name.getText(file) !== 'query'
    )
      return false
    const target = unwrap(node.expression)
    if (
      !ts.isPropertyAccessExpression(target) ||
      !ts.isIdentifier(target.expression) ||
      target.expression.text !== 'client' ||
      target.name.text !== 'query'
    )
      return false
    return (
      node.arguments.length === arrow.parameters.length &&
      node.arguments.length === 2 &&
      arrow.parameters.every(
        (parameter, index) =>
          ts.isIdentifier(parameter.name) &&
          ts.isIdentifier(node.arguments[index]) &&
          parameter.name.text === node.arguments[index].text
      )
    )
  }
  function visit(node) {
    if (ts.isCallExpression(node) || ts.isTaggedTemplateExpression(node)) {
      const expression = unwrap(
        ts.isCallExpression(node) ? node.expression : node.tag
      )
      const name = callee(expression)
      // bind constructs a function; its later invocation is resolved above.
      if (effects.has(name) && member(expression) !== 'bind')
        finding(effects.get(name), node)
      if (name === 'query') {
        let argument = ts.isCallExpression(node)
          ? node.arguments[0]
          : node.template
        if (ts.isCallExpression(node) && member(expression) === 'call')
          argument = node.arguments[1]
        if (ts.isCallExpression(node) && member(expression) === 'apply') {
          const args = unwrap(node.arguments[1])
          argument =
            args && ts.isArrayLiteralExpression(args) ? args.elements[0] : null
        }
        const variants = sqlVariants(argument)
        if (variants === null) {
          if (transparentForwarder(node))
            forwardingQueries.push({
              path: relativePath,
              line:
                file.getLineAndCharacterOfPosition(node.getStart(file)).line +
                1,
              kind: 'existing-transparent-parameter-forwarder',
              sqlTargetExemption: false
            })
          else
            finding('direct_sql_write', node, {
              reason: 'unresolved_query_expression'
            })
        } else {
          for (const sql of variants)
            for (const result of auditSqlWrites(sql, {
              allowQuota: relativePath === quotaStore,
              allowSecurityStore: replayStores.has(relativePath)
            }))
              finding(result.id, node, result)
        }
      }
    }
    if (ts.isIdentifier(node)) {
      if (/EvolutionAPI/.test(node.text)) finding('direct_evolution', node)
      if (/Chatwoot/.test(node.text)) finding('direct_chatwoot', node)
    }
    // Visit executable template expressions independently from SQL text.
    ts.forEachChild(node, visit)
  }
  visit(file)
}

const report = {
  schemaVersion: 1,
  kind: 'phase11-bypass-audit',
  status: findings.length === 0 ? 'PASS' : 'FAIL',
  scannedFiles: files.length,
  findings,
  forwardingQueries,
  allowedEffectBoundaries: [
    'packages/channel-gateway/src/adapters/',
    'packages/model-gateway/src/providers/',
    'packages/adapters/src/fake/'
  ],
  allowedSqlWriteInfrastructure: [...replayStores]
    .map(([file, rationale]) => ({ file, rationale }))
    .concat([
      {
        file: quotaStore,
        table: 'api_rate_limit_buckets',
        rationale:
          'bounded pre-authentication quota; exact static target and supported write grammar only'
      }
    ]),
  note: 'Host calls are inspected as ASTs independently of SQL. Inert strings are data. SQL query text uses a separate lexer; quota requires validated static target/grammar. The existing exact pure parameter forwarder is disclosed without granting a SQL target exemption. Constructed effects are not universally decided; fresh artifact review remains required.'
}
console.log(JSON.stringify(report, null, 2))
process.exitCode = findings.length ? 1 : 0
