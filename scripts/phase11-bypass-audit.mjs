#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
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

const program = ts.createProgram(
  files.map((file) => path.join(root, file)),
  {
    target: ts.ScriptTarget.Latest,
    allowJs: true,
    checkJs: true,
    noLib: true,
    noResolve: true
  }
)

for (const relativePath of files) {
  const file = program.getSourceFile(path.join(root, relativePath))
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
  const checker = program.getTypeChecker()
  const mutatedSymbols = new Set()
  const assignedValues = new Map()
  const mutatedObjects = new Set()
  const symbol = (node) =>
    node.parent &&
    ts.isShorthandPropertyAssignment(node.parent) &&
    node.parent.name === node
      ? checker.getShorthandAssignmentValueSymbol(node.parent)
      : checker.getSymbolAtLocation(node)
  const declaration = (node) => {
    const declarations = symbol(node)?.declarations
    return declarations?.length === 1 ? declarations[0] : null
  }
  const isConst = (decl) =>
    ts.isVariableDeclaration(decl) &&
    ts.isVariableDeclarationList(decl.parent) &&
    Boolean(decl.parent.flags & ts.NodeFlags.Const)

  function bindingInitializer(node, forSql = false) {
    const decl = declaration(node)
    if (!decl || mutatedSymbols.has(symbol(node))) return null
    if (ts.isVariableDeclaration(decl))
      return !forSql || isConst(decl) ? decl.initializer : null
    if (ts.isBindingElement(decl)) {
      const container = decl.parent.parent
      if (
        !ts.isVariableDeclaration(container) ||
        (forSql && !isConst(container))
      )
        return null
      if (!ts.isObjectBindingPattern(decl.parent)) return null
      return propertyValue(
        container.initializer,
        decl.propertyName ? propertyKey(decl.propertyName) : decl.name.text
      )
    }
    return null
  }
  function scalar(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node))
      return node.text
    if (ts.isIdentifier(node))
      return scalar(bindingInitializer(node, true), seen)
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const left = scalar(node.left, new Set(seen)),
        right = scalar(node.right, new Set(seen))
      return left === null || right === null ? null : left + right
    }
    if (ts.isTemplateExpression(node)) {
      let text = node.head.text
      for (const span of node.templateSpans) {
        const part = scalar(span.expression, new Set(seen))
        if (part === null) return null
        text += part + span.literal.text
      }
      return text
    }
    return null
  }
  function propertyKey(node) {
    if (
      ts.isIdentifier(node) ||
      ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node)
    )
      return node.text
    return ts.isComputedPropertyName(node) ? scalar(node.expression) : null
  }
  function member(node) {
    node = unwrap(node)
    if (ts.isPropertyAccessExpression(node)) return node.name.text
    return ts.isElementAccessExpression(node)
      ? scalar(node.argumentExpression)
      : null
  }
  function objectNode(node, seen = new Set(), forSql = false) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node))
      return node
    if (ts.isIdentifier(node))
      return objectNode(bindingInitializer(node, forSql), seen, forSql)
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      return objectNode(
        propertyValue(node.expression, member(node), seen, forSql),
        seen,
        forSql
      )
    return null
  }
  // Fold properties in runtime order. An unresolved override erases knowledge,
  // while a later explicit property can establish it again without executing a getter.
  function propertyValue(node, key, seen = new Set(), forSql = true) {
    if (key === null) return null
    const object = objectNode(node, new Set(seen), forSql)
    if (
      !object ||
      !ts.isObjectLiteralExpression(object) ||
      seen.has(object) ||
      mutatedObjects.has(object)
    )
      return null
    seen.add(object)
    let value = null
    for (const prop of object.properties) {
      if (ts.isSpreadAssignment(prop)) {
        const spread = objectNode(prop.expression, new Set(seen), forSql)
        if (!spread || !ts.isObjectLiteralExpression(spread)) value = null
        else {
          const info = propertyPresence(spread, key, new Set(seen), forSql)
          if (info.present) value = info.value
        }
        continue
      }
      const name = prop.name ? propertyKey(prop.name) : null
      if (name === null) {
        value = null
        continue
      }
      if (name !== key) continue
      value = ts.isPropertyAssignment(prop)
        ? prop.initializer
        : ts.isShorthandPropertyAssignment(prop)
          ? prop.name
          : ts.isMethodDeclaration(prop)
            ? prop
            : null
    }
    return value
  }
  function propertyPresence(object, key, seen, forSql) {
    if (seen.has(object) || mutatedObjects.has(object))
      return { present: true, value: null }
    seen.add(object)
    let present = false,
      value = null
    for (const prop of object.properties) {
      if (ts.isSpreadAssignment(prop)) {
        const spread = objectNode(prop.expression, new Set(seen), forSql)
        const info =
          spread && ts.isObjectLiteralExpression(spread)
            ? propertyPresence(spread, key, new Set(seen), forSql)
            : { present: true, value: null }
        if (info.present) {
          present = true
          value = info.value
        }
      } else {
        const name = prop.name ? propertyKey(prop.name) : null
        if (name === null || name === key) {
          present = true
          value =
            name === key && ts.isPropertyAssignment(prop)
              ? prop.initializer
              : name === key && ts.isShorthandPropertyAssignment(prop)
                ? prop.name
                : null
        }
      }
    }
    return { present, value }
  }
  function importEffect(decl) {
    let source = decl
    while (source && !ts.isImportDeclaration(source)) source = source.parent
    const module = source?.moduleSpecifier?.text
    const imported = ts.isImportSpecifier(decl)
      ? (decl.propertyName ?? decl.name).text
      : null
    if (effects.has(imported) || imported === 'query') return imported
    if (['axios', 'got', 'undici'].includes(module)) return module
    if (module === 'node-fetch') return 'fetch'
    return null
  }
  function callee(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      if (symbol(node) && mutatedSymbols.has(symbol(node))) {
        const values = [
          ...(ts.isVariableDeclaration(decl) && decl.initializer
            ? [decl.initializer]
            : []),
          ...(assignedValues.get(symbol(node)) ?? [])
        ]
        const possible = values.map((value) => callee(value, new Set(seen)))
        return (
          possible.find((value) => effects.has(value)) ??
          possible.find(
            (value) =>
              value === 'query' || value === 'unresolved_static_callable'
          ) ??
          null
        )
      }
      if (
        decl &&
        (ts.isImportSpecifier(decl) ||
          ts.isImportClause(decl) ||
          ts.isNamespaceImport(decl))
      )
        return importEffect(decl)
      if (decl && ts.isFunctionDeclaration(decl)) return null
      if (decl && ts.isBindingElement(decl)) {
        const container = decl.parent.parent
        if (
          ts.isVariableDeclaration(container) &&
          ts.isObjectBindingPattern(decl.parent)
        )
          return memberEffect(
            container.initializer,
            decl.propertyName ? propertyKey(decl.propertyName) : decl.name.text,
            seen
          )
      }
      const value = bindingInitializer(node)
      if (value) return callee(value, seen)
      return effects.has(node.text) || node.text === 'query' ? node.text : null
    }
    if (
      ts.isArrowFunction(node) &&
      ts.isCallExpression(node.body) &&
      transparentForwarder(node.body)
    )
      return 'query'
    if (ts.isAwaitExpression(node)) return callee(node.expression, seen)
    if (
      ts.isCallExpression(node) &&
      node.arguments.length === 1 &&
      ts.isStringLiteralLike(node.arguments[0]) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) &&
          node.expression.text === 'require' &&
          !symbol(node.expression)))
    ) {
      const module = node.arguments[0].text
      return module === 'node-fetch'
        ? 'fetch'
        : ['axios', 'got', 'undici'].includes(module)
          ? module
          : null
    }
    if (ts.isCallExpression(node) && member(node.expression) === 'bind')
      return callee(unwrap(node.expression).expression, seen)
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      return memberEffect(node.expression, member(node), seen)
    return null
  }
  function memberEffect(base, name, seen) {
    if (name === null) return null
    if (['call', 'apply', 'bind'].includes(name))
      return callee(base, new Set(seen))
    const baseEffect = callee(base, new Set(seen))
    if (['axios', 'got', 'undici'].includes(baseEffect)) return baseEffect
    const object = objectNode(base)
    if (object && ts.isObjectLiteralExpression(object)) {
      if (mutatedObjects.has(object)) return 'unresolved_static_callable'
      const value = propertyValue(base, name)
      return value ? callee(value, new Set(seen)) : 'unresolved_static_callable'
    }
    return effects.has(name) || name === 'query' ? name : null
  }
  function mutationOrigin(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      if (decl && ts.isVariableDeclaration(decl))
        return mutationOrigin(decl.initializer, seen)
      if (decl && ts.isBindingElement(decl)) {
        const container = decl.parent.parent
        if (ts.isVariableDeclaration(container)) {
          const value = ts.isObjectBindingPattern(decl.parent)
            ? propertyValue(
                container.initializer,
                decl.propertyName
                  ? propertyKey(decl.propertyName)
                  : decl.name.text,
                new Set(),
                false
              )
            : null
          return (
            (value && mutationOrigin(value, new Set(seen))) ??
            mutationOrigin(container.initializer, seen)
          )
        }
      }
      return null
    }
    if (ts.isObjectLiteralExpression(node) || ts.isArrayLiteralExpression(node))
      return node
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    ) {
      const property = propertyValue(
        node.expression,
        member(node),
        new Set(),
        false
      )
      return (
        (property && mutationOrigin(property, seen)) ??
        mutationOrigin(node.expression, seen)
      )
    }
    if (ts.isCallExpression(node) && member(node.expression) === 'bind')
      return mutationOrigin(unwrap(node.expression).expression, seen)
    return null
  }
  function pureLocalCallable(node) {
    node = unwrap(node)
    if (
      !node ||
      !(
        ts.isArrowFunction(node) ||
        ts.isFunctionExpression(node) ||
        ts.isMethodDeclaration(node)
      )
    )
      return false
    let pure = true
    function inspect(child) {
      if (
        ts.isCallExpression(child) ||
        ts.isTaggedTemplateExpression(child) ||
        ts.isNewExpression(child) ||
        ts.isDeleteExpression(child) ||
        ts.isAwaitExpression(child) ||
        (ts.isBinaryExpression(child) &&
          child.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
          child.operatorToken.kind <= ts.SyntaxKind.LastAssignment) ||
        ((ts.isPrefixUnaryExpression(child) ||
          ts.isPostfixUnaryExpression(child)) &&
          [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(
            child.operator
          ))
      )
        pure = false
      ts.forEachChild(child, inspect)
    }
    inspect(node.body)
    return pure
  }
  const readMethods = new Set([
    'join',
    'includes',
    'indexOf',
    'lastIndexOf',
    'at',
    'slice',
    'concat',
    'toString',
    'entries',
    'keys',
    'values'
  ])
  const nodes = []
  function gather(node) {
    nodes.push(node)
    ts.forEachChild(node, gather)
  }
  gather(file)
  for (const node of nodes) {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      ts.isIdentifier(unwrap(node.left))
    ) {
      const binding = symbol(unwrap(node.left))
      if (binding) {
        const values = assignedValues.get(binding) ?? []
        values.push(node.right)
        assignedValues.set(binding, values)
      }
    }
  }
  // Discover all mutation/escape sites before inferring any query. Aliases are
  // chased to object identities even when a different alias was already tainted.
  for (const node of nodes) {
    let target = null
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
    )
      target = node.left
    if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      [ts.SyntaxKind.PlusPlusToken, ts.SyntaxKind.MinusMinusToken].includes(
        node.operator
      )
    )
      target = node.operand
    if (ts.isDeleteExpression(node)) target = node.expression
    if (target) {
      if (ts.isIdentifier(unwrap(target)))
        mutatedSymbols.add(symbol(unwrap(target)))
      const origin = mutationOrigin(target)
      if (origin) mutatedObjects.add(origin)
    }
    if (!ts.isCallExpression(node)) continue
    const expr = unwrap(node.expression),
      name = member(expr)
    let receiver =
      ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)
        ? expr.expression
        : expr
    const receiverObject = mutationOrigin(receiver)
    const effect = callee(expr)
    const localMember =
      name &&
      (ts.isPropertyAccessExpression(expr) ||
        ts.isElementAccessExpression(expr))
        ? propertyValue(expr.expression, name)
        : null
    if (
      receiverObject &&
      !readMethods.has(name) &&
      !effects.has(effect) &&
      effect !== 'query' &&
      !pureLocalCallable(localMember)
    )
      mutatedObjects.add(receiverObject)
    for (const arg of node.arguments) {
      const origin = mutationOrigin(arg)
      if (origin && effect !== 'query') mutatedObjects.add(origin)
    }
  }
  function finiteLoopValues(expression) {
    if (!ts.isIdentifier(expression)) return null
    const reference = symbol(expression)
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
      const decl = ancestor.initializer.declarations[0]
      if (!ts.isIdentifier(decl.name) || symbol(decl.name) !== reference)
        continue
      const array = objectNode(ancestor.expression, new Set(), true)
      if (
        !array ||
        mutatedObjects.has(array) ||
        !ts.isArrayLiteralExpression(array) ||
        !array.elements.length ||
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
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node))
      return [node.text]
    if (ts.isIdentifier(node)) {
      const loop = finiteLoopValues(node)
      return loop ?? sqlVariants(bindingInitializer(node, true), seen)
    }
    if (ts.isObjectLiteralExpression(node))
      return sqlVariants(propertyValue(node, 'text'), seen)
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      return sqlVariants(propertyValue(node.expression, member(node)), seen)
    const cross = (left, right) =>
      left.length * right.length > 64
        ? null
        : left.flatMap((a) => right.map((b) => a + b))
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const left = sqlVariants(node.left, new Set(seen)),
        right = sqlVariants(node.right, new Set(seen))
      return left === null && right === null
        ? null
        : cross(left ?? [placeholder], right ?? [placeholder])
    }
    if (ts.isTemplateExpression(node)) {
      let result = [node.head.text]
      for (const span of node.templateSpans) {
        const choices = sqlVariants(span.expression, new Set(seen))
        const expr = unwrap(span.expression)
        if (choices === null && ts.isIdentifier(expr) && declaration(expr))
          return null
        result = cross(result, choices ?? [placeholder])
        if (result === null) return null
        result = result.map((prefix) => prefix + span.literal.text)
      }
      return result
    }
    return null
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
      if (name === 'unresolved_static_callable') finding(name, node)
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
