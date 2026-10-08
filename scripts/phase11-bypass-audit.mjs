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
  const assignedContainerValues = new Map()
  const assignedProperties = new Map()
  const mutatedObjects = new Set()
  const symbol = (node) =>
    node.parent &&
    ts.isShorthandPropertyAssignment(node.parent) &&
    node.parent.name === node
      ? checker.getShorthandAssignmentValueSymbol(node.parent)
      : checker.getSymbolAtLocation(node)
  const declaration = (node) => {
    // TypeScript also records expando property-assignment identifiers on a
    // function symbol. They are not additional lexical binding declarations.
    const declarations = symbol(node)?.declarations?.filter(
      (decl) => !ts.isIdentifier(decl)
    )
    return declarations?.length === 1 ? declarations[0] : null
  }
  const isConst = (decl) =>
    ts.isVariableDeclaration(decl) &&
    ts.isVariableDeclarationList(decl.parent) &&
    Boolean(decl.parent.flags & ts.NodeFlags.Const)

  function undefinedValue(node, seen = new Set()) {
    node = unwrap(node)
    if (!node) return true
    if (seen.has(node)) return null
    seen.add(node)
    if (
      ts.isVoidExpression(node) ||
      (ts.isIdentifier(node) && node.text === 'undefined' && !declaration(node))
    )
      return true
    if (ts.isIdentifier(node)) {
      const value = bindingInitializer(node)
      if (value) return undefinedValue(value, seen)
      return effects.has(node.text) ? false : null
    }
    return ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node) ||
      ts.isObjectLiteralExpression(node) ||
      ts.isArrayLiteralExpression(node) ||
      ts.isFunctionLike(node) ||
      [
        ts.SyntaxKind.TrueKeyword,
        ts.SyntaxKind.FalseKeyword,
        ts.SyntaxKind.NullKeyword
      ].includes(node.kind)
      ? false
      : null
  }
  function objectRest(input, excluded, seen = new Set()) {
    const object = objectNode(input, new Set(seen), false)
    if (
      !object ||
      !ts.isObjectLiteralExpression(object) ||
      seen.has(object) ||
      mutatedObjects.has(object)
    )
      return null
    seen.add(object)
    const properties = new Map()
    for (const prop of object.properties) {
      if (ts.isSpreadAssignment(prop)) {
        const nested = objectRest(prop.expression, [], new Set(seen))
        if (!nested) return null
        for (const item of nested.properties)
          properties.set(propertyKey(item.name), item)
      } else {
        const key = prop.name ? propertyKey(prop.name) : null
        if (key === null) return null
        properties.set(key, prop)
      }
      if (properties.size > 64) return null
    }
    return ts.factory.createObjectLiteralExpression(
      [...properties]
        .filter(([key]) => !excluded.includes(key))
        .map(([, value]) => value)
    )
  }
  function bindingSource(decl, forSql = false) {
    const pattern = decl.parent,
      owner = pattern.parent
    const input = ts.isVariableDeclaration(owner)
      ? !forSql || isConst(owner)
        ? owner.initializer
        : null
      : ts.isBindingElement(owner)
        ? bindingSource(owner, forSql)
        : null
    if (!input) return null
    if (ts.isArrayBindingPattern(pattern)) {
      const index = pattern.elements.indexOf(decl)
      const array = objectNode(input, new Set(), forSql)
      const values =
        array && ts.isArrayLiteralExpression(array)
          ? arrayValues(array, new Set(), forSql)
          : null
      if (decl.dotDotDotToken)
        return values
          ? ts.factory.createArrayLiteralExpression(values.slice(index))
          : null
      const selected = values?.[index]
      return decl.initializer && undefinedValue(selected) === true
        ? decl.initializer
        : (selected ?? null)
    }
    if (!ts.isObjectBindingPattern(pattern)) return null
    if (decl.dotDotDotToken)
      return objectRest(
        input,
        pattern.elements
          .filter((item) => !item.dotDotDotToken)
          .map((item) =>
            item.propertyName ? propertyKey(item.propertyName) : item.name.text
          )
      )
    const selected = propertyValue(
      input,
      decl.propertyName ? propertyKey(decl.propertyName) : decl.name.text,
      new Set(),
      forSql
    )
    return decl.initializer && undefinedValue(selected) === true
      ? decl.initializer
      : (selected ?? null)
  }
  function bindingInitializer(node, forSql = false) {
    const decl = declaration(node)
    if (!decl || mutatedSymbols.has(symbol(node))) return null
    if (ts.isVariableDeclaration(decl))
      return !forSql || isConst(decl) ? decl.initializer : null
    return ts.isBindingElement(decl) ? bindingSource(decl, forSql) : null
  }
  function arrayValues(array, seen = new Set(), forSql = false) {
    if (seen.has(array) || mutatedObjects.has(array)) return null
    seen.add(array)
    const values = []
    for (const item of array.elements) {
      if (ts.isSpreadElement(item)) {
        const source = objectNode(item.expression, new Set(seen), forSql)
        const nested =
          source && ts.isArrayLiteralExpression(source)
            ? arrayValues(source, new Set(seen), forSql)
            : null
        if (!nested) return null
        values.push(...nested)
      } else values.push(ts.isOmittedExpression(item) ? null : item)
      if (values.length > 64) return null
    }
    return values
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
    if (object && ts.isArrayLiteralExpression(object)) {
      const values = arrayValues(object, new Set(seen), forSql)
      if (!values) return null
      if (key === 'length')
        return ts.factory.createNumericLiteral(values.length)
      return /^(?:0|[1-9][0-9]*)$/.test(key)
        ? (values[Number(key)] ?? null)
        : null
    }
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
          ...(decl && ts.isVariableDeclaration(decl) && decl.initializer
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
      if (decl && ts.isFunctionDeclaration(decl) && decl.body) return null
      if (decl && ts.isBindingElement(decl)) {
        const value = bindingSource(decl)
        if (value) return callee(value, seen)
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
    if (!base || name === null) return null
    if (['call', 'apply', 'bind'].includes(name))
      return callee(base, new Set(seen))
    const baseEffect = callee(base, new Set(seen))
    if (['axios', 'got', 'undici'].includes(baseEffect)) return baseEffect
    if (baseEffect === 'fetch' && name === 'default') return 'fetch'
    const object = objectNode(base)
    if (object) {
      if (
        ts.isArrayLiteralExpression(object) &&
        !/^(?:0|[1-9][0-9]*)$/.test(name)
      ) {
        const assigned = assignedProperties.get(object)?.get(name) ?? []
        const possible = assigned.map((value) => callee(value, new Set(seen)))
        if (possible.some((value) => effects.has(value)))
          return possible.find((value) => effects.has(value))
        if (possible.includes('query')) return 'query'
        return effects.has(name) || name === 'query' ? name : null
      }
      if (mutatedObjects.has(object)) return 'unresolved_static_callable'
      const value = propertyValue(base, name, new Set(), false)
      return value ? callee(value, new Set(seen)) : 'unresolved_static_callable'
    }
    const candidates = [
      ...(ts.isIdentifier(unwrap(base)) || member(base) !== null
        ? receiverOrigins(base)
        : [])
    ].filter(
      (owner) =>
        ts.isObjectLiteralExpression(owner) ||
        ts.isArrayLiteralExpression(owner)
    )
    if (candidates.length) {
      const possible = candidates.map((owner) =>
        memberEffect(owner, name, new Set(seen))
      )
      return (
        possible.find((value) => effects.has(value)) ??
        possible.find(
          (value) => value === 'query' || value === 'unresolved_static_callable'
        ) ??
        null
      )
    }
    return effects.has(name) || name === 'query' ? name : null
  }
  function mutationOrigin(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      if (decl && ts.isFunctionDeclaration(decl)) return decl
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
    if (
      ts.isObjectLiteralExpression(node) ||
      ts.isArrayLiteralExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isFunctionExpression(node) ||
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node)
    )
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
        ts.isMethodDeclaration(node) ||
        ts.isFunctionDeclaration(node)
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
    if (!node.body) return false
    inspect(node.body)
    return pure
  }
  function reachableOrigins(node, seen = new Set(), found = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return found
    seen.add(node)
    // These expressions expose a primitive value, not the objects read to
    // produce it. Their executable calls/mutations are audited separately.
    if (
      ts.isStringLiteralLike(node) ||
      ts.isNumericLiteral(node) ||
      ts.isTemplateExpression(node)
    )
      return found
    if (
      ts.isBinaryExpression(node) &&
      [
        ts.SyntaxKind.PlusToken,
        ts.SyntaxKind.MinusToken,
        ts.SyntaxKind.AsteriskToken,
        ts.SyntaxKind.SlashToken,
        ts.SyntaxKind.PercentToken,
        ts.SyntaxKind.EqualsEqualsToken,
        ts.SyntaxKind.EqualsEqualsEqualsToken,
        ts.SyntaxKind.ExclamationEqualsToken,
        ts.SyntaxKind.ExclamationEqualsEqualsToken,
        ts.SyntaxKind.LessThanToken,
        ts.SyntaxKind.GreaterThanToken,
        ts.SyntaxKind.LessThanEqualsToken,
        ts.SyntaxKind.GreaterThanEqualsToken
      ].includes(node.operatorToken.kind)
    )
      return found
    if (ts.isCallExpression(node)) {
      const expr = unwrap(node.expression),
        name = member(expr)
      if (
        ts.isPropertyAccessExpression(expr) ||
        ts.isElementAccessExpression(expr)
      ) {
        const origin = objectNode(expr.expression, new Set(), false)
        if (
          origin &&
          ts.isArrayLiteralExpression(origin) &&
          !mutatedObjects.has(origin) &&
          ['join', 'includes', 'indexOf', 'lastIndexOf', 'toString'].includes(
            name
          )
        )
          return found
      }
    }
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      if (decl && ts.isVariableDeclaration(decl))
        reachableOrigins(decl.initializer, seen, found)
      if (decl && ts.isBindingElement(decl))
        reachableOrigins(bindingInitializer(node), seen, found)
      if (decl && ts.isFunctionDeclaration(decl))
        reachableOrigins(decl, seen, found)
      for (const value of assignedValues.get(symbol(node)) ?? [])
        reachableOrigins(value, seen, found)
      return found
    }
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    ) {
      const value = propertyValue(
        node.expression,
        member(node),
        new Set(),
        false
      )
      if (value) reachableOrigins(value, seen, found)
      else reachableOrigins(node.expression, seen, found)
      return found
    }
    if (
      ts.isObjectLiteralExpression(node) ||
      ts.isArrayLiteralExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isFunctionExpression(node) ||
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isGetAccessorDeclaration(node) ||
      ts.isSetAccessorDeclaration(node)
    ) {
      found.add(node)
      for (const value of assignedContainerValues.get(node) ?? [])
        reachableOrigins(value, seen, found)
    }
    if (ts.isObjectLiteralExpression(node)) {
      for (const prop of node.properties) {
        if (ts.isPropertyAssignment(prop))
          reachableOrigins(prop.initializer, seen, found)
        else if (ts.isShorthandPropertyAssignment(prop))
          reachableOrigins(prop.name, seen, found)
        else if (ts.isSpreadAssignment(prop))
          reachableOrigins(prop.expression, seen, found)
        else if (
          ts.isMethodDeclaration(prop) ||
          ts.isGetAccessorDeclaration(prop) ||
          ts.isSetAccessorDeclaration(prop)
        )
          reachableOrigins(prop, seen, found)
      }
    } else if (ts.isArrayLiteralExpression(node)) {
      for (const item of node.elements) reachableOrigins(item, seen, found)
    } else if (ts.isFunctionLike(node)) {
      // A closure exposes returned references. Captured references that are
      // only read cannot be acquired by its caller. Mutation and calls in its
      // body are still discovered by the normal whole-AST pass.
      const returns = (body) => {
        if (ts.isReturnStatement(body)) {
          reachableOrigins(body.expression, seen, found)
          return
        }
        if (ts.isFunctionLike(body)) return
        if (
          ts.isBinaryExpression(body) &&
          body.operatorToken.kind === ts.SyntaxKind.EqualsToken
        ) {
          for (const leaf of assignmentLeaves(body.left)) {
            let owner = leaf
            while (
              ts.isPropertyAccessExpression(owner) ||
              ts.isElementAccessExpression(owner)
            )
              owner = unwrap(owner.expression)
            const decl = ts.isIdentifier(owner) ? declaration(owner) : null
            let functionOwner = decl?.parent
            while (functionOwner && !ts.isFunctionLike(functionOwner))
              functionOwner = functionOwner.parent
            // A local scratch object is inaccessible unless subsequently returned.
            if (functionOwner !== node || (decl && ts.isParameter(decl)))
              reachableOrigins(body.right, seen, found)
          }
        }
        ts.forEachChild(body, returns)
      }
      if (node.body && ts.isBlock(node.body)) returns(node.body)
      else if (node.body) reachableOrigins(node.body, seen, found)
    } else
      ts.forEachChild(node, (child) => {
        reachableOrigins(child, seen, found)
      })
    return found
  }
  function receiverOrigins(node, seen = new Set(), found = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return found
    seen.add(node)
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      if (decl && ts.isVariableDeclaration(decl))
        receiverOrigins(decl.initializer, seen, found)
      if (decl && ts.isBindingElement(decl))
        receiverOrigins(bindingSource(decl), seen, found)
      if (decl && ts.isFunctionDeclaration(decl)) found.add(decl)
      for (const value of assignedValues.get(symbol(node)) ?? [])
        receiverOrigins(value, seen, found)
      return found
    }
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    ) {
      const name = member(node),
        owners = receiverOrigins(node.expression, new Set(seen))
      let resolved = false
      for (const owner of owners) {
        const value = propertyValue(owner, name, new Set(), false)
        if (value) {
          resolved = true
          receiverOrigins(value, seen, found)
        }
        for (const stored of assignedProperties.get(owner)?.get(name) ?? []) {
          resolved = true
          receiverOrigins(stored, seen, found)
        }
        if (ts.isObjectLiteralExpression(owner)) {
          for (const prop of owner.properties)
            if (
              ts.isGetAccessorDeclaration(prop) &&
              propertyKey(prop.name) === name
            ) {
              resolved = true
              for (const ref of reachableOrigins(prop))
                if (ref !== prop) found.add(ref)
            }
        }
      }
      if (!resolved) for (const owner of owners) found.add(owner)
      return found
    }
    if (
      ts.isObjectLiteralExpression(node) ||
      ts.isArrayLiteralExpression(node) ||
      ts.isFunctionLike(node)
    )
      found.add(node)
    return found
  }
  function assignmentLeaves(node) {
    node = unwrap(node)
    if (!node) return []
    if (ts.isObjectLiteralExpression(node))
      return node.properties.flatMap((prop) =>
        ts.isPropertyAssignment(prop)
          ? assignmentLeaves(prop.initializer)
          : ts.isShorthandPropertyAssignment(prop)
            ? assignmentLeaves(prop.name)
            : ts.isSpreadAssignment(prop)
              ? assignmentLeaves(prop.expression)
              : []
      )
    if (ts.isArrayLiteralExpression(node))
      return node.elements.flatMap(assignmentLeaves)
    if (ts.isSpreadElement(node)) return assignmentLeaves(node.expression)
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    )
      return assignmentLeaves(node.left)
    return [node]
  }
  function callableValue(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (
      ts.isArrowFunction(node) ||
      ts.isFunctionExpression(node) ||
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node)
    )
      return node
    if (ts.isIdentifier(node)) {
      const decl = declaration(node)
      return decl && ts.isFunctionDeclaration(decl)
        ? decl
        : callableValue(bindingInitializer(node), seen)
    }
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      return callableValue(propertyValue(node.expression, member(node)), seen)
    return null
  }
  function boundArguments(node, seen = new Set()) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isIdentifier(node)) {
      const value = bindingInitializer(node)
      return value ? boundArguments(value, seen) : []
    }
    if (ts.isCallExpression(node) && member(node.expression) === 'bind') {
      const prior = boundArguments(unwrap(node.expression).expression, seen)
      if (prior === null) return null
      const prefix = []
      for (const arg of node.arguments.slice(1)) {
        if (ts.isSpreadElement(arg)) {
          const array = objectNode(arg.expression, new Set(), true)
          if (
            !array ||
            !ts.isArrayLiteralExpression(array) ||
            mutatedObjects.has(array) ||
            array.elements.some(ts.isSpreadElement)
          )
            return null
          prefix.push(...array.elements)
        } else prefix.push(arg)
      }
      return [...prior, ...prefix]
    }
    return []
  }
  function invocationSqlArgument(node) {
    if (!ts.isCallExpression(node)) return node.template
    let target = unwrap(node.expression),
      args = [...node.arguments]
    if (member(target) === 'call') {
      args = args.slice(1)
      target = unwrap(target.expression)
    } else if (member(target) === 'apply') {
      const array = objectNode(args[1], new Set(), true)
      args =
        array &&
        ts.isArrayLiteralExpression(array) &&
        !mutatedObjects.has(array)
          ? [...array.elements]
          : null
      target = unwrap(target.expression)
    }
    const prefix = boundArguments(target)
    if (prefix === null) return null
    return prefix.length ? prefix[0] : args?.[0]
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
  function assignedPairs(target, value) {
    target = unwrap(target)
    if (!target) return []
    if (ts.isArrayLiteralExpression(target))
      return target.elements.flatMap((item, index) => {
        if (ts.isOmittedExpression(item)) return []
        if (ts.isSpreadElement(item)) {
          const array = objectNode(value, new Set(), false)
          const values =
            array && ts.isArrayLiteralExpression(array)
              ? arrayValues(array)
              : null
          return assignedPairs(
            item.expression,
            values
              ? ts.factory.createArrayLiteralExpression(values.slice(index))
              : null
          )
        }
        return assignedPairs(
          item,
          propertyValue(value, String(index), new Set(), false)
        )
      })
    if (ts.isObjectLiteralExpression(target))
      return target.properties.flatMap((prop) => {
        if (ts.isSpreadAssignment(prop))
          return assignedPairs(
            prop.expression,
            objectRest(
              value,
              target.properties
                .filter((item) => !ts.isSpreadAssignment(item))
                .map((item) => propertyKey(item.name))
            )
          )
        const dest = ts.isPropertyAssignment(prop)
          ? prop.initializer
          : ts.isShorthandPropertyAssignment(prop)
            ? prop.name
            : null
        return dest
          ? assignedPairs(
              dest,
              propertyValue(value, propertyKey(prop.name), new Set(), false)
            )
          : []
      })
    if (
      ts.isBinaryExpression(target) &&
      target.operatorToken.kind === ts.SyntaxKind.EqualsToken
    )
      return undefinedValue(value) === true
        ? assignedPairs(target.left, target.right)
        : undefinedValue(value) === false
          ? assignedPairs(target.left, value)
          : [
              ...assignedPairs(target.left, value),
              ...assignedPairs(target.left, target.right)
            ]
    return [{ target, value }]
  }
  function patternDefault(node) {
    let current = node,
      parent = node.parent
    while (parent) {
      if (
        ts.isBinaryExpression(parent) &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        parent.left === current
      )
        return (
          ts.isArrayLiteralExpression(current) ||
          ts.isObjectLiteralExpression(current)
        )
      if (
        !(
          ts.isParenthesizedExpression(parent) ||
          ts.isArrayLiteralExpression(parent) ||
          ts.isObjectLiteralExpression(parent) ||
          ts.isPropertyAssignment(parent) ||
          ts.isSpreadElement(parent) ||
          ts.isSpreadAssignment(parent)
        )
      )
        return false
      current = parent
      parent = parent.parent
    }
    return false
  }
  for (const node of nodes) {
    if (
      !ts.isBinaryExpression(node) ||
      node.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
      patternDefault(node)
    )
      continue
    for (const pair of assignedPairs(node.left, node.right)) {
      if (!ts.isIdentifier(pair.target) || !pair.value) continue
      const binding = symbol(pair.target)
      if (binding) {
        const values = assignedValues.get(binding) ?? []
        values.push(pair.value)
        assignedValues.set(binding, values)
      }
    }
  }
  for (const node of nodes) {
    if (
      !ts.isBinaryExpression(node) ||
      node.operatorToken.kind < ts.SyntaxKind.FirstAssignment ||
      node.operatorToken.kind > ts.SyntaxKind.LastAssignment ||
      patternDefault(node)
    )
      continue
    for (const pair of assignedPairs(node.left, node.right)) {
      const leaf = pair.target
      if (
        !(
          ts.isPropertyAccessExpression(leaf) ||
          ts.isElementAccessExpression(leaf)
        )
      )
        continue
      for (const owner of receiverOrigins(leaf.expression)) {
        const values = assignedContainerValues.get(owner) ?? []
        if (pair.value) values.push(pair.value)
        assignedContainerValues.set(owner, values)
        const name = member(leaf)
        if (name !== null && pair.value) {
          const properties = assignedProperties.get(owner) ?? new Map()
          const stored = properties.get(name) ?? []
          stored.push(pair.value)
          properties.set(name, stored)
          assignedProperties.set(owner, properties)
        }
      }
    }
  }
  function auditCoercion(expression) {
    for (const owner of reachableOrigins(expression)) {
      if (!ts.isObjectLiteralExpression(owner)) continue
      for (const name of ['toString', 'valueOf']) {
        const info = propertyPresence(owner, name, new Set(), false)
        const hook = propertyValue(owner, name, new Set(), false)
        if (info.present && !pureLocalCallable(hook)) mutatedObjects.add(owner)
      }
      if (
        owner.properties.some(
          (prop) =>
            prop.name &&
            ts.isComputedPropertyName(prop.name) &&
            ts.isPropertyAccessExpression(prop.name.expression) &&
            prop.name.expression.expression.getText(file) === 'Symbol' &&
            !symbol(prop.name.expression.expression) &&
            prop.name.expression.name.text === 'toPrimitive'
        )
      )
        mutatedObjects.add(owner)
    }
  }
  // Discover all mutation/escape sites before inferring any query. Aliases are
  // chased to object identities even when a different alias was already tainted.
  for (const node of nodes) {
    if (
      ts.isTemplateExpression(node) &&
      !ts.isTaggedTemplateExpression(node.parent)
    )
      for (const span of node.templateSpans) auditCoercion(span.expression)
    if (
      ts.isBinaryExpression(node) &&
      [
        ts.SyntaxKind.PlusToken,
        ts.SyntaxKind.MinusToken,
        ts.SyntaxKind.AsteriskToken,
        ts.SyntaxKind.SlashToken
      ].includes(node.operatorToken.kind)
    ) {
      auditCoercion(node.left)
      auditCoercion(node.right)
    }
    let target = null
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
      node.operatorToken.kind <= ts.SyntaxKind.LastAssignment &&
      !patternDefault(node)
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
      for (const leaf of assignmentLeaves(target)) {
        if (ts.isIdentifier(leaf)) mutatedSymbols.add(symbol(leaf))
        const origin = mutationOrigin(leaf)
        if (origin) mutatedObjects.add(origin)
        if (
          ts.isPropertyAccessExpression(leaf) ||
          ts.isElementAccessExpression(leaf)
        ) {
          for (const owner of receiverOrigins(leaf.expression))
            mutatedObjects.add(owner)
        }
      }
    }
    if (
      !(
        ts.isCallExpression(node) ||
        ts.isNewExpression(node) ||
        ts.isTaggedTemplateExpression(node)
      )
    )
      continue
    const expr = unwrap(
        ts.isTaggedTemplateExpression(node) ? node.tag : node.expression
      ),
      name = member(expr)
    const effect = callee(expr)
    const receiver =
      ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)
        ? expr.expression
        : expr
    const receiverObject = mutationOrigin(receiver)
    const localMember =
      name &&
      (ts.isPropertyAccessExpression(expr) ||
        ts.isElementAccessExpression(expr))
        ? propertyValue(expr.expression, name)
        : null
    const bindConstruction =
      ts.isCallExpression(node) &&
      name === 'bind' &&
      (effects.has(effect) ||
        effect === 'query' ||
        Boolean(callableValue(receiver)))
    if (bindConstruction) continue
    const nativeRead =
      receiverObject &&
      ts.isArrayLiteralExpression(receiverObject) &&
      readMethods.has(name) &&
      !mutatedObjects.has(receiverObject)
    if (
      receiverObject &&
      !nativeRead &&
      !effects.has(effect) &&
      effect !== 'query' &&
      !pureLocalCallable(localMember) &&
      !pureLocalCallable(callableValue(expr))
    )
      for (const origin of reachableOrigins(receiver))
        mutatedObjects.add(origin)
    if (nativeRead)
      for (const origin of reachableOrigins(receiver))
        if (origin !== receiverObject) mutatedObjects.add(origin)
    const args = ts.isTaggedTemplateExpression(node)
      ? ts.isTemplateExpression(node.template)
        ? node.template.templateSpans.map((span) => span.expression)
        : []
      : [...(node.arguments ?? [])]
    for (const [index, arg] of args.entries()) {
      if (effect === 'query' && index === 0) continue
      for (const origin of reachableOrigins(arg)) mutatedObjects.add(origin)
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
  function sqlVariants(node, seen = new Set(), allowConfig = true) {
    node = unwrap(node)
    if (!node || seen.has(node)) return null
    seen.add(node)
    if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node))
      return [node.text]
    if (ts.isIdentifier(node)) {
      const loop = finiteLoopValues(node)
      return (
        loop ?? sqlVariants(bindingInitializer(node, true), seen, allowConfig)
      )
    }
    if (ts.isObjectLiteralExpression(node))
      return allowConfig
        ? sqlVariants(propertyValue(node, 'text'), seen, false)
        : null
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    )
      return sqlVariants(
        propertyValue(node.expression, member(node)),
        seen,
        allowConfig
      )
    const cross = (left, right) =>
      left.length * right.length > 64
        ? null
        : left.flatMap((a) => right.map((b) => a + b))
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken
    ) {
      const left = sqlVariants(node.left, new Set(seen), false),
        right = sqlVariants(node.right, new Set(seen), false)
      const opaque = (part) =>
        ts.isIdentifier(unwrap(part)) && !declaration(unwrap(part))
      if (
        (left === null && !opaque(node.left)) ||
        (right === null && !opaque(node.right))
      )
        return null
      return left === null && right === null
        ? null
        : cross(left ?? [placeholder], right ?? [placeholder])
    }
    if (ts.isTemplateExpression(node)) {
      let result = [node.head.text]
      for (const span of node.templateSpans) {
        const choices = sqlVariants(span.expression, new Set(seen), false)
        const expr = unwrap(span.expression)
        if (choices === null && !(ts.isIdentifier(expr) && !declaration(expr)))
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
      arrow.modifiers?.length ||
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
          !parameter.initializer &&
          !parameter.dotDotDotToken &&
          !parameter.questionToken &&
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
      if (name === 'query' && member(expression) !== 'bind') {
        const argument = invocationSqlArgument(node)
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
