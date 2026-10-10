// Bounded static SQL control, not a PostgreSQL parser or an execution boundary.
// The caller owns source-file authorization and host-language AST inspection.
const quotaTable = 'api_rate_limit_buckets'
const writes = new Set(['INSERT', 'UPDATE', 'DELETE'])
const reserved = new Set(
  'INSERT UPDATE DELETE INTO FROM SET VALUES SELECT WITH AS ONLY ON CONFLICT DO NOTHING WHERE RETURNING USING DEFAULT OVERRIDING JOIN ORDER LIMIT GROUP UNION FOR AND OR NOT NULL TRUE FALSE'.split(
    ' '
  )
)

function lex(text) {
  const tokens = []
  const findings = []
  const unresolved = (reason, offset) =>
    findings.push({ id: 'sql_lexical_unresolved', reason, offset })
  const add = (kind, start, end, value = text.slice(start, end)) =>
    tokens.push({ kind, value, offset: start, end })
  let i = 0
  while (i < text.length) {
    const start = i
    const ch = text[i]
    if (/\s/.test(ch)) {
      i += 1
    } else if (text.startsWith('--', i)) {
      while (i < text.length && !/[\r\n]/.test(text[i])) i += 1
    } else if (text.startsWith('/*', i)) {
      let depth = 1
      i += 2
      while (i < text.length && depth) {
        if (text.startsWith('/*', i)) {
          depth += 1
          i += 2
        } else if (text.startsWith('*/', i)) {
          depth -= 1
          i += 2
        } else i += 1
      }
      if (depth) unresolved('Unterminated SQL block comment', start)
    } else if (
      ch === "'" ||
      ch === '"' ||
      (/[eE]/.test(ch) && text[i + 1] === "'")
    ) {
      const escape = ch !== "'" && ch !== '"'
      const quote = escape ? "'" : ch
      i += escape ? 2 : 1
      let closed = false
      while (i < text.length) {
        if (text[i] === quote && text[i + 1] === quote) i += 2
        else if (text[i] === quote) {
          i += 1
          closed = true
          break
        } else if (text[i] === '\\' && quote === "'") {
          if (escape) i += 2
          else {
            // Never let an ordinary backslash consume the following quote.
            unresolved(
              'Ordinary string backslash has uncertain SQL semantics',
              i
            )
            i += 1
          }
        } else i += 1
      }
      if (!closed) unresolved('Unterminated SQL quoted token', start)
      add(quote === '"' ? 'identifier' : 'value', start, i)
    } else if (ch === '$') {
      const tag = text.slice(i).match(/^\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$/)?.[0]
      const parameter = text.slice(i).match(/^\$[0-9]+/)?.[0]
      if (tag) {
        const close = text.indexOf(tag, i + tag.length)
        if (close < 0) {
          unresolved('Unterminated SQL dollar-quoted value', start)
          i = text.length
        } else i = close + tag.length
        add('value', start, i)
      } else if (parameter) {
        i += parameter.length
        add('parameter', start, i)
      } else if (text.startsWith('${', i)) {
        // Opaque host placeholder: do not inspect or evaluate its contents.
        let depth = 1
        i += 2
        while (i < text.length && depth) {
          if (text[i] === '{') depth += 1
          if (text[i] === '}') depth -= 1
          i += 1
        }
        unresolved('Unknown SQL interpolation', start)
        add('unknown', start, i)
      } else {
        unresolved('Unknown SQL dollar token', start)
        add('unknown', start, ++i)
      }
    } else if (/[A-Za-z_\u0080-\uffff]/.test(ch)) {
      i += 1
      while (i < text.length && /[A-Za-z_0-9$\u0080-\uffff]/.test(text[i]))
        i += 1
      add('word', start, i, text.slice(start, i).toUpperCase())
    } else if (/[0-9]/.test(ch)) {
      const number = text.slice(i).match(/^\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/)[0]
      i += number.length
      add('number', start, i)
    } else {
      const operator = text.slice(i).match(/^(?:::|<=|>=|<>|!=|\|\|)/)?.[0]
      if (operator) {
        i += operator.length
        add('symbol', start, i)
      } else if ('()[],;.=+-*/%<>'.includes(ch)) add('symbol', start, ++i)
      else {
        unresolved('Unsupported or unknown SQL token', start)
        add('unknown', start, ++i)
      }
    }
  }
  const stack = []
  const brackets = []
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    // Array delimiters remain ordinary tokens. Their contents are never masked
    // or skipped by write detection, and cannot create a write-scope boundary.
    if (token.kind === 'symbol' && token.value === '[') brackets.push(index)
    if (
      token.kind === 'symbol' &&
      token.value === ']' &&
      brackets.pop() === undefined
    )
      unresolved('Unmatched SQL closing array bracket', token.offset)
    if (token.value === ')' && token.kind === 'symbol') {
      const open = stack.pop()
      if (open === undefined)
        unresolved('Unmatched SQL closing parenthesis', token.offset)
      else {
        token.pair = open
        tokens[open].pair = index
      }
    }
    token.depth = stack.length
    if (token.value === '(' && token.kind === 'symbol') stack.push(index)
  }
  for (const open of stack)
    unresolved('Unclosed SQL parenthesis', tokens[open].offset)
  for (const open of brackets)
    unresolved('Unclosed SQL array bracket', tokens[open].offset)
  return { tokens, findings }
}

const isWord = (token, value) => token?.kind === 'word' && token.value === value
const isIdentifier = (token) =>
  token?.kind === 'identifier' ||
  (token?.kind === 'word' && !reserved.has(token.value))

// Expressions are deliberately bounded: metadata arithmetic, calls, casts,
// comparisons, boolean conditions and EXTRACT used by the existing quota SQL.
class Reader {
  constructor(tokens, start, end) {
    this.tokens = tokens
    this.i = start
    this.end = end
  }

  peek(value) {
    const token = this.tokens[this.i]
    return this.i < this.end && token?.value === value
  }

  take(value) {
    if (!this.peek(value)) return false
    this.i += 1
    return true
  }

  identifier() {
    if (this.i >= this.end || !isIdentifier(this.tokens[this.i])) return false
    this.i += 1
    return true
  }

  identifiers() {
    if (!this.identifier()) return false
    while (this.take(',')) if (!this.identifier()) return false
    return true
  }

  expression(min = 0) {
    if (!this.atom()) return false
    while (this.i < this.end) {
      if (this.take('::')) {
        if (!this.identifier()) return false
        const type = this.tokens[this.i - 1].value
        if (type === 'DOUBLE' && !this.take('PRECISION')) return false
        if (
          (type === 'CHARACTER' || type === 'TIMESTAMP') &&
          this.peek('VARYING')
        )
          this.i += 1
        // Only the ordinary empty array type suffix is admitted in write bodies.
        // Subscripts and nonempty dimensions need separate grammar support.
        while (this.take('[')) if (!this.take(']')) return false
        continue
      }
      const op = this.tokens[this.i].value
      const precedence = {
        OR: 1,
        AND: 2,
        '=': 3,
        '<': 3,
        '>': 3,
        '<=': 3,
        '>=': 3,
        '<>': 3,
        '!=': 3,
        IS: 3,
        '+': 4,
        '-': 4,
        '||': 4,
        '*': 5,
        '/': 5,
        '%': 5
      }[op]
      if (!precedence || precedence < min) break
      this.i += 1
      if (op === 'IS') {
        this.take('NOT')
        if (!['NULL', 'TRUE', 'FALSE'].some((value) => this.take(value)))
          return false
        continue
      }
      if (!this.expression(precedence + 1)) return false
    }
    return true
  }

  atom() {
    if (this.i >= this.end) return false
    if (this.take('+') || this.take('-') || this.take('NOT')) return this.atom()
    if (this.take('(')) return this.expression() && this.take(')')
    const token = this.tokens[this.i]
    if (['value', 'number', 'parameter'].includes(token.kind)) {
      this.i += 1
      return true
    }
    if (['NULL', 'TRUE', 'FALSE', 'DEFAULT'].some((v) => isWord(token, v))) {
      this.i += 1
      return true
    }
    if (this.take('INTERVAL')) {
      if (this.tokens[this.i]?.kind !== 'value' || this.i >= this.end)
        return false
      this.i += 1
      return true
    }
    if (this.take('EXTRACT')) {
      return (
        this.take('(') &&
        this.identifier() &&
        this.take('FROM') &&
        this.expression() &&
        this.take(')')
      )
    }
    if (!this.identifier()) return false
    while (this.take('.')) if (!this.identifier()) return false
    if (this.take('(')) {
      if (this.take(')')) return true
      if (!this.expression()) return false
      while (this.take(',')) if (!this.expression()) return false
      return this.take(')')
    }
    return true
  }

  assignments() {
    do {
      if (!this.identifier() || !this.take('=') || !this.expression())
        return false
    } while (this.take(','))
    return true
  }

  returning() {
    if (!this.take('RETURNING')) return true
    do {
      if (!this.take('*') && !this.expression()) return false
      if (this.take('AS') && !this.identifier()) return false
    } while (this.take(','))
    return true
  }

  tail() {
    if (this.take('WHERE') && !this.expression()) return false
    return this.returning() && this.i === this.end
  }
}

function commandEnd(tokens, start) {
  const depth = tokens[start].depth
  let end = start + 1
  while (
    end < tokens.length &&
    tokens[end].value !== ';' &&
    tokens[end].depth >= depth
  )
    end += 1
  return end
}

function validateWrite(tokens, start, end) {
  const command = tokens[start].value
  const reader = new Reader(tokens, start + 1, end)
  if (command === 'INSERT' && !reader.take('INTO')) return { valid: false }
  if (command === 'DELETE' && !reader.take('FROM')) return { valid: false }
  const target = tokens[reader.i]
  if (!isIdentifier(target)) return { valid: false }
  reader.i += 1
  const targetName =
    target.kind === 'word' ? target.value.toLowerCase() : target.value
  const result = { valid: false, target: targetName, targetToken: target }
  // Qualified targets and modifiers are outside the admitted quota grammar.
  if (reader.peek('.')) {
    while (reader.take('.')) {
      const part = tokens[reader.i]
      if (!reader.identifier()) break
      result.target +=
        '.' + (part.kind === 'word' ? part.value.toLowerCase() : part.value)
    }
    return result
  }
  if (reader.take('AS')) {
    if (!reader.identifier()) return result
  } else if (command !== 'INSERT' && isIdentifier(tokens[reader.i])) {
    reader.i += 1
  }
  if (command === 'UPDATE') {
    result.valid = reader.take('SET') && reader.assignments() && reader.tail()
    return result
  }
  if (command === 'DELETE') {
    result.valid = reader.tail()
    return result
  }
  if (reader.take('(') && (!reader.identifiers() || !reader.take(')')))
    return result
  if (!reader.take('VALUES')) return result
  do {
    if (!reader.take('(') || !reader.expression()) return result
    while (reader.take(',')) if (!reader.expression()) return result
    if (!reader.take(')')) return result
  } while (reader.take(','))
  if (reader.take('ON')) {
    if (!reader.take('CONFLICT')) return result
    const conflictTarget = reader.take('(')
    if (conflictTarget && (!reader.identifiers() || !reader.take(')')))
      return result
    if (!reader.take('DO')) return result
    if (reader.peek('UPDATE')) {
      result.upsertUpdate = reader.i
      if (
        !conflictTarget ||
        !reader.take('UPDATE') ||
        !reader.take('SET') ||
        !reader.assignments()
      )
        return result
    } else if (!reader.take('NOTHING')) return result
  }
  // WHERE here belongs only to DO UPDATE, never VALUES or DO NOTHING.
  if (result.upsertUpdate === undefined && reader.peek('WHERE')) return result
  result.valid = reader.tail()
  return result
}

function isReadLock(tokens, index, end) {
  let forIndex = index - 1
  if (isWord(tokens[index - 1], 'KEY') && isWord(tokens[index - 2], 'NO'))
    forIndex = index - 3
  if (!isWord(tokens[forIndex], 'FOR')) return false
  const depth = tokens[index].depth
  let hasSelect = false
  for (let i = forIndex - 1; i >= 0; i -= 1) {
    if (tokens[i].value === ';' || tokens[i].depth < depth) break
    if (tokens[i].depth === depth && isWord(tokens[i], 'SELECT'))
      hasSelect = true
    if (tokens[i].depth === depth && writes.has(tokens[i].value)) return false
  }
  if (!hasSelect) return false
  const reader = new Reader(tokens, index + 1, end)
  if (reader.take('OF') && !reader.identifiers()) return false
  if (!reader.take('NOWAIT') && reader.take('SKIP') && !reader.take('LOCKED'))
    return false
  return reader.i === end
}

// Classify executable statement positions independently of the write-token
// scan. An unknown class is never inferred to be read-only. Quota/replay grants
// apply only to the separately validated INSERT/UPDATE/DELETE path below.
function auditStatementClasses(tokens, findings) {
  const unresolved = (reason, start) =>
    findings.push({
      id: 'sql_lexical_unresolved',
      reason,
      offset: tokens[start].offset
    })
  const refuse = (start, reason) =>
    findings.push({
      id: 'direct_sql_write',
      reason,
      offset: tokens[start].offset
    })

  function nestedQueries(start, end) {
    for (let i = start; i < end; i += 1) {
      const token = tokens[i]
      if (token.kind !== 'symbol' || token.value !== '(') continue
      if (token.pair === undefined || token.pair >= end) continue
      if (isWord(tokens[i + 1], 'SELECT') || isWord(tokens[i + 1], 'WITH')) {
        statement(i + 1, token.pair, true)
        i = token.pair
      }
    }
  }

  function withStatement(start, end) {
    const reader = new Reader(tokens, start + 1, end)
    reader.take('RECURSIVE')
    do {
      if (!reader.identifier()) return false
      if (reader.take('(') && (!reader.identifiers() || !reader.take(')')))
        return false
      if (!reader.take('AS')) return false
      if (reader.take('NOT')) {
        if (!reader.take('MATERIALIZED')) return false
      } else reader.take('MATERIALIZED')
      const open = reader.i
      if (!reader.take('(')) return false
      const close = tokens[open].pair
      if (close === undefined || close >= end || close === open + 1)
        return false
      statement(open + 1, close, true)
      reader.i = close + 1
    } while (reader.take(','))
    if (reader.i >= end) return false
    statement(reader.i, end, true)
    return true
  }

  function statement(start, end, queryOnly = false) {
    if (start >= end) return
    const token = tokens[start]
    // A parenthesized query has the same class as its enclosed statement.
    if (
      token.kind === 'symbol' &&
      token.value === '(' &&
      token.pair === end - 1
    ) {
      statement(start + 1, end - 1, true)
      return
    }
    // Semicolons inside a query/CTE cannot define an admitted command batch.
    // Quoted bodies/values have already been reduced to single inert tokens.
    if (
      tokens
        .slice(start, end)
        .some((t) => t.kind === 'symbol' && t.value === ';')
    )
      unresolved('Unexpected statement separator inside SQL query', start)
    if (isWord(token, 'WITH')) {
      if (!withStatement(start, end))
        unresolved('Unrecognized or incomplete WITH statement grammar', start)
      return
    }
    if (isWord(token, 'SELECT')) {
      if (start + 1 === end) unresolved('Incomplete SELECT statement', start)
      // INTO at query depth creates a table. A quoted identifier, qualified
      // field, alias or nested expression is not this clause. Other command
      // words in SELECT expressions/column names remain ordinary identifiers.
      for (let i = start + 1; i < end; i += 1) {
        if (
          tokens[i].depth === token.depth &&
          isWord(tokens[i], 'INTO') &&
          tokens[i - 1]?.value !== '.' &&
          !isWord(tokens[i - 1], 'AS')
        ) {
          refuse(
            start,
            'SELECT INTO is outside the authorized SQL statement classes'
          )
          break
        }
      }
      nestedQueries(start + 1, end)
      return
    }
    if (token.kind === 'word' && writes.has(token.value)) {
      nestedQueries(start + 1, end)
      return
    }
    if (queryOnly) {
      refuse(start, `Unsupported executable SQL query class: ${token.value}`)
      return
    }
    if (
      token.kind === 'word' &&
      ['BEGIN', 'COMMIT', 'ROLLBACK'].includes(token.value)
    ) {
      const reader = new Reader(tokens, start + 1, end)
      if (!reader.take('WORK')) reader.take('TRANSACTION')
      if (reader.i !== end)
        unresolved(`Unrecognized ${token.value} transaction grammar`, start)
      return
    }
    if (isWord(token, 'SET')) {
      // Preserve only the two current transaction-local timeout controls.
      // Session settings, role/search_path changes and unknown SET forms do
      // not receive a quota or legacy replay-store exception.
      const reader = new Reader(tokens, start + 1, end)
      if (
        reader.take('LOCAL') &&
        (reader.take('LOCK_TIMEOUT') || reader.take('STATEMENT_TIMEOUT')) &&
        reader.take('=') &&
        tokens[reader.i]?.kind === 'value' &&
        reader.i + 1 === end
      )
        return
    }
    refuse(start, `Unsupported executable SQL statement class: ${token.value}`)
  }

  let start = 0
  for (let i = 0; i <= tokens.length; i += 1) {
    if (
      i === tokens.length ||
      (tokens[i].kind === 'symbol' &&
        tokens[i].value === ';' &&
        tokens[i].depth === 0)
    ) {
      statement(start, i)
      start = i + 1
    }
  }
}

/** Findings use UTF-16 string offsets, matching JS/TypeScript source offsets. */
export function auditSqlWrites(
  text,
  { allowQuota = false, allowSecurityStore = false } = {}
) {
  if (typeof text !== 'string')
    throw new TypeError('SQL input must be a string')
  const { tokens, findings } = lex(text)
  const suppressed = new Set()
  const lexicalUnresolved = findings.length > 0
  auditStatementClasses(tokens, findings)
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (token.kind !== 'word' || !writes.has(token.value) || suppressed.has(i))
      continue
    const end = commandEnd(tokens, i)
    if (token.value === 'UPDATE' && isReadLock(tokens, i, end)) continue
    const result = validateWrite(tokens, i, end)
    const allowed =
      allowSecurityStore ||
      (allowQuota &&
        result.valid &&
        !lexicalUnresolved &&
        result.targetToken?.kind === 'word' &&
        result.target === quotaTable)
    if (result.valid && result.upsertUpdate !== undefined)
      suppressed.add(result.upsertUpdate)
    // Preserve the source-owned legacy replay-store write exception. It never
    // hides uncertainty, and the caller must restrict it to its two files.
    if (!result.valid) {
      findings.push({
        id: 'sql_lexical_unresolved',
        reason: `Unrecognized or incomplete ${token.value} grammar`,
        offset: token.offset,
        ...(result.target ? { target: result.target } : {})
      })
    }
    if (!allowed) {
      findings.push({
        id: 'direct_sql_write',
        reason: `${token.value} is outside the authorized SQL write boundary`,
        offset: token.offset,
        ...(result.target ? { target: result.target } : {})
      })
    }
  }
  return findings.sort((a, b) => a.offset - b.offset)
}
