import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

export const TELEMETRY_SERVICES = Object.freeze(['api-a', 'api-b', 'worker'])
export const TELEMETRY_CANARY = 'SENSITIVE-AUD06-TELEMETRY-FIXTURE'
const maximumBytes = 16 * 1024 * 1024
const forbiddenKeys =
  /^(?:body|payload|prompt|objective|secret|password|authorization|headers|rawPath|root)$/i

export function prepareTelemetryDirectories(temp) {
  const uid = process.getuid?.()
  const gid = process.getgid?.()
  assert.ok(
    Number.isSafeInteger(uid) && uid > 0,
    'run AUD06 as a non-root Linux user'
  )
  assert.ok(
    Number.isSafeInteger(gid) && gid >= 0,
    'Linux group identity required'
  )
  fs.mkdirSync(path.join(temp, 'telemetry'), { mode: 0o700 })
  for (const service of TELEMETRY_SERVICES) {
    fs.mkdirSync(path.join(temp, 'telemetry', service), { mode: 0o700 })
  }
  return { uid, gid }
}

/** Verifies the observed export, without substituting a collector or rewriting bytes. */
export function verifyTelemetryExport(bytes, forbiddenValues = []) {
  assert.ok(
    bytes.length > 0 && bytes.length <= maximumBytes,
    'telemetry file missing, empty or oversized'
  )
  const text = bytes.toString('utf8')
  assert.ok(
    text.endsWith('\n'),
    'telemetry export has an incomplete JSONL record'
  )
  for (const value of [
    TELEMETRY_CANARY,
    'AUD06-SYNTHETIC-before',
    'AUD06-SYNTHETIC-after',
    ...forbiddenValues
  ]) {
    assert.ok(
      value && !text.includes(value),
      'telemetry contains a forbidden synthetic value'
    )
  }
  assert.ok(!text.includes('/tmp/'), 'telemetry contains a raw temporary path')
  function inspect(value) {
    if (!value || typeof value !== 'object') return
    for (const [key, child] of Object.entries(value)) {
      assert.ok(
        !forbiddenKeys.test(key),
        'telemetry contains a sensitive field'
      )
      inspect(child)
    }
  }
  const batches = text
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  const counts = { logs: 0, metrics: 0, spans: 0 }
  const events = new Set()
  const metricNames = new Set()
  for (const batch of batches) {
    assert.equal(
      batch.kind,
      'cvg-observability-export',
      'not a collector export'
    )
    assert.equal(batch.schemaVersion, 1)
    assert.equal(
      batch.enabled,
      true,
      'disabled collector cannot qualify export'
    )
    assert.ok(
      Number.isFinite(Date.parse(batch.exportedAt)),
      'export timestamp missing'
    )
    assert.ok(
      batch.resource?.environment && batch.resource.environment !== 'production'
    )
    let records = 0
    for (const kind of ['logs', 'metrics', 'spans']) {
      assert.ok(Array.isArray(batch[kind]), `telemetry ${kind} missing`)
      records += batch[kind].length
      counts[kind] += batch[kind].length
    }
    assert.ok(
      records > 0 && records <= 256,
      'empty or unbounded collector batch'
    )
    for (const record of batch.logs) {
      assert.equal(typeof record.event, 'string')
      events.add(record.event)
    }
    for (const record of batch.metrics) {
      assert.ok(Number.isFinite(record.value))
      metricNames.add(record.name)
    }
    inspect(batch)
  }
  return {
    bytes: bytes.length,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    batches: batches.length,
    counts,
    events: [...events].sort(),
    metricNames: [...metricNames].sort(),
    firstExportedAt: batches[0].exportedAt,
    lastExportedAt: batches.at(-1).exportedAt
  }
}

export function readTelemetryFile(temp, service, forbiddenValues = []) {
  assert.ok(TELEMETRY_SERVICES.includes(service), 'unknown telemetry service')
  const filename = service === 'worker' ? 'worker.jsonl' : 'api.jsonl'
  const directory = path.join(temp, 'telemetry', service)
  const folder = fs.lstatSync(directory)
  assert.ok(
    folder.isDirectory() && !folder.isSymbolicLink(),
    'telemetry directory replaced'
  )
  assert.deepEqual(
    fs.readdirSync(directory),
    [filename],
    'unexpected telemetry files'
  )
  const file = path.join(directory, filename)
  const stat = fs.lstatSync(file)
  assert.ok(
    stat.isFile() && !stat.isSymbolicLink(),
    'telemetry must be a regular file'
  )
  assert.ok(stat.size <= maximumBytes, 'telemetry file oversized')
  const bytes = fs.readFileSync(file)
  return { bytes, stats: verifyTelemetryExport(bytes, forbiddenValues) }
}

export function assertTelemetryRetained(before, after) {
  assert.ok(
    after.length >= before.length,
    'telemetry was truncated during shutdown or restart'
  )
  assert.ok(
    after.subarray(0, before.length).equals(before),
    'telemetry history was rewritten'
  )
}
