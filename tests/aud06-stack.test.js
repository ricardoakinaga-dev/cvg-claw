import { describe, expect, it } from 'vitest'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  verifyTelemetryExport,
  assertTelemetryRetained,
  TELEMETRY_CANARY
} from '../scripts/aud06-stack-telemetry.mjs'
import {
  assertResourceOwnership,
  assertRestoreIntegrity,
  assertSecurityHeaders,
  removeOwnedResource
} from '../scripts/aud06-stack-run.mjs'

const runId = 'cvg-aud06-stack-test-1234567890'
const headers = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'strict-transport-security': 'max-age=300'
}

const collectorBatch = () => ({
  schemaVersion: 1,
  kind: 'cvg-observability-export',
  enabled: true,
  resource: {
    serviceName: 'synthetic-test',
    serviceVersion: '1',
    environment: 'test'
  },
  exportedAt: '2026-10-06T23:00:00.000Z',
  logs: [{ level: 'info', event: 'worker.continuous_ready', fields: {} }],
  spans: [],
  metrics: [{ name: 'worker.queue', value: 1, attributes: {} }],
  redaction: { droppedRecords: 0 }
})
const encodeBatch = (batch) => Buffer.from(`${JSON.stringify(batch)}\n`)

// Run the real CLI in an isolated directory. Every Docker command is intercepted;
// the startup failure enters its actual finally/cleanup orchestration.
function cleanupFixture({ stop = 0, logs = 0, foreign = null }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aud06-cleanup-test-'))
  try {
    for (const directory of ['scripts', 'bin', 'tmp'])
      fs.mkdirSync(path.join(root, directory))
    for (const file of ['aud06-stack-run.mjs', 'aud06-stack-telemetry.mjs'])
      fs.copyFileSync(
        path.resolve('scripts', file),
        path.join(root, 'scripts', file)
      )
    fs.writeFileSync(
      path.join(root, 'bin', 'docker'),
      `#!${process.execPath}
const fs = require('node:fs')
const path = require('node:path')
const root = path.resolve(__dirname, '..')
const args = process.argv.slice(2)
const config = ${JSON.stringify({ stop, logs, foreign })}
const owned = 'a'.repeat(64), other = 'b'.repeat(64)
const removed = path.join(root, 'removed')
const runId = fs.readdirSync(path.join(root, 'docs/04_audit/evidence/AUD06/stack'))[0]
fs.appendFileSync(path.join(root, 'calls.jsonl'), JSON.stringify(args) + '\\n')
if (args[0] === 'version') {
  console.error('synthetic startup failure'); process.exit(23)
}
if (args[0] === 'ps') {
  if (config.foreign) console.log(other)
  if (!fs.existsSync(removed)) console.log(owned)
  process.exit(0)
}
if (args[0] === 'inspect') {
  const isForeign = args.at(-1) === other
  if (isForeign && config.foreign === 'inspect') {
    console.error('ownership unavailable'); process.exit(31)
  }
  console.log(JSON.stringify({
    name: isForeign && config.foreign === 'name' ? '/foreign-db' : '/' + runId + '-db',
    labels: { 'org.cvg.aud06.run': isForeign && config.foreign === 'label' ? 'another-run' : runId }
  })); process.exit(0)
}
if (args[0] === 'stop' || args[0] === 'logs') {
  const code = config[args[0]]
  if (code) console.error('synthetic ' + args[0] + ' failure')
  process.exit(code)
}
if (args[0] === 'rm') {
  if (args.at(-1) !== owned) process.exit(99)
  if (config.stop && !args.includes('--force')) process.exit(32)
  fs.writeFileSync(removed, owned); process.exit(0)
}
if (['network', 'volume'].includes(args[0]) && args[1] === 'ls') process.exit(0)
console.error('unexpected Docker command'); process.exit(99)
`,
      { mode: 0o755 }
    )
    const result = spawnSync(
      process.execPath,
      [path.join(root, 'scripts', 'aud06-stack-run.mjs')],
      {
        env: {
          PATH: `${path.join(root, 'bin')}:${path.dirname(process.execPath)}`,
          HOME: root,
          TMPDIR: path.join(root, 'tmp')
        },
        encoding: 'utf8',
        timeout: 10_000
      }
    )
    expect(result.error).toBeUndefined()
    const evidence = path.join(root, 'docs/04_audit/evidence/AUD06/stack')
    const run = fs.readdirSync(evidence)[0]
    const directory = path.join(evidence, run)
    return {
      result,
      removed: fs.existsSync(path.join(root, 'removed')),
      calls: fs
        .readFileSync(path.join(root, 'calls.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map(JSON.parse),
      summary: JSON.parse(
        fs.readFileSync(path.join(directory, 'summary.json'), 'utf8')
      ),
      commands: fs
        .readFileSync(path.join(directory, 'commands.jsonl'), 'utf8')
        .trim()
        .split('\n')
        .map(JSON.parse)
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
}

describe('AUD06 whole-run cleanup orchestration', () => {
  it.each([
    { stop: 0, logs: 28 },
    { stop: 29, logs: 0 },
    { stop: 29, logs: 28 }
  ])(
    'removes the immutable owned ID despite diagnostics failing: %j',
    (config) => {
      const { result, removed, calls, summary, commands } =
        cleanupFixture(config)
      const owned = 'a'.repeat(64)
      expect(result.status).toBe(1)
      expect(removed).toBe(true)
      expect(
        calls.filter((args) => ['stop', 'logs', 'rm'].includes(args[0]))
      ).toEqual([
        ['stop', '--time', '20', owned],
        ['logs', owned],
        ['rm', '--force', owned]
      ])
      expect(summary.error).toContain('docker-version: exit=23')
      expect(summary.status).toBe('FAILED_CLEANUP')
      expect(summary.teardown.remaining).toEqual({
        containers: [],
        networks: [],
        volumes: []
      })
      expect(summary.teardown.passed).toBe(false)
      expect(summary.cleanupErrors).toHaveLength(
        Number(config.stop !== 0) + Number(config.logs !== 0)
      )
      for (const [operation, code] of Object.entries(config)) {
        const command = commands.find((item) => item.command[1] === operation)
        expect(command.exitCode).toBe(code)
        if (code)
          expect(
            summary.cleanupErrors.some((error) =>
              error.includes(`exit=${code}`)
            )
          ).toBe(true)
      }
    }
  )

  it.each(['name', 'label', 'inspect'])(
    'never stops, reads logs or removes an unverified foreign ID (%s)',
    (foreign) => {
      const { result, removed, calls, summary } = cleanupFixture({
        stop: 29,
        logs: 28,
        foreign
      })
      expect(result.status).toBe(1)
      expect(removed).toBe(true)
      const other = 'b'.repeat(64)
      expect(
        calls.some(
          (args) =>
            ['stop', 'logs', 'rm'].includes(args[0]) && args.includes(other)
        )
      ).toBe(false)
      expect(summary.teardown.remaining.containers).toEqual([other])
      expect(
        summary.cleanupErrors.some((error) =>
          error.includes(
            foreign === 'inspect'
              ? 'ownership unavailable'
              : `foreign resource ${foreign}`
          )
        )
      ).toBe(true)
      expect(summary.teardown.passed).toBe(false)
    }
  )

  it('preserves the startup failure when all cleanup operations succeed', () => {
    const { result, removed, summary } = cleanupFixture({})
    expect(result.status).toBe(1)
    expect(removed).toBe(true)
    expect(summary.status).toBe('FAILED')
    expect(summary.error).toContain('docker-version: exit=23')
    expect(summary.cleanupErrors).toEqual([])
    expect(summary.teardown.passed).toBe(true)
  })
})

describe('AUD06 actual telemetry evidence verifier', () => {
  it('accepts nonempty bounded collector exports and fingerprints their original bytes', () => {
    const bytes = encodeBatch(collectorBatch())
    const result = verifyTelemetryExport(bytes)
    expect(result.counts).toEqual({ logs: 1, metrics: 1, spans: 0 })
    expect(result.events).toContain('worker.continuous_ready')
    expect(result.batches).toBe(1)
    expect(result.bytes).toBe(bytes.length)
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/)
  })
  it('rejects empty, partial, malformed, disabled or fake telemetry output', () => {
    for (const bytes of [
      Buffer.alloc(0),
      Buffer.from('{}'),
      Buffer.from('not-json\n'),
      encodeBatch({ ...collectorBatch(), enabled: false }),
      encodeBatch({ ...collectorBatch(), kind: 'simulated-evidence' }),
      encodeBatch({ ...collectorBatch(), logs: [], metrics: [] })
    ])
      expect(() => verifyTelemetryExport(bytes)).toThrow()
  })
  it('rejects synthetic canaries, raw payload fields, credentials and temporary paths', () => {
    for (const fields of [
      { status: TELEMETRY_CANARY },
      { payload: { raw: 'fixture' } },
      { status: '/tmp/exclusive-test-root' },
      { status: 'throwaway-password-must-not-leak' }
    ]) {
      const batch = collectorBatch()
      batch.logs[0].fields = fields
      expect(() =>
        verifyTelemetryExport(encodeBatch(batch), [
          'throwaway-password-must-not-leak'
        ])
      ).toThrow()
    }
  })
  it('rejects an export larger than the collector batch cap', () => {
    const batch = collectorBatch()
    batch.metrics = Array.from({ length: 256 }, () => ({
      name: 'queue',
      value: 1,
      attributes: {}
    }))
    expect(() => verifyTelemetryExport(encodeBatch(batch))).toThrow('unbounded')
  })
  it('preserves periodic file bytes through restart and shutdown, detecting rewrites and truncation', () => {
    const before = encodeBatch(collectorBatch())
    const after = Buffer.concat([before, before])
    expect(() => assertTelemetryRetained(before, after)).not.toThrow()
    expect(() => assertTelemetryRetained(after, before)).toThrow('truncated')
    expect(() =>
      assertTelemetryRetained(before, Buffer.alloc(before.length, 32))
    ).toThrow('rewritten')
  })
})

describe('AUD06 executable safety and evidence boundaries', () => {
  it('does not remove a similarly named resource carrying another owner label', async () => {
    const removed = []
    await expect(
      removeOwnedResource({
        name: `${runId}-db`,
        runId,
        inspect: async () => ({ 'org.cvg.aud06.run': 'another-run' }),
        remove: async (name) => {
          removed.push(name)
        }
      })
    ).rejects.toThrow('foreign resource label')
    expect(removed).toEqual([])
  })
  it('does not remove an unrelated resource even when its label matches', () => {
    expect(() =>
      assertResourceOwnership(
        'existing-hospital-db',
        { 'org.cvg.aud06.run': runId },
        runId
      )
    ).toThrow('foreign resource name')
  })
  it('removes a positively identified owned resource once', async () => {
    const removed = []
    await removeOwnedResource({
      name: `${runId}-db-data`,
      runId,
      inspect: async () => ({ 'org.cvg.aud06.run': runId }),
      remove: async (name) => {
        removed.push(name)
      }
    })
    expect(removed).toEqual([`${runId}-db-data`])
  })
  it('propagates failed teardown rather than reporting successful cleanup', async () => {
    await expect(
      removeOwnedResource({
        name: `${runId}-network`,
        runId,
        inspect: async () => ({ 'org.cvg.aud06.run': runId }),
        remove: async () => {
          throw new Error('network still has endpoints')
        }
      })
    ).rejects.toThrow('network still has endpoints')
  })
  it('rejects missing CSP and HSTS on HTTPS, and accepts an HTTP redirect without HSTS', () => {
    expect(() => assertSecurityHeaders(headers)).not.toThrow()
    expect(() =>
      assertSecurityHeaders({
        ...headers,
        'content-security-policy': undefined
      })
    ).toThrow('CSP missing')
    expect(() =>
      assertSecurityHeaders({
        ...headers,
        'strict-transport-security': undefined
      })
    ).toThrow()
    expect(() =>
      assertSecurityHeaders(
        { ...headers, 'strict-transport-security': undefined },
        false
      )
    ).not.toThrow()
  })
  it('rejects a restored database with missing rows, changed bytes or altered policies', () => {
    const source = {
      sha256: 'same',
      tables: [{ relname: 'outbox_events', count: 2, sha256: 'rows' }],
      policies: ['tenant-bound'],
      constraints: ['CHECK (length(source) >= 1 AND length(source) <= 200)']
    }
    expect(() =>
      assertRestoreIntegrity(source, structuredClone(source))
    ).not.toThrow()
    for (const changed of [
      {
        ...source,
        tables: [{ relname: 'outbox_events', count: 1, sha256: 'rows' }]
      },
      {
        ...source,
        tables: [{ relname: 'outbox_events', count: 2, sha256: 'changed' }]
      },
      { ...source, policies: ['unrestricted'] },
      {
        ...source,
        constraints: ['CHECK (length(source) >= 1 AND length(source) <= 201)']
      },
      {
        ...source,
        constraints: ['CHECK (length(source) >= 1 OR length(source) <= 200)']
      }
    ])
      expect(() => assertRestoreIntegrity(source, changed)).toThrow()
    expect(() =>
      assertRestoreIntegrity({ tables: [] }, { tables: [] })
    ).toThrow()
  })
})
