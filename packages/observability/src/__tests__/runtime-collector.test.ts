// @vitest-environment node
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  mkdirSync,
  symlinkSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as collectors from '../collector.ts'
import type {
  CollectorExport,
  ObservabilityCollectorPort
} from '../collector.ts'
import {
  createRuntimeCollector,
  parseRuntimeCollectorConfig
} from '../runtime-collector.ts'

const roots: string[] = []
const opened: ObservabilityCollectorPort[] = []
function root() {
  const path = mkdtempSync(join(tmpdir(), 'cvg-aud06-telemetry-'))
  roots.push(path)
  return path
}
function env(path = root()): NodeJS.ProcessEnv {
  return {
    NODE_ENV: 'test',
    CVG_TELEMETRY_MODE: 'local_file',
    CVG_TELEMETRY_PROFILE: 'CONTROLLED_LOCAL_SYNTHETIC',
    CVG_TELEMETRY_ROOT: path
  }
}
function open(
  environment: NodeJS.ProcessEnv,
  role: 'api' | 'worker' = 'api',
  options: Parameters<typeof createRuntimeCollector>[2] = {}
) {
  const port = createRuntimeCollector(environment, role, options)!
  opened.push(port)
  return port
}
function record(port: ObservabilityCollectorPort, message = 'synthetic.event') {
  port.recordLog({
    level: 'info',
    message,
    timestamp: '2026-10-06T12:00:00.000Z',
    fields: { operation: 'synthetic' }
  })
}
function batches(path: string, role = 'api'): CollectorExport[] {
  return readFileSync(join(path, `${role}.jsonl`), 'utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as CollectorExport)
}
afterEach(async () => {
  await Promise.allSettled(opened.splice(0).map((port) => port.close()))
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  for (const path of roots.splice(0))
    rmSync(path, { recursive: true, force: true })
})

describe('AUD06 runtime collector configuration', () => {
  it('is disabled without opt-in, including production, without disk or timers', () => {
    vi.useFakeTimers()
    const path = root()
    for (const environment of [
      {},
      { NODE_ENV: 'production' },
      { ...env(path), CVG_TELEMETRY_MODE: 'disabled' }
    ]) {
      expect(createRuntimeCollector(environment, 'api')).toBeUndefined()
    }
    expect(readdirSync(path)).toEqual([])
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each([
    { CVG_TELEMETRY_MODE: 'otlp' },
    { CVG_TELEMETRY_MODE: '' },
    { CVG_TELEMETRY_MODE: 'LOCAL_FILE' },
    { NODE_ENV: 'production' },
    { NODE_ENV: undefined },
    { CVG_TELEMETRY_PROFILE: undefined },
    { CVG_TELEMETRY_PROFILE: 'production' },
    { CVG_TELEMETRY_ROOT: undefined },
    { CVG_TELEMETRY_ROOT: 'relative' },
    { CVG_TELEMETRY_ROOT: tmpdir() },
    { ENABLE_REAL_CHANNELS: 'true' },
    { ENABLE_REAL_PAYMENTS: 'true' },
    { ENABLE_REAL_MEDICAL_RECORDS: 'true' },
    { ENABLE_REAL_RAG: 'true' }
  ])('rejects invalid or non-synthetic configuration: %j', (override) => {
    vi.useFakeTimers()
    expect(() =>
      createRuntimeCollector({ ...env(), ...override }, 'api')
    ).toThrow('Runtime telemetry configuration is invalid')
    expect(vi.getTimerCount()).toBe(0)
  })

  it('refuses production inherited by the process even with a test override', () => {
    vi.stubEnv('NODE_ENV', 'production')
    expect(() => createRuntimeCollector(env(), 'worker')).toThrow(
      'Runtime telemetry configuration is invalid'
    )
  })

  it('rejects symlinks, traversal, invalid roles and missing paths without leaking paths', () => {
    const path = root()
    const link = join(path, 'link')
    symlinkSync(path, link)
    for (const location of [
      link,
      join(path, 'SENSITIVE-secret-missing'),
      `${path}/../outside`
    ]) {
      expect(() => createRuntimeCollector(env(location), 'api')).toThrow(
        /^Runtime telemetry configuration is invalid$/
      )
    }
    expect(() => createRuntimeCollector(env(path), 'other' as never)).toThrow(
      /^Runtime telemetry configuration is invalid$/
    )
    expect(Object.isFrozen(parseRuntimeCollectorConfig(env(path), 'api'))).toBe(
      true
    )
  })

  it.each([0, 99, 60_001, 1.5, Number.NaN])(
    'rejects unbounded or invalid cadence %s',
    (flushIntervalMs) => {
      expect(() =>
        createRuntimeCollector(env(), 'api', { flushIntervalMs })
      ).toThrow('Runtime telemetry configuration is invalid')
    }
  )
})

describe('AUD06 runtime collector lifecycle and export', () => {
  it('exports sanitized records periodically to constant api/worker names', async () => {
    vi.useFakeTimers()
    const path = root()
    for (const role of ['api', 'worker'] as const) {
      const port = open(env(path), role, { flushIntervalMs: 100 })
      port.recordLog({
        level: 'info',
        message: 'synthetic.event',
        timestamp: '2026-10-06T12:00:00.000Z',
        fields: {
          operation: 'synthetic',
          payload: 'SENSITIVE-PAYLOAD',
          token: 'SENSITIVE-TOKEN',
          tenantId: 'SENSITIVE-TENANT',
          objective: 'SENSITIVE-OBJECTIVE'
        }
      })
      port.recordMetric({
        name: 'synthetic.count',
        value: 1,
        attributes: { operation: 'synthetic', provider: 'SENSITIVE-PROVIDER' },
        timestamp: '2026-10-06T12:00:00.000Z'
      })
    }
    expect(readdirSync(path)).toEqual([])
    await vi.advanceTimersByTimeAsync(100)
    expect(readdirSync(path).sort()).toEqual(['api.jsonl', 'worker.jsonl'])
    for (const role of ['api', 'worker']) {
      const raw = readFileSync(join(path, `${role}.jsonl`), 'utf8')
      expect(raw).not.toContain('SENSITIVE-')
      const [batch] = batches(path, role)
      expect(batch?.logs[0]?.fields).toEqual({ operation: 'synthetic' })
      expect(batch?.metrics[0]?.attributes).toEqual({ operation: 'synthetic' })
      expect(batch?.redaction.blockedCanaries).toBe(2)
      expect(batch?.redaction.droppedLogFields).toBe(4)
    }
  })

  it('caps buffering and batch size, drains the remainder once and removes timers', async () => {
    vi.useFakeTimers()
    const path = root()
    const port = open(env(path), 'api', { flushIntervalMs: 100 })
    for (let i = 0; i < 600; i++) record(port)
    await vi.advanceTimersByTimeAsync(100)
    expect(batches(path)[0]?.logs).toHaveLength(256)
    const firstClose = port.close()
    expect(port.close()).toBe(firstClose)
    await firstClose
    const output = batches(path)
    expect(output.map((batch) => batch.logs.length)).toEqual([256, 256])
    expect(port.redaction().droppedRecords).toBe(88)
    record(port, 'synthetic.after_close')
    await vi.advanceTimersByTimeAsync(60_000)
    await expect(port.flush()).rejects.toThrow(
      'Runtime telemetry collector is closed'
    )
    expect(batches(path)).toHaveLength(2)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('drains a full buffer on immediate shutdown before the first timer', async () => {
    const path = root()
    const port = open(env(path))
    for (let i = 0; i < 512; i++) record(port)
    await port.close()
    expect(batches(path).map((batch) => batch.logs.length)).toEqual([256, 256])
  })

  it('coalesces manual/timer flushes and waits for slow export before closing', async () => {
    vi.useFakeTimers()
    const path = root()
    const factory = collectors.createControlledLocalCollector
    let release!: () => void
    const pending = new Promise<void>((resolve) => {
      release = resolve
    })
    const sink = factory(parseRuntimeCollectorConfig(env(path), 'api')!)
    const originalFlush = sink.flush.bind(sink)
    const writes = vi.spyOn(sink, 'flush').mockImplementation(async () => {
      await pending
      return originalFlush()
    })
    const closeSink = vi.spyOn(sink, 'close')
    vi.spyOn(collectors, 'createControlledLocalCollector').mockReturnValue(sink)
    const port = open(env(path), 'api', { flushIntervalMs: 100 })
    record(port)
    const first = port.flush()
    expect(port.flush()).toBe(first)
    await vi.advanceTimersByTimeAsync(1_000)
    expect(writes).toHaveBeenCalledTimes(1)
    const closing = port.close()
    await Promise.resolve()
    expect(closeSink).not.toHaveBeenCalled()
    release()
    await closing
    expect(closeSink).toHaveBeenCalledTimes(1)
    expect(batches(path)).toHaveLength(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('reports write failure generically, retries only on the next tick and drains later records', async () => {
    vi.useFakeTimers()
    const path = root()
    const onError = vi.fn()
    const port = open(env(path), 'api', { flushIntervalMs: 100, onError })
    // A directory at the constant sink name provokes a real filesystem error.
    mkdirSync(join(path, 'api.jsonl'))
    record(port)
    await vi.advanceTimersByTimeAsync(100)
    expect(onError).toHaveBeenCalledExactlyOnceWith({
      event: 'telemetry.export_failed',
      role: 'api',
      message: 'Controlled telemetry export failed'
    })
    expect(JSON.stringify(onError.mock.calls)).not.toContain(path)
    rmSync(join(path, 'api.jsonl'), { recursive: true })
    record(port, 'synthetic.recovered')
    await vi.advanceTimersByTimeAsync(100)
    expect(batches(path)[0]?.logs[0]?.event).toBe('synthetic.recovered')
    expect(onError).toHaveBeenCalledTimes(1)
    await port.close()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('rejects shutdown export failure generically and still clears every timer', async () => {
    vi.useFakeTimers()
    const path = root()
    const onError = vi.fn(() => {
      throw new Error('SENSITIVE-LOGGER')
    })
    const stderr = vi.spyOn(console, 'error').mockImplementation(() => {})
    const port = open(env(path), 'worker', { onError })
    mkdirSync(join(path, 'worker.jsonl'))
    record(port)
    await expect(port.close()).rejects.toThrow(
      /^Controlled telemetry export failed$/
    )
    expect(stderr).toHaveBeenCalledExactlyOnceWith(
      JSON.stringify({
        event: 'telemetry.export_failed',
        role: 'worker',
        message: 'Controlled telemetry export failed'
      })
    )
    expect(vi.getTimerCount()).toBe(0)
  })
})
