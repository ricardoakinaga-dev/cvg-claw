// @vitest-environment node
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ShutdownControllerOptions } from '@cvg/shared'
import type { WorkerTelemetry } from '../worker-observability.ts'

const seams = vi.hoisted(() => ({
  create: vi.fn(),
  shutdown: vi.fn(),
  install: vi.fn(),
  preflight: vi.fn(),
  health: vi.fn(),
  startup: vi.fn(),
  bootstrap: vi.fn()
}))
vi.mock('../postgres-controlled.ts', () => ({
  createPostgresContinuousWorker: seams.create,
  createPostgresControlledWorker: vi.fn(),
  parseControlledDrainLimit: vi.fn(),
  POSTGRES_CONTROLLED_QUEUE_ADAPTER: 'postgres-controlled'
}))
vi.mock('../worker.ts', () => ({ getWorkerStartupFailure: seams.startup }))
vi.mock('../postgres-role-preflight.ts', () => ({
  assertPostgresWorkerPreflight: seams.preflight
}))
vi.mock('../kernel-composition.ts', () => ({
  KERNEL_WORKER_RUNTIME: 'governed-kernel',
  resolveWorkerRuntimeKind: () => 'published-agent',
  assertPostgresKernelPrerequisites: vi.fn()
}))
vi.mock('../worker-health.ts', () => ({
  createWorkerHealthReporter: seams.health,
  parseWorkerHealthConfig: () => ({})
}))
vi.mock('../../../../scripts/lib/production-preflight-core.mjs', () => ({
  assertProductionBootstrap: seams.bootstrap
}))
vi.mock('@cvg/shared', async (original) => ({
  ...(await original<typeof import('@cvg/shared')>()),
  createShutdownController: seams.shutdown
}))

let root: string
let telemetry: WorkerTelemetry
let shutdown: ShutdownControllerOptions | undefined
let previousExitCode: typeof process.exitCode
let health: {
  markReady: ReturnType<typeof vi.fn>
  markDraining: ReturnType<typeof vi.fn>
  markStopped: ReturnType<typeof vi.fn>
}
let runtime: {
  pool: { end: ReturnType<typeof vi.fn> }
  worker: { start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn> }
  workerId: string
  tenantId: string
  tuning: {
    drainMs: number
    concurrency: number
    pollIntervalMs: number
    leaseMs: number
  }
}

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  vi.useFakeTimers()
  previousExitCode = process.exitCode
  process.exitCode = 0
  root = mkdtempSync(join(tmpdir(), 'cvg-aud06-worker-main-'))
  shutdown = undefined
  vi.stubEnv('NODE_ENV', 'test')
  for (const key of [
    'ENABLE_REAL_CHANNELS',
    'ENABLE_REAL_RAG',
    'ENABLE_REAL_PAYMENTS',
    'ENABLE_REAL_MEDICAL_RECORDS'
  ])
    vi.stubEnv(key, 'false')
  vi.stubEnv('CVG_TELEMETRY_MODE', 'local_file')
  vi.stubEnv('CVG_TELEMETRY_PROFILE', 'CONTROLLED_LOCAL_SYNTHETIC')
  vi.stubEnv('CVG_TELEMETRY_ROOT', root)
  vi.stubEnv('CVG_WORKER_QUEUE_ADAPTER', 'postgres-controlled')
  vi.stubEnv('CVG_WORKER_RUN_MODE', 'continuous')
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
  vi.spyOn(process, 'exit').mockImplementation(() => undefined as never)
  health = {
    markReady: vi.fn(async () => {}),
    markDraining: vi.fn(async () => {}),
    markStopped: vi.fn(async () => {})
  }
  runtime = {
    pool: { end: vi.fn(async () => {}) },
    worker: {
      start: vi.fn(() => {
        telemetry.metric('synthetic.worker_started', 1)
      }),
      stop: vi.fn(async () => {
        telemetry.log('synthetic.worker_stopped', { operation: 'synthetic' })
        return { drained: true, released: 0, releaseFailed: 0 }
      })
    },
    workerId: 'synthetic-worker',
    tenantId: 'tenant_00000000-0000-4000-8000-000000000001',
    tuning: {
      drainMs: 1_000,
      concurrency: 1,
      pollIntervalMs: 100,
      leaseMs: 30_000
    }
  }
  seams.startup.mockReturnValue(null)
  seams.preflight.mockResolvedValue(undefined)
  seams.health.mockResolvedValue(health)
  seams.create.mockImplementation(
    (_env, options: { telemetry: WorkerTelemetry }) => {
      telemetry = options.telemetry
      return runtime
    }
  )
  seams.shutdown.mockImplementation((options: ShutdownControllerOptions) => {
    shutdown = options
    return { install: seams.install }
  })
})

afterEach(async () => {
  await Promise.resolve()
    .then(() => shutdown?.close())
    .catch(() => undefined)
  process.exitCode = previousExitCode
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  rmSync(root, { recursive: true, force: true })
})

describe('AUD06 durable worker entrypoint telemetry composition', () => {
  it('exports through the actual sanitized collector sink and drains after stopping the worker', async () => {
    await import('../main.ts')
    await vi.waitFor(() => expect(seams.install).toHaveBeenCalled())
    telemetry.log('synthetic.worker', {
      operation: 'synthetic',
      tenantId: 'SENSITIVE-TENANT',
      payload: 'SENSITIVE-PAYLOAD'
    })
    telemetry.metric('synthetic.worker_count', 1, {
      outcome: 'processed',
      provider: 'SENSITIVE-PROVIDER'
    })
    await vi.advanceTimersByTimeAsync(1_000)
    const output = readFileSync(join(root, 'worker.jsonl'), 'utf8')
    expect(output).toContain('synthetic.worker_count')
    expect(output).toContain('worker.continuous_ready')
    expect(output).not.toContain('SENSITIVE-')
    await shutdown!.close()
    const final = readFileSync(join(root, 'worker.jsonl'), 'utf8')
    expect(final).toContain('synthetic.worker_stopped')
    expect(final).toContain('worker.continuous_drained')
    expect(runtime.pool.end).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
    shutdown!.log?.({ type: 'shutdown.completed', signal: 'SIGTERM', code: 0 })
    expect(console.error).toHaveBeenCalledWith(
      JSON.stringify({
        event: 'worker.shutdown.completed',
        signal: 'SIGTERM',
        code: 0
      })
    )
  })

  it('retains the JSON sink when export is disabled', async () => {
    vi.stubEnv('CVG_TELEMETRY_MODE', undefined)
    await import('../main.ts')
    await vi.waitFor(() => expect(seams.install).toHaveBeenCalled())
    expect(process.stdout.write).toHaveBeenCalled()
    expect(readdirSync(root)).toEqual([])
    await shutdown!.close()
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['invalid', 'production', 'unsupported_mode'])(
    'fails closed for %s before opening the durable runtime',
    async (kind) => {
      if (kind === 'invalid')
        vi.stubEnv('CVG_TELEMETRY_ROOT', join(root, 'SENSITIVE-MISSING'))
      if (kind === 'production') vi.stubEnv('NODE_ENV', 'production')
      if (kind === 'unsupported_mode')
        vi.stubEnv('CVG_WORKER_RUN_MODE', undefined)
      await import('../main.ts')
      expect(process.exitCode).toBe(1)
      expect(seams.create).not.toHaveBeenCalled()
      expect(console.error).toHaveBeenCalledWith(
        JSON.stringify({
          event: 'worker.startup_failed',
          code: 'telemetry_configuration_invalid',
          message: 'Runtime telemetry configuration is invalid'
        })
      )
      expect(vi.getTimerCount()).toBe(0)
    }
  )

  it.each(['create', 'health', 'preflight', 'ready'])(
    'cleans up the collector on %s startup failure',
    async (phase) => {
      if (phase === 'create')
        seams.create.mockImplementationOnce(() => {
          throw new Error('Synthetic create failure')
        })
      if (phase === 'health')
        seams.health.mockRejectedValueOnce(
          new Error('Synthetic health failure')
        )
      if (phase === 'preflight')
        seams.preflight.mockRejectedValueOnce(
          new Error('Synthetic preflight failure')
        )
      if (phase === 'ready')
        health.markReady.mockRejectedValueOnce(
          new Error('Synthetic ready failure')
        )
      await import('../main.ts')
      await vi.waitFor(() => expect(process.exitCode).toBe(1))
      if (phase !== 'create') expect(runtime.pool.end).toHaveBeenCalledTimes(1)
      expect(vi.getTimerCount()).toBe(0)
    }
  )

  it.each(['health', 'stop', 'pool'])(
    'still drains telemetry when %s fails during shutdown',
    async (phase) => {
      await import('../main.ts')
      await vi.waitFor(() => expect(seams.install).toHaveBeenCalled())
      if (phase === 'health')
        health.markDraining.mockRejectedValueOnce(
          new Error('Synthetic shutdown failure')
        )
      if (phase === 'stop')
        runtime.worker.stop.mockRejectedValueOnce(
          new Error('Synthetic shutdown failure')
        )
      if (phase === 'pool')
        runtime.pool.end.mockRejectedValueOnce(
          new Error('Synthetic shutdown failure')
        )
      telemetry.log('synthetic.before_shutdown')
      await expect(shutdown!.close()).rejects.toThrow(
        'Synthetic shutdown failure'
      )
      expect(runtime.pool.end).toHaveBeenCalledTimes(1)
      expect(readFileSync(join(root, 'worker.jsonl'), 'utf8')).toContain(
        'synthetic.before_shutdown'
      )
      expect(vi.getTimerCount()).toBe(0)
    }
  )
})
