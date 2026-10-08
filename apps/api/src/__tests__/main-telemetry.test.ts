// @vitest-environment node
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ObservabilityCollectorPort } from '@cvg/observability'
import type { ShutdownControllerOptions } from '@cvg/shared'

const seams = vi.hoisted(() => ({
  build: vi.fn(),
  shutdown: vi.fn(),
  install: vi.fn(),
  preflight: vi.fn(),
  identity: vi.fn()
}))
vi.mock('../server.ts', () => ({ buildServerFromEnv: seams.build }))
vi.mock('../operator-identity.ts', () => ({
  createConfiguredOperatorIdentityResolver: seams.identity
}))
vi.mock('../../../../scripts/lib/production-preflight-core.mjs', () => ({
  assertProductionBootstrap: seams.preflight
}))
vi.mock('@cvg/shared', async (original) => ({
  ...(await original<typeof import('@cvg/shared')>()),
  createShutdownController: seams.shutdown
}))

let root: string
let collector: ObservabilityCollectorPort | undefined
let shutdown: ShutdownControllerOptions | undefined
let app: { listen: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> }

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  vi.useFakeTimers()
  root = mkdtempSync(join(tmpdir(), 'cvg-aud06-api-main-'))
  collector = undefined
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
  vi.stubEnv('API_TRUSTED_PROXY_HOPS', '0')
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(process, 'exit').mockImplementation(() => undefined as never)
  app = {
    listen: vi.fn(async () => {}),
    close: vi.fn(async () => {
      // Same lifecycle as the existing API onClose hook.
      if (collector) await collector.flush().finally(() => collector?.close())
    })
  }
  seams.build.mockImplementation(
    async (
      _env,
      options: { runtimeCollector?: ObservabilityCollectorPort }
    ) => {
      collector = options.runtimeCollector
      return app
    }
  )
  seams.shutdown.mockImplementation((options: ShutdownControllerOptions) => {
    shutdown = options
    return { install: seams.install }
  })
})

afterEach(async () => {
  await collector?.close().catch(() => undefined)
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  rmSync(root, { recursive: true, force: true })
})

describe('AUD06 API entrypoint telemetry composition', () => {
  it('injects the real collector, exports while running and drains on shutdown', async () => {
    await import('../main.ts')
    await vi.waitFor(() => expect(app.listen).toHaveBeenCalledTimes(1))
    expect(collector?.enabled).toBe(true)
    collector!.recordLog({
      level: 'info',
      message: 'synthetic.api',
      fields: { operation: 'synthetic', token: 'SENSITIVE-TOKEN' },
      timestamp: new Date().toISOString()
    })
    await vi.advanceTimersByTimeAsync(1_000)
    const first = readFileSync(join(root, 'api.jsonl'), 'utf8')
    expect(first).toContain('synthetic.api')
    expect(first).not.toContain('SENSITIVE-')
    collector!.recordLog({
      level: 'info',
      message: 'synthetic.last',
      fields: {},
      timestamp: new Date().toISOString()
    })
    await shutdown!.close()
    expect(readFileSync(join(root, 'api.jsonl'), 'utf8')).toContain(
      'synthetic.last'
    )
    expect(app.close).toHaveBeenCalledTimes(1)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('leaves export disabled by default', async () => {
    vi.stubEnv('CVG_TELEMETRY_MODE', undefined)
    await import('../main.ts')
    await vi.waitFor(() => expect(app.listen).toHaveBeenCalledTimes(1))
    expect(collector).toBeUndefined()
    expect(readdirSync(root)).toEqual([])
    await shutdown!.close()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('refuses invalid telemetry before constructing a server, with a generic error', async () => {
    vi.stubEnv('CVG_TELEMETRY_ROOT', join(root, 'SENSITIVE-MISSING'))
    await import('../main.ts')
    await vi.waitFor(() => expect(process.exit).toHaveBeenCalledWith(1))
    expect(seams.build).not.toHaveBeenCalled()
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).toContain(
      'Runtime telemetry configuration is invalid'
    )
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(
      root
    )
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each(['build', 'listen', 'close'])(
    'cleans up the exporter after a %s failure',
    async (phase) => {
      if (phase === 'build')
        seams.build.mockRejectedValueOnce(new Error('Synthetic build failure'))
      if (phase === 'listen')
        app.listen.mockRejectedValueOnce(new Error('Synthetic listen failure'))
      if (phase === 'close')
        app.close.mockRejectedValueOnce(new Error('Synthetic close failure'))
      await import('../main.ts')
      if (phase === 'close') {
        await vi.waitFor(() => expect(app.listen).toHaveBeenCalled())
        collector!.recordLog({
          level: 'info',
          message: 'synthetic.cleanup',
          fields: {},
          timestamp: new Date().toISOString()
        })
        await expect(shutdown!.close()).rejects.toThrow(
          'Synthetic close failure'
        )
        expect(readFileSync(join(root, 'api.jsonl'), 'utf8')).toContain(
          'synthetic.cleanup'
        )
      } else {
        await vi.waitFor(() => expect(process.exit).toHaveBeenCalledWith(1))
      }
      expect(vi.getTimerCount()).toBe(0)
    }
  )
})
