// @vitest-environment node
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import {
  mkdtempSync,
  readFileSync,
  existsSync,
  readdirSync,
  rmSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { describe, expect, it } from 'vitest'
import type { CollectorExport } from '@cvg/observability'

async function unusedPort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>((resolve, reject) => {
    probe.once('error', reject)
    probe.listen(0, '127.0.0.1', resolve)
  })
  const address = probe.address()
  if (!address || typeof address === 'string')
    throw new Error('Synthetic API port unavailable')
  await new Promise<void>((resolve, reject) =>
    probe.close((error) => (error ? reject(error) : resolve()))
  )
  return address.port
}

async function eventually(
  check: () => boolean | Promise<boolean>
): Promise<void> {
  const deadline = Date.now() + 15_000
  while (Date.now() < deadline) {
    if (await check()) return
    await delay(40)
  }
  throw new Error('Synthetic API condition timed out')
}

function readBatches(root: string): CollectorExport[] {
  return readFileSync(join(root, 'api.jsonl'), 'utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as CollectorExport)
}

describe('AUD06 actual API process telemetry', () => {
  it.each([true, false])(
    'exports only when opted in (%s) and drains on real SIGTERM',
    async (enabled) => {
      const root = mkdtempSync(join(tmpdir(), 'cvg-aud06-api-process-'))
      const port = await unusedPort()
      // No inherited application secrets, database URL, provider or real flags.
      const env: NodeJS.ProcessEnv = {
        PATH: process.env.PATH,
        NODE_ENV: 'test',
        PORT: String(port),
        API_PERSISTENCE_MODE: 'memory',
        API_IDENTITY_MODE: 'legacy',
        ENABLE_REAL_CHANNELS: 'false',
        ENABLE_REAL_RAG: 'false',
        ENABLE_REAL_PAYMENTS: 'false',
        ENABLE_REAL_MEDICAL_RECORDS: 'false',
        CVG_TELEMETRY_PROFILE: 'CONTROLLED_LOCAL_SYNTHETIC',
        CVG_TELEMETRY_ROOT: root,
        ...(enabled ? { CVG_TELEMETRY_MODE: 'local_file' } : {})
      }
      const child = spawn(
        process.execPath,
        ['--import', 'tsx', 'apps/api/src/main.ts'],
        {
          cwd: process.cwd(),
          env,
          stdio: ['ignore', 'pipe', 'pipe']
        }
      )
      let output = ''
      child.stdout.on('data', (chunk) => {
        output += String(chunk)
      })
      child.stderr.on('data', (chunk) => {
        output += String(chunk)
      })
      const exited = new Promise<{
        code: number | null
        signal: NodeJS.Signals | null
      }>((resolve, reject) => {
        child.once('error', reject)
        child.once('close', (code, signal) => resolve({ code, signal }))
      })
      const base = `http://127.0.0.1:${port}`
      try {
        await eventually(async () => {
          if (child.exitCode !== null)
            throw new Error(`Synthetic API startup failed: ${output}`)
          try {
            return (
              await fetch(`${base}/live`, {
                signal: AbortSignal.timeout(500)
              })
            ).ok
          } catch {
            return false
          }
        })
        const send = async (id: string) => {
          const response = await fetch(
            `${base}/v1/webhooks/channels/whatsapp/messages`,
            {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({
                externalMessageId: id,
                senderRef: 'synthetic-aud06-sender',
                body: 'SENSITIVE-AUD06-CANARY',
                receivedAt: '2026-10-06T12:00:00.000Z'
              }),
              signal: AbortSignal.timeout(3_000)
            }
          )
          expect(response.ok, await response.text()).toBe(true)
        }
        await send('aud06-process-first')
        if (enabled) {
          await eventually(() => existsSync(join(root, 'api.jsonl')))
          expect(
            readBatches(root)
              .flatMap((batch) => batch.logs)
              .some((log) => log.event === 'inbound.accepted')
          ).toBe(true)
          expect(child.exitCode).toBeNull()
        } else {
          await delay(1_100)
          expect(readdirSync(root)).toEqual([])
        }
        await send('aud06-process-last')
        child.kill('SIGTERM')
        await eventually(() => child.exitCode !== null)
        expect(await exited).toEqual({ code: 0, signal: null })
        expect(output).toContain('shutdown.completed')
        if (enabled) {
          const batches = readBatches(root)
          expect(
            batches
              .flatMap((batch) => batch.logs)
              .filter((log) => log.event === 'inbound.accepted')
          ).toHaveLength(2)
          expect(readFileSync(join(root, 'api.jsonl'), 'utf8')).not.toContain(
            'SENSITIVE-'
          )
          console.log(
            JSON.stringify({
              check: 'api-process-telemetry',
              mode: 'local_file',
              batches: batches.length,
              inboundRecords: 2,
              canaryAbsent: true,
              shutdownExit: 0
            })
          )
        } else {
          expect(readdirSync(root)).toEqual([])
          console.log(
            JSON.stringify({
              check: 'api-process-telemetry',
              mode: 'disabled',
              files: 0,
              shutdownExit: 0
            })
          )
        }
      } finally {
        if (child.exitCode === null && child.signalCode === null)
          child.kill('SIGKILL')
        await exited.catch(() => undefined)
        rmSync(root, { recursive: true, force: true })
      }
    },
    25_000
  )
})
